//! The thick-engine requests of IPC v9: server lists, dat sync, relay probes and account validation. Everything here is
//! network or file work with no root-only effects, so it is shared by every platform's daemon.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use vpngate_core::client_account::ConnectOptions;
use vpngate_core::ipc::{
    HelperRequest, ProbeEntry, ProbeResult, ProbeTarget, ProxySettings, ServerListResult, SyncResult, ValidateResult,
};
use vpngate_core::server_list::VpnServer;
use vpngate_core::validation;
use vpngate_net::dat_fetcher::{DatFetcher, DatFetcherConfig, ServerFetchResult};
use vpngate_net::entropy::{Entropy, SystemEntropy};
use vpngate_net::probe::{self, ProbeOutcome};
use vpngate_net::session::tls_stream_factory;
use vpngate_net::stream::StreamFactory;

use crate::validate::{validate, validate_proxy};

/// The most relays one `probe` request may name.
pub const MAX_PROBE_TARGETS: usize = 200;
/// Relays tested at the same time.
pub const PROBE_CONCURRENCY: usize = 8;
pub const DEFAULT_PROBE_TIMEOUT_SECONDS: f64 = 8.0;
const MIN_PROBE_TIMEOUT_SECONDS: f64 = 1.0;
const MAX_PROBE_TIMEOUT_SECONDS: f64 = 60.0;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Engine {
    fetcher: DatFetcher,
    probe_streams: StreamFactory,
    /// One sync at a time: a second request waits and then answers from the first one's cache.
    sync_lock: AsyncMutex<()>,
    /// The servers of the last list, which are the relays the next sync asks for the new one.
    current: Mutex<Vec<VpnServer>>,
}

impl Engine {
    pub fn new(fetcher: DatFetcher, probe_streams: StreamFactory) -> Self {
        Engine { fetcher, probe_streams, sync_lock: AsyncMutex::new(()), current: Mutex::new(Vec::new()) }
    }

    /// The real network, with the list kept at `cache_path` and `bundle_paths` as the shipped fallback.
    pub fn production(cache_path: PathBuf, bundle_paths: Vec<PathBuf>) -> Self {
        let mut config = DatFetcherConfig::new(cache_path);
        config.bundle_paths = bundle_paths;
        let streams = tls_stream_factory(&vpngate_core::ipc::ConnectConfig::new(""));
        Engine::new(DatFetcher::new(streams.clone(), config), streams)
    }

    fn remember(&self, servers: &[VpnServer]) {
        if !servers.is_empty() {
            *lock(&self.current) = servers.to_vec();
        }
    }

    fn known_servers(&self) -> Vec<VpnServer> {
        let current = lock(&self.current).clone();
        if !current.is_empty() {
            return current;
        }
        self.fetcher.stored().map(|r| r.servers).unwrap_or_default()
    }

    fn list_result(&self, r: ServerFetchResult, next_poll: Option<f64>) -> ServerListResult {
        ServerListResult {
            servers: r.servers,
            source: r.source,
            timestamp_ms: r.timestamp_ms,
            is_fresh: r.is_fresh,
            outcome: r.outcome,
            next_poll_seconds: next_poll,
        }
    }

    /// `listServers`: what the daemon already holds (cache or the shipped list), no network.
    pub fn list_servers(&self) -> Result<ServerListResult, String> {
        let r = self.fetcher.stored().ok_or("No server list stored yet; send refreshServers")?;
        self.remember(&r.servers);
        Ok(self.list_result(r, None))
    }

    async fn sync(&self, proxy: &ProxySettings, mirror: Option<&str>) -> (ServerFetchResult, f64) {
        let _one_at_a_time = self.sync_lock.lock().await;
        let r = self.fetcher.sync(self.known_servers(), proxy, mirror).await;
        self.remember(&r.servers);
        let random = SystemEntropy.bytes(8).try_into().expect("8 bytes");
        let delay = self.fetcher.next_poll_delay(r.outcome, u64::from_le_bytes(random));
        (r, delay.as_secs_f64())
    }

    /// `refreshServers`: the whole sync pipeline, with the servers.
    pub async fn refresh_servers(
        &self,
        proxy: &ProxySettings,
        mirror: Option<&str>,
    ) -> Result<ServerListResult, String> {
        let (r, next) = self.sync(proxy, mirror).await;
        Ok(self.list_result(r, Some(next)))
    }

    /// `syncDat`: the same sync, answering with its metadata only.
    pub async fn sync_dat(&self, proxy: &ProxySettings, mirror: Option<&str>) -> Result<SyncResult, String> {
        let (r, next) = self.sync(proxy, mirror).await;
        Ok(SyncResult {
            source: r.source,
            timestamp_ms: r.timestamp_ms,
            is_fresh: r.is_fresh,
            outcome: r.outcome,
            server_count: r.servers.len() as u64,
            next_poll_seconds: next,
        })
    }

    /// `probe`: tests the relays a few at a time; the answer keeps the order of the request.
    pub async fn probe(
        &self,
        targets: Vec<ProbeTarget>,
        proxy: &ProxySettings,
        timeout_seconds: f64,
    ) -> Result<ProbeResult, String> {
        let known = self.known_servers();
        let timeout =
            Duration::from_secs_f64(timeout_seconds.clamp(MIN_PROBE_TIMEOUT_SECONDS, MAX_PROBE_TIMEOUT_SECONDS));
        let gate = Arc::new(Semaphore::new(PROBE_CONCURRENCY));
        let mut tasks = Vec::with_capacity(targets.len());
        for target in targets {
            let ports = ports_for(&target, &known);
            let (gate, streams, proxy) = (gate.clone(), self.probe_streams.clone(), proxy.clone());
            tasks.push(tokio::spawn(async move {
                let _slot = gate.acquire_owned().await;
                let outcome = probe::run(&target.host, &ports, &proxy, timeout, &streams).await;
                entry(target.host, outcome)
            }));
        }
        let mut results = Vec::with_capacity(tasks.len());
        for t in tasks {
            results.push(t.await.map_err(|e| format!("probe task failed: {e}"))?);
        }
        Ok(ProbeResult { results })
    }
}

/// The ports the request names, else the relay's own (matched by host name or IP), else 443.
fn ports_for(target: &ProbeTarget, known: &[VpnServer]) -> Vec<u16> {
    if let Some(ports) = &target.ports {
        let mut p: Vec<u16> = ports.iter().filter_map(|&p| u16::try_from(p).ok()).collect();
        p.truncate(probe::MAX_PORTS);
        return p;
    }
    known.iter().find(|s| s.host_name == target.host || s.ip == target.host).map_or_else(|| vec![443], probe::ports)
}

fn entry(host: String, outcome: ProbeOutcome) -> ProbeEntry {
    let blank = ProbeEntry { host, ok: false, port: None, connect_ms: None, hello_ms: None, build: None, error: None };
    match outcome {
        ProbeOutcome::Ok { port, connect_ms, hello_ms, build } => ProbeEntry {
            ok: true,
            port: Some(port),
            connect_ms: Some(connect_ms),
            hello_ms: Some(hello_ms),
            build,
            ..blank
        },
        ProbeOutcome::Failed(m) => ProbeEntry { error: Some(m), ..blank },
        ProbeOutcome::Queued | ProbeOutcome::Testing => ProbeEntry { error: Some("Not tested".into()), ..blank },
    }
}

/// Checks a `probe` request before any socket is opened.
pub fn check_probe(r: &HelperRequest) -> Result<(Vec<ProbeTarget>, ProxySettings, f64), String> {
    let targets = r.targets.clone().filter(|t| !t.is_empty()).ok_or("probe needs at least one target")?;
    if targets.len() > MAX_PROBE_TARGETS {
        return Err(format!("too many targets (at most {MAX_PROBE_TARGETS})"));
    }
    for t in &targets {
        if !validation::is_valid_host(&t.host) {
            return Err(format!("invalid host {}", t.host));
        }
        if let Some(bad) = t.ports.iter().flatten().find(|&&p| !validation::is_valid_port(Some(p))) {
            return Err(format!("invalid port {bad}"));
        }
    }
    let proxy = check_proxy(r)?;
    let timeout = r.timeout.filter(|t| t.is_finite()).unwrap_or(DEFAULT_PROBE_TIMEOUT_SECONDS);
    Ok((targets, proxy, timeout))
}

/// The request's proxy (default: none), validated like a connect's.
pub fn check_proxy(r: &HelperRequest) -> Result<ProxySettings, String> {
    let proxy = r.proxy.clone().unwrap_or_default();
    match validate_proxy(&proxy) {
        Some(problem) => Err(problem),
        None => Ok(proxy),
    }
}

/// `validateAccount`: would a connect with this account be accepted?
pub fn validate_account(r: &HelperRequest) -> Result<ValidateResult, String> {
    let account = r.account.clone().ok_or("validateAccount needs an account")?;
    let mut connect = HelperRequest::new("connect");
    connect.config = Some(account.to_connect_config(ConnectOptions::default()));
    let error = validate(&connect);
    Ok(ValidateResult { valid: error.is_none(), error })
}

#[cfg(test)]
mod tests;
