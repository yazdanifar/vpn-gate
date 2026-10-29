//! Drives the daemon for the UI: feeds events into the [`AppModel`], sends connect/disconnect, loads the server list and
//! retries list connections (the daemon makes a single attempt; `MainViewModel.cs` does the same on Windows).
//! Everything runs on the caller's tokio runtime; the UI is told about changes through `notify` and reads the model.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::UnboundedReceiver;
use uuid::Uuid;
use vpngate_core::client_account::{AccountAuthType, ConnectOptions};
use vpngate_core::ipc::{ConnectionState, HelperEvent, HelperRequest, ProbeTarget, ProxyKind, ProxySettings};
use vpngate_core::server_list::VpnServer;
use vpngate_ipc_client::{ClientError, ClientEvent, IpcClient};

use crate::accounts::AccountStore;
use crate::history::History;
use crate::model::{AppModel, Probe};
use crate::secrets::SecretStore;
use crate::settings::{Settings, SettingsStore, PROXY_PASSWORD_KEY};

/// Everything the controller persists besides the settings.
pub struct Stores {
    pub accounts: AccountStore,
    pub history: History,
    pub secrets: Arc<dyn SecretStore>,
}

impl Stores {
    /// Nothing touches the real config directory or keyring (tests).
    pub fn memory() -> Stores {
        let secrets: Arc<dyn SecretStore> = Arc::new(crate::secrets::MemorySecrets::default());
        let path = std::env::temp_dir().join(format!("vg-mem-{}/accounts.json", Uuid::new_v4()));
        Stores { accounts: AccountStore::new(path, secrets.clone()), history: History::new(None), secrets }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// List connections are retried this long after the daemon reports a drop.
    pub reconnect_delay: Duration,
    /// A daemon that accepts the socket but never answers must not leave the UI on "Connecting…" forever.
    pub answer_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing { reconnect_delay: Duration::from_secs(15), answer_timeout: Duration::from_secs(10) }
    }
}

#[derive(Default)]
struct Flow {
    /// The list server the user asked for; cleared by Disconnect and by a failed start.
    wanted: Option<String>,
    /// A connect parked behind the disclaimer.
    parked: Option<String>,
    last_server: Option<String>,
    /// Identifies the pending reconnect timer.
    reconnect: Option<u64>,
    reconnect_seq: u64,
    attempts: u32,
    connect_seq: u64,
    last_event_at_ms: u64,
    loading: bool,
    /// The history entry of the connected period in progress.
    history_id: Option<Uuid>,
    testing: bool,
}

struct Inner {
    ipc: IpcClient,
    model: Mutex<AppModel>,
    settings: Mutex<Settings>,
    store: Box<dyn SettingsStore>,
    stores: Mutex<Stores>,
    flow: Mutex<Flow>,
    timing: Timing,
    notify: Box<dyn Fn() + Send + Sync>,
    quit: Box<dyn Fn() + Send + Sync>,
}

#[derive(Clone)]
pub struct Controller(Arc<Inner>);

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

impl Controller {
    /// `notify` is called (from any thread) after every change of the model; `quit` when the user declines the disclaimer.
    pub fn new(
        ipc: IpcClient,
        store: Box<dyn SettingsStore>,
        stores: Stores,
        timing: Timing,
        notify: impl Fn() + Send + Sync + 'static,
        quit: impl Fn() + Send + Sync + 'static,
    ) -> Controller {
        let settings = store.load();
        let model = AppModel::new(settings.has_agreed_to_disclaimer, settings.favorites.iter().cloned());
        Controller(Arc::new(Inner {
            ipc,
            model: Mutex::new(model),
            settings: Mutex::new(settings),
            store,
            stores: Mutex::new(stores),
            flow: Mutex::new(Flow::default()),
            timing,
            notify: Box::new(notify),
            quit: Box::new(quit),
        }))
    }

    pub fn read<R>(&self, f: impl FnOnce(&AppModel) -> R) -> R {
        f(&lock(&self.0.model))
    }

    /// Changes the model and tells the UI. For view-only state: filter, sort, selection.
    pub fn change<R>(&self, f: impl FnOnce(&mut AppModel) -> R) -> R {
        let r = f(&mut lock(&self.0.model));
        (self.0.notify)();
        r
    }

    pub fn settings(&self) -> Settings {
        lock(&self.0.settings).clone()
    }

    pub fn update_settings(&self, f: impl FnOnce(&mut Settings)) {
        let mut s = lock(&self.0.settings);
        f(&mut s);
        let _ = self.0.store.save(&s);
    }

    /// The accounts, the history and the secret store, for the UI's windows.
    pub fn with_stores<R>(&self, f: impl FnOnce(&mut Stores) -> R) -> R {
        f(&mut lock(&self.0.stores))
    }

    pub fn proxy_password(&self) -> Option<String> {
        self.with_stores(|s| s.secrets.get(PROXY_PASSWORD_KEY))
    }

    /// `false` when the secret service refused the value.
    pub fn set_proxy_password(&self, password: &str) -> bool {
        self.with_stores(|s| {
            if password.is_empty() {
                s.secrets.delete(PROXY_PASSWORD_KEY);
                true
            } else {
                s.secrets.set(PROXY_PASSWORD_KEY, password)
            }
        })
    }

    // MARK: events

    /// Handles the client's event stream until it closes.
    pub async fn pump(&self, mut rx: UnboundedReceiver<ClientEvent>) {
        while let Some(ev) = rx.recv().await {
            match ev {
                ClientEvent::Event(e) => self.handle_event(&e),
                ClientEvent::Disconnected => {
                    let pending = lock(&self.0.flow).reconnect.is_some();
                    self.change(|m| m.on_connection_dropped(pending));
                }
            }
        }
    }

    fn handle_event(&self, e: &HelperEvent) {
        let now = now_ms();
        let pending = {
            let mut f = lock(&self.0.flow);
            f.last_event_at_ms = now;
            f.reconnect.is_some()
        };
        let (was_in, was_out) = self.read(|m| (m.bytes_in, m.bytes_out));
        self.change(|m| m.apply_event(e, now, pending));
        if e.state == ConnectionState::Connected {
            lock(&self.0.flow).attempts = 0;
            self.history_start(now);
        } else if e.state == ConnectionState::Disconnected {
            self.history_end(now, was_in.max(e.bytes_in), was_out.max(e.bytes_out), e.error.clone());
            self.consider_reconnect();
        }
    }

    fn history_start(&self, now: u64) {
        if lock(&self.0.flow).history_id.is_some() {
            return;
        }
        let (name, ip) = self.read(|m| (m.server_name().unwrap_or_default(), m.server.clone().unwrap_or_default()));
        let id = self.with_stores(|s| s.history.record_start(&name, &ip, now));
        lock(&self.0.flow).history_id = Some(id);
        self.change(|_| {});
    }

    fn history_end(&self, now: u64, bytes_in: u64, bytes_out: u64, error: Option<String>) {
        let Some(id) = lock(&self.0.flow).history_id.take() else { return };
        self.with_stores(|s| s.history.record_end(id, bytes_in, bytes_out, error, now));
    }

    // MARK: reconnect

    fn consider_reconnect(&self) {
        let auto = lock(&self.0.settings).auto_reconnect;
        let (server, token, attempt) = {
            let mut f = lock(&self.0.flow);
            let Some(id) = f.wanted.clone().filter(|_| auto && f.reconnect.is_none()) else { return };
            let Some(server) = self.read(|m| m.find(&id).cloned()) else { return };
            f.attempts += 1;
            f.reconnect_seq += 1;
            f.reconnect = Some(f.reconnect_seq);
            (server, f.reconnect_seq, f.attempts)
        };
        let delay = self.0.timing.reconnect_delay;
        self.change(|m| {
            m.append_log(format!(
                "Reconnecting to {} in {} s (attempt {attempt})",
                server.host_name,
                delay.as_secs_f64().ceil() as u64
            ));
            m.state = ConnectionState::Reconnecting;
            m.server = Some(server.ip.clone());
        });
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let go = {
                let mut f = lock(&this.0.flow);
                if f.reconnect != Some(token) {
                    return;
                }
                f.reconnect = None;
                f.wanted.as_deref() == Some(server.id())
            };
            if go && this.read(|m| m.state) == ConnectionState::Reconnecting {
                this.send_connect(server).await;
            } else if this.read(|m| m.state) == ConnectionState::Reconnecting {
                this.change(|m| m.state = ConnectionState::Disconnected);
            }
        });
    }

    fn cancel_reconnect(&self) {
        lock(&self.0.flow).reconnect = None;
    }

    // MARK: commands

    /// Every 2 s: asks the daemon for a snapshot, or notices it is gone.
    pub async fn poll(&self) {
        let up = self.0.ipc.status().await;
        let pending = lock(&self.0.flow).reconnect.is_some();
        self.change(|m| {
            m.service_running = up;
            if !up && m.state != ConnectionState::Disconnected && !pending {
                m.state = ConnectionState::Disconnected;
            }
        });
    }

    pub async fn start(&self) {
        self.poll().await;
        self.load_list().await;
    }

    pub fn select(&self, id: Option<String>) {
        self.change(|m| m.selected = id);
    }

    /// The bottom-bar button: connect the selection when disconnected, otherwise disconnect / cancel.
    pub async fn primary_action(&self) {
        if self.read(|m| m.state) == ConnectionState::Disconnected {
            if let Some(id) = self.read(|m| m.selected.clone()) {
                self.connect(&id).await;
            }
        } else {
            self.disconnect().await;
        }
    }

    pub async fn connect(&self, id: &str) {
        let Some(server) = self.read(|m| m.find(id).cloned()) else { return };
        if !self.change(|m| m.require_agreement()) {
            lock(&self.0.flow).parked = Some(id.to_string());
            return;
        }
        self.cancel_reconnect();
        {
            let mut f = lock(&self.0.flow);
            f.wanted = Some(id.to_string());
            f.last_server = Some(id.to_string());
            f.attempts = 0;
        }
        self.change(|m| {
            m.notice = None;
            m.active_account = None;
        });
        self.send_connect(server).await;
    }

    /// Connects with one of the user's own accounts (UI-SPEC 5). The daemon reconnects by itself when the account says so.
    pub async fn connect_account(&self, id: Uuid) {
        let Some(account) = self.with_stores(|s| s.accounts.find(id).cloned()) else { return };
        if !self.change(|m| m.require_agreement()) {
            return;
        }
        self.cancel_reconnect();
        {
            let mut f = lock(&self.0.flow);
            f.wanted = None;
            f.last_server = None;
        }
        self.change(|m| m.notice = None);
        let (cert, key, password, proxy_pw) = self.with_stores(|s| {
            (
                s.accounts.certificate(&account),
                s.accounts.private_key(&account),
                s.accounts.password(&account),
                s.accounts.proxy_password(&account),
            )
        });
        if account.auth_type == AccountAuthType::Certificate && (cert.is_none() || key.is_none()) {
            self.change(|m| {
                m.notice = Some(format!(
                    "“{}” needs a certificate and RSA private key. Open its properties and import them.",
                    account.name
                ))
            });
            return;
        }
        let settings = self.settings();
        let mut acc = account.clone();
        if acc.proxy.kind != ProxyKind::None && acc.proxy.password.is_none() {
            acc.proxy.password = proxy_pw;
        }
        let cfg = acc.to_connect_config(ConnectOptions {
            password,
            cert_der: cert,
            private_key_der: key,
            block_ipv6: settings.block_ipv6,
            global_routing: Some(settings.routing.clone()).filter(|r| !r.is_empty()),
            tunnel_mode: settings.tunnel_mode,
            socks_port: settings.socks_port,
        });
        let mut r = HelperRequest::new("connect");
        r.config = Some(cfg);
        self.change(|m| m.active_account = Some(account.id));
        self.dispatch(r, account.host.clone(), None).await;
    }

    /// Connects to the last list server again.
    pub async fn reconnect_last(&self) {
        let last = lock(&self.0.flow).last_server.clone();
        if let Some(id) = last {
            self.connect(&id).await;
        }
    }

    pub async fn disconnect(&self) {
        {
            let mut f = lock(&self.0.flow);
            f.wanted = None;
            f.reconnect = None;
        }
        self.change(|m| {
            if m.state == ConnectionState::Reconnecting {
                m.state = ConnectionState::Disconnected;
            }
        });
        self.0.ipc.disconnect_vpn().await;
    }

    pub async fn agree(&self) {
        self.update_settings(|s| s.has_agreed_to_disclaimer = true);
        self.change(|m| m.agree());
        let parked = lock(&self.0.flow).parked.take();
        if let Some(id) = parked {
            self.connect(&id).await;
        }
    }

    pub fn disagree(&self) {
        lock(&self.0.flow).parked = None;
        (self.0.quit)();
    }

    pub fn toggle_favorite(&self, id: &str) {
        let now_favorite = self.change(|m| m.toggle_favorite(id));
        self.update_settings(|s| {
            if now_favorite {
                s.favorites.insert(id.to_string());
            } else {
                s.favorites.remove(id);
            }
        });
    }

    async fn send_connect(&self, s: VpnServer) {
        let settings = self.settings();
        let mut r = HelperRequest::new("connect");
        r.host = Some(s.ip.clone());
        r.port = s.connect_port();
        let ports = s.prioritized_ssl_ports();
        if !ports.is_empty() {
            r.ports = Some(ports.into_iter().map(i64::from).collect());
        }
        r.proxy = Some(self.proxy_settings(&settings));
        // Retrying is done here (consider_reconnect), so the daemon makes a single attempt.
        r.auto_reconnect = Some(false);
        r.block_ipv6 = Some(settings.block_ipv6);
        r.routing = Some(settings.routing.clone()).filter(|r| !r.is_empty());
        r.tunnel_mode = Some(settings.tunnel_mode);
        r.socks_port = Some(settings.socks_port);
        self.dispatch(r, s.ip.clone(), Some(s.id().to_string())).await;
    }

    /// The proxy of Settings → Proxy; credentials travel only when a user name is set.
    fn proxy_settings(&self, s: &Settings) -> ProxySettings {
        if s.proxy_kind == ProxyKind::None {
            return ProxySettings::default();
        }
        let user = Some(s.proxy_username.clone()).filter(|u| !u.is_empty());
        ProxySettings {
            kind: s.proxy_kind,
            host: s.proxy_host.trim().to_string(),
            port: s.proxy_port,
            password: user.as_ref().and_then(|_| self.proxy_password()),
            username: user,
        }
    }

    /// Sends a connect request and watches for a silent daemon. `list_id`: the list server being connected (None for
    /// accounts), which the watchdog checks against `wanted`.
    async fn dispatch(&self, r: HelperRequest, ip: String, list_id: Option<String>) {
        let (seq, sent_at) = {
            let mut f = lock(&self.0.flow);
            f.connect_seq += 1;
            (f.connect_seq, now_ms())
        };
        // Optimistic: the daemon's events may arrive before the send returns, and must not be overwritten afterwards.
        self.change(|m| {
            m.state = ConnectionState::Connecting;
            m.server = Some(ip.clone());
        });
        if !self.0.ipc.send(&r).await {
            lock(&self.0.flow).wanted = None;
            self.change(|m| {
                m.service_running = false;
                m.state = ConnectionState::Disconnected;
                m.active_account = None;
                m.notice = Some(
                    "The VPN Gate service is not running. Start it with “sudo systemctl start vpngate” or reinstall VPN Gate."
                        .into(),
                );
                m.append_log("Cannot reach the VPN Gate service".into());
            });
            return;
        }
        tokio::time::sleep(self.0.timing.answer_timeout).await;
        let silent = {
            let f = lock(&self.0.flow);
            f.last_event_at_ms < sent_at && f.connect_seq == seq && f.wanted == list_id
        };
        if silent && self.read(|m| m.state) == ConnectionState::Connecting {
            lock(&self.0.flow).wanted = None;
            let secs = self.0.timing.answer_timeout.as_secs();
            self.change(|m| {
                m.state = ConnectionState::Disconnected;
                m.active_account = None;
                m.notice = Some(
                    "The VPN Gate service is not responding. Restart it with “sudo systemctl restart vpngate”.".into(),
                );
                m.append_log(format!("No answer from the service within {secs} s"));
            });
        }
    }

    // MARK: test connection

    /// Servers per `probe` request: the daemon tests them concurrently, and results show up batch by batch.
    const PROBE_BATCH: usize = 8;

    /// "Test Connection": a real SoftEther handshake with every server in the current view.
    pub async fn test_connections(&self) {
        {
            let mut f = lock(&self.0.flow);
            if std::mem::replace(&mut f.testing, true) {
                return;
            }
        }
        let targets: Vec<(String, ProbeTarget)> = self.read(|m| {
            m.servers()
                .iter()
                .map(|s| {
                    let ports: Vec<i64> = s.prioritized_ssl_ports().into_iter().map(i64::from).collect();
                    (
                        s.id().to_string(),
                        ProbeTarget { host: s.ip.clone(), ports: Some(ports).filter(|p| !p.is_empty()) },
                    )
                })
                .collect()
        });
        self.change(|m| {
            for (id, _) in &targets {
                m.set_probe(id, Probe::Queued);
            }
        });
        let proxy = self.proxy_settings(&self.settings());
        for batch in targets.chunks(Self::PROBE_BATCH) {
            self.change(|m| {
                for (id, _) in batch {
                    m.set_probe(id, Probe::Testing);
                }
            });
            let result = self.0.ipc.probe(batch.iter().map(|b| b.1.clone()).collect(), Some(proxy.clone()), None).await;
            self.change(|m| match &result {
                Ok(r) => {
                    for (entry, (id, _)) in r.results.iter().zip(batch) {
                        let p = match (entry.ok, entry.connect_ms) {
                            (true, Some(connect_ms)) => {
                                Probe::Ok { connect_ms, hello_ms: entry.hello_ms, port: entry.port }
                            }
                            _ => Probe::Failed(entry.error.clone().unwrap_or_else(|| "failed".into())),
                        };
                        m.set_probe(id, p);
                    }
                }
                Err(e) => {
                    for (id, _) in batch {
                        m.set_probe(id, Probe::Failed(e.to_string()));
                    }
                }
            });
        }
        lock(&self.0.flow).testing = false;
        self.change(|_| {});
    }

    pub fn is_testing(&self) -> bool {
        lock(&self.0.flow).testing
    }

    // MARK: list

    /// The daemon's cached or shipped list; downloads when it has none.
    pub async fn load_list(&self) {
        match self.0.ipc.list_servers().await {
            Ok(r) => self.change(|m| m.apply_list(r)),
            Err(ClientError::Rejected(_)) => self.refresh().await,
            Err(e) => self.change(|m| m.list_error = Some(e.to_string())),
        }
    }

    pub async fn refresh(&self) {
        {
            let mut f = lock(&self.0.flow);
            if std::mem::replace(&mut f.loading, true) {
                return;
            }
        }
        self.change(|m| {
            m.is_loading = true;
            m.list_error = None;
        });
        let mirror = Some(self.settings().mirror_url.trim().to_string()).filter(|u| !u.is_empty());
        let result = self.0.ipc.refresh_servers(Some(ProxySettings::default()), mirror).await;
        lock(&self.0.flow).loading = false;
        self.change(|m| {
            m.is_loading = false;
            match result {
                Ok(r) => m.apply_list(r),
                Err(e) => m.list_error = Some(e.to_string()),
            }
        });
    }
}

#[cfg(test)]
mod tests;
