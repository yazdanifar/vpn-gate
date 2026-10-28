//! Drives the daemon for the UI: feeds events into the [`AppModel`], sends connect/disconnect, loads the server list and
//! retries list connections (the daemon makes a single attempt; `MainViewModel.cs` does the same on Windows).
//! Everything runs on the caller's tokio runtime; the UI is told about changes through `notify` and reads the model.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::UnboundedReceiver;
use vpngate_core::ipc::{ConnectionState, HelperEvent, HelperRequest, ProxySettings, TunnelMode, DEFAULT_SOCKS_PORT};
use vpngate_core::server_list::VpnServer;
use vpngate_ipc_client::{ClientError, ClientEvent, IpcClient};

use crate::model::AppModel;
use crate::settings::{Settings, SettingsStore};

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
}

struct Inner {
    ipc: IpcClient,
    model: Mutex<AppModel>,
    settings: Mutex<Settings>,
    store: Box<dyn SettingsStore>,
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
        self.change(|m| m.apply_event(e, now, pending));
        if e.state == ConnectionState::Connected {
            lock(&self.0.flow).attempts = 0;
        } else if e.state == ConnectionState::Disconnected {
            self.consider_reconnect();
        }
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
        self.change(|m| m.notice = None);
        self.send_connect(server).await;
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
        let (seq, sent_at) = {
            let mut f = lock(&self.0.flow);
            f.connect_seq += 1;
            (f.connect_seq, now_ms())
        };
        let block_ipv6 = lock(&self.0.settings).block_ipv6;
        let mut r = HelperRequest::new("connect");
        r.host = Some(s.ip.clone());
        r.port = s.connect_port();
        let ports = s.prioritized_ssl_ports();
        if !ports.is_empty() {
            r.ports = Some(ports.into_iter().map(i64::from).collect());
        }
        r.proxy = Some(ProxySettings::default());
        // Retrying is done here (consider_reconnect), so the daemon makes a single attempt.
        r.auto_reconnect = Some(false);
        r.block_ipv6 = Some(block_ipv6);
        r.tunnel_mode = Some(TunnelMode::FullTunnel);
        r.socks_port = Some(DEFAULT_SOCKS_PORT);
        // Optimistic: the daemon's events may arrive before the send returns, and must not be overwritten afterwards.
        self.change(|m| {
            m.state = ConnectionState::Connecting;
            m.server = Some(s.ip.clone());
        });
        if !self.0.ipc.send(&r).await {
            lock(&self.0.flow).wanted = None;
            self.change(|m| {
                m.service_running = false;
                m.state = ConnectionState::Disconnected;
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
            f.last_event_at_ms < sent_at && f.connect_seq == seq && f.wanted.as_deref() == Some(s.id())
        };
        if silent && self.read(|m| m.state) == ConnectionState::Connecting {
            lock(&self.0.flow).wanted = None;
            let secs = self.0.timing.answer_timeout.as_secs();
            self.change(|m| {
                m.state = ConnectionState::Disconnected;
                m.notice = Some(
                    "The VPN Gate service is not responding. Restart it with “sudo systemctl restart vpngate”.".into(),
                );
                m.append_log(format!("No answer from the service within {secs} s"));
            });
        }
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
