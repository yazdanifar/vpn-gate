//! The main window's state: the daemon's session, the server list and the disclaimer gate. Pure and synchronous: the
//! controller feeds it events and replies, the UI reads it. Times come in as unix milliseconds so tests need no clock.

use std::collections::VecDeque;

use vpngate_core::ipc::{ConnectionState, HelperEvent, ListSource, ServerListResult, IPC_VERSION};
use vpngate_core::server_filter::ServerFilter;
use vpngate_core::server_list::VpnServer;

use crate::format;

pub const MAX_LOG_LINES: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Score,
    Host,
    Country,
    Uptime,
    Sessions,
    Speed,
    Ping,
    Logging,
}

impl SortKey {
    /// Numeric columns start with the best value first.
    fn starts_descending(self) -> bool {
        matches!(self, SortKey::Score | SortKey::Uptime | SortKey::Sessions | SortKey::Speed)
    }
}

pub struct AppModel {
    pub state: ConnectionState,
    pub server: Option<String>,
    pub virtual_ip: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connected_at_ms: Option<u64>,
    pub notice: Option<String>,
    pub service_running: bool,
    pub has_agreed: bool,
    pub show_disclaimer: bool,
    pub is_loading: bool,
    pub list_error: Option<String>,
    pub list_source: Option<ListSource>,
    pub list_timestamp_ms: Option<u64>,
    pub filter: ServerFilter,
    pub sort_key: SortKey,
    pub sort_descending: bool,
    /// The row the user picked, by `VpnServer::id`.
    pub selected: Option<String>,
    all: Vec<VpnServer>,
    visible: Vec<VpnServer>,
    countries: Vec<String>,
    log: VecDeque<String>,
}

impl AppModel {
    pub fn new(has_agreed: bool, favorites: impl IntoIterator<Item = String>) -> Self {
        let filter = ServerFilter { favorites: favorites.into_iter().collect(), ..ServerFilter::default() };
        AppModel {
            state: ConnectionState::Disconnected,
            server: None,
            virtual_ip: None,
            bytes_in: 0,
            bytes_out: 0,
            connected_at_ms: None,
            notice: None,
            service_running: false,
            has_agreed,
            show_disclaimer: !has_agreed,
            is_loading: false,
            list_error: None,
            list_source: None,
            list_timestamp_ms: None,
            filter,
            sort_key: SortKey::Score,
            sort_descending: true,
            selected: None,
            all: Vec::new(),
            visible: Vec::new(),
            countries: Vec::new(),
            log: VecDeque::new(),
        }
    }

    // MARK: derived values

    pub fn servers(&self) -> &[VpnServer] {
        &self.visible
    }

    pub fn total_servers(&self) -> usize {
        self.all.len()
    }

    pub fn countries(&self) -> &[String] {
        &self.countries
    }

    pub fn log_lines(&self) -> impl Iterator<Item = &str> {
        self.log.iter().map(String::as_str)
    }

    pub fn log_text(&self) -> String {
        self.log.iter().map(String::as_str).collect::<Vec<_>>().join("\n")
    }

    pub fn find(&self, id: &str) -> Option<&VpnServer> {
        self.all.iter().find(|s| s.id() == id)
    }

    pub fn selected_server(&self) -> Option<&VpnServer> {
        self.selected.as_deref().and_then(|id| self.find(id))
    }

    pub fn state_title(&self) -> &'static str {
        format::title(self.state)
    }

    pub fn is_busy(&self) -> bool {
        !matches!(self.state, ConnectionState::Disconnected | ConnectionState::Connected)
    }

    pub fn can_connect(&self) -> bool {
        self.state == ConnectionState::Disconnected && self.selected_server().is_some()
    }

    /// The bottom-bar button: Connect needs a selection, Disconnect and Cancel are always possible.
    pub fn can_act(&self) -> bool {
        self.state != ConnectionState::Disconnected || self.selected_server().is_some()
    }

    pub fn action_label(&self) -> &'static str {
        match self.state {
            ConnectionState::Disconnected => "Connect to the VPN Server",
            ConnectionState::Connected => "Disconnect",
            _ => "Cancel",
        }
    }

    /// The host name of the connected server when the list knows it, else the raw address.
    pub fn server_name(&self) -> Option<String> {
        let ip = self.server.as_deref()?;
        Some(self.all.iter().find(|s| s.ip == ip).map_or_else(|| ip.to_string(), |s| s.host_name.clone()))
    }

    pub fn traffic_text(&self, now_ms: u64) -> String {
        let since = self.connected_at_ms.map(|t| now_ms.saturating_sub(t) / 1000);
        format::traffic(self.bytes_in, self.bytes_out, since)
    }

    pub fn is_favorite(&self, s: &VpnServer) -> bool {
        self.filter.favorites.contains(s.id())
    }

    pub fn filter_active(&self) -> bool {
        let f = &self.filter;
        !f.search.is_empty() || f.country != "All" || f.favorites_only || f.max_log_weeks.is_some()
    }

    pub fn list_is_stale(&self, now_ms: u64) -> bool {
        self.list_timestamp_ms.is_some_and(|t| !format::list_is_ok(t, now_ms))
    }

    /// UI-SPEC 4, "List status line".
    pub fn list_status(&self, now_ms: u64) -> String {
        if let Some(err) = &self.list_error {
            return format!("List update failed ({err}). Try again.");
        }
        if self.is_loading {
            return if self.all.is_empty() {
                "Refreshing the List… (about 1 MB, can take 10–20 s)".into()
            } else {
                "Refreshing the List…".into()
            };
        }
        if self.all.is_empty() {
            return "No servers yet. Press Refresh List.".into();
        }
        let mut s = format!("{} Public VPN Relay Servers on the Earth!", self.all.len());
        if let Some(t) = self.list_timestamp_ms {
            s += &format!(" (Updated {})", format_timestamp(t));
            if !format::list_is_ok(t, now_ms) {
                s += " — The list is old — press Refresh List.";
            }
        }
        if self.visible.len() != self.all.len() {
            s += &format!(" — showing {}", self.visible.len());
        }
        s
    }

    // MARK: disclaimer

    pub fn agree(&mut self) {
        self.has_agreed = true;
        self.show_disclaimer = false;
    }

    /// Shows the disclaimer when consent is missing; `true` when the caller may go on.
    pub fn require_agreement(&mut self) -> bool {
        if !self.has_agreed {
            self.show_disclaimer = true;
        }
        self.has_agreed
    }

    // MARK: session

    /// `reconnect_pending`: the controller will retry soon, so the daemon's own "disconnected" must not wipe the
    /// "Reconnecting…" state.
    pub fn apply_event(&mut self, e: &HelperEvent, now_ms: u64, reconnect_pending: bool) {
        self.service_running = true;
        if e.ipc_version.is_some_and(|v| v < IPC_VERSION) {
            self.notice = Some("The installed VPN service is too old for this app. Reinstall VPN Gate.".into());
        }
        if let Some(l) = e.log.as_deref().filter(|l| !l.is_empty()) {
            self.append_log(l.to_string());
        }
        if let Some(err) = e.error.as_deref().filter(|l| !l.is_empty()) {
            self.append_log(format!("Error: {err}"));
            self.notice = Some(err.to_string());
        }
        if !(reconnect_pending && e.state == ConnectionState::Disconnected) {
            self.state = e.state;
            self.server = e.server.clone();
            self.virtual_ip = e.virtual_ip.clone();
        }
        self.bytes_in = e.bytes_in;
        self.bytes_out = e.bytes_out;
        match e.state {
            ConnectionState::Connected => {
                self.connected_at_ms.get_or_insert(now_ms);
                self.notice = None;
            }
            ConnectionState::Disconnected => self.connected_at_ms = None,
            _ => {}
        }
    }

    /// The socket to the daemon broke.
    pub fn on_connection_dropped(&mut self, reconnect_pending: bool) {
        self.service_running = false;
        if !reconnect_pending {
            self.state = ConnectionState::Disconnected;
        }
        self.connected_at_ms = None;
    }

    pub fn append_log(&mut self, line: String) {
        self.log.push_back(line);
        while self.log.len() > MAX_LOG_LINES {
            self.log.pop_front();
        }
    }

    // MARK: list

    pub fn apply_list(&mut self, r: ServerListResult) {
        self.all = r.servers;
        self.list_source = Some(r.source);
        self.list_timestamp_ms = r.timestamp_ms;
        self.list_error = None;
        let mut countries: Vec<String> =
            self.all.iter().map(|s| s.country_long.clone()).filter(|c| !c.is_empty()).collect();
        countries.sort_by_key(|c| c.to_lowercase());
        countries.dedup();
        self.countries = countries;
        if self.selected.as_deref().is_some_and(|id| self.find(id).is_none()) {
            self.selected = None;
        }
        self.rebuild();
    }

    /// Re-applies filter and sort after the caller changed `filter`, `sort_key` or the favorites.
    pub fn rebuild(&mut self) {
        let mut rows: Vec<VpnServer> = self.filter.apply(&self.all).into_iter().cloned().collect();
        let key = self.sort_key;
        rows.sort_by(|a, b| {
            let ord = compare(key, a, b);
            if self.sort_descending {
                ord.reverse()
            } else {
                ord
            }
        });
        self.visible = rows;
    }

    pub fn sort(&mut self, key: SortKey) {
        if self.sort_key == key {
            self.sort_descending = !self.sort_descending;
        } else {
            self.sort_key = key;
            self.sort_descending = key.starts_descending();
        }
        self.rebuild();
    }

    pub fn clear_filters(&mut self) {
        self.filter.search.clear();
        self.filter.country = "All".into();
        self.filter.favorites_only = false;
        self.filter.max_log_weeks = None;
        self.rebuild();
    }

    /// Returns whether the server is a favorite afterwards.
    pub fn toggle_favorite(&mut self, id: &str) -> bool {
        let now_favorite = if self.filter.favorites.remove(id) {
            false
        } else {
            self.filter.favorites.insert(id.to_string());
            true
        };
        self.rebuild();
        now_favorite
    }
}

fn compare(key: SortKey, a: &VpnServer, b: &VpnServer) -> std::cmp::Ordering {
    let weeks = |s: &VpnServer| ServerFilter::log_weeks(&s.log_type).unwrap_or(i64::MAX);
    // An unknown ping (0) sorts as the slowest.
    let ping = |s: &VpnServer| if s.ping == 0 { i64::MAX } else { s.ping };
    match key {
        SortKey::Host => a.host_name.to_lowercase().cmp(&b.host_name.to_lowercase()),
        SortKey::Country => a.country_long.to_lowercase().cmp(&b.country_long.to_lowercase()),
        SortKey::Uptime => a.uptime_ms.cmp(&b.uptime_ms),
        SortKey::Sessions => a.sessions.cmp(&b.sessions),
        SortKey::Speed => a.speed.cmp(&b.speed),
        SortKey::Ping => ping(a).cmp(&ping(b)),
        SortKey::Logging => weeks(a).cmp(&weeks(b)),
        SortKey::Score => a.score.cmp(&b.score),
    }
}

/// "YYYY-MM-DD HH:MM" in UTC. The list timestamp is informational; avoiding a time-zone dependency is worth the offset.
pub fn format_timestamp(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

#[cfg(test)]
mod tests;
