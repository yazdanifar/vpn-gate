use vpngate_core::ipc::SyncOutcome;

use super::*;

fn server(host: &str, ip: &str, country: &str, score: i64) -> VpnServer {
    let mut s = VpnServer::new(host, ip);
    s.country_long = country.into();
    s.score = score;
    s
}

fn list(servers: Vec<VpnServer>, ts: Option<u64>) -> ServerListResult {
    ServerListResult {
        servers,
        source: ListSource::HttpApi,
        timestamp_ms: ts,
        is_fresh: true,
        outcome: SyncOutcome::Synced,
        next_poll_seconds: None,
    }
}

fn event(state: ConnectionState) -> HelperEvent {
    HelperEvent::new(state)
}

#[test]
fn timestamps_format_as_utc() {
    assert_eq!(format_timestamp(0), "1970-01-01 00:00 UTC");
    assert_eq!(format_timestamp(1_782_820_800_000), "2026-06-30 12:00 UTC");
    assert_eq!(format_timestamp(951_782_400_000), "2000-02-29 00:00 UTC");
}

#[test]
fn disclaimer_gate() {
    let mut m = AppModel::new(false, []);
    assert!(m.show_disclaimer);
    assert!(!m.require_agreement());
    m.agree();
    assert!(!m.show_disclaimer && m.require_agreement());
    assert!(!AppModel::new(true, []).show_disclaimer);
}

#[test]
fn list_sorts_filters_and_reports_status() {
    let mut m = AppModel::new(true, []);
    assert_eq!(m.list_status(0), "No servers yet. Press Refresh List.");
    m.is_loading = true;
    assert_eq!(m.list_status(0), "Refreshing the List… (about 1 MB, can take 10–20 s)");
    m.is_loading = false;
    m.apply_list(list(
        vec![
            server("a", "1.1.1.1", "Japan", 10),
            server("b", "2.2.2.2", "Korea", 30),
            server("c", "3.3.3.3", "japan", 20),
        ],
        Some(0),
    ));
    let hosts = |m: &AppModel| m.servers().iter().map(|s| s.host_name.clone()).collect::<Vec<_>>();
    assert_eq!(hosts(&m), ["b", "c", "a"], "score descending");
    assert_eq!(m.countries(), ["Japan", "japan", "Korea"]);
    m.sort(SortKey::Score);
    assert_eq!(hosts(&m), ["a", "c", "b"], "same key flips");
    m.sort(SortKey::Host);
    assert_eq!(hosts(&m), ["a", "b", "c"], "text columns start ascending");
    m.filter.country = "Korea".into();
    m.rebuild();
    assert!(m.filter_active());
    assert_eq!(hosts(&m), ["b"]);
    assert!(m.list_status(1000).ends_with("— showing 1"));
    m.clear_filters();
    assert!(!m.filter_active() && m.servers().len() == 3);
    assert!(m.list_status(86_400_001).contains("The list is old"));
    assert!(m.list_is_stale(86_400_001) && !m.list_is_stale(1000));
    m.list_error = Some("boom".into());
    assert_eq!(m.list_status(0), "List update failed (boom). Try again.");
}

#[test]
fn unknown_ping_sorts_last_and_selection_survives_a_new_list() {
    let mut m = AppModel::new(true, []);
    let mut fast = server("fast", "1.1.1.1", "X", 1);
    fast.ping = 5;
    let unknown = server("unknown", "2.2.2.2", "X", 2);
    m.apply_list(list(vec![unknown.clone(), fast.clone()], None));
    m.sort(SortKey::Ping);
    m.sort_descending = false;
    m.rebuild();
    assert_eq!(m.servers()[0].host_name, "fast");
    m.selected = Some(fast.id().to_string());
    assert!(m.can_connect() && m.can_act());
    m.apply_list(list(vec![unknown], None));
    assert_eq!(m.selected, None, "the selected server left the list");
    assert!(!m.can_connect() && !m.can_act());
}

#[test]
fn favorites_toggle_and_filter() {
    let mut m = AppModel::new(true, ["b".to_string()]);
    let a = server("a", "1.1.1.1", "X", 1);
    let b = server("b", "2.2.2.2", "X", 2);
    m.apply_list(list(vec![a.clone(), b.clone()], None));
    assert!(m.is_favorite(&b) && !m.is_favorite(&a));
    m.filter.favorites_only = true;
    m.rebuild();
    assert_eq!(m.servers().len(), 1);
    assert!(m.toggle_favorite(a.id()));
    assert_eq!(m.servers().len(), 2);
    assert!(!m.toggle_favorite(a.id()));
}

#[test]
fn events_drive_state_traffic_and_notice() {
    let mut m = AppModel::new(true, []);
    m.apply_list(list(vec![server("host-a", "9.9.9.9", "X", 1)], None));
    m.notice = Some("old".into());
    let mut e = event(ConnectionState::Connected);
    e.server = Some("9.9.9.9".into());
    e.virtual_ip = Some("10.0.0.2".into());
    e.bytes_in = 2048;
    m.apply_event(&e, 5_000, false);
    assert_eq!((m.state, m.notice.clone(), m.connected_at_ms), (ConnectionState::Connected, None, Some(5_000)));
    assert_eq!(m.server_name().as_deref(), Some("host-a"));
    assert_eq!(m.traffic_text(65_000), "0:01:00  ↓ 2.0 KB  ↑ 0 bytes");
    assert_eq!(m.action_label(), "Disconnect");
    m.apply_event(&e, 9_000, false);
    assert_eq!(m.connected_at_ms, Some(5_000), "a later snapshot keeps the original start");
    let mut bad = event(ConnectionState::Disconnected);
    bad.error = Some("auth failed".into());
    bad.log = Some("bye".into());
    m.apply_event(&bad, 10_000, false);
    assert_eq!(
        (m.state, m.connected_at_ms, m.notice.as_deref()),
        (ConnectionState::Disconnected, None, Some("auth failed"))
    );
    assert_eq!(m.log_text(), "bye\nError: auth failed");
    assert_eq!(m.server_name(), None);
}

#[test]
fn pending_reconnect_keeps_its_state_against_the_daemons_disconnected() {
    let mut m = AppModel::new(true, []);
    m.state = ConnectionState::Reconnecting;
    m.server = Some("9.9.9.9".into());
    m.apply_event(&event(ConnectionState::Disconnected), 0, true);
    assert_eq!((m.state, m.server.as_deref()), (ConnectionState::Reconnecting, Some("9.9.9.9")));
    m.on_connection_dropped(true);
    assert_eq!(m.state, ConnectionState::Reconnecting);
    assert!(!m.service_running);
    m.on_connection_dropped(false);
    assert_eq!(m.state, ConnectionState::Disconnected);
}

#[test]
fn old_daemon_and_log_cap() {
    let mut m = AppModel::new(true, []);
    let mut e = event(ConnectionState::Disconnected);
    e.ipc_version = Some(IPC_VERSION - 1);
    m.apply_event(&e, 0, false);
    assert!(m.notice.as_deref().unwrap().contains("too old"));
    for i in 0..(MAX_LOG_LINES + 20) {
        m.append_log(format!("l{i}"));
    }
    assert_eq!(m.log_lines().count(), MAX_LOG_LINES);
    assert_eq!(m.log_lines().next(), Some("l20"));
}

#[test]
fn busy_states_offer_cancel() {
    let mut m = AppModel::new(true, []);
    m.state = ConnectionState::Authenticating;
    assert!(m.is_busy() && m.can_act() && !m.can_connect());
    assert_eq!(m.action_label(), "Cancel");
}
