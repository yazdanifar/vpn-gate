//! The controller against the fake daemon on a real Unix socket.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use vpngate_core::ipc::{HelperReply, ListSource, ServerListResult, SyncOutcome, TunnelMode};
use vpngate_testkit::fake_daemon::{FakeDaemon, Line};

use super::*;
use crate::model::SortKey;
use crate::settings::MemorySettings;

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn temp_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/vga-{}-{}-{name}.sock", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)))
}

fn fast() -> Timing {
    Timing { reconnect_delay: Duration::from_millis(80), answer_timeout: Duration::from_millis(400) }
}

fn server(host: &str, ip: &str) -> VpnServer {
    let mut s = VpnServer::new(host, ip);
    s.country_long = "Japan".into();
    s.ssl_ports = vec![995, 443];
    s.listed_port = 443;
    s
}

fn list_line(id: Option<i64>, cmd: &str, servers: Vec<VpnServer>) -> Line {
    let r = ServerListResult {
        servers,
        source: ListSource::HttpApi,
        timestamp_ms: Some(now_ms()),
        is_fresh: true,
        outcome: SyncOutcome::Synced,
        next_poll_seconds: None,
    };
    Line::Reply(HelperReply::success(cmd, id, &r))
}

struct Rig {
    ctl: Controller,
    daemon: FakeDaemon,
    changes: Arc<AtomicUsize>,
    quits: Arc<AtomicUsize>,
}

async fn rig(agreed: bool, servers: Vec<VpnServer>) -> Rig {
    let daemon = FakeDaemon::start(temp_path("c")).unwrap();
    daemon.on_request(move |r| match r.cmd.as_str() {
        "listServers" => vec![list_line(r.id, "listServers", servers.clone())],
        "connect" => vec![Line::Event(HelperEvent::new(ConnectionState::Connecting))],
        _ => vec![],
    });
    let (ipc, rx) = IpcClient::new(daemon.path());
    let changes = Arc::new(AtomicUsize::new(0));
    let quits = Arc::new(AtomicUsize::new(0));
    let (c, q) = (changes.clone(), quits.clone());
    let store = MemorySettings::with(Settings { has_agreed_to_disclaimer: agreed, ..Settings::default() });
    let ctl = Controller::new(
        ipc,
        Box::new(store),
        Stores::memory(),
        fast(),
        move || {
            c.fetch_add(1, Ordering::SeqCst);
        },
        move || {
            q.fetch_add(1, Ordering::SeqCst);
        },
    );
    let pump = ctl.clone();
    tokio::spawn(async move { pump.pump(rx).await });
    Rig { ctl, daemon, changes, quits }
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..300 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

fn event(state: ConnectionState, server: &str) -> Line {
    let mut e = HelperEvent::new(state);
    e.server = Some(server.into());
    Line::Event(e)
}

#[tokio::test]
async fn start_loads_the_list_and_sees_the_service() {
    let r = rig(true, vec![server("a", "1.1.1.1"), server("b", "2.2.2.2")]).await;
    r.ctl.start().await;
    assert!(eventually(|| r.ctl.read(|m| m.service_running)).await);
    assert_eq!(r.ctl.read(|m| m.servers().len()), 2);
    assert_eq!(r.ctl.read(|m| m.state), ConnectionState::Disconnected);
    assert!(r.changes.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn an_empty_cache_falls_back_to_a_download() {
    let daemon = FakeDaemon::start(temp_path("dl")).unwrap();
    daemon.on_request(|r| match r.cmd.as_str() {
        "listServers" => vec![Line::Reply(HelperReply::failure("listServers", r.id, "no list"))],
        "refreshServers" => vec![list_line(r.id, "refreshServers", vec![server("a", "1.1.1.1")])],
        _ => vec![],
    });
    let (ipc, _rx) = IpcClient::new(daemon.path());
    let ctl = Controller::new(ipc, Box::new(MemorySettings::default()), Stores::memory(), fast(), || {}, || {});
    ctl.load_list().await;
    assert_eq!(ctl.read(|m| m.servers().len()), 1);
    assert!(!ctl.read(|m| m.is_loading));
    let sent: Vec<_> = daemon.requests().iter().map(|r| r.cmd.clone()).collect();
    assert_eq!(sent, ["listServers", "refreshServers"]);
}

#[tokio::test]
async fn list_failures_are_shown() {
    let (ipc, _rx) = IpcClient::new(temp_path("nobody"));
    let ctl = Controller::new(ipc, Box::new(MemorySettings::default()), Stores::memory(), fast(), || {}, || {});
    ctl.load_list().await;
    assert_eq!(ctl.read(|m| m.list_error.clone()).as_deref(), Some("Not connected to the daemon"));
    ctl.refresh().await;
    assert!(ctl.read(|m| m.list_status(0)).starts_with("List update failed"));
}

#[tokio::test]
async fn connect_sends_the_servers_ports_and_follows_the_events() {
    let r = rig(true, vec![server("a", "1.1.1.1")]).await;
    r.ctl.load_list().await;
    r.ctl.select(Some("a".into()));
    r.ctl.primary_action().await;
    let sent = r.daemon.requests().into_iter().find(|q| q.cmd == "connect").expect("connect request");
    assert_eq!(sent.host.as_deref(), Some("1.1.1.1"));
    assert_eq!(sent.port, Some(443), "ports are tried in the preferred order");
    assert_eq!(sent.ports, Some(vec![443, 995]));
    assert_eq!(sent.auto_reconnect, Some(false));
    assert_eq!(sent.tunnel_mode, Some(TunnelMode::FullTunnel));
    r.daemon.push(&event(ConnectionState::Connected, "1.1.1.1"));
    assert!(eventually(|| r.ctl.read(|m| m.state) == ConnectionState::Connected).await);
    assert_eq!(r.ctl.read(|m| m.action_label()), "Disconnect");
    r.ctl.primary_action().await;
    assert!(eventually(|| r.daemon.requests().iter().any(|q| q.cmd == "disconnect")).await);
}

#[tokio::test]
async fn connecting_without_consent_parks_until_agreed() {
    let r = rig(false, vec![server("a", "1.1.1.1")]).await;
    r.ctl.load_list().await;
    r.ctl.connect("a").await;
    assert!(r.ctl.read(|m| m.show_disclaimer));
    assert!(r.daemon.requests().iter().all(|q| q.cmd != "connect"), "nothing is sent before consent");
    r.ctl.agree().await;
    assert!(!r.ctl.read(|m| m.show_disclaimer));
    assert!(r.ctl.settings().has_agreed_to_disclaimer);
    assert!(eventually(|| r.daemon.requests().iter().any(|q| q.cmd == "connect")).await, "the parked connect resumed");
}

#[tokio::test]
async fn declining_quits() {
    let r = rig(false, vec![]).await;
    r.ctl.disagree();
    assert_eq!(r.quits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_dropped_list_connection_is_retried_until_disconnect() {
    let r = rig(true, vec![server("a", "1.1.1.1")]).await;
    r.ctl.load_list().await;
    r.ctl.connect("a").await;
    r.daemon.push(&event(ConnectionState::Connected, "1.1.1.1"));
    assert!(eventually(|| r.ctl.read(|m| m.state) == ConnectionState::Connected).await);
    r.daemon.push(&event(ConnectionState::Disconnected, "1.1.1.1"));
    assert!(eventually(|| r.ctl.read(|m| m.state) == ConnectionState::Reconnecting).await);
    assert!(r.ctl.read(|m| m.log_text()).contains("Reconnecting to a in 1 s (attempt 1)"));
    assert!(eventually(|| r.daemon.requests().iter().filter(|q| q.cmd == "connect").count() == 2).await, "retried");
    // the user gives up while another retry is pending
    r.daemon.push(&event(ConnectionState::Disconnected, "1.1.1.1"));
    assert!(eventually(|| r.ctl.read(|m| m.state) == ConnectionState::Reconnecting).await);
    r.ctl.disconnect().await;
    assert_eq!(r.ctl.read(|m| m.state), ConnectionState::Disconnected);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(r.daemon.requests().iter().filter(|q| q.cmd == "connect").count(), 2, "no retry after Disconnect");
}

#[tokio::test]
async fn auto_reconnect_can_be_turned_off() {
    let r = rig(true, vec![server("a", "1.1.1.1")]).await;
    r.ctl.update_settings(|s| s.auto_reconnect = false);
    r.ctl.load_list().await;
    r.ctl.connect("a").await;
    r.daemon.push(&event(ConnectionState::Disconnected, "1.1.1.1"));
    assert!(eventually(|| r.ctl.read(|m| m.state) == ConnectionState::Disconnected).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r.ctl.read(|m| m.state), ConnectionState::Disconnected);
    assert_eq!(r.daemon.requests().iter().filter(|q| q.cmd == "connect").count(), 1);
}

#[tokio::test]
async fn an_unreachable_service_is_explained() {
    let (ipc, _rx) = IpcClient::new(temp_path("absent"));
    let ctl = Controller::new(
        ipc,
        Box::new(MemorySettings::with(Settings { has_agreed_to_disclaimer: true, ..Settings::default() })),
        Stores::memory(),
        fast(),
        || {},
        || {},
    );
    ctl.change(|m| {
        m.apply_list(ServerListResult {
            servers: vec![server("a", "1.1.1.1")],
            source: ListSource::HttpApi,
            timestamp_ms: None,
            is_fresh: true,
            outcome: SyncOutcome::Synced,
            next_poll_seconds: None,
        })
    });
    ctl.connect("a").await;
    assert_eq!(ctl.read(|m| m.state), ConnectionState::Disconnected);
    assert!(ctl.read(|m| m.notice.clone()).unwrap().contains("not running"));
    ctl.poll().await;
    assert!(!ctl.read(|m| m.service_running));
}

#[tokio::test]
async fn a_silent_daemon_does_not_leave_connecting_forever() {
    let daemon = FakeDaemon::start(temp_path("mute")).unwrap();
    daemon.set_snapshot(HelperEvent::new(ConnectionState::Disconnected));
    // no snapshot-triggering requests answered: the fake only replies to what on_request returns (nothing)
    daemon.on_request(|_| vec![]);
    let (ipc, _rx) = IpcClient::new(daemon.path());
    let ctl = Controller::new(
        ipc,
        Box::new(MemorySettings::with(Settings { has_agreed_to_disclaimer: true, ..Settings::default() })),
        Stores::memory(),
        fast(),
        || {},
        || {},
    );
    ctl.change(|m| {
        m.apply_list(ServerListResult {
            servers: vec![server("a", "1.1.1.1")],
            source: ListSource::HttpApi,
            timestamp_ms: None,
            is_fresh: true,
            outcome: SyncOutcome::Synced,
            next_poll_seconds: None,
        })
    });
    ctl.connect("a").await;
    assert_eq!(ctl.read(|m| m.state), ConnectionState::Disconnected);
    assert!(ctl.read(|m| m.notice.clone()).unwrap().contains("not responding"));
}

#[tokio::test]
async fn favorites_persist_to_the_settings() {
    let r = rig(true, vec![server("a", "1.1.1.1")]).await;
    r.ctl.load_list().await;
    r.ctl.toggle_favorite("a");
    assert!(r.ctl.settings().favorites.contains("a"));
    r.ctl.toggle_favorite("a");
    assert!(r.ctl.settings().favorites.is_empty());
}

#[tokio::test]
async fn account_connect_sends_the_full_config_with_secrets() {
    use crate::accounts::AccountEditor;
    let r = rig(true, vec![]).await;
    r.ctl.update_settings(|s| {
        s.tunnel_mode = TunnelMode::SocksProxy;
        s.socks_port = 1090;
    });
    let mut e = AccountEditor {
        host: "vpn.example.com".into(),
        username: "bob".into(),
        password: "hunter2".into(),
        ..AccountEditor::default()
    };
    e.ports = "443, 992".into();
    let account = e.make_account(None);
    let id = account.id;
    r.ctl.with_stores(|s| s.accounts.add(account, e.secrets()));
    r.ctl.connect_account(id).await;
    let sent = r.daemon.requests().into_iter().find(|q| q.cmd == "connect").expect("connect request");
    let cfg = sent.config.expect("account connects carry a config");
    assert_eq!(
        (cfg.host.as_str(), cfg.user_name.as_str(), cfg.password.as_deref()),
        ("vpn.example.com", "bob", Some("hunter2"))
    );
    assert_eq!(cfg.ports, [443, 992]);
    assert_eq!((cfg.tunnel_mode, cfg.socks_port), (TunnelMode::SocksProxy, 1090));
    r.daemon.push(&event(ConnectionState::Connected, "vpn.example.com"));
    assert!(eventually(|| r.ctl.read(|m| m.live_account()) == Some(id)).await);
    r.daemon.push(&event(ConnectionState::Disconnected, "vpn.example.com"));
    assert!(eventually(|| r.ctl.read(|m| m.live_account()).is_none()).await, "not live once disconnected");
}

#[tokio::test]
async fn certificate_accounts_without_an_identity_explain_themselves() {
    use crate::accounts::AccountEditor;
    use vpngate_core::client_account::AccountAuthType;
    let r = rig(true, vec![]).await;
    let e =
        AccountEditor { host: "1.2.3.4".into(), auth_type: AccountAuthType::Certificate, ..AccountEditor::default() };
    let account = e.make_account(None);
    let id = account.id;
    r.ctl.with_stores(|s| s.accounts.add(account, e.secrets()));
    r.ctl.connect_account(id).await;
    assert!(r.ctl.read(|m| m.notice.clone()).unwrap().contains("needs a certificate"));
    assert!(r.daemon.requests().iter().all(|q| q.cmd != "connect"));
}

#[tokio::test]
async fn history_records_one_entry_per_connected_period() {
    let r = rig(true, vec![server("a", "1.1.1.1")]).await;
    r.ctl.load_list().await;
    r.ctl.connect("a").await;
    r.daemon.push(&event(ConnectionState::Connected, "1.1.1.1"));
    assert!(eventually(|| r.ctl.with_stores(|s| s.history.entries.len()) == 1).await);
    r.daemon.push(&event(ConnectionState::Connected, "1.1.1.1"));
    r.ctl.disconnect().await;
    r.daemon.push(&event(ConnectionState::Disconnected, "1.1.1.1"));
    assert!(eventually(|| r.ctl.with_stores(|s| s.history.entries[0].disconnected_at_ms.is_some())).await);
    assert_eq!(r.ctl.with_stores(|s| s.history.entries.len()), 1, "a repeated Connected event is the same period");
    assert_eq!(r.ctl.with_stores(|s| s.history.entries[0].server_name.clone()), "a");
}

#[tokio::test]
async fn list_connects_use_the_proxy_and_global_routing_settings() {
    use vpngate_core::ipc::ProxyKind;
    use vpngate_core::routing_rule::{RoutingAction, RoutingRule, RoutingRuleType};
    let r = rig(true, vec![server("a", "1.1.1.1")]).await;
    r.ctl.load_list().await;
    r.ctl.update_settings(|s| {
        s.proxy_kind = ProxyKind::Http;
        s.proxy_host = " proxy.local ".into();
        s.proxy_port = 8080;
        s.proxy_username = "u".into();
        s.routing.rules.push(RoutingRule::new(RoutingRuleType::DomainSuffix, "example.com", RoutingAction::Direct));
    });
    assert!(r.ctl.set_proxy_password("pw"));
    r.ctl.connect("a").await;
    let sent = r.daemon.requests().into_iter().find(|q| q.cmd == "connect").unwrap();
    let p = sent.proxy.unwrap();
    assert_eq!(
        (p.kind, p.host.as_str(), p.port, p.username.as_deref(), p.password.as_deref()),
        (ProxyKind::Http, "proxy.local", 8080, Some("u"), Some("pw"))
    );
    assert_eq!(sent.routing.unwrap().rules.len(), 1);
    // Without a user name no credentials are sent.
    r.ctl.update_settings(|s| s.proxy_username.clear());
    r.ctl.disconnect().await;
    r.ctl.connect("a").await;
    let last = r.daemon.requests().into_iter().rfind(|q| q.cmd == "connect").unwrap();
    assert_eq!(last.proxy.unwrap().password, None);
}

#[tokio::test]
async fn test_connection_probes_the_view_in_batches_and_sorts_by_result() {
    use vpngate_core::ipc::{ProbeEntry, ProbeResult};
    let servers: Vec<VpnServer> = (1..=10).map(|i| server(&format!("h{i}"), &format!("10.0.0.{i}"))).collect();
    let daemon = FakeDaemon::start(temp_path("probe")).unwrap();
    daemon.on_request(move |r| match r.cmd.as_str() {
        "probe" => {
            let results = r
                .targets
                .clone()
                .unwrap()
                .into_iter()
                .map(|t| {
                    let n: i64 = t.host.rsplit('.').next().unwrap().parse().unwrap();
                    let ok = n != 3;
                    ProbeEntry {
                        host: t.host,
                        ok,
                        port: ok.then_some(443),
                        connect_ms: ok.then_some(100 - n),
                        hello_ms: ok.then_some(5),
                        build: None,
                        error: (!ok).then(|| "timed out".to_string()),
                    }
                })
                .collect();
            vec![Line::Reply(HelperReply::success("probe", r.id, &ProbeResult { results }))]
        }
        _ => vec![],
    });
    let (ipc, _rx) = IpcClient::new(daemon.path());
    let ctl = Controller::new(ipc, Box::new(MemorySettings::default()), Stores::memory(), fast(), || {}, || {});
    ctl.change(|m| {
        m.apply_list(ServerListResult {
            servers,
            source: ListSource::HttpApi,
            timestamp_ms: None,
            is_fresh: true,
            outcome: SyncOutcome::Synced,
            next_poll_seconds: None,
        })
    });
    ctl.test_connections().await;
    let probes = daemon.requests().iter().filter(|r| r.cmd == "probe").count();
    assert_eq!(probes, 2, "10 servers in batches of 8");
    assert_eq!(ctl.read(|m| m.probe_text("h1")), "99 ms");
    assert_eq!(ctl.read(|m| m.probe_text("h3")), "timed out");
    assert!(!ctl.is_testing());
    ctl.change(|m| m.sort(SortKey::Test));
    let order: Vec<String> = ctl.read(|m| m.servers().iter().map(|s| s.host_name.clone()).collect());
    assert_eq!((order[0].as_str(), order[9].as_str()), ("h10", "h3"), "fastest first, failures last: {order:?}");
}
