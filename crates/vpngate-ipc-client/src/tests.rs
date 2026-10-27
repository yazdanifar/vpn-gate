//! Ports of the `helperclient/*` cases of `IPCTests.swift`, plus the v9 request/reply calls against the fake daemon.

use std::sync::atomic::{AtomicUsize, Ordering};

use vpngate_core::ipc::{ConnectionState, ListSource, SyncOutcome};
use vpngate_testkit::fake_daemon::{FakeDaemon, Line};

use super::*;

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn temp_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/vgc-{}-{}-{name}.sock", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)))
}

async fn next(rx: &mut mpsc::UnboundedReceiver<ClientEvent>) -> ClientEvent {
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("no event in time").expect("channel closed")
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    f()
}

#[tokio::test]
async fn delivers_the_snapshot_and_status_answers() {
    let daemon = FakeDaemon::start(temp_path("a")).unwrap();
    let (client, mut rx) = IpcClient::new(daemon.path());
    assert!(!client.is_connected().await);
    assert!(client.connect().await);
    let ClientEvent::Event(e) = next(&mut rx).await else { panic!("expected an event") };
    assert_eq!(e.state, ConnectionState::Disconnected);
    assert_eq!(e.ipc_version, Some(vpngate_core::ipc::IPC_VERSION));
    assert!(client.status().await);
    assert!(matches!(next(&mut rx).await, ClientEvent::Event(_)));
}

#[tokio::test]
async fn reconnects_after_the_server_restarts() {
    let path = temp_path("restart");
    let mut first = FakeDaemon::start(&path).unwrap();
    let (client, mut rx) = IpcClient::new(&path);
    assert!(client.connect().await);
    assert!(matches!(next(&mut rx).await, ClientEvent::Event(_)));
    first.stop();
    assert_eq!(next(&mut rx).await, ClientEvent::Disconnected);
    assert!(!client.is_connected().await, "client did not notice the server going away");

    let second = FakeDaemon::start(&path).unwrap();
    let mut r = HelperRequest::new("connect");
    r.host = Some("1.2.3.4".into());
    assert!(client.send(&r).await, "send reconnects on demand");
    assert!(eventually(|| second.requests().len() == 1).await, "request after restart was lost");
    assert_eq!(second.requests()[0].host.as_deref(), Some("1.2.3.4"));
}

#[tokio::test]
async fn sending_to_a_dead_server_does_not_kill_the_process() {
    let mut daemon = FakeDaemon::start(temp_path("dead")).unwrap();
    let (client, _rx) = IpcClient::new(daemon.path());
    assert!(client.connect().await);
    daemon.stop();
    for _ in 0..5 {
        // The first sends may still succeed into the socket buffer; none may crash or hang.
        let _ = client.send(&HelperRequest::new("status")).await;
    }
}

#[tokio::test]
async fn unreachable_daemon_reports_it() {
    let (client, _rx) = IpcClient::new(temp_path("nobody"));
    assert!(!client.connect().await);
    assert!(!client.send(&HelperRequest::new("status")).await);
    assert_eq!(client.list_servers().await.unwrap_err(), ClientError::Disconnected);
}

fn list_reply(id: Option<i64>) -> Line {
    let result = ServerListResult {
        servers: vec![],
        source: ListSource::HttpApi,
        timestamp_ms: Some(42),
        is_fresh: true,
        outcome: SyncOutcome::Synced,
        next_poll_seconds: Some(12.5),
    };
    Line::Reply(HelperReply::success("refreshServers", id, &result))
}

#[tokio::test]
async fn requests_are_matched_to_replies_by_id() {
    let daemon = FakeDaemon::start(temp_path("ids")).unwrap();
    daemon.on_request(|r| match r.cmd.as_str() {
        "refreshServers" => vec![
            // an unrelated reply and an event first: the client must still find its own
            Line::Reply(HelperReply::failure("probe", Some(9999), "someone else's")),
            Line::Event(HelperEvent::new(ConnectionState::Connecting)),
            list_reply(r.id),
        ],
        _ => vec![],
    });
    let (client, mut rx) = IpcClient::new(daemon.path());
    let got = client.refresh_servers(None, Some("http://mirror/".into())).await.unwrap();
    assert_eq!((got.source, got.timestamp_ms, got.next_poll_seconds), (ListSource::HttpApi, Some(42), Some(12.5)));
    let sent = daemon.requests();
    assert_eq!(sent[0].cmd, "refreshServers");
    assert_eq!(sent[0].mirror.as_deref(), Some("http://mirror/"));
    assert!(sent[0].id.is_some());
    // snapshot, then the Connecting event pushed between
    let mut states = Vec::new();
    while let Ok(Some(ClientEvent::Event(e))) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
        states.push(e.state);
    }
    assert_eq!(states, vec![ConnectionState::Disconnected, ConnectionState::Connecting]);
}

#[tokio::test]
async fn concurrent_requests_do_not_mix_up_replies() {
    let daemon = FakeDaemon::start(temp_path("conc")).unwrap();
    daemon.on_request(|r| {
        let ok = ValidateResult { valid: r.account.as_ref().is_some_and(|a| a.host == "good"), error: None };
        vec![Line::Reply(HelperReply::success("validateAccount", r.id, &ok))]
    });
    let (client, _rx) = IpcClient::new(daemon.path());
    let mut tasks = Vec::new();
    for i in 0..20 {
        let c = client.clone();
        tasks.push(tokio::spawn(async move {
            let host = if i % 2 == 0 { "good" } else { "bad" };
            let v = c.validate_account(ClientAccount::new("n", host)).await.unwrap();
            assert_eq!(v.valid, i % 2 == 0);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test]
async fn a_rejection_a_silent_daemon_and_a_bad_shape_are_distinct_errors() {
    let daemon = FakeDaemon::start(temp_path("err")).unwrap();
    daemon.on_request(|r| match r.cmd.as_str() {
        "probe" => vec![Line::Reply(HelperReply::failure("probe", r.id, "too many targets"))],
        "syncDat" => vec![Line::Reply(HelperReply::success("syncDat", r.id, &"not a SyncResult"))],
        _ => vec![],
    });
    let (client, _rx) = IpcClient::new(daemon.path());
    let target = ProbeTarget { host: "h".into(), ports: None };
    assert_eq!(
        client.probe(vec![target], None, None).await.unwrap_err(),
        ClientError::Rejected("too many targets".into())
    );
    assert!(matches!(client.sync_dat(None, None).await.unwrap_err(), ClientError::BadReply(_)));
    // listServers is never answered
    let r = client.request(HelperRequest::new("listServers"), Duration::from_millis(100)).await;
    assert_eq!(r.unwrap_err(), ClientError::Timeout);
}

#[tokio::test]
async fn a_pending_request_fails_when_the_daemon_goes_away() {
    let mut daemon = FakeDaemon::start(temp_path("gone")).unwrap();
    let (client, _rx) = IpcClient::new(daemon.path());
    assert!(client.connect().await);
    let c = client.clone();
    let waiting =
        tokio::spawn(async move { c.request(HelperRequest::new("listServers"), Duration::from_secs(30)).await });
    assert!(eventually(|| daemon.requests().len() == 1).await);
    daemon.stop();
    assert_eq!(waiting.await.unwrap().unwrap_err(), ClientError::Disconnected);
}

#[tokio::test]
async fn garbage_lines_are_ignored() {
    let daemon = FakeDaemon::start(temp_path("junk")).unwrap();
    daemon.on_request(|r| vec![Line::Raw("not json".into()), Line::Raw("{}".into()), list_reply(r.id)]);
    let (client, _rx) = IpcClient::new(daemon.path());
    assert!(client.refresh_servers(None, None).await.is_ok());
}

#[tokio::test]
async fn connect_and_disconnect_send_the_session_commands() {
    let daemon = FakeDaemon::start(temp_path("ctl")).unwrap();
    let (client, _rx) = IpcClient::new(daemon.path());
    assert!(client.connect_vpn(ConnectConfig::new("1.2.3.4")).await);
    assert!(client.disconnect_vpn().await);
    assert!(eventually(|| daemon.requests().len() == 2).await);
    let sent = daemon.requests();
    assert_eq!((sent[0].cmd.as_str(), sent[1].cmd.as_str()), ("connect", "disconnect"));
    assert_eq!(sent[0].config.as_ref().unwrap().host, "1.2.3.4");
    assert_eq!(sent[0].id, None, "fire-and-forget commands carry no id");
}
