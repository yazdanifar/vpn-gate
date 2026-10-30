//! The tray against a fake `org.kde.StatusNotifierWatcher` on a private session bus (U33). The watcher is a few lines of `zbus`: it
//! records the item that registers and says a host is present, which is all `ksni` asks of it. The test then talks to the
//! registered item like a desktop shell does: reads its properties, fetches its menu over `com.canonical.dbusmenu`, clicks entries and
//! checks that the app's dispatch callback receives them.
//!
//! Needs a session bus: `VPNGATE_TRAY_TESTS=1 dbus-run-session -- cargo test --test tray`. Without the variable it skips itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vpngate_gtk::tray::{self, TrayAction, TraySnapshot};
use zbus::zvariant::{OwnedValue, Value};

struct Watcher {
    items: Arc<Mutex<Vec<String>>>,
}

#[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
impl Watcher {
    async fn register_status_notifier_item(&self, service: &str, #[zbus(header)] header: zbus::message::Header<'_>) {
        // The argument is the item's bus name (or, from some clients, just its object path; the sender is then the service).
        let name = if service.starts_with('/') {
            header.sender().map(ToString::to_string).unwrap_or_default()
        } else {
            service.to_string()
        };
        self.items.lock().unwrap().push(name);
    }

    fn register_status_notifier_host(&self, _service: &str) {}

    #[zbus(property)]
    fn registered_status_notifier_items(&self) -> Vec<String> {
        self.items.lock().unwrap().clone()
    }

    #[zbus(property)]
    fn is_status_notifier_host_registered(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn protocol_version(&self) -> i32 {
        0
    }
}

type Layout = (u32, (i32, HashMap<String, OwnedValue>, Vec<OwnedValue>));

/// The menu entries as (id, debug text of the entry); the text contains the label, so tests search it.
fn entries(layout: &Layout) -> Vec<(i32, String)> {
    layout
        .1
         .2
        .iter()
        .map(|child| {
            let Value::Structure(s) = &**child else { panic!("a menu entry is a struct, got {child:?}") };
            let id: i32 = s.fields()[0].downcast_ref().expect("the entry id");
            (id, format!("{child:?}"))
        })
        .collect()
}

async fn wait_for<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = probe() {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(15), "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn the_tray_registers_exposes_its_menu_and_dispatches_clicks() {
    if std::env::var_os("VPNGATE_TRAY_TESTS").is_none() {
        println!("tray test skipped: set VPNGATE_TRAY_TESTS=1 and run it under dbus-run-session");
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let items = Arc::new(Mutex::new(Vec::<String>::new()));
        let _watcher = zbus::connection::Builder::session()
            .unwrap()
            .name("org.kde.StatusNotifierWatcher")
            .unwrap()
            .serve_at("/StatusNotifierWatcher", Watcher { items: items.clone() })
            .unwrap()
            .build()
            .await
            .expect("the fake watcher on the session bus");

        let actions = Arc::new(Mutex::new(Vec::<TrayAction>::new()));
        let seen = actions.clone();
        let tx = tray::spawn(&tokio::runtime::Handle::current(), move |a| seen.lock().unwrap().push(a));
        let disconnected = TraySnapshot {
            icon: "network-vpn-disconnected-symbolic".into(),
            title: "Disconnected".into(),
            disconnected: true,
            connect_label: Some("Connect to tokyo1.opengw.net".into()),
            ..TraySnapshot::default()
        };
        tx.send(disconnected).unwrap();

        // the item registers itself with the watcher
        let service = wait_for("the item to register", || items.lock().unwrap().first().cloned()).await;
        let conn = zbus::Connection::session().await.unwrap();
        let item = zbus::Proxy::new(&conn, service.as_str(), "/StatusNotifierItem", "org.kde.StatusNotifierItem")
            .await
            .unwrap();
        let id: String = item.get_property("Id").await.unwrap();
        assert_eq!(id, "net.vpngate.App");
        let title: String = item.get_property("Title").await.unwrap();
        assert_eq!(title, "VPN Gate — Disconnected");
        let icon: String = item.get_property("IconName").await.unwrap();
        assert_eq!(icon, "network-vpn-disconnected-symbolic");

        // its menu
        let menu_path: zbus::zvariant::OwnedObjectPath = item.get_property("Menu").await.unwrap();
        let menu =
            zbus::Proxy::new(&conn, service.as_str(), menu_path.as_str(), "com.canonical.dbusmenu").await.unwrap();
        let layout: Layout = menu.call("GetLayout", &(0i32, -1i32, Vec::<String>::new())).await.unwrap();
        let shown = entries(&layout);
        let has = |text: &str| shown.iter().any(|(_, t)| t.contains(text));
        for label in ["Disconnected", "Connect to tokyo1.opengw.net", "Show VPN Gate", "Connection Log", "Quit"] {
            assert!(has(label), "menu entry {label:?} missing from {shown:?}");
        }
        assert!(!has("Reconnect"), "a disconnected tray offers no Reconnect: {shown:?}");

        // clicking an entry reaches the app
        let click = |label: &'static str| {
            let shown = shown.clone();
            let menu = menu.clone();
            async move {
                let (entry, _) = shown.iter().find(|(_, t)| t.contains(label)).expect("entry").clone();
                menu.call_method("Event", &(entry, "clicked", Value::from(0i32), 0u32)).await.unwrap();
            }
        };
        click("Connection Log").await;
        wait_for("ShowLog", || actions.lock().unwrap().contains(&TrayAction::ShowLog).then_some(())).await;
        click("Connect to tokyo1.opengw.net").await;
        wait_for("Connect", || actions.lock().unwrap().contains(&TrayAction::Connect).then_some(())).await;
        click("Quit").await;
        wait_for("Quit", || actions.lock().unwrap().contains(&TrayAction::Quit).then_some(())).await;
        // activating the icon shows the window
        item.call_method("Activate", &(0i32, 0i32)).await.unwrap();
        wait_for("Show", || actions.lock().unwrap().contains(&TrayAction::Show).then_some(())).await;

        // a new snapshot rebuilds the menu
        let connected = TraySnapshot {
            icon: "channel-secure-symbolic".into(),
            title: "Connected".into(),
            server_line: Some("tokyo1.opengw.net (1.1.1.1)".into()),
            virtual_ip: Some("10.21.0.7".into()),
            traffic: Some("0:00:05".into()),
            disconnected: false,
            connect_label: None,
            can_reconnect: true,
        };
        tx.send(connected).unwrap();
        let connected_entries = wait_for_layout(&menu, |e| e.iter().any(|(_, t)| t.contains("Disconnect"))).await;
        for label in ["Virtual IP 10.21.0.7", "tokyo1.opengw.net (1.1.1.1)", "Disconnect", "Reconnect"] {
            assert!(
                connected_entries.iter().any(|(_, t)| t.contains(label)),
                "{label:?} missing from {connected_entries:?}"
            );
        }
        let title: String = item.get_property("Title").await.unwrap();
        assert_eq!(title, "VPN Gate — Connected");
        let (disconnect, _) = connected_entries.iter().find(|(_, t)| t.contains("Disconnect")).unwrap().clone();
        menu.call_method("Event", &(disconnect, "clicked", Value::from(0i32), 0u32)).await.unwrap();
        wait_for("Disconnect", || actions.lock().unwrap().contains(&TrayAction::Disconnect).then_some(())).await;
    });
}

async fn wait_for_layout(menu: &zbus::Proxy<'_>, ok: impl Fn(&[(i32, String)]) -> bool) -> Vec<(i32, String)> {
    let start = Instant::now();
    loop {
        let layout: Layout = menu.call("GetLayout", &(0i32, -1i32, Vec::<String>::new())).await.unwrap();
        let shown = entries(&layout);
        if ok(&shown) {
            return shown;
        }
        assert!(start.elapsed() < Duration::from_secs(15), "the menu never changed: {shown:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
