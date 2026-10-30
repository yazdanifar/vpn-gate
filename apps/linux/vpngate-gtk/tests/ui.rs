//! In-process UI tests of the GTK app (U33). The real windows are built against a `FakeDaemon` and in-memory stores, widgets are
//! found by name, title or label, driven the way a click would drive them, and the result is read back from the controller (the
//! app's model) or from other widgets. The golden screenshots are rendered with GSK's offscreen path.
//!
//! GTK widgets are not `Send`, so this is one test binary without the libtest harness (`harness = false`): GTK is initialised
//! once on the main thread and the cases run one after the other. Run it under Xvfb:
//! `VPNGATE_UI_TESTS=1 xvfb-run -a cargo test --test ui` (without the variable it skips itself, so a plain `cargo test` works
//! on a machine without a display). `VPNGATE_UI_RECORD=1` writes the goldens instead of comparing; see `tests/golden/README.md`.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::{gdk, gio, glib};
use vpngate_app_model::accounts::AccountEditor;
use vpngate_app_model::autostart;
use vpngate_app_model::columns;
use vpngate_app_model::model::SortKey;
use vpngate_app_model::settings::{MemorySettings, Settings};
use vpngate_app_model::{Controller, Stores, Timing};
use vpngate_core::ipc::{ConnectionState, HelperEvent, HelperReply, ListSource, ServerListResult, SyncOutcome};
use vpngate_core::routing_rule::{RoutingAction, RoutingRule, RoutingRuleType};
use vpngate_core::server_list::VpnServer;
use vpngate_gtk::routing_editor;
use vpngate_gtk::window::{self, Built, Env};
use vpngate_testkit::fake_daemon::{FakeDaemon, Line};

/// Fixed, so the list status line (and with it every screenshot) does not depend on the clock.
const LIST_TIMESTAMP_MS: u64 = 1_700_000_000_000;

struct Harness {
    app: adw::Application,
    rt: Arc<tokio::runtime::Runtime>,
}

type Case = fn(&Harness);

// ---------------------------------------------------------------------------------------------------------------- driving GTK

fn pump() {
    let ctx = glib::MainContext::default();
    while ctx.iteration(false) {}
}

/// Runs the main loop for `ms` (layout, frame clock, delayed signals).
fn settle(ms: u64) {
    let end = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < end {
        pump();
        std::thread::sleep(Duration::from_millis(5));
    }
    pump();
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    loop {
        pump();
        if cond() {
            return;
        }
        assert!(start.elapsed() < Duration::from_secs(15), "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn descendants(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Widget> {
    let root: gtk::Widget = root.as_ref().clone();
    let mut out = vec![root.clone()];
    let mut stack = vec![root];
    while let Some(w) = stack.pop() {
        let mut child = w.first_child();
        while let Some(c) = child {
            child = c.next_sibling();
            out.push(c.clone());
            stack.push(c);
        }
    }
    out
}

fn all<T: IsA<gtk::Widget>>(root: &impl IsA<gtk::Widget>) -> Vec<T> {
    descendants(root).into_iter().filter_map(|w| w.downcast::<T>().ok()).collect()
}

fn try_find<T: IsA<gtk::Widget>>(root: &impl IsA<gtk::Widget>, pred: impl Fn(&T) -> bool) -> Option<T> {
    all::<T>(root).into_iter().find(|w| pred(w))
}

fn find<T: IsA<gtk::Widget>>(root: &impl IsA<gtk::Widget>, what: &str, pred: impl Fn(&T) -> bool) -> T {
    try_find(root, pred).unwrap_or_else(|| panic!("no {} named or titled {what:?}", std::any::type_name::<T>()))
}

fn named<T: IsA<gtk::Widget>>(root: &impl IsA<gtk::Widget>, name: &str) -> T {
    find(root, name, |w: &T| w.widget_name() == name)
}

fn button(root: &impl IsA<gtk::Widget>, label: &str) -> gtk::Button {
    find(root, label, |b: &gtk::Button| b.label().as_deref() == Some(label))
}

fn button_with_tooltip(root: &impl IsA<gtk::Widget>, tip: &str) -> gtk::Button {
    find(root, tip, |b: &gtk::Button| b.tooltip_text().as_deref() == Some(tip))
}

fn row<T: IsA<adw::PreferencesRow> + IsA<gtk::Widget>>(root: &impl IsA<gtk::Widget>, title: &str) -> T {
    find(root, title, |r: &T| r.title() == title)
}

fn has_label(root: &impl IsA<gtk::Widget>, text: &str) -> bool {
    try_find(root, |l: &gtk::Label| l.text() == text).is_some()
}

fn has_label_containing(root: &impl IsA<gtk::Widget>, text: &str) -> bool {
    try_find(root, |l: &gtk::Label| l.text().contains(text)).is_some()
}

fn subtitle(r: &adw::ActionRow) -> String {
    r.property::<Option<String>>("subtitle").unwrap_or_default()
}

fn click(b: &gtk::Button) {
    assert!(b.is_sensitive(), "button {:?} is not sensitive", b.label());
    b.emit_clicked();
    pump();
}

fn toplevel(title: &str) -> gtk::Window {
    let find_it = || {
        gtk::Window::list_toplevels()
            .into_iter()
            .filter_map(|w| w.downcast::<gtk::Window>().ok())
            .find(|w| w.is_visible() && w.title().as_deref() == Some(title))
    };
    wait_until(&format!("window {title:?}"), || find_it().is_some());
    find_it().expect("window")
}

/// The dialog on top of an `AdwApplicationWindow` / `AdwWindow`, waiting for it to appear.
fn dialog_of(win: &gtk::Window) -> adw::Dialog {
    let top = || {
        if let Some(w) = win.downcast_ref::<adw::ApplicationWindow>() {
            w.visible_dialog()
        } else {
            win.downcast_ref::<adw::Window>().and_then(|w| w.visible_dialog())
        }
    };
    wait_until("a dialog", || top().is_some());
    top().expect("dialog")
}

fn wait_no_dialog(win: &gtk::Window) {
    let top = || {
        if let Some(w) = win.downcast_ref::<adw::ApplicationWindow>() {
            w.visible_dialog()
        } else {
            win.downcast_ref::<adw::Window>().and_then(|w| w.visible_dialog())
        }
    };
    wait_until("the dialog to close", || top().is_none());
}

fn string_items(model: &impl IsA<gio::ListModel>) -> Vec<String> {
    (0..model.n_items())
        .filter_map(|i| model.item(i).and_downcast::<gtk::StringObject>())
        .map(|o| o.string().to_string())
        .collect()
}

fn select_string(dd: &gtk::DropDown, text: &str) {
    let items = string_items(&dd.model().expect("drop-down model"));
    let i = items.iter().position(|s| s == text).unwrap_or_else(|| panic!("{text:?} is not in {items:?}"));
    dd.set_selected(i as u32);
    pump();
}

fn selected_string(dd: &gtk::DropDown) -> String {
    dd.selected_item().and_downcast::<gtk::StringObject>().map(|o| o.string().to_string()).unwrap_or_default()
}

fn text_of(view: &gtk::TextView) -> String {
    let b = view.buffer();
    b.text(&b.start_iter(), &b.end_iter(), false).to_string()
}

// ------------------------------------------------------------------------------------------------------------------ the rig

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn server(host: &str, ip: &str, place: (&str, &str), numbers: (i64, i64, i64), log: &str) -> VpnServer {
    let ((cc, country), (score, mbps, ping)) = (place, numbers);
    let mut s = VpnServer::new(host, ip);
    s.country_short = cc.into();
    s.country_long = country.into();
    s.score = score;
    s.speed = mbps * 1_000_000;
    s.ping = ping;
    s.ping_to_google = ping + 5;
    s.sessions = 100 - ping;
    s.uptime_ms = (score / 100) * 86_400_000;
    s.total_users = score * 10;
    s.total_traffic = score * 1_000_000_000;
    s.log_type = log.into();
    s.operator_name = format!("Volunteer {cc}");
    s.ssl_ports = vec![443, 995];
    s.listed_port = 443;
    s
}

/// Score order: tokyo1, seoul, osaka, paris, berlin. Speed order (ascending): berlin, paris, osaka, seoul, tokyo1.
fn servers() -> Vec<VpnServer> {
    vec![
        server("tokyo1.opengw.net", "1.1.1.1", ("JP", "Japan"), (5000, 100, 20), "2 weeks"),
        server("osaka.opengw.net", "2.2.2.2", ("JP", "Japan"), (3000, 60, 35), "none"),
        server("seoul.opengw.net", "3.3.3.3", ("KR", "Korea Republic of"), (4000, 80, 60), "3 months"),
        server("berlin.opengw.net", "4.4.4.4", ("DE", "Germany"), (1000, 20, 90), "1 year"),
        server("paris.opengw.net", "5.5.5.5", ("FR", "France"), (2000, 40, 80), "2 weeks"),
    ]
}

const BY_SCORE: [&str; 5] =
    ["tokyo1.opengw.net", "seoul.opengw.net", "osaka.opengw.net", "paris.opengw.net", "berlin.opengw.net"];

fn list_line(id: Option<i64>, cmd: &str, servers: Vec<VpnServer>) -> Line {
    let r = ServerListResult {
        servers,
        source: ListSource::HttpApi,
        timestamp_ms: Some(LIST_TIMESTAMP_MS),
        is_fresh: true,
        outcome: SyncOutcome::Synced,
        next_poll_seconds: None,
    };
    Line::Reply(HelperReply::success(cmd, id, &r))
}

struct Rig {
    daemon: FakeDaemon,
    built: Built,
}

impl Rig {
    fn new(h: &Harness, agreed: bool) -> Rig {
        Rig::with_stores(h, agreed, |_| {})
    }

    fn with_stores(h: &Harness, agreed: bool, setup: impl FnOnce(&mut Stores)) -> Rig {
        let sock =
            PathBuf::from(format!("/tmp/vgui-{}-{}.sock", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
        let daemon = {
            let _in_runtime = h.rt.enter();
            FakeDaemon::start(&sock).expect("fake daemon")
        };
        let list = servers();
        daemon.on_request(move |r| match r.cmd.as_str() {
            "listServers" | "refreshServers" => vec![list_line(r.id, &r.cmd, list.clone())],
            "connect" => vec![Line::Event(HelperEvent::new(ConnectionState::Connecting))],
            "disconnect" => vec![Line::Event(HelperEvent::new(ConnectionState::Disconnected))],
            _ => vec![],
        });
        let mut stores = Stores::memory();
        setup(&mut stores);
        let env = Env {
            socket: sock.to_string_lossy().into_owned(),
            settings: Box::new(MemorySettings::with(Settings {
                has_agreed_to_disclaimer: agreed,
                ..Settings::default()
            })),
            stores,
            timing: Timing::default(),
            tray: false,
        };
        let built = window::build_with(&h.app, h.rt.clone(), env);
        Rig { daemon, built }
    }

    fn win(&self) -> &adw::ApplicationWindow {
        &self.built.window
    }

    fn ctl(&self) -> &Controller {
        &self.built.ctl
    }

    fn top(&self) -> gtk::Window {
        self.built.window.clone().upcast()
    }

    fn loaded(&self) {
        wait_until("the server list", || self.ctl().read(|m| m.servers().len() == 5));
        wait_until("the table rows", || self.table_ids().len() == 5);
    }

    fn table(&self) -> gtk::ColumnView {
        named(self.win(), "table")
    }

    fn table_ids(&self) -> Vec<String> {
        string_items(&self.table().model().expect("selection model"))
    }

    fn visible_ids(&self) -> Vec<String> {
        self.ctl().read(|m| m.servers().iter().map(|s| s.id().to_string()).collect())
    }

    fn select(&self, id: &str) {
        let sel = self.table().model().and_downcast::<gtk::SingleSelection>().expect("single selection");
        let pos = self.table_ids().iter().position(|i| i == id).unwrap_or_else(|| panic!("{id} is not listed"));
        sel.set_selected(pos as u32);
        wait_until("the selection", || self.ctl().read(|m| m.selected.as_deref() == Some(id)));
    }

    fn requests(&self) -> Vec<String> {
        self.daemon.requests().into_iter().map(|r| r.cmd).collect()
    }

    fn wait_request(&self, cmd: &str) {
        wait_until(&format!("a {cmd:?} request"), || self.requests().iter().any(|c| c == cmd));
    }

    fn text(&self, name: &str) -> String {
        named::<gtk::Label>(self.win(), name).text().to_string()
    }

    fn open(&self, action: &str, title: &str) -> gtk::Window {
        gtk::prelude::WidgetExt::activate_action(self.win(), action, None).expect("window action");
        toplevel(title)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        for w in gtk::Window::list_toplevels() {
            if let Some(w) = w.downcast_ref::<gtk::Window>() {
                w.destroy();
            }
        }
        pump();
    }
}

// ------------------------------------------------------------------------------------------------------------------- golden

fn out_dir() -> PathBuf {
    std::env::var_os("VPNGATE_UI_OUT")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/ui-out"), PathBuf::from)
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn recording() -> bool {
    std::env::var_os("VPNGATE_UI_RECORD").is_some_and(|v| !v.is_empty() && v != "0")
}

/// The window as a PNG: its widget tree painted by the renderer of its surface (Cairo, see `main`).
fn render_png(win: &gtk::Window) -> Vec<u8> {
    let (w, h) = (win.width(), win.height());
    assert!(w > 0 && h > 0, "the window has no size yet ({w}x{h})");
    let paintable = gtk::WidgetPaintable::new(Some(win));
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, f64::from(w), f64::from(h));
    let node = snapshot.to_node().expect("the window painted nothing");
    let renderer = win.native().and_then(|n| n.renderer()).expect("a realized window has a renderer");
    let texture = renderer.render_texture(&node, None);
    texture.save_to_png_bytes().to_vec()
}

fn pixels(png: &[u8]) -> (usize, usize, Vec<u8>) {
    let t = gdk::Texture::from_bytes(&glib::Bytes::from(png)).expect("a decodable PNG");
    let (w, h) = (t.width() as usize, t.height() as usize);
    let mut buf = vec![0u8; w * h * 4];
    t.download(&mut buf, w * 4);
    (w, h, buf)
}

fn png_of(w: usize, h: usize, bgra: Vec<u8>) -> Vec<u8> {
    let bytes = glib::Bytes::from_owned(bgra);
    gdk::MemoryTexture::new(w as i32, h as i32, gdk::MemoryFormat::B8g8r8a8Premultiplied, &bytes, w * 4)
        .save_to_png_bytes()
        .to_vec()
}

/// Compares the window with `tests/golden/<name>.png` (a few percent of the channel range and 0.5 % of the pixels may differ:
/// antialiasing is not bit-stable across Pango and Cairo patch releases). Always leaves the actual image in the output directory
/// so a CI run can upload it; on a mismatch also the diff.
fn golden(name: &str, win: &gtk::Window) {
    settle(600);
    let actual = render_png(win);
    let out = out_dir();
    std::fs::create_dir_all(&out).expect("output directory");
    std::fs::write(out.join(format!("{name}.png")), &actual).expect("write the actual image");
    let path = golden_dir().join(format!("{name}.png"));
    if recording() {
        std::fs::create_dir_all(golden_dir()).expect("golden directory");
        std::fs::write(&path, &actual).expect("write the golden");
        return;
    }
    let Ok(want) = std::fs::read(&path) else {
        panic!(
            "no golden image {}: record it (workflow 'GTK goldens', or VPNGATE_UI_RECORD=1) and have it approved; the actual image \
             is in the 'gtk-ui-actual' artifact",
            path.display()
        );
    };
    let ((aw, ah, a), (ww, wh, b)) = (pixels(&actual), pixels(&want));
    if (aw, ah) != (ww, wh) {
        panic!("{name}: the image is {aw}x{ah}, the golden {ww}x{wh}");
    }
    let mut diff = vec![0u8; a.len()];
    let mut bad = 0usize;
    for ((x, y), d) in a.chunks(4).zip(b.chunks(4)).zip(diff.chunks_mut(4)) {
        if x.iter().zip(y).any(|(p, q)| p.abs_diff(*q) > 16) {
            bad += 1;
            d.copy_from_slice(&[0, 0, 255, 255]);
        } else {
            d.copy_from_slice(&[y[0] / 3 + 170, y[1] / 3 + 170, y[2] / 3 + 170, 255]);
        }
    }
    let allowed = aw * ah / 200;
    if bad > allowed {
        std::fs::write(out.join(format!("{name}.diff.png")), png_of(aw, ah, diff)).expect("write the diff");
        panic!(
            "{name}: {bad} of {} pixels differ (allowed {allowed}); see {}/{name}.png and .diff.png (CI artifact 'gtk-ui-actual')",
            aw * ah,
            out.display()
        );
    }
}

// --------------------------------------------------------------------------------------------------------------------- cases

fn main_window_lists_servers(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    assert_eq!(r.table_ids(), BY_SCORE, "default order is the total score, best first");
    assert!(r.text("list-status").contains("5 Public VPN Relay Servers on the Earth!"), "{}", r.text("list-status"));
    assert_eq!(r.text("state"), "Not connected");
    assert!(!named::<gtk::Button>(r.win(), "action").is_sensitive(), "nothing selected, nothing to connect to");
    assert!(!named::<gtk::Button>(r.win(), "clear-filters").is_visible());
    // the cells really show the servers (rows are created once the table is laid out)
    wait_until("cells with the host names", || {
        let t = r.table();
        has_label(&t, "1.1.1.1 (tokyo1.opengw.net)") && has_label(&t, "4.4.4.4 (berlin.opengw.net)")
    });
    let cols = r.table().columns();
    let visible = (0..cols.n_items())
        .filter_map(|i| cols.item(i).and_downcast::<gtk::ColumnViewColumn>())
        .filter(|c| c.is_visible())
        .count();
    assert_eq!(visible, 9, "the default layout shows 9 of the 16 columns");
}

fn search_and_clear_filters(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let search: gtk::SearchEntry = named(r.win(), "search");
    search.set_text("tokyo");
    wait_until("the search to filter", || r.visible_ids() == ["tokyo1.opengw.net"]);
    wait_until("the table to follow", || r.table_ids() == ["tokyo1.opengw.net"]);
    let clear: gtk::Button = named(r.win(), "clear-filters");
    assert!(clear.is_visible(), "Clear Filters appears while a filter is on");
    assert!(r.text("list-status").contains("showing 1"), "{}", r.text("list-status"));
    // the country is searched too
    search.set_text("japan");
    wait_until("the country search", || r.visible_ids().len() == 2);
    click(&clear);
    wait_until("the filters to clear", || r.visible_ids().len() == 5);
    assert_eq!(search.text(), "");
    assert!(!clear.is_visible());
    assert_eq!(r.table_ids(), BY_SCORE);
}

fn country_and_logging_filters(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let country: gtk::DropDown = named(r.win(), "country");
    let items = string_items(&country.model().unwrap());
    assert_eq!(items[0], "All countries");
    for c in ["France", "Germany", "Japan", "Korea Republic of"] {
        assert!(items.iter().any(|i| i == c), "{c} missing from {items:?}");
    }
    select_string(&country, "Japan");
    wait_until("the country filter", || r.visible_ids() == ["tokyo1.opengw.net", "osaka.opengw.net"]);
    wait_until("the table", || r.table_ids().len() == 2);
    select_string(&country, "All countries");
    wait_until("all countries", || r.visible_ids().len() == 5);

    let logging: gtk::DropDown = named(r.win(), "logging");
    select_string(&logging, "No logs only");
    wait_until("the no-logs filter", || r.visible_ids() == ["osaka.opengw.net"]);
    select_string(&logging, "2 weeks or less");
    wait_until("the two-weeks filter", || {
        r.visible_ids() == ["tokyo1.opengw.net", "osaka.opengw.net", "paris.opengw.net"]
    });
    select_string(&logging, "Any logging policy");
    wait_until("any logging policy", || r.visible_ids().len() == 5);
}

fn sort_drop_down_and_direction(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let sort: gtk::DropDown = named(r.win(), "sort");
    assert_eq!(selected_string(&sort), "Total Score");
    select_string(&sort, "Host name");
    let by_host =
        ["berlin.opengw.net", "osaka.opengw.net", "paris.opengw.net", "seoul.opengw.net", "tokyo1.opengw.net"];
    wait_until("the host sort", || r.table_ids() == by_host);
    let desc: gtk::ToggleButton = named(r.win(), "descending");
    assert!(!desc.is_active(), "text columns start ascending");
    click(desc.upcast_ref());
    let mut reversed = by_host;
    reversed.reverse();
    wait_until("the reversed order", || r.table_ids() == reversed);
    assert!(r.ctl().read(|m| m.sort_descending));
}

fn header_click_sorts(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let table = r.table();
    let cols = table.columns();
    let speed = (0..cols.n_items())
        .filter_map(|i| cols.item(i).and_downcast::<gtk::ColumnViewColumn>())
        .find(|c| c.id().as_deref() == Some("speed"))
        .expect("the Line Speed column");
    // What a header click does: the column view sorts by that column, its sorter reports the change.
    table.sort_by_column(Some(&speed), gtk::SortType::Ascending);
    wait_until("the model to sort by speed", || r.ctl().read(|m| m.sort_key == SortKey::Speed && !m.sort_descending));
    let ascending =
        ["berlin.opengw.net", "paris.opengw.net", "osaka.opengw.net", "seoul.opengw.net", "tokyo1.opengw.net"];
    wait_until("the rows", || r.table_ids() == ascending);
    assert_eq!(selected_string(&named(r.win(), "sort")), "Line Speed", "the drop-down follows the header");
    table.sort_by_column(Some(&speed), gtk::SortType::Descending);
    wait_until("the descending speed order", || {
        r.table_ids()
            == ["tokyo1.opengw.net", "seoul.opengw.net", "osaka.opengw.net", "paris.opengw.net", "berlin.opengw.net"]
    });
    assert!(r.ctl().read(|m| m.sort_descending));
}

fn column_chooser(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let button: gtk::MenuButton = named(r.win(), "columns");
    let popover = button.popover().expect("the column chooser popover");
    let checks = all::<gtk::CheckButton>(&popover);
    assert_eq!(checks.len(), 16, "one check box per column");
    assert_eq!(checks.iter().filter(|c| c.is_active()).count(), 9);
    let operator: gtk::CheckButton = named(&popover, "col-operator");
    assert_eq!(operator.label().as_deref(), Some("Operator's Name"));
    assert!(!operator.is_active());
    assert!(r.ctl().settings().list_columns.is_empty(), "nothing saved before the user changes the layout");

    let column = |key: &str| {
        let cols = r.table().columns();
        (0..cols.n_items())
            .filter_map(|i| cols.item(i).and_downcast::<gtk::ColumnViewColumn>())
            .find(|c| c.id().as_deref() == Some(key))
            .unwrap_or_else(|| panic!("no column {key}"))
    };
    operator.set_active(true);
    assert!(column("operator").is_visible());
    let score: gtk::CheckButton = named(&popover, "col-score");
    assert!(score.is_active());
    score.set_active(false);
    assert!(!column("score").is_visible());
    assert_eq!(
        r.ctl().settings().list_columns,
        ["host", "region", "uptime", "sessions", "speed", "ping", "test", "logging", "operator"],
        "the visible columns are saved in table order"
    );
    // and read back the way the next start does
    let layout = columns::layout(&r.ctl().settings().list_columns);
    assert_eq!(layout.iter().filter(|(_, v)| *v).count(), 9);
    assert!(layout.iter().any(|(c, v)| c.key == "operator" && *v));
}

fn menu_labels(menu: &gio::Menu) -> Vec<String> {
    (0..menu.n_items())
        .filter_map(|i| menu.item_attribute_value(i, "label", Some(glib::VariantTy::STRING)))
        .filter_map(|v| v.str().map(String::from))
        .collect()
}

fn row_context_menu_and_actions(h: &Harness) {
    // the menu itself, in both states
    assert_eq!(
        menu_labels(&window::row_menu_model(true, false)),
        ["Connect to the VPN Server", "Server Details…", "Add to Favorites"]
    );
    assert_eq!(menu_labels(&window::row_menu_model(false, true)), ["Server Details…", "Remove from Favorites"]);

    let r = Rig::new(h, true);
    r.loaded();
    r.select("tokyo1.opengw.net");
    let table = r.table();

    // row.favorite: the favorite toggle of the menu
    table.activate_action("row.favorite", None).expect("row.favorite");
    wait_until("the favorite", || r.ctl().read(|m| m.filter.favorites.contains("tokyo1.opengw.net")));
    wait_until("the button label", || {
        named::<gtk::Button>(r.win(), "favorite").label().as_deref() == Some("Remove from Favorites")
    });
    let only: gtk::ToggleButton = named(r.win(), "favorites-only");
    click(only.upcast_ref());
    wait_until("favorites only", || r.visible_ids() == ["tokyo1.opengw.net"]);
    wait_until("the table", || r.table_ids() == ["tokyo1.opengw.net"]);
    click(only.upcast_ref());
    wait_until("all rows again", || r.visible_ids().len() == 5);
    r.select("tokyo1.opengw.net");
    table.activate_action("row.favorite", None).expect("row.favorite");
    wait_until("the favorite to go", || r.ctl().read(|m| m.filter.favorites.is_empty()));

    // row.details: the Server Details sheet
    table.activate_action("row.details", None).expect("row.details");
    let dialog = dialog_of(&r.top());
    assert!(dialog.title().contains("tokyo1.opengw.net"), "{}", dialog.title());
    let ip: adw::ActionRow = row(&dialog, "IP Address");
    assert_eq!(subtitle(&ip), "1.1.1.1");
    let country: adw::ActionRow = row(&dialog, "Country");
    assert_eq!(subtitle(&country), "Japan (JP)");
    click(&button(&dialog, "Done"));
    wait_no_dialog(&r.top());

    // the Details button does the same
    click(&named::<gtk::Button>(r.win(), "details"));
    assert!(dialog_of(&r.top()).title().contains("tokyo1.opengw.net"));
    click(&button(&dialog_of(&r.top()), "Done"));
    wait_no_dialog(&r.top());

    // row.connect: sends the connect request
    table.activate_action("row.connect", None).expect("row.connect");
    r.wait_request("connect");
    wait_until("the busy state", || r.ctl().read(|m| m.state == ConnectionState::Connecting));
    assert_eq!(named::<gtk::Button>(r.win(), "action").label().as_deref(), Some("Cancel"));
}

fn connect_and_disconnect_buttons(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let action: gtk::Button = named(r.win(), "action");
    assert!(!action.is_sensitive());
    r.select("osaka.opengw.net");
    wait_until("the button to enable", || action.is_sensitive());
    assert_eq!(action.label().as_deref(), Some("Connect to the VPN Server"));
    click(&action);
    r.wait_request("connect");
    wait_until("Cancel", || action.label().as_deref() == Some("Cancel"));
    assert_eq!(r.text("state"), "Connecting…");
    click(&action);
    r.wait_request("disconnect");
    wait_until("the disconnected state", || r.ctl().read(|m| m.state == ConnectionState::Disconnected));
    wait_until("Connect again", || action.label().as_deref() == Some("Connect to the VPN Server"));
}

fn disclaimer_gates_the_app(h: &Harness) {
    let r = Rig::new(h, false);
    let dialog = dialog_of(&r.top());
    let alert = dialog.downcast::<adw::AlertDialog>().expect("the disclaimer is an alert dialog");
    assert_eq!(alert.property::<Option<String>>("heading").as_deref(), Some("VPN Gate Academic Experiment Service"));
    assert!(alert.property::<Option<String>>("body").unwrap_or_default().contains("academic research project"));
    assert!(r.ctl().read(|m| m.show_disclaimer));
    // Agree and Continue
    match try_find(&alert, |b: &gtk::Button| b.label().as_deref() == Some("Agree and Continue")) {
        Some(b) => b.emit_clicked(),
        None => alert.emit_by_name::<()>("response", &[&"agree"]),
    }
    wait_until("the agreement", || !r.ctl().read(|m| m.show_disclaimer) && r.ctl().settings().has_agreed_to_disclaimer);
    alert.close();
    wait_no_dialog(&r.top());
}

fn accounts_window_and_editor(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let win = r.open("win.accounts", "VPN Connection Settings");
    wait_until("the empty state", || has_label(&win, "No VPN connection settings yet"));
    for b in ["Properties", "Delete", "Connect"] {
        assert!(!button(&win, b).is_sensitive(), "{b} needs a selected account");
    }

    // New Setting: validation drives the Save button and the message under the form
    click(&button(&win, "New Setting"));
    let dialog = dialog_of(&win);
    assert_eq!(dialog.title(), "New VPN Connection Setting");
    let save = button(&dialog, "Save");
    assert!(!save.is_sensitive(), "a new setting has no host");
    let probe = AccountEditor { host: "bad host!".into(), ..AccountEditor::default() };
    let host_msg = probe.host_error().expect("an invalid host").to_string();
    let host: adw::EntryRow = row(&dialog, "Host Name / IP Address");
    host.set_text("bad host!");
    pump();
    assert!(has_label_containing(&dialog, &host_msg), "the host message {host_msg:?} is shown");
    assert!(!save.is_sensitive());
    host.set_text("vpn.example.com");
    let name: adw::EntryRow = row(&dialog, "Setting Name");
    name.set_text("Home");
    pump();
    assert!(!has_label_containing(&dialog, &host_msg));
    assert!(save.is_sensitive(), "name and host are enough");

    // certificate authentication needs an imported identity
    let auth: adw::ComboRow = row(&dialog, "Auth Type");
    auth.set_selected(3);
    pump();
    assert!(!save.is_sensitive(), "certificate auth without a certificate cannot be saved");
    let cert: adw::ActionRow = row(&dialog, "Certificate");
    assert!(cert.is_visible());
    let user: adw::EntryRow = row(&dialog, "User Name");
    assert!(user.is_visible());
    auth.set_selected(0);
    pump();
    assert!(!user.is_visible(), "anonymous login has no user name");
    assert!(save.is_sensitive());
    auth.set_selected(1);

    // advanced fields are validated too
    let mtu: adw::EntryRow = row(&dialog, "MTU (blank = automatic)");
    mtu.set_text("9999");
    pump();
    assert!(!save.is_sensitive());
    assert!(has_label_containing(&dialog, "MTU must be 576–1500, or blank for automatic."));
    mtu.set_text("1400");
    pump();
    assert!(save.is_sensitive());

    // custom routing shows its rule groups
    let custom: adw::SwitchRow = row(&dialog, "Use custom routing rules for this connection");
    let rules: adw::PreferencesGroup = find(&dialog, "Rules", |g: &adw::PreferencesGroup| g.title() == "Rules");
    assert!(!rules.is_visible());
    custom.set_active(true);
    pump();
    assert!(rules.is_visible());
    custom.set_active(false);

    click(&save);
    wait_no_dialog(&win);
    let saved = r.ctl().with_stores(|s| s.accounts.accounts.clone());
    assert_eq!(saved.len(), 1);
    assert_eq!((saved[0].name.as_str(), saved[0].host.as_str()), ("Home", "vpn.example.com"));
    wait_until("the row in the list", || try_find(&win, |r: &adw::ActionRow| r.title() == "Home").is_some());

    // select it: Properties / Duplicate / Delete
    let list = find(&win, "the accounts list", |l: &gtk::ListBox| l.selection_mode() == gtk::SelectionMode::Single);
    list.select_row(list.row_at_index(0).as_ref());
    pump();
    assert!(button(&win, "Properties").is_sensitive() && button(&win, "Delete").is_sensitive());
    click(&button(&win, "Properties"));
    let edit = dialog_of(&win);
    assert_eq!(edit.title(), "Edit VPN Connection Setting");
    assert_eq!(row::<adw::EntryRow>(&edit, "Host Name / IP Address").text(), "vpn.example.com");
    assert!(button(&edit, "Save").is_sensitive());
    click(&button(&edit, "Cancel"));
    wait_no_dialog(&win);
    click(&button(&win, "Duplicate"));
    wait_until("the copy", || r.ctl().with_stores(|s| s.accounts.accounts.len()) == 2);
    wait_until("the copy in the list", || {
        all::<adw::ActionRow>(&win).iter().filter(|r| r.title().starts_with("Home")).count() == 2
    });
    list.select_row(list.row_at_index(0).as_ref());
    pump();
    click(&button(&win, "Delete"));
    wait_until("the delete", || r.ctl().with_stores(|s| s.accounts.accounts.len()) == 1);

    // connecting with an account sends a connect request
    list.select_row(list.row_at_index(0).as_ref());
    pump();
    click(&button(&win, "Connect"));
    r.wait_request("connect");
}

fn rule_values(r: &Rig) -> Vec<String> {
    r.ctl().settings().routing.rules.iter().map(|x| x.value.clone()).collect()
}

fn add_rule(
    settings: &adw::PreferencesDialog,
    host: &gtk::Window,
    kind: Option<u32>,
    action: Option<u32>,
    value: &str,
) {
    click(&button(settings, "Add Rule…"));
    let rule = dialog_of(host);
    assert_eq!(rule.title(), "New Rule");
    let add = button(&rule, "Add");
    assert!(!add.is_sensitive(), "an empty value cannot be added");
    if let Some(k) = kind {
        row::<adw::ComboRow>(&rule, "Match").set_selected(k);
    }
    if let Some(a) = action {
        row::<adw::ComboRow>(&rule, "Action").set_selected(a);
    }
    row::<adw::EntryRow>(&rule, "Value").set_text(value);
    pump();
    click(&add);
    wait_until("the rule dialog to close", || {
        let top = dialog_of(host);
        top.is::<adw::PreferencesDialog>()
    });
}

fn settings_dialog_tabs_and_routing(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    gtk::prelude::WidgetExt::activate_action(r.win(), "win.settings", None).expect("win.settings");
    let host = r.top();
    let settings = dialog_of(&host).downcast::<adw::PreferencesDialog>().expect("the settings dialog");
    let titles: Vec<String> = all::<adw::PreferencesPage>(&settings).iter().map(|p| p.title().to_string()).collect();
    for t in ["General", "Proxy", "Routing", "Advanced"] {
        assert!(titles.iter().any(|x| x == t), "tab {t} missing from {titles:?}");
    }
    let page = |title: &str| find(&settings, title, |p: &adw::PreferencesPage| p.title() == title);

    // General
    settings.set_visible_page(&page("General"));
    let reconnect: adw::SwitchRow = row(&settings, "Reconnect automatically");
    assert!(reconnect.is_active());
    reconnect.set_active(false);
    assert!(!r.ctl().settings().auto_reconnect, "settings are written through at once");
    let ipv6: adw::SwitchRow = row(&settings, "Block IPv6 while connected");
    ipv6.set_active(true);
    assert!(r.ctl().settings().block_ipv6);
    let socks_port: adw::SpinRow = row(&settings, "SOCKS port");
    assert!(!socks_port.is_visible(), "the SOCKS port only shows in SOCKS mode");
    row::<adw::ComboRow>(&settings, "Use the VPN as").set_selected(1);
    pump();
    assert!(socks_port.is_visible());
    assert_eq!(r.ctl().settings().tunnel_mode, vpngate_core::ipc::TunnelMode::SocksProxy);
    socks_port.set_value(1081.0);
    assert_eq!(r.ctl().settings().socks_port, 1081);
    // launch at login writes the XDG autostart entry (XDG_CONFIG_HOME is a temporary directory)
    let login: adw::SwitchRow = row(&settings, "Launch at login");
    assert!(!autostart::is_enabled(&autostart::entry_path()));
    login.set_active(true);
    assert!(autostart::is_enabled(&autostart::entry_path()), "{}", autostart::entry_path().display());
    login.set_active(false);
    assert!(!autostart::is_enabled(&autostart::entry_path()));

    // Proxy
    settings.set_visible_page(&page("Proxy"));
    let proxy_host: adw::EntryRow = row(&settings, "Proxy host");
    assert!(!proxy_host.is_sensitive(), "no proxy, no proxy fields");
    row::<adw::ComboRow>(&settings, "Proxy").set_selected(1);
    pump();
    assert!(proxy_host.is_sensitive());
    assert_eq!(r.ctl().settings().proxy_kind, vpngate_core::ipc::ProxyKind::Http);
    proxy_host.set_text("proxy.example.com");
    assert_eq!(r.ctl().settings().proxy_host, "proxy.example.com");
    row::<adw::SpinRow>(&settings, "Proxy port").set_value(3128.0);
    assert_eq!(r.ctl().settings().proxy_port, 3128);
    row::<adw::PasswordEntryRow>(&settings, "Password").set_text("s3cret");
    assert_eq!(r.ctl().proxy_password().as_deref(), Some("s3cret"), "the password goes to the secret store");
    assert!(r.ctl().settings().proxy_username.is_empty());

    // Advanced
    settings.set_visible_page(&page("Advanced"));
    row::<adw::EntryRow>(&settings, "Mirror URL (optional)").set_text("https://mirror.example/list.csv");
    assert_eq!(r.ctl().settings().mirror_url, "https://mirror.example/list.csv");

    // Routing: defaults
    settings.set_visible_page(&page("Routing"));
    row::<adw::ComboRow>(&settings, "By default").set_selected(1);
    assert_eq!(r.ctl().settings().routing.default_action, RoutingAction::Direct);
    row::<adw::ComboRow>(&settings, "By default").set_selected(0);
    let bypass: adw::SwitchRow = row(&settings, "Bypass private networks");
    let before = r.ctl().settings().routing.bypass_private_networks;
    bypass.set_active(!before);
    assert_eq!(r.ctl().settings().routing.bypass_private_networks, !before);
    // ... rules: add three
    assert!(try_find(&settings, |r: &adw::ActionRow| r.title().starts_with("No custom rules")).is_some());
    add_rule(&settings, &host, None, None, "a.example");
    add_rule(&settings, &host, None, Some(1), "b.example");
    add_rule(&settings, &host, None, Some(2), "c.example");
    assert_eq!(rule_values(&r), ["a.example", "b.example", "c.example"]);
    let rules = r.ctl().settings().routing.rules;
    assert_eq!(
        rules.iter().map(|x| x.action).collect::<Vec<_>>(),
        [RoutingAction::Proxy, RoutingAction::Direct, RoutingAction::Block]
    );
    // up / down buttons of a row
    let rule_row = |value: &str| -> adw::ActionRow { row(&settings, value) };
    click(&button_with_tooltip(&rule_row("a.example"), "Move down"));
    assert_eq!(rule_values(&r), ["b.example", "a.example", "c.example"]);
    click(&button_with_tooltip(&rule_row("c.example"), "Move up"));
    assert_eq!(rule_values(&r), ["b.example", "c.example", "a.example"]);
    assert!(!button_with_tooltip(&rule_row("b.example"), "Move up").is_sensitive(), "the first rule cannot move up");
    assert!(!button_with_tooltip(&rule_row("a.example"), "Move down").is_sensitive(), "the last rule cannot move down");
    click(&button_with_tooltip(&rule_row("b.example"), "Delete"));
    assert_eq!(rule_values(&r), ["c.example", "a.example"]);

    // the rule sheet validates the value for the chosen type
    click(&button(&settings, "Add Rule…"));
    let sheet = dialog_of(&host);
    row::<adw::ComboRow>(&sheet, "Match").set_selected(5); // IP range (CIDR)
    row::<adw::EntryRow>(&sheet, "Value").set_text("not a range");
    pump();
    assert!(!button(&sheet, "Add").is_sensitive());
    let why = RoutingRule::validation_error(RoutingRuleType::Cidr, "not a range").expect("invalid CIDR");
    assert!(has_label(&sheet, why), "{why:?} is shown");
    row::<adw::EntryRow>(&sheet, "Value").set_text("10.0.0.0/8");
    pump();
    assert!(button(&sheet, "Add").is_sensitive());
    click(&button(&sheet, "Cancel"));
    wait_until("the sheet to close", || dialog_of(&host).is::<adw::PreferencesDialog>());
    assert_eq!(rule_values(&r), ["c.example", "a.example"], "Cancel adds nothing");

    // Advanced: Show Log… opens the log window
    settings.set_visible_page(&page("Advanced"));
    let show_log: adw::ActionRow = row(&settings, "Show Log…");
    show_log.emit_by_name::<()>("activated", &[]);
    toplevel("Connection Log");
}

fn drag_reorder_moves_the_rule(_: &Harness) {
    let rule = |v: &str| RoutingRule::new(RoutingRuleType::DomainSuffix, v, RoutingAction::Proxy);
    let order = |rules: &[RoutingRule]| rules.iter().map(|r| r.value.clone()).collect::<Vec<_>>();
    let mut rules = vec![rule("a"), rule("b"), rule("c"), rule("d")];
    assert!(routing_editor::move_rule(&mut rules, 0, 2), "dropping the first rule on the third row");
    assert_eq!(order(&rules), ["b", "c", "a", "d"]);
    assert!(routing_editor::move_rule(&mut rules, 3, 0), "dropping the last rule on the first row");
    assert_eq!(order(&rules), ["d", "b", "c", "a"]);
    assert!(!routing_editor::move_rule(&mut rules, 1, 1), "dropping a rule on itself changes nothing");
    assert!(!routing_editor::move_rule(&mut rules, 9, 0), "a stale source index is ignored");
    assert!(!routing_editor::move_rule(&mut rules, 0, 9), "a stale target index is ignored");
    assert_eq!(order(&rules), ["d", "b", "c", "a"]);
}

fn fill_history(s: &mut Stores) {
    let a = s.history.record_start("tokyo1.opengw.net", "1.1.1.1", 1_700_000_000_000);
    s.history.record_end(a, 1_500_000, 250_000, None, 1_700_000_000_000 + 3_725_000);
    let b = s.history.record_start("osaka.opengw.net", "2.2.2.2", 1_700_100_000_000);
    s.history.record_end(b, 0, 0, Some("Authentication failed".into()), 1_700_100_000_000 + 12_000);
}

fn history_window_lists_and_clears(h: &Harness) {
    let r = Rig::with_stores(h, true, fill_history);
    r.loaded();
    let win = r.open("win.history", "Connection history");
    wait_until("the entries", || try_find(&win, |x: &adw::ActionRow| x.title() == "osaka.opengw.net").is_some());
    let ok: adw::ActionRow = row(&win, "tokyo1.opengw.net");
    let sub = subtitle(&ok);
    assert!(sub.contains("1.1.1.1") && sub.contains("2023-11-14") && sub.contains("ended"), "{sub}");
    let failed: adw::ActionRow = row(&win, "osaka.opengw.net");
    assert!(subtitle(&failed).contains("Authentication failed"));
    assert!(failed.has_css_class("error"));
    let clear = button(&win, "Clear");
    assert!(clear.is_sensitive());
    click(&clear);
    wait_until("the history to empty", || r.ctl().with_stores(|s| s.history.entries.is_empty()));
    wait_until("the empty state", || try_find(&win, |x: &adw::ActionRow| x.title() == "No connections yet.").is_some());
    assert!(!clear.is_sensitive());
}

fn log_window_follows_the_daemon(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let win = r.open("win.log", "Connection Log");
    wait_until("the daemon connection", || r.daemon.client_count() > 0);
    let mut ev = HelperEvent::new(ConnectionState::Disconnected);
    ev.log = Some("Hello from the fake daemon".into());
    r.daemon.push(&Line::Event(ev));
    let view: gtk::TextView = find(&win, "the log text", |_: &gtk::TextView| true);
    wait_until("the log line", || text_of(&view).contains("Hello from the fake daemon"));
}

// --------------------------------------------------------------------------------------------------------- golden screenshots

fn golden_main_window(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    wait_until("the cells", || has_label(&r.table(), "1.1.1.1 (tokyo1.opengw.net)"));
    r.select("seoul.opengw.net");
    golden("main-window", &r.top());
}

fn golden_disclaimer(h: &Harness) {
    let r = Rig::new(h, false);
    dialog_of(&r.top());
    golden("disclaimer", &r.top());
}

fn golden_server_details(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    r.select("tokyo1.opengw.net");
    click(&named::<gtk::Button>(r.win(), "details"));
    dialog_of(&r.top());
    golden("server-details", &r.top());
}

fn golden_accounts_window(h: &Harness) {
    let r = Rig::with_stores(h, true, |s| {
        let mut a = vpngate_core::client_account::ClientAccount::new("Office", "vpn.office.example");
        a.username = "alice".into();
        let mut b = vpngate_core::client_account::ClientAccount::new("Home server", "home.example.net");
        b.username = "bob".into();
        let e = AccountEditor::from_account(&a, Some("pw".into()), false);
        s.accounts.add(a, e.secrets());
        let e = AccountEditor::from_account(&b, Some("pw".into()), false);
        s.accounts.add(b, e.secrets());
    });
    r.loaded();
    let win = r.open("win.accounts", "VPN Connection Settings");
    wait_until("the accounts", || try_find(&win, |x: &adw::ActionRow| x.title() == "Office").is_some());
    golden("accounts-window", &win);
}

fn golden_account_editor(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    let win = r.open("win.accounts", "VPN Connection Settings");
    click(&button(&win, "New Setting"));
    dialog_of(&win);
    golden("account-editor", &win);
}

fn golden_settings(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    gtk::prelude::WidgetExt::activate_action(r.win(), "win.settings", None).expect("win.settings");
    let settings = dialog_of(&r.top()).downcast::<adw::PreferencesDialog>().expect("settings");
    golden("settings-general", &r.top());
    let page = find(&settings, "Routing", |p: &adw::PreferencesPage| p.title() == "Routing");
    settings.set_visible_page(&page);
    for v in ["example.com", "ads.example.net"] {
        add_rule(&settings, &r.top(), None, Some(u32::from(v.starts_with("ads")) * 2), v);
    }
    golden("settings-routing", &r.top());
}

fn golden_history(h: &Harness) {
    let r = Rig::with_stores(h, true, fill_history);
    r.loaded();
    let win = r.open("win.history", "Connection history");
    wait_until("the entries", || try_find(&win, |x: &adw::ActionRow| x.title() == "osaka.opengw.net").is_some());
    golden("history", &win);
}

fn golden_log(h: &Harness) {
    let r = Rig::new(h, true);
    r.loaded();
    r.ctl().change(|m| {
        for l in [
            "Connecting to tokyo1.opengw.net (1.1.1.1:443)",
            "TLS handshake done",
            "Authenticated as anonymous",
            "DHCP lease 10.21.0.7",
        ] {
            m.append_log(l.to_string());
        }
    });
    let win = r.open("win.log", "Connection Log");
    let view: gtk::TextView = find(&win, "the log text", |_: &gtk::TextView| true);
    wait_until("the log text", || text_of(&view).contains("DHCP lease"));
    golden("log", &win);
}

// ------------------------------------------------------------------------------------------------------------------------ main

fn main() {
    if std::env::var_os("VPNGATE_UI_TESTS").is_none() {
        println!("ui tests skipped: set VPNGATE_UI_TESTS=1 and run under a display (xvfb-run -a cargo test --test ui)");
        return;
    }
    // Deterministic rendering: Cairo (software) renderer, X11 on the virtual display, no accessibility bus.
    std::env::set_var("GSK_RENDERER", "cairo");
    std::env::set_var("GDK_BACKEND", "x11");
    std::env::set_var("GTK_A11Y", "none");
    std::env::set_var("GSETTINGS_BACKEND", "memory");
    // Nothing of the user's: settings, autostart entries and caches go to a temporary directory.
    let home = std::env::temp_dir().join(format!("vpngate-ui-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("temporary home");
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", home.join("config"));
    std::env::set_var("XDG_DATA_HOME", home.join("data"));
    std::env::set_var("XDG_CACHE_HOME", home.join("cache"));

    adw::init().expect("GTK needs a display: run under xvfb-run");
    let settings = gtk::Settings::default().expect("GTK settings");
    settings.set_property("gtk-enable-animations", false);
    settings.set_property("gtk-cursor-blink", false);
    settings.set_property("gtk-font-name", "DejaVu Sans 10");
    settings.set_property("gtk-icon-theme-name", "Adwaita");
    settings.set_property("gtk-xft-antialias", 1i32);
    settings.set_property("gtk-xft-hinting", 0i32);
    settings.set_property("gtk-xft-dpi", 98304i32);
    settings.set_property("gtk-xft-rgba", "none");
    adw::StyleManager::default().set_color_scheme(adw::ColorScheme::ForceLight);

    let rt =
        Arc::new(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio"));
    let app = adw::Application::builder()
        .application_id("net.vpngate.UiTest")
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    app.register(gio::Cancellable::NONE).expect("register the test application");
    let harness = Harness { app, rt };

    let cases: &[(&str, Case)] = &[
        ("main_window_lists_servers", main_window_lists_servers),
        ("search_and_clear_filters", search_and_clear_filters),
        ("country_and_logging_filters", country_and_logging_filters),
        ("sort_drop_down_and_direction", sort_drop_down_and_direction),
        ("header_click_sorts", header_click_sorts),
        ("column_chooser", column_chooser),
        ("row_context_menu_and_actions", row_context_menu_and_actions),
        ("connect_and_disconnect_buttons", connect_and_disconnect_buttons),
        ("disclaimer_gates_the_app", disclaimer_gates_the_app),
        ("accounts_window_and_editor", accounts_window_and_editor),
        ("settings_dialog_tabs_and_routing", settings_dialog_tabs_and_routing),
        ("drag_reorder_moves_the_rule", drag_reorder_moves_the_rule),
        ("history_window_lists_and_clears", history_window_lists_and_clears),
        ("log_window_follows_the_daemon", log_window_follows_the_daemon),
        ("golden_main_window", golden_main_window),
        ("golden_disclaimer", golden_disclaimer),
        ("golden_server_details", golden_server_details),
        ("golden_accounts_window", golden_accounts_window),
        ("golden_account_editor", golden_account_editor),
        ("golden_settings", golden_settings),
        ("golden_history", golden_history),
        ("golden_log", golden_log),
    ];
    let filter: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
    let (mut passed, mut failed) = (0, Vec::new());
    println!("running {} ui tests", cases.len());
    for (name, case) in cases {
        if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        let result = catch_unwind(AssertUnwindSafe(|| case(&harness)));
        match result {
            Ok(()) => {
                println!("test {name} ... ok");
                passed += 1;
            }
            Err(_) => {
                println!("test {name} ... FAILED");
                failed.push(*name);
            }
        }
    }
    println!(
        "\nui test result: {}. {passed} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len()
    );
    if !failed.is_empty() {
        println!("failed: {}", failed.join(", "));
        std::process::exit(1);
    }
}
