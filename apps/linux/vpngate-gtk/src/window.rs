//! The main window (UI-SPEC 1, 4, 10): header, connection card, filter bar, server table, action bar, and the disclaimer.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use gtk::{gio, glib};
use vpngate_app_model::accounts::AccountStore;
use vpngate_app_model::format;
use vpngate_app_model::history::History;
use vpngate_app_model::model::SortKey;
use vpngate_app_model::secrets::SecretTool;
use vpngate_app_model::settings::FileSettings;
use vpngate_app_model::{now_ms, Controller, Stores, Timing};
use vpngate_core::ipc::ConnectionState;
use vpngate_core::server_list::VpnServer;
use vpngate_ipc_client::IpcClient;

use crate::accounts_window::AccountsWindow;
use crate::ctx::Ctx;
use crate::history_window::HistoryWindow;
use crate::log_window::LogWindow;
use crate::settings_window;
use crate::tray::{self, TrayAction, TraySnapshot};

const INTRO: &str =
    "Gain freedom access to Internet by using VPN connection via Public VPN Servers provided by volunteers \
around the world. Bypass your local malfunctioning firewall's packet blocking, and hide your IP address safely.";

const DISCLAIMER: &str = "VPN Gate is an academic research project of the Graduate School of University of Tsukuba, \
Japan.\n\nPublic VPN relay servers are hosted by volunteers around the world. Anyone can connect through these servers to \
achieve anonymity and bypass censorship.\n\nBy clicking “Agree and Continue”, you confirm that you will use this service in \
compliance with local laws.\n\nOptional diagnostics upload is off and can be turned on in Settings → Advanced.";

const LOGGING_CHOICES: [(&str, Option<i64>); 4] =
    [("Any logging policy", None), ("2 weeks or less", Some(2)), ("Up to 1 month", Some(5)), ("No logs only", Some(0))];

const SORT_CHOICES: [(&str, SortKey); 8] = [
    ("Total Score", SortKey::Score),
    ("Host name", SortKey::Host),
    ("Region", SortKey::Country),
    ("Uptime", SortKey::Uptime),
    ("VPN Sessions", SortKey::Sessions),
    ("Line Speed", SortKey::Speed),
    ("Ping", SortKey::Ping),
    ("Logging Policy", SortKey::Logging),
];

/// Messages from other threads (the controller's `notify`, the tray) to the GTK main loop.
enum Ui {
    Changed,
    Tray(TrayAction),
    Quit,
}

struct Widgets {
    state: gtk::Label,
    spinner: gtk::Spinner,
    server: gtk::Label,
    virtual_ip: gtk::Label,
    traffic: gtk::Label,
    notice: gtk::Label,
    list_status: gtk::Label,
    search: gtk::SearchEntry,
    country: gtk::DropDown,
    country_list: gtk::StringList,
    logging: gtk::DropDown,
    sort: gtk::DropDown,
    descending: gtk::ToggleButton,
    favorites_only: gtk::ToggleButton,
    clear: gtk::Button,
    refresh: gtk::Button,
    favorite: gtk::Button,
    details: gtk::Button,
    action: gtk::Button,
    store: gtk::StringList,
    selection: gtk::SingleSelection,
    table: gtk::ColumnView,
}

struct Shown {
    ids: Vec<String>,
    favorites: BTreeSet<String>,
    countries: Vec<String>,
}

pub fn build(app: &adw::Application, rt: Arc<tokio::runtime::Runtime>, socket: String) {
    let (tx, rx) = async_channel::unbounded::<Ui>();
    let (ipc, events) = IpcClient::new(socket);
    let notify = tx.clone();
    let quit = tx.clone();
    let secrets: Arc<dyn vpngate_app_model::secrets::SecretStore> = Arc::new(SecretTool::new());
    let stores = Stores {
        accounts: AccountStore::new(AccountStore::default_path(), secrets.clone()),
        history: History::new(Some(History::default_path())),
        secrets,
    };
    let ctl = Controller::new(
        ipc,
        Box::new(FileSettings::new(FileSettings::default_path())),
        stores,
        Timing::default(),
        move || {
            let _ = notify.try_send(Ui::Changed);
        },
        move || {
            let _ = quit.try_send(Ui::Quit);
        },
    );

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("VPN Gate Public VPN Relay Servers")
        .default_width(980)
        .default_height(680)
        .width_request(560)
        .build();
    let w = Rc::new(widgets());
    window.set_content(Some(&layout(&w)));
    let log = Rc::new(LogWindow::new(&window));
    let ctx = Ctx { ctl: ctl.clone(), rt: rt.clone() };
    let accounts = {
        let w = window.clone();
        AccountsWindow::new(&window, &ctx, move || w.present())
    };
    let history = HistoryWindow::new(&window, &ctx);
    let tray_tx = {
        let tx = tx.clone();
        tray::spawn(rt.handle(), move |a| {
            let _ = tx.try_send(Ui::Tray(a));
        })
    };

    wire_table(&w, &ctl, &rt);
    wire_filters(&w, &ctl);
    wire_buttons(&w, &ctl, &rt);
    add_actions(app, &window, &log, &tx);
    add_window_actions(&window, &ctx, &log, &accounts, &history);
    wire_details(&w, &ctl, &window);

    let shown = Rc::new(RefCell::new(Shown { ids: vec![], favorites: BTreeSet::new(), countries: vec![] }));
    let disclaimer_open = Rc::new(Cell::new(false));
    let updating = Rc::new(Cell::new(false));
    let sync = {
        let (w, ctl, log, window, rt) = (w.clone(), ctl.clone(), log.clone(), window.clone(), rt.clone());
        let (accounts, history) = (accounts.clone(), history.clone());
        let tray_tx = tray_tx.clone();
        Rc::new(move || {
            updating.set(true);
            refresh_widgets(&w, &ctl, &shown);
            updating.set(false);
            if log.is_visible() {
                log.set_text(&ctl.read(|m| m.log_text()));
            }
            accounts.refresh();
            history.refresh();
            let _ = tray_tx.send(tray_snapshot(&ctl));
            if ctl.read(|m| m.show_disclaimer) && !disclaimer_open.replace(true) {
                show_disclaimer(&window, &ctl, &rt, disclaimer_open.clone());
            }
        })
    };

    // Everything from other threads arrives here. Bursts of `Changed` collapse into one refresh.
    {
        let (sync, window, app, ctl, rt, log) =
            (sync.clone(), window.clone(), app.clone(), ctl.clone(), rt.clone(), log.clone());
        glib::spawn_future_local(async move {
            while let Ok(msg) = rx.recv().await {
                let mut msgs = vec![msg];
                while let Ok(m) = rx.try_recv() {
                    msgs.push(m);
                }
                for m in msgs {
                    match m {
                        Ui::Changed => {}
                        Ui::Quit => app.quit(),
                        Ui::Tray(a) => on_tray(a, &window, &app, &ctl, &rt, &log),
                    }
                }
                sync();
            }
        });
    }
    // The traffic line shows the connection time, which ticks without any daemon event.
    {
        let sync = sync.clone();
        glib::timeout_add_seconds_local(1, move || {
            sync();
            glib::ControlFlow::Continue
        });
    }

    let c = ctl.clone();
    rt.spawn(async move { c.pump(events).await });
    let c = ctl.clone();
    rt.spawn(async move {
        c.start().await;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            c.poll().await;
        }
    });
    sync();
    window.present();
}

fn widgets() -> Widgets {
    let label = |css: &[&str]| {
        let l = gtk::Label::builder().xalign(0.0).wrap(true).build();
        for c in css {
            l.add_css_class(c);
        }
        l
    };
    let country_list = gtk::StringList::new(&["All countries"]);
    let store = gtk::StringList::new(&[]);
    let selection = gtk::SingleSelection::new(Some(store.clone()));
    selection.set_autoselect(false);
    selection.set_can_unselect(true);
    let logging = gtk::DropDown::from_strings(&LOGGING_CHOICES.map(|c| c.0));
    logging.set_tooltip_text(Some("Logging policy"));
    let sort = gtk::DropDown::from_strings(&SORT_CHOICES.map(|c| c.0));
    sort.set_tooltip_text(Some("Sort by"));
    let country = gtk::DropDown::new(Some(country_list.clone()), gtk::Expression::NONE);
    country.set_tooltip_text(Some("Country"));
    Widgets {
        state: label(&["title-3"]),
        spinner: gtk::Spinner::new(),
        server: label(&[]),
        virtual_ip: label(&["dim-label"]),
        traffic: label(&["dim-label", "numeric"]),
        notice: {
            let l = label(&["error"]);
            l.set_lines(3);
            l.set_ellipsize(gtk::pango::EllipsizeMode::End);
            l
        },
        list_status: label(&["dim-label"]),
        search: gtk::SearchEntry::builder()
            .placeholder_text("Search host, IP, country, operator")
            .hexpand(true)
            .build(),
        country,
        country_list,
        logging,
        sort,
        descending: gtk::ToggleButton::builder()
            .icon_name("view-sort-descending-symbolic")
            .tooltip_text("Descending")
            .active(true)
            .build(),
        favorites_only: gtk::ToggleButton::builder().label("Favorites only").build(),
        clear: gtk::Button::builder().label("Clear Filters").build(),
        refresh: gtk::Button::builder().icon_name("view-refresh-symbolic").tooltip_text("Refresh List").build(),
        favorite: gtk::Button::builder().label("Add to Favorites").build(),
        details: gtk::Button::builder().label("Details").build(),
        action: gtk::Button::builder().label("Connect to the VPN Server").build(),
        store,
        table: gtk::ColumnView::new(Some(selection.clone())),
        selection,
    }
}

fn layout(w: &Widgets) -> adw::ToolbarView {
    let header = adw::HeaderBar::new();
    header.pack_start(&w.refresh);
    let menu = gio::Menu::new();
    menu.append(Some("VPN Connection Settings…"), Some("win.accounts"));
    menu.append(Some("Connection History"), Some("win.history"));
    menu.append(Some("Settings…"), Some("win.settings"));
    menu.append(Some("Connection Log"), Some("win.log"));
    menu.append(Some("VPN Gate Web Site"), Some("app.website"));
    menu.append(Some("Quit"), Some("app.quit"));
    header.pack_end(&gtk::MenuButton::builder().icon_name("open-menu-symbolic").menu_model(&menu).build());

    // card: state with spinner, server, virtual IP, traffic, notice
    let state_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    state_row.append(&w.spinner);
    state_row.append(&w.state);
    let card = gtk::Box::new(gtk::Orientation::Vertical, 4);
    card.add_css_class("card");
    card.set_width_request(260);
    card.set_valign(gtk::Align::Start);
    for m in [("margin_top", 12), ("margin_bottom", 12), ("margin_start", 12), ("margin_end", 12)] {
        card.set_property(m.0, m.1);
    }
    card.append(&state_row);
    card.append(&w.server);
    card.append(&w.virtual_ip);
    card.append(&w.traffic);
    card.append(&w.notice);

    let title = gtk::Label::builder()
        .label("VPN Gate Public VPN Relay Servers")
        .xalign(0.0)
        .wrap(true)
        .css_classes(["title-2"])
        .build();
    let intro = gtk::Label::builder().label(INTRO).xalign(0.0).wrap(true).build();
    let intro_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    intro_box.set_hexpand(true);
    intro_box.append(&title);
    intro_box.append(&intro);
    let top = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    top.append(&intro_box);
    top.append(&card);

    let filters = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    for c in [
        w.search.clone().upcast::<gtk::Widget>(),
        w.country.clone().upcast(),
        w.logging.clone().upcast(),
        w.favorites_only.clone().upcast(),
        w.sort.clone().upcast(),
        w.descending.clone().upcast(),
        w.clear.clone().upcast(),
    ] {
        filters.append(&c);
    }

    w.table.set_show_row_separators(true);
    w.table.set_vexpand(true);
    let scroller = gtk::ScrolledWindow::builder().child(&w.table).vexpand(true).has_frame(true).build();

    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    bar.set_halign(gtk::Align::End);
    bar.append(&w.details);
    bar.append(&w.favorite);
    bar.append(&w.action);

    let body = gtk::Box::new(gtk::Orientation::Vertical, 10);
    for m in ["margin_top", "margin_bottom", "margin_start", "margin_end"] {
        body.set_property(m, 16);
    }
    body.append(&top);
    body.append(&filters);
    body.append(&w.list_status);
    body.append(&scroller);
    body.append(&bar);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&body));
    toolbar
}

type CellText = fn(&VpnServer) -> String;

/// Default columns of UI-SPEC 4; the rest (and reordering) come with U23.
fn columns() -> Vec<(&'static str, CellText)> {
    vec![
        ("IP Address (Hostname)", |s| format!("{} ({})", s.ip, s.host_name)),
        ("Region", |s| format!("{} {}", s.flag(), s.country_long)),
        ("Uptime", |s| format::uptime(s.uptime_ms)),
        ("VPN Sessions", |s| format::sessions(s.sessions)),
        ("Line Speed", |s| format::speed(s.speed)),
        ("Ping (Google, SE)", |s| format::pings(s.ping_to_google, s.ping)),
        ("Logging Policy", |s| format::logging(&s.log_type)),
        ("Total Score", |s| s.score.to_string()),
    ]
}

fn wire_table(w: &Rc<Widgets>, ctl: &Controller, rt: &Arc<tokio::runtime::Runtime>) {
    let table = &w.table;
    for (i, (title, cell)) in columns().into_iter().enumerate() {
        let factory = gtk::SignalListItemFactory::new();
        factory.connect_setup(|_, item| {
            let l = gtk::Label::builder().xalign(0.0).margin_start(6).margin_end(6).build();
            item.downcast_ref::<gtk::ListItem>().expect("list item").set_child(Some(&l));
        });
        let ctl = ctl.clone();
        factory.connect_bind(move |_, item| {
            let item = item.downcast_ref::<gtk::ListItem>().expect("list item");
            let Some(id) = item.item().and_then(|o| o.downcast::<gtk::StringObject>().ok()) else { return };
            let Some(label) = item.child().and_then(|c| c.downcast::<gtk::Label>().ok()) else { return };
            let text = ctl.read(|m| {
                m.find(id.string().as_str()).map(|s| {
                    let t = cell(s);
                    if i == 0 && m.is_favorite(s) {
                        format!("★ {t}")
                    } else {
                        t
                    }
                })
            });
            label.set_text(&text.unwrap_or_default());
        });
        let col = gtk::ColumnViewColumn::new(Some(title), Some(factory));
        // A sorter makes the header clickable; the real ordering is the model's (see `wire_header_sort`).
        col.set_sorter(Some(&gtk::CustomSorter::new(|_, _| gtk::Ordering::Equal)));
        col.set_resizable(true);
        col.set_expand(i == 0);
        table.append_column(&col);
    }
    wire_header_sort(w, ctl);
    // selection -> model; the sync guard keeps a programmatic change from echoing back
    let (store, ctl2) = (w.store.clone(), ctl.clone());
    w.selection.connect_selection_changed(move |sel, _, _| {
        if syncing() {
            return;
        }
        let id =
            sel.selected_item().and_then(|o| o.downcast::<gtk::StringObject>().ok()).map(|o| o.string().to_string());
        ctl2.select(id);
    });
    let (ctl, rt) = (ctl.clone(), rt.clone());
    table.connect_activate(move |_, pos| {
        if let Some(id) = store.string(pos) {
            let c = ctl.clone();
            rt.spawn(async move {
                if c.read(|m| m.state) == ConnectionState::Disconnected {
                    c.connect(id.as_str()).await;
                }
            });
        }
    });
}

/// Sort key of each default column, in `columns()` order.
const COLUMN_SORT: [SortKey; 8] = [
    SortKey::Host,
    SortKey::Country,
    SortKey::Uptime,
    SortKey::Sessions,
    SortKey::Speed,
    SortKey::Ping,
    SortKey::Logging,
    SortKey::Score,
];

/// Clicking a header sorts like the drop-down does: the model orders the rows, the header only shows the arrow.
fn wire_header_sort(w: &Rc<Widgets>, ctl: &Controller) {
    let (table, ctl) = (w.table.clone(), ctl.clone());
    let t = table.clone();
    table.sorter().expect("column view sorter").connect_changed(move |sorter, _| {
        if syncing() {
            return;
        }
        let Some(cs) = sorter.downcast_ref::<gtk::ColumnViewSorter>() else { return };
        let Some(col) = cs.primary_sort_column() else { return };
        let Some(i) = (0..t.columns().n_items()).find(|&i| t.columns().item(i).as_ref() == Some(col.upcast_ref()))
        else {
            return;
        };
        let descending = cs.primary_sort_order() == gtk::SortType::Descending;
        ctl.change(|m| {
            m.sort_key = COLUMN_SORT[i as usize % COLUMN_SORT.len()];
            m.sort_descending = descending;
            m.rebuild();
        });
    });
}

/// True while `refresh_widgets` sets widgets from the model, so their signals do not echo back as user input.
fn syncing() -> bool {
    SYNCING.with(Cell::get)
}

thread_local! {
    static SYNCING: Cell<bool> = const { Cell::new(false) };
}

fn wire_filters(w: &Rc<Widgets>, ctl: &Controller) {
    let c = ctl.clone();
    let search = w.search.clone();
    w.search.connect_search_changed(move |_| {
        if syncing() {
            return;
        }
        let text = search.text().to_string();
        c.change(|m| {
            m.filter.search = text;
            m.rebuild();
        });
    });
    let (c, dd, list) = (ctl.clone(), w.country.clone(), w.country_list.clone());
    w.country.connect_selected_notify(move |_| {
        if syncing() {
            return;
        }
        let pick = list.string(dd.selected()).map(|s| s.to_string());
        c.change(|m| {
            m.filter.country = match pick {
                Some(p) if dd.selected() > 0 => p,
                _ => "All".into(),
            };
            m.rebuild();
        });
    });
    let (c, dd) = (ctl.clone(), w.logging.clone());
    w.logging.connect_selected_notify(move |_| {
        if syncing() {
            return;
        }
        let weeks = LOGGING_CHOICES.get(dd.selected() as usize).and_then(|c| c.1);
        c.change(|m| {
            m.filter.max_log_weeks = weeks;
            m.rebuild();
        });
    });
    let (c, b) = (ctl.clone(), w.favorites_only.clone());
    w.favorites_only.connect_toggled(move |_| {
        if syncing() {
            return;
        }
        let on = b.is_active();
        c.change(|m| {
            m.filter.favorites_only = on;
            m.rebuild();
        });
    });
    let (c, dd) = (ctl.clone(), w.sort.clone());
    w.sort.connect_selected_notify(move |_| {
        if syncing() {
            return;
        }
        if let Some((_, key)) = SORT_CHOICES.get(dd.selected() as usize) {
            c.change(|m| {
                if m.sort_key != *key {
                    m.sort(*key);
                }
            });
        }
    });
    let (c, b) = (ctl.clone(), w.descending.clone());
    w.descending.connect_toggled(move |_| {
        if syncing() {
            return;
        }
        let desc = b.is_active();
        c.change(|m| {
            m.sort_descending = desc;
            m.rebuild();
        });
    });
    let c = ctl.clone();
    w.clear.connect_clicked(move |_| c.change(|m| m.clear_filters()));
}

fn wire_buttons(w: &Rc<Widgets>, ctl: &Controller, rt: &Arc<tokio::runtime::Runtime>) {
    let (c, rt2) = (ctl.clone(), rt.clone());
    w.refresh.connect_clicked(move |_| {
        let c = c.clone();
        rt2.spawn(async move { c.refresh().await });
    });
    let (c, rt2) = (ctl.clone(), rt.clone());
    w.action.connect_clicked(move |_| {
        let c = c.clone();
        rt2.spawn(async move { c.primary_action().await });
    });
    let c = ctl.clone();
    w.favorite.connect_clicked(move |_| {
        if let Some(id) = c.read(|m| m.selected.clone()) {
            c.toggle_favorite(&id);
        }
    });
}

fn add_actions(
    app: &adw::Application,
    window: &adw::ApplicationWindow,
    log: &Rc<LogWindow>,
    tx: &async_channel::Sender<Ui>,
) {
    let show_log = gio::SimpleAction::new("log", None);
    let l = log.clone();
    show_log.connect_activate(move |_, _| l.show());
    window.add_action(&show_log);
    let website = gio::SimpleAction::new("website", None);
    website.connect_activate(|_, _| {
        let _ = gio::AppInfo::launch_default_for_uri("http://www.vpngate.net/", gio::AppLaunchContext::NONE);
    });
    app.add_action(&website);
    let quit = gio::SimpleAction::new("quit", None);
    let tx = tx.clone();
    quit.connect_activate(move |_, _| {
        let _ = tx.try_send(Ui::Quit);
    });
    app.add_action(&quit);
    app.set_accels_for_action("app.quit", &["<Primary>q"]);
}

fn on_tray(
    a: TrayAction,
    window: &adw::ApplicationWindow,
    app: &adw::Application,
    ctl: &Controller,
    rt: &Arc<tokio::runtime::Runtime>,
    log: &LogWindow,
) {
    let c = ctl.clone();
    match a {
        TrayAction::Show => window.present(),
        TrayAction::ShowLog => log.show(),
        TrayAction::Quit => app.quit(),
        TrayAction::Connect => {
            window.present();
            rt.spawn(async move {
                if let Some(id) = c.read(tray_target) {
                    c.connect(&id).await;
                }
            });
        }
        TrayAction::Disconnect => {
            rt.spawn(async move { c.disconnect().await });
        }
        TrayAction::Reconnect => {
            rt.spawn(async move { c.reconnect_last().await });
        }
    }
}

/// The server "Connect to …" in the tray means: the selection, else the first favorite in the list.
fn tray_target(m: &vpngate_app_model::model::AppModel) -> Option<String> {
    m.selected_server().or_else(|| m.servers().iter().find(|s| m.is_favorite(s))).map(|s| s.id().to_string())
}

fn tray_snapshot(ctl: &Controller) -> TraySnapshot {
    ctl.read(|m| {
        let disconnected = m.state == ConnectionState::Disconnected;
        TraySnapshot {
            icon: format::icon_name(m.state).into(),
            title: m.state_title().into(),
            server_line: m.server_name().map(|n| match &m.server {
                Some(ip) if *ip != n => format!("{n} ({ip})"),
                _ => n,
            }),
            virtual_ip: m.virtual_ip.clone(),
            traffic: (m.state == ConnectionState::Connected).then(|| m.traffic_text(now_ms())),
            disconnected,
            connect_label: tray_target(m).and_then(|id| m.find(&id).map(|s| format!("Connect to {}", s.host_name))),
            can_reconnect: m.selected.is_some() || m.server.is_some(),
        }
    })
}

fn show_disclaimer(
    window: &adw::ApplicationWindow,
    ctl: &Controller,
    rt: &Arc<tokio::runtime::Runtime>,
    open: Rc<Cell<bool>>,
) {
    let dialog = adw::AlertDialog::builder().heading("VPN Gate Academic Experiment Service").body(DISCLAIMER).build();
    dialog.add_responses(&[("quit", "Disagree & Quit"), ("agree", "Agree and Continue")]);
    dialog.set_response_appearance("agree", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("agree"));
    // Escape counts as declining: the dialog cannot be dismissed otherwise.
    dialog.set_close_response("quit");
    let (ctl, rt) = (ctl.clone(), rt.clone());
    dialog.connect_response(None, move |_, response| {
        open.set(false);
        let c = ctl.clone();
        if response == "agree" {
            rt.spawn(async move { c.agree().await });
        } else {
            c.disagree();
        }
    });
    dialog.present(Some(window));
}

fn refresh_widgets(w: &Widgets, ctl: &Controller, shown: &Rc<RefCell<Shown>>) {
    SYNCING.with(|s| s.set(true));
    let now = now_ms();
    ctl.read(|m| {
        let busy = m.is_busy();
        w.spinner.set_spinning(busy);
        w.spinner.set_visible(busy);
        w.state.set_text(if m.state == ConnectionState::Disconnected && m.notice.is_none() {
            "Not connected"
        } else {
            m.state_title()
        });
        for c in ["success", "warning"] {
            w.state.remove_css_class(c);
        }
        match m.state {
            ConnectionState::Connected => w.state.add_css_class("success"),
            ConnectionState::Disconnected => {}
            _ => w.state.add_css_class("warning"),
        }
        let name = m.server_name().and_then(|n| m.server.as_ref().map(|ip| format!("{} {}", flag_of(m, ip), n)));
        w.server.set_text(&name.unwrap_or_default());
        w.server.set_visible(m.server.is_some());
        w.virtual_ip.set_text(&m.virtual_ip.as_ref().map(|ip| format!("Virtual IP {ip}")).unwrap_or_default());
        w.virtual_ip.set_visible(m.virtual_ip.is_some());
        w.traffic.set_text(&m.traffic_text(now));
        w.traffic.set_visible(m.state == ConnectionState::Connected);
        match (&m.notice, m.state) {
            (Some(n), ConnectionState::Disconnected) => {
                w.notice.set_text(n);
                w.notice.set_visible(true);
            }
            (None, ConnectionState::Disconnected) => {
                w.notice.set_text("Select a server and press Connect.");
                w.notice.set_visible(true);
            }
            _ => w.notice.set_visible(false),
        }
        w.notice.set_css_classes(if m.notice.is_some() { &["error"] } else { &["dim-label"] });

        w.list_status.set_text(&m.list_status(now));
        for c in ["error", "warning"] {
            w.list_status.remove_css_class(c);
        }
        if m.list_error.is_some() {
            w.list_status.add_css_class("error");
        } else if m.list_is_stale(now) {
            w.list_status.add_css_class("warning");
        }
        w.refresh.set_sensitive(!m.is_loading);
        w.clear.set_visible(m.filter_active());
        w.action.set_label(m.action_label());
        w.action.set_sensitive(m.can_act());
        w.action.remove_css_class("suggested-action");
        w.action.remove_css_class("destructive-action");
        w.action.add_css_class(if m.state == ConnectionState::Disconnected {
            "suggested-action"
        } else {
            "destructive-action"
        });
        w.favorite.set_sensitive(m.selected_server().is_some());
        w.details.set_sensitive(m.selected_server().is_some());
        w.favorite.set_label(match m.selected_server() {
            Some(s) if m.is_favorite(s) => "Remove from Favorites",
            _ => "Add to Favorites",
        });

        // country drop-down follows the list
        let mut sh = shown.borrow_mut();
        if sh.countries != m.countries() {
            let n = w.country_list.n_items();
            let items: Vec<&str> = m.countries().iter().map(String::as_str).collect();
            w.country_list.splice(1, n.saturating_sub(1), &items);
            sh.countries = m.countries().to_vec();
        }
        let wanted_country = m.countries().iter().position(|c| *c == m.filter.country).map_or(0, |i| i as u32 + 1);
        if w.country.selected() != wanted_country {
            w.country.set_selected(wanted_country);
        }
        if w.search.text() != m.filter.search {
            w.search.set_text(&m.filter.search);
        }
        w.favorites_only.set_active(m.filter.favorites_only);
        w.descending.set_active(m.sort_descending);
        if let Some(i) = SORT_CHOICES.iter().position(|c| c.1 == m.sort_key) {
            w.sort.set_selected(i as u32);
        }
        if let Some(i) = COLUMN_SORT.iter().position(|k| *k == m.sort_key) {
            if let Some(col) = w.table.columns().item(i as u32).and_downcast::<gtk::ColumnViewColumn>() {
                let order = if m.sort_descending { gtk::SortType::Descending } else { gtk::SortType::Ascending };
                w.table.sort_by_column(Some(&col), order);
            }
        }
        let logging = LOGGING_CHOICES.iter().position(|c| c.1 == m.filter.max_log_weeks).unwrap_or(0);
        w.logging.set_selected(logging as u32);

        // rows: rebuilt only when the visible ids or the favorites changed, so scrolling and selection survive traffic ticks
        let ids: Vec<String> = m.servers().iter().map(|s| s.id().to_string()).collect();
        let favorites: BTreeSet<String> = m.filter.favorites.iter().cloned().collect();
        if sh.ids != ids || sh.favorites != favorites {
            let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
            w.store.splice(0, w.store.n_items(), &refs);
            sh.ids = ids;
            sh.favorites = favorites;
        }
        let pos = m.selected.as_ref().and_then(|id| sh.ids.iter().position(|i| i == id));
        let want = pos.map_or(gtk::INVALID_LIST_POSITION, |p| p as u32);
        if w.selection.selected() != want {
            w.selection.set_selected(want);
        }
    });
    SYNCING.with(|s| s.set(false));
}

fn flag_of(m: &vpngate_app_model::model::AppModel, ip: &str) -> String {
    m.servers().iter().find(|s| s.ip == ip).map(VpnServer::flag).unwrap_or_default()
}

fn add_window_actions(
    window: &adw::ApplicationWindow,
    ctx: &Ctx,
    log: &Rc<LogWindow>,
    accounts: &Rc<AccountsWindow>,
    history: &Rc<HistoryWindow>,
) {
    let a = accounts.clone();
    let open = gio::SimpleAction::new("accounts", None);
    open.connect_activate(move |_, _| {
        a.show();
        a.refresh();
    });
    window.add_action(&open);
    let h = history.clone();
    let open = gio::SimpleAction::new("history", None);
    open.connect_activate(move |_, _| h.show());
    window.add_action(&open);
    let (ctx, w, a, l) = (ctx.clone(), window.clone(), accounts.clone(), log.clone());
    let open = gio::SimpleAction::new("settings", None);
    open.connect_activate(move |_, _| {
        let (a, l) = (a.clone(), l.clone());
        settings_window::open(
            &w,
            &ctx,
            settings_window::Actions {
                open_accounts: Rc::new(move || {
                    a.show();
                    a.refresh();
                }),
                open_log: Rc::new(move || l.show()),
            },
        );
    });
    window.add_action(&open);
}

fn wire_details(w: &Rc<Widgets>, ctl: &Controller, window: &adw::ApplicationWindow) {
    let (c, win) = (ctl.clone(), window.clone());
    w.details.connect_clicked(move |_| {
        if let Some(s) = c.read(|m| m.selected_server().cloned()) {
            crate::details::show(&win, &s);
        }
    });
}
