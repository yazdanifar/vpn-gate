//! "VPN Connection Settings" (UI-SPEC 5): the user's own SoftEther accounts.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use uuid::Uuid;
use vpngate_core::ipc::ConnectionState;

use crate::account_editor;
use crate::ctx::Ctx;

pub struct AccountsWindow {
    window: adw::Window,
    list: gtk::ListBox,
    notice: gtk::Label,
    buttons: [gtk::Button; 5],
    /// What the list shows now, to rebuild only on change.
    shown: RefCell<Option<Vec<String>>>,
    ids: RefCell<Vec<Uuid>>,
    ctx: Ctx,
}

impl AccountsWindow {
    /// `open_main`: the pinned first row, which brings the server list forward.
    pub fn new(parent: &impl IsA<gtk::Window>, ctx: &Ctx, open_main: impl Fn() + 'static) -> Rc<Self> {
        let list =
            gtk::ListBox::builder().selection_mode(gtk::SelectionMode::Single).css_classes(["boxed-list"]).build();
        let notice = gtk::Label::builder().xalign(0.0).wrap(true).css_classes(["warning"]).visible(false).build();
        let btn = |label: &str| gtk::Button::with_label(label);
        let buttons = [btn("New Setting"), btn("Connect"), btn("Disconnect"), btn("Properties"), btn("Delete")];
        let bar = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        for b in &buttons {
            bar.append(b);
        }
        let duplicate = btn("Duplicate");
        bar.append(&duplicate);
        let pinned = adw::ActionRow::builder()
            .title("VPN Gate Public VPN Relay Servers")
            .subtitle("Free servers run by volunteers — open the list")
            .activatable(true)
            .build();
        pinned.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        pinned.connect_activated(move |_| open_main());
        let body = gtk::Box::new(gtk::Orientation::Vertical, 10);
        for m in ["margin_top", "margin_bottom", "margin_start", "margin_end"] {
            body.set_property(m, 16);
        }
        body.append(&bar);
        body.append(&notice);
        let pinned_list =
            gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).css_classes(["boxed-list"]).build();
        pinned_list.append(&pinned);
        body.append(&pinned_list);
        body.append(&gtk::ScrolledWindow::builder().child(&list).vexpand(true).build());
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&adw::HeaderBar::new());
        toolbar.set_content(Some(&body));
        let window = adw::Window::builder()
            .title("VPN Connection Settings")
            .default_width(760)
            .default_height(520)
            .transient_for(parent)
            .hide_on_close(true)
            .content(&toolbar)
            .build();
        let this = Rc::new(AccountsWindow {
            window,
            list,
            notice,
            buttons,
            shown: RefCell::new(None),
            ids: RefCell::new(Vec::new()),
            ctx: ctx.clone(),
        });
        let t = this.clone();
        this.buttons[0].connect_clicked(move |b| t.edit(b.upcast_ref(), None));
        let t = this.clone();
        this.buttons[1].connect_clicked(move |_| t.connect_selected());
        let c = ctx.clone();
        this.buttons[2].connect_clicked(move |_| {
            let c = c.clone();
            c.clone().spawn(async move { c.ctl.disconnect().await });
        });
        let t = this.clone();
        this.buttons[3].connect_clicked(move |b| t.edit_selected(b.upcast_ref()));
        let t = this.clone();
        this.buttons[4].connect_clicked(move |_| {
            if let Some(id) = t.selected() {
                t.ctx.ctl.with_stores(|s| s.accounts.delete(id));
                t.ctx.ctl.change(|_| {});
            }
        });
        let t = this.clone();
        duplicate.connect_clicked(move |_| {
            if let Some(id) = t.selected() {
                t.ctx.ctl.with_stores(|s| s.accounts.duplicate(id));
                t.ctx.ctl.change(|_| {});
            }
        });
        let t = this.clone();
        this.list.connect_row_activated(move |_, _| t.connect_selected());
        let t = this.clone();
        this.list.connect_selected_rows_changed(move |_| t.update_buttons());
        this
    }

    pub fn show(&self) {
        self.window.present();
    }

    fn selected(&self) -> Option<Uuid> {
        let row = self.list.selected_row()?;
        self.ids.borrow().get(usize::try_from(row.index()).ok()?).copied()
    }

    fn edit(self: &Rc<Self>, anchor: &gtk::Widget, account: Option<vpngate_core::client_account::ClientAccount>) {
        let ctl = self.ctx.ctl.clone();
        account_editor::open(anchor, &self.ctx, account, move || ctl.change(|_| {}));
    }

    fn edit_selected(self: &Rc<Self>, anchor: &gtk::Widget) {
        if let Some(a) = self.selected().and_then(|id| self.ctx.ctl.with_stores(|s| s.accounts.find(id).cloned())) {
            self.edit(anchor, Some(a));
        }
    }

    fn connect_selected(&self) {
        let Some(id) = self.selected() else { return };
        let c = self.ctx.clone();
        if c.ctl.read(|m| m.state) == ConnectionState::Disconnected {
            c.clone().spawn(async move { c.ctl.connect_account(id).await });
        }
    }

    fn update_buttons(&self) {
        let (disconnected, busy) =
            self.ctx.ctl.read(|m| (m.state == ConnectionState::Disconnected, m.state != ConnectionState::Disconnected));
        let has = self.selected().is_some();
        self.buttons[1].set_sensitive(has && disconnected);
        self.buttons[2].set_sensitive(busy);
        self.buttons[3].set_sensitive(has);
        self.buttons[4].set_sensitive(has);
    }

    /// Called on every model change; rebuilds the rows only when what they show differs.
    pub fn refresh(&self) {
        if !self.window.is_visible() {
            return;
        }
        let (rows, ids, notice) = self.ctx.ctl.with_stores(|s| {
            let live = self.ctx.ctl.read(|m| m.live_account().map(|id| (id, m.state)));
            let rows: Vec<String> = s
                .accounts
                .accounts
                .iter()
                .map(|a| {
                    let status = match live {
                        Some((id, ConnectionState::Connected)) if id == a.id => "Connected",
                        Some((id, ConnectionState::Reconnecting)) if id == a.id => "Reconnecting…",
                        Some((id, _)) if id == a.id => "Connecting",
                        _ => "Offline",
                    };
                    format!(
                        "{}\t{}\t{}:{}\t{}",
                        a.name,
                        status,
                        a.host,
                        a.port_list.first().copied().unwrap_or(443),
                        a.hub
                    )
                })
                .collect();
            (rows, s.accounts.accounts.iter().map(|a| a.id).collect::<Vec<_>>(), s.accounts.load_notice.clone())
        });
        self.notice.set_visible(notice.is_some());
        self.notice.set_text(notice.as_deref().unwrap_or(""));
        if self.shown.borrow().as_ref() != Some(&rows) {
            let keep = self.selected();
            while let Some(r) = self.list.first_child() {
                self.list.remove(&r);
            }
            if rows.is_empty() {
                let empty = adw::ActionRow::builder()
                    .title("No VPN connection settings yet")
                    .subtitle("Add one to connect to your own SoftEther VPN server.")
                    .selectable(false)
                    .activatable(false)
                    .build();
                self.list.append(&empty);
            }
            for r in &rows {
                let f: Vec<&str> = r.split('\t').collect();
                let row = adw::ActionRow::builder()
                    .title(gtk::glib::markup_escape_text(f[0]))
                    .subtitle(format!("{} · {} · hub {}", f[1], f[2], f[3]))
                    .build();
                if f[1] == "Connected" {
                    row.add_css_class("success");
                }
                self.list.append(&row);
            }
            *self.shown.borrow_mut() = Some(rows);
            *self.ids.borrow_mut() = ids;
            if let Some(i) = keep.and_then(|k| self.ids.borrow().iter().position(|x| *x == k)) {
                self.list.select_row(self.list.row_at_index(i as i32).as_ref());
            }
        }
        self.update_buttons();
    }
}
