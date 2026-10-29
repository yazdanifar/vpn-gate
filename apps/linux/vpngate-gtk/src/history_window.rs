//! "Connection history" (UI-SPEC 9).

use std::cell::RefCell;

use adw::prelude::*;
use vpngate_app_model::format;

use crate::ctx::Ctx;

pub struct HistoryWindow {
    window: adw::Window,
    list: gtk::ListBox,
    clear: gtk::Button,
    shown: RefCell<String>,
    ctx: Ctx,
}

impl HistoryWindow {
    pub fn new(parent: &impl IsA<gtk::Window>, ctx: &Ctx) -> std::rc::Rc<Self> {
        let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).css_classes(["boxed-list"]).build();
        let clear = gtk::Button::builder().label("Clear").build();
        let header = adw::HeaderBar::new();
        header.pack_start(&clear);
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        let body = gtk::ScrolledWindow::builder().child(&list).build();
        list.set_margin_top(12);
        list.set_margin_bottom(12);
        list.set_margin_start(12);
        list.set_margin_end(12);
        toolbar.set_content(Some(&body));
        let window = adw::Window::builder()
            .title("Connection history")
            .default_width(760)
            .default_height(480)
            .transient_for(parent)
            .hide_on_close(true)
            .content(&toolbar)
            .build();
        let this = std::rc::Rc::new(HistoryWindow {
            window,
            list,
            clear,
            shown: RefCell::new(String::new()),
            ctx: ctx.clone(),
        });
        let t = this.clone();
        this.clear.connect_clicked(move |_| {
            t.ctx.ctl.with_stores(|s| s.history.clear());
            t.ctx.ctl.change(|_| {});
        });
        this
    }

    pub fn show(&self) {
        self.window.present();
        self.refresh();
    }

    pub fn refresh(&self) {
        if !self.window.is_visible() {
            return;
        }
        let entries = self.ctx.ctl.with_stores(|s| s.history.entries.clone());
        let key = format!("{entries:?}");
        if *self.shown.borrow() == key {
            return;
        }
        *self.shown.borrow_mut() = key;
        self.clear.set_sensitive(!entries.is_empty());
        while let Some(r) = self.list.first_child() {
            self.list.remove(&r);
        }
        if entries.is_empty() {
            self.list.append(&adw::ActionRow::builder().title("No connections yet.").build());
        }
        for e in entries {
            let when = vpngate_app_model::model::format_timestamp(e.connected_at_ms);
            let result = match (&e.error, e.disconnected_at_ms) {
                (Some(err), _) => err.clone(),
                (None, Some(_)) => "ended".into(),
                _ => String::new(),
            };
            let row = adw::ActionRow::builder()
                .title(gtk::glib::markup_escape_text(&e.server_name))
                .subtitle(gtk::glib::markup_escape_text(&format!(
                    "{} · {} · {} · {}{}",
                    e.server_ip,
                    when,
                    format::history_duration(e.duration_seconds()),
                    format::traffic(e.bytes_in, e.bytes_out, None),
                    if result.is_empty() { String::new() } else { format!(" · {result}") }
                )))
                .build();
            if e.error.is_some() {
                row.add_css_class("error");
            }
            self.list.append(&row);
        }
    }
}
