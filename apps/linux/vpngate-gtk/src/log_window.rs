//! "Connection Log" (UI-SPEC 11): the daemon's log lines, newest at the bottom.

use adw::prelude::*;

pub struct LogWindow {
    window: adw::Window,
    view: gtk::TextView,
}

impl LogWindow {
    pub fn new(parent: &impl IsA<gtk::Window>) -> LogWindow {
        let view = gtk::TextView::builder()
            .editable(false)
            .cursor_visible(false)
            .monospace(true)
            .wrap_mode(gtk::WrapMode::WordChar)
            .left_margin(8)
            .right_margin(8)
            .top_margin(8)
            .bottom_margin(8)
            .build();
        let scroller = gtk::ScrolledWindow::builder().child(&view).vexpand(true).build();
        let header = adw::HeaderBar::new();
        let copy = gtk::Button::builder().icon_name("edit-copy-symbolic").tooltip_text("Copy the log").build();
        header.pack_start(&copy);
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        toolbar.set_content(Some(&scroller));
        let window = adw::Window::builder()
            .title("Connection Log")
            .default_width(720)
            .default_height(420)
            .transient_for(parent)
            .hide_on_close(true)
            .content(&toolbar)
            .build();
        let v = view.clone();
        copy.connect_clicked(move |_| {
            let b = v.buffer();
            let text = b.text(&b.start_iter(), &b.end_iter(), false);
            v.clipboard().set_text(&text);
        });
        LogWindow { window, view }
    }

    pub fn show(&self) {
        self.window.present();
    }

    pub fn is_visible(&self) -> bool {
        self.window.is_visible()
    }

    /// Replaces the text and scrolls to the end.
    pub fn set_text(&self, text: &str) {
        let buffer = self.view.buffer();
        if buffer.text(&buffer.start_iter(), &buffer.end_iter(), false) == text {
            return;
        }
        buffer.set_text(text);
        let mark = buffer.create_mark(None, &buffer.end_iter(), false);
        self.view.scroll_mark_onscreen(&mark);
        buffer.delete_mark(&mark);
    }
}
