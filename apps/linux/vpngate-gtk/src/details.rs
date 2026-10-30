//! The "Server Details" sheet (UI-SPEC 4).

use adw::prelude::*;
use vpngate_app_model::format;
use vpngate_core::server_list::VpnServer;

pub fn show(parent: &impl IsA<gtk::Widget>, s: &VpnServer) {
    let group = adw::PreferencesGroup::new();
    for (label, value) in format::server_details(s) {
        let row = adw::ActionRow::builder()
            .title(label)
            .subtitle(gtk::glib::markup_escape_text(&value))
            .subtitle_selectable(true)
            .build();
        row.add_css_class("property");
        group.add(&row);
    }
    let page = adw::PreferencesPage::new();
    page.add(&group);
    let done = gtk::Button::builder().label("Done").css_classes(["suggested-action"]).build();
    let header = adw::HeaderBar::builder().show_end_title_buttons(false).show_start_title_buttons(false).build();
    header.pack_end(&done);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&page));
    let title = format!("{} {}", s.flag(), s.host_name);
    let dialog =
        adw::Dialog::builder().title(title.trim()).content_width(520).content_height(620).child(&toolbar).build();
    let d = dialog.clone();
    done.connect_clicked(move |_| {
        d.close();
    });
    dialog.present(Some(parent));
}
