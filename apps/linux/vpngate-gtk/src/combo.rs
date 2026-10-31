//! Combo rows whose current value is shown in full.

use adw::prelude::*;

/// An `adw::ComboRow` over `items`. Adwaita's own factory caps the value beside the title at about 20 characters, which
/// cut "Full tunnel (whole computer)" and "Standard Password (SHA-0)" short (and left only "…" next to a long subtitle);
/// this factory's label has no cap, so a long subtitle wraps instead.
pub fn row(title: &str, items: &[&str]) -> adw::ComboRow {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let item = item.downcast_ref::<gtk::ListItem>().expect("a list item");
        item.set_child(Some(&gtk::Label::builder().xalign(0.0).build()));
    });
    factory.connect_bind(|_, item| {
        let item = item.downcast_ref::<gtk::ListItem>().expect("a list item");
        let (Some(label), Some(text)) =
            (item.child().and_downcast::<gtk::Label>(), item.item().and_downcast::<gtk::StringObject>())
        else {
            return;
        };
        label.set_label(&text.string());
    });
    adw::ComboRow::builder().title(title).model(&gtk::StringList::new(items)).factory(&factory).build()
}
