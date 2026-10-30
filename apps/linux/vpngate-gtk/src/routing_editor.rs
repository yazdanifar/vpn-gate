//! The routing rules editor of UI-SPEC 7, shared by Settings and the account editor. It edits a `RoutingConfig` in place
//! and calls `changed` after every edit; the caller adds the returned groups to its page.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib::prelude::StaticType;
use vpngate_core::routing_rule::{RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType};

const TYPES: [(RoutingRuleType, &str, &str); 6] = [
    (RoutingRuleType::DomainSuffix, "Domain suffix", "example.com"),
    (RoutingRuleType::DomainFull, "Domain (exact)", "example.com"),
    (RoutingRuleType::DomainKeyword, "Domain keyword", "ads"),
    (RoutingRuleType::DomainRegex, "Domain regex", "^(.+\\.)?example\\.com$"),
    (RoutingRuleType::Ip, "IP address", "203.0.113.5"),
    (RoutingRuleType::Cidr, "IP range (CIDR)", "10.0.0.0/8"),
];

const ACTIONS: [(RoutingAction, &str); 3] =
    [(RoutingAction::Proxy, "Proxy"), (RoutingAction::Direct, "Direct"), (RoutingAction::Block, "Block")];

const DEFAULT_CAPTIONS: [&str; 2] = [
    "Everything goes through the tunnel except what the rules below send elsewhere.",
    "Everything bypasses the tunnel except what the rules below send into it. IPv6 keeps being captured and dropped regardless (see “Block IPv6” in General).",
];

const FOOTER: &str = "Rules are checked in order from top to bottom; the first one that matches wins. Domain rules need the DNS proxy, \
which only runs while one is configured. A domain marked “Direct” is looked up through your regular network connection, never through the \
VPN or its DNS — everything else is resolved only through the tunnel.";

struct Editor {
    cfg: Rc<RefCell<RoutingConfig>>,
    changed: Rc<dyn Fn()>,
    rules: adw::PreferencesGroup,
    rows: RefCell<Vec<gtk::Widget>>,
}

pub fn groups(cfg: Rc<RefCell<RoutingConfig>>, changed: Rc<dyn Fn()>) -> Vec<adw::PreferencesGroup> {
    let defaults = adw::PreferencesGroup::builder().title("Unmatched traffic").build();
    let default_row = adw::ComboRow::builder()
        .title("By default")
        .model(&gtk::StringList::new(&["Proxy (through the tunnel)", "Direct (bypass the tunnel)"]))
        .build();
    let bypass = adw::SwitchRow::builder().title("Bypass private networks").subtitle("LAN, link-local, CGNAT").build();
    defaults.add(&default_row);
    defaults.add(&bypass);
    let direct = cfg.borrow().default_action == RoutingAction::Direct;
    default_row.set_selected(u32::from(direct));
    default_row.set_subtitle(DEFAULT_CAPTIONS[usize::from(direct)]);
    bypass.set_active(cfg.borrow().bypass_private_networks);

    let (c, ch) = (cfg.clone(), changed.clone());
    default_row.connect_selected_notify(move |r| {
        let direct = r.selected() == 1;
        c.borrow_mut().default_action = if direct { RoutingAction::Direct } else { RoutingAction::Proxy };
        r.set_subtitle(DEFAULT_CAPTIONS[usize::from(direct)]);
        ch();
    });
    let (c, ch) = (cfg.clone(), changed.clone());
    bypass.connect_active_notify(move |r| {
        c.borrow_mut().bypass_private_networks = r.is_active();
        ch();
    });

    let add = gtk::Button::builder().label("Add Rule…").valign(gtk::Align::Center).build();
    let rules = adw::PreferencesGroup::builder().title("Rules").description(FOOTER).header_suffix(&add).build();
    let ed = Rc::new(Editor { cfg, changed, rules, rows: RefCell::new(Vec::new()) });
    let e = ed.clone();
    add.connect_clicked(move |b| open_rule(&e, b.upcast_ref(), None));
    ed.rebuild();
    vec![defaults, ed.rules.clone()]
}

/// What a drop on another row does: the rule at `from` ends up at position `to`. `false` when nothing changes.
pub fn move_rule(rules: &mut Vec<RoutingRule>, from: usize, to: usize) -> bool {
    if from == to || from >= rules.len() || to >= rules.len() {
        return false;
    }
    let rule = rules.remove(from);
    rules.insert(to, rule);
    true
}

impl Editor {
    /// Moves the rule at `from` to position `to`; `false` when nothing changes.
    fn move_rule(&self, from: usize, to: usize) -> bool {
        move_rule(&mut self.cfg.borrow_mut().rules, from, to)
    }

    fn rebuild(self: &Rc<Self>) {
        for r in self.rows.borrow_mut().drain(..) {
            self.rules.remove(&r);
        }
        let rules = self.cfg.borrow().rules.clone();
        if rules.is_empty() {
            let empty =
                adw::ActionRow::builder().title("No custom rules. Traffic follows the default action above.").build();
            empty.add_css_class("dim-label");
            self.rules.add(&empty);
            self.rows.borrow_mut().push(empty.upcast());
        }
        let last = rules.len().saturating_sub(1);
        for (i, rule) in rules.iter().enumerate() {
            let caption = TYPES.iter().find(|t| t.0 == rule.rule_type).map_or("", |t| t.1);
            let row =
                adw::ActionRow::builder().title(glib_escape(&rule.value)).subtitle(caption).activatable(true).build();
            row.add_css_class("monospace");
            let action = ACTIONS.iter().find(|a| a.0 == rule.action).map_or("", |a| a.1);
            let pill =
                gtk::Label::new(Some(&if rule.enabled { action.to_string() } else { format!("{action} · Off") }));
            pill.add_css_class(match rule.action {
                RoutingAction::Proxy => "accent",
                RoutingAction::Direct => "success",
                RoutingAction::Block => "error",
            });
            row.add_suffix(&pill);
            let button = |icon: &str, tip: &str, on: bool| {
                gtk::Button::builder()
                    .icon_name(icon)
                    .tooltip_text(tip)
                    .valign(gtk::Align::Center)
                    .sensitive(on)
                    .css_classes(["flat"])
                    .build()
            };
            let (up, down, del) = (
                button("go-up-symbolic", "Move up", i > 0),
                button("go-down-symbolic", "Move down", i < last),
                button("user-trash-symbolic", "Delete", true),
            );
            for (b, f) in [(&up, 0), (&down, 1), (&del, 2)] {
                row.add_suffix(b);
                let e = self.clone();
                b.connect_clicked(move |_| {
                    {
                        let mut c = e.cfg.borrow_mut();
                        match f {
                            0 => c.rules.swap(i, i - 1),
                            1 => c.rules.swap(i, i + 1),
                            _ => {
                                c.rules.remove(i);
                            }
                        }
                    }
                    e.rebuild();
                    (e.changed)();
                });
            }
            // Drag the handle onto another row to move the rule there.
            let handle = gtk::Image::from_icon_name("list-drag-handle-symbolic");
            row.add_prefix(&handle);
            let source = gtk::DragSource::builder().actions(gtk::gdk::DragAction::MOVE).build();
            source.connect_prepare(move |_, _, _| Some(gtk::gdk::ContentProvider::for_value(&(i as u32).to_value())));
            handle.add_controller(source);
            let target = gtk::DropTarget::new(u32::static_type(), gtk::gdk::DragAction::MOVE);
            let e = self.clone();
            target.connect_drop(move |_, value, _, _| {
                let Ok(from) = value.get::<u32>() else { return false };
                let moved = e.move_rule(from as usize, i);
                if moved {
                    // Not inside the drop handler: the rebuild destroys this very row.
                    let e = e.clone();
                    gtk::glib::idle_add_local_once(move || {
                        e.rebuild();
                        (e.changed)();
                    });
                }
                moved
            });
            row.add_controller(target);
            let (e, rule) = (self.clone(), rule.clone());
            row.connect_activated(move |r| open_rule(&e, r.upcast_ref(), Some(rule.clone())));
            self.rules.add(&row);
            self.rows.borrow_mut().push(row.upcast());
        }
    }
}

/// `ActionRow` titles are Pango markup.
fn glib_escape(s: &str) -> String {
    gtk::glib::markup_escape_text(s).to_string()
}

/// The rule sheet: add (`existing` is `None`) or edit.
fn open_rule(ed: &Rc<Editor>, anchor: &gtk::Widget, existing: Option<RoutingRule>) {
    let kind = adw::ComboRow::builder().title("Match").model(&gtk::StringList::new(&TYPES.map(|t| t.1))).build();
    let value = adw::EntryRow::builder().title("Value").build();
    let action = adw::ComboRow::builder().title("Action").model(&gtk::StringList::new(&ACTIONS.map(|a| a.1))).build();
    let enabled = adw::SwitchRow::builder().title("Enabled").active(true).build();
    let group = adw::PreferencesGroup::new();
    for r in [kind.upcast_ref::<gtk::Widget>(), value.upcast_ref(), action.upcast_ref(), enabled.upcast_ref()] {
        group.add(r);
    }
    let error = gtk::Label::builder().xalign(0.0).css_classes(["error"]).build();
    let save = gtk::Button::builder()
        .label(if existing.is_some() { "Save" } else { "Add" })
        .css_classes(["suggested-action"])
        .build();
    let cancel = gtk::Button::with_label("Cancel");
    let delete =
        gtk::Button::builder().label("Delete").css_classes(["destructive-action"]).visible(existing.is_some()).build();
    let header = adw::HeaderBar::builder().show_end_title_buttons(false).show_start_title_buttons(false).build();
    header.pack_start(&cancel);
    header.pack_end(&save);
    let body = gtk::Box::new(gtk::Orientation::Vertical, 8);
    for m in ["margin_top", "margin_bottom", "margin_start", "margin_end"] {
        body.set_property(m, 16);
    }
    body.append(&group);
    body.append(&error);
    body.append(&delete);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&body));
    let dialog = adw::Dialog::builder()
        .title(if existing.is_some() { "Edit Rule" } else { "New Rule" })
        .content_width(440)
        .child(&toolbar)
        .build();

    if let Some(r) = &existing {
        kind.set_selected(TYPES.iter().position(|t| t.0 == r.rule_type).unwrap_or(0) as u32);
        value.set_text(&r.value);
        action.set_selected(ACTIONS.iter().position(|a| a.0 == r.action).unwrap_or(0) as u32);
        enabled.set_active(r.enabled);
    }
    // validation shows only for a non-empty value; Save needs a valid one
    let check = {
        let (kind, value, error, save) = (kind.clone(), value.clone(), error.clone(), save.clone());
        Rc::new(move || {
            let t = TYPES[kind.selected() as usize % TYPES.len()];
            let text = value.text();
            let err = RoutingRule::validation_error(t.0, &text);
            error.set_text(if text.trim().is_empty() { "" } else { err.unwrap_or("") });
            save.set_sensitive(err.is_none());
        })
    };
    let update = {
        let (kind, value, check) = (kind.clone(), value.clone(), check.clone());
        move || {
            // The placeholder follows the type.
            value.set_tooltip_text(Some(&format!("e.g. {}", TYPES[kind.selected() as usize % TYPES.len()].2)));
            check();
        }
    };
    update();
    let u = update.clone();
    kind.connect_selected_notify(move |_| u());
    let c = check.clone();
    value.connect_changed(move |_| c());

    let d = dialog.clone();
    cancel.connect_clicked(move |_| {
        d.close();
    });
    let (e, d, existing2) = (ed.clone(), dialog.clone(), existing.clone());
    delete.connect_clicked(move |_| {
        if let Some(r) = &existing2 {
            e.cfg.borrow_mut().rules.retain(|x| x.id != r.id);
            e.rebuild();
            (e.changed)();
        }
        d.close();
    });
    let (e, d) = (ed.clone(), dialog.clone());
    save.connect_clicked(move |_| {
        let t = TYPES[kind.selected() as usize % TYPES.len()].0;
        let a = ACTIONS[action.selected() as usize % ACTIONS.len()].0;
        let id = existing.as_ref().map_or_else(uuid::Uuid::new_v4, |r| r.id);
        let rule = RoutingRule::with_id(id, t, &value.text(), a, enabled.is_active());
        {
            let mut c = e.cfg.borrow_mut();
            match c.rules.iter().position(|x| x.id == id) {
                Some(i) => c.rules[i] = rule,
                None => c.rules.push(rule),
            }
        }
        e.rebuild();
        (e.changed)();
        d.close();
    });
    dialog.present(Some(anchor));
}
