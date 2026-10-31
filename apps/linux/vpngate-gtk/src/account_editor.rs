//! The account editor sheet (UI-SPEC 6). The form state and validation are `AccountEditor` in the app model; this file
//! only binds widgets to it.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use gtk::gio;
use vpngate_app_model::accounts::{uses_password, AccountEditor, AUTH_TYPES};
use vpngate_core::client_account::{AccountAuthType, ClientAccount};

use crate::ctx::Ctx;
use crate::routing_editor;

type Refresh = Rc<dyn Fn()>;

/// `account`: `None` for a new setting. `done` runs after a successful save.
pub fn open(parent: &impl IsA<gtk::Widget>, ctx: &Ctx, account: Option<ClientAccount>, done: impl Fn() + 'static) {
    let (state, base) = match &account {
        Some(a) => {
            let (pw, ident) = ctx.ctl.with_stores(|s| (s.accounts.password(a), s.accounts.has_identity(a)));
            (AccountEditor::from_account(a, pw, ident), Some(a.clone()))
        }
        None => (AccountEditor::default(), None),
    };
    let st = Rc::new(RefCell::new(state));
    let page = adw::PreferencesPage::new();

    let entry = |title: &str, text: &str| adw::EntryRow::builder().title(title).text(text).build();
    let combo = crate::combo::row;
    let spin = |title: &str, lo: f64, hi: f64, v: i64| {
        let r = adw::SpinRow::with_range(lo, hi, 1.0);
        r.set_title(title);
        r.set_value(v as f64);
        r
    };
    let switch = |title: &str, on: bool| adw::SwitchRow::builder().title(title).active(on).build();

    // General + destination
    let s = st.borrow().clone();
    let name = entry("Setting Name", &s.name);
    let host = entry("Host Name / IP Address", &s.host);
    let ports = entry("Port Number (comma separated)", &s.ports);
    let hub = entry("Virtual HUB Name", &s.hub);
    let general = adw::PreferencesGroup::builder().title("General Setting").build();
    general.add(&name);
    let dest = adw::PreferencesGroup::builder().title("Destination VPN Server").build();
    for r in [&host, &ports, &hub] {
        dest.add(r);
    }

    // Authentication
    let auth = combo("Auth Type", &AUTH_TYPES.map(|t| t.raw_value()));
    auth.set_selected(AUTH_TYPES.iter().position(|t| *t == s.auth_type).unwrap_or(1) as u32);
    let user = entry("User Name", &s.username);
    let password = adw::PasswordEntryRow::builder().title("Password").text(&s.password).build();
    let cert_status = adw::ActionRow::builder().title("Certificate").build();
    let import = gtk::Button::builder().label("Certificate + Key…").valign(gtk::Align::Center).build();
    cert_status.add_suffix(&import);
    let import_p12 = gtk::Button::builder().label("PKCS#12 (.p12)…").valign(gtk::Align::Center).build();
    cert_status.add_suffix(&import_p12);
    let p12_pass = adw::PasswordEntryRow::builder().title("Passphrase for the .p12 file").build();
    let import_error = gtk::Label::builder().xalign(0.0).wrap(true).css_classes(["error"]).build();
    let auth_group = adw::PreferencesGroup::builder().title("User Authentication Setting").build();
    for r in [
        auth.upcast_ref::<gtk::Widget>(),
        user.upcast_ref(),
        password.upcast_ref(),
        cert_status.upcast_ref(),
        p12_pass.upcast_ref(),
    ] {
        auth_group.add(r);
    }
    auth_group.add(&import_error);

    // Advanced
    let max_conn = spin("Max TCP Connections", 1.0, 32.0, s.max_connection);
    let compression = switch("Use Data Compression", s.compression);
    let udp = switch("Use UDP Acceleration (Fastest)", s.udp_acceleration);
    let qos = switch("Use QoS", s.use_qos);
    let half = switch("Use Half Connection (separate send/receive sockets)", s.half_connection);
    let mtu = entry("MTU (blank = automatic)", &s.mtu);
    let mac = entry("Virtual MAC address (blank = random)", &s.mac);
    let verify = switch("Verify Server Certificate", s.check_server_cert);
    let fingerprint = entry("Server certificate fingerprint (SHA-1 / SHA-256, optional)", &s.fingerprint);
    let reconnect = switch("Auto Reconnect on disconnect", s.auto_reconnect);
    let interval = spin("Retry every n s", 1.0, 300.0, s.reconnect_interval);
    let count = spin("Give up after n attempts", 1.0, 1000.0, s.reconnect_count);
    let advanced = adw::ExpanderRow::builder().title("Advanced Options").build();
    for r in [
        max_conn.upcast_ref::<gtk::Widget>(),
        compression.upcast_ref(),
        udp.upcast_ref(),
        qos.upcast_ref(),
        half.upcast_ref(),
        mtu.upcast_ref(),
        mac.upcast_ref(),
        verify.upcast_ref(),
        fingerprint.upcast_ref(),
        reconnect.upcast_ref(),
        interval.upcast_ref(),
        count.upcast_ref(),
    ] {
        advanced.add_row(r);
    }
    let advanced_group = adw::PreferencesGroup::new();
    advanced_group.add(&advanced);
    let problems = gtk::Label::builder().xalign(0.0).wrap(true).css_classes(["error"]).build();

    // Routing
    let custom = switch("Use custom routing rules for this connection", s.use_custom_routing);
    custom.set_subtitle("Uses the app's global routing rules (Settings → Routing).");
    let routing_cfg = Rc::new(RefCell::new(s.routing.clone()));
    let refresh_cell: Rc<RefCell<Option<Refresh>>> = Rc::new(RefCell::new(None));
    let rc = refresh_cell.clone();
    let routing_groups = routing_editor::groups(
        routing_cfg.clone(),
        Rc::new(move || {
            if let Some(f) = rc.borrow().as_ref() {
                f();
            }
        }),
    );
    let route_toggle = adw::PreferencesGroup::builder().title("Routing").build();
    route_toggle.add(&custom);

    for g in [&general, &dest, &auth_group, &advanced_group, &route_toggle] {
        page.add(g);
    }
    for g in &routing_groups {
        page.add(g);
    }

    let save = gtk::Button::builder().label("Save").css_classes(["suggested-action"]).build();
    let cancel = gtk::Button::with_label("Cancel");
    let header = adw::HeaderBar::builder().show_end_title_buttons(false).show_start_title_buttons(false).build();
    header.pack_start(&cancel);
    header.pack_end(&save);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    let scroller = gtk::ScrolledWindow::builder().child(&page).vexpand(true).build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&scroller);
    problems.set_margin_start(16);
    problems.set_margin_end(16);
    problems.set_margin_bottom(8);
    content.append(&problems);
    toolbar.set_content(Some(&content));
    let dialog = adw::Dialog::builder()
        .title(if account.is_some() { "Edit VPN Connection Setting" } else { "New VPN Connection Setting" })
        .content_width(560)
        .content_height(720)
        .child(&toolbar)
        .build();

    // state -> widgets that depend on it
    let refresh: Refresh = {
        let st = st.clone();
        let (user, password, cert_status, import, import_error, import_p12, p12_pass) = (
            user.clone(),
            password.clone(),
            cert_status.clone(),
            import.clone(),
            import_error.clone(),
            import_p12.clone(),
            p12_pass.clone(),
        );
        let (host, mtu, mac, fingerprint, save, problems, advanced) = (
            host.clone(),
            mtu.clone(),
            mac.clone(),
            fingerprint.clone(),
            save.clone(),
            problems.clone(),
            advanced.clone(),
        );
        let (interval, count) = (interval.clone(), count.clone());
        let (routing_groups, custom) = (routing_groups.clone(), custom.clone());
        Rc::new(move || {
            let e = st.borrow();
            user.set_visible(e.auth_type != AccountAuthType::Anonymous);
            password.set_visible(uses_password(e.auth_type));
            let is_cert = e.auth_type == AccountAuthType::Certificate;
            cert_status.set_visible(is_cert);
            import.set_visible(is_cert);
            import_p12.set_visible(is_cert);
            p12_pass.set_visible(is_cert);
            cert_status.set_subtitle(e.certificate_status());
            import_error.set_visible(is_cert && e.import_error.is_some());
            import_error.set_text(e.import_error.as_deref().unwrap_or(""));
            interval.set_sensitive(e.auto_reconnect);
            count.set_sensitive(e.auto_reconnect);
            for g in &routing_groups {
                g.set_visible(e.use_custom_routing);
            }
            custom.set_subtitle(if e.use_custom_routing {
                ""
            } else {
                "Uses the app's global routing rules (Settings → Routing)."
            });
            let flag = |row: &adw::EntryRow, bad: bool| {
                if bad {
                    row.add_css_class("error");
                } else {
                    row.remove_css_class("error");
                }
            };
            flag(&host, e.host_error().is_some());
            flag(&mtu, e.mtu_error().is_some());
            flag(&mac, e.mac_error().is_some());
            flag(&fingerprint, e.fingerprint_error().is_some());
            let mut msgs: Vec<&str> =
                [e.host_error(), e.mtu_error(), e.mac_error(), e.fingerprint_error()].into_iter().flatten().collect();
            if e.advanced_invalid() && !advanced.is_expanded() {
                msgs.push("Something in the Advanced Options needs fixing before you can save.");
            }
            problems.set_text(&msgs.join("\n"));
            save.set_sensitive(e.can_save());
        })
    };
    *refresh_cell.borrow_mut() = Some(refresh.clone());

    macro_rules! bind_text {
        ($row:expr, $field:ident) => {{
            let (st, r) = (st.clone(), refresh.clone());
            $row.connect_changed(move |w| {
                st.borrow_mut().$field = w.text().to_string();
                r();
            });
        }};
    }
    macro_rules! bind_switch {
        ($row:expr, $field:ident) => {{
            let (st, r) = (st.clone(), refresh.clone());
            $row.connect_active_notify(move |w| {
                st.borrow_mut().$field = w.is_active();
                r();
            });
        }};
    }
    macro_rules! bind_spin {
        ($row:expr, $field:ident) => {{
            let (st, r) = (st.clone(), refresh.clone());
            $row.connect_value_notify(move |w| {
                st.borrow_mut().$field = w.value() as i64;
                r();
            });
        }};
    }
    bind_text!(name, name);
    bind_text!(host, host);
    bind_text!(ports, ports);
    bind_text!(hub, hub);
    bind_text!(user, username);
    bind_text!(password, password);
    bind_text!(p12_pass, p12_passphrase);
    bind_text!(mtu, mtu);
    bind_text!(mac, mac);
    bind_text!(fingerprint, fingerprint);
    bind_switch!(compression, compression);
    bind_switch!(udp, udp_acceleration);
    bind_switch!(qos, use_qos);
    bind_switch!(half, half_connection);
    bind_switch!(verify, check_server_cert);
    bind_switch!(reconnect, auto_reconnect);
    bind_switch!(custom, use_custom_routing);
    bind_spin!(max_conn, max_connection);
    bind_spin!(interval, reconnect_interval);
    bind_spin!(count, reconnect_count);
    {
        let (st, r) = (st.clone(), refresh.clone());
        auth.connect_selected_notify(move |w| {
            st.borrow_mut().auth_type = AUTH_TYPES[w.selected() as usize % AUTH_TYPES.len()];
            r();
        });
    }
    {
        let r = refresh.clone();
        advanced.connect_expanded_notify(move |_| r());
    }
    // certificate import: pick the certificate, then its key
    {
        let (st, r) = (st.clone(), refresh.clone());
        import.connect_clicked(move |b| {
            let (st, r) = (st.clone(), r.clone());
            let window = b.root().and_downcast::<gtk::Window>();
            pick_file("Choose the certificate (PEM or DER)", window.clone(), move |cert_path, window| {
                let (st, r) = (st.clone(), r.clone());
                pick_file(
                    "Choose its RSA private key (PEM or DER, not passphrase-protected)",
                    window,
                    move |key_path, _| {
                        let read = |p: &std::path::Path| {
                            std::fs::read(p).map_err(|e| format!("Cannot read {}: {e}", p.display()))
                        };
                        match (read(&cert_path), read(&key_path)) {
                            (Ok(c), Ok(k)) => st.borrow_mut().import_identity(&c, &k),
                            (Err(e), _) | (_, Err(e)) => st.borrow_mut().import_error = Some(e),
                        }
                        r();
                    },
                );
            });
        });
    }

    {
        let (st, r) = (st.clone(), refresh.clone());
        import_p12.connect_clicked(move |b| {
            let (st, r) = (st.clone(), r.clone());
            pick_file(
                "Choose the PKCS#12 file (.p12 / .pfx)",
                b.root().and_downcast::<gtk::Window>(),
                move |path, _| {
                    match std::fs::read(&path) {
                        Ok(bytes) => st.borrow_mut().import_pkcs12(&bytes),
                        Err(e) => st.borrow_mut().import_error = Some(format!("Cannot read {}: {e}", path.display())),
                    }
                    r();
                },
            );
        });
    }

    let d = dialog.clone();
    cancel.connect_clicked(move |_| {
        d.close();
    });
    let (st2, d, ctx2) = (st.clone(), dialog.clone(), ctx.clone());
    save.connect_clicked(move |_| {
        let mut e = st2.borrow().clone();
        e.routing = routing_cfg.borrow().clone();
        if !e.can_save() {
            return;
        }
        let acc = e.make_account(base.as_ref());
        let secrets = e.secrets();
        let ok = ctx2.ctl.with_stores(|s| {
            if base.is_some() {
                s.accounts.update(acc, secrets)
            } else {
                s.accounts.add(acc, secrets)
            }
        });
        if !ok {
            ctx2.ctl.change(|m| {
                m.notice =
                    Some("Saving failed: the keyring refused a secret, or the settings file is not writable.".into())
            });
        }
        done();
        d.close();
    });
    refresh();
    dialog.present(Some(parent));
}

fn pick_file(
    title: &str,
    window: Option<gtk::Window>,
    then: impl FnOnce(std::path::PathBuf, Option<gtk::Window>) + 'static,
) {
    let dialog = gtk::FileDialog::builder().title(title).build();
    let w = window.clone();
    dialog.open(window.as_ref(), gio::Cancellable::NONE, move |res| {
        if let Ok(file) = res {
            if let Some(path) = file.path() {
                then(path, w);
            }
        }
    });
}
