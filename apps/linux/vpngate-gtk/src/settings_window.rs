//! Settings (UI-SPEC 8): General, Proxy, Routing and Advanced. Every control writes through to the settings file at once.

use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use vpngate_app_model::autostart;
use vpngate_core::ipc::{ProxyKind, TunnelMode};

use crate::ctx::Ctx;
use crate::routing_editor;

pub struct Actions {
    pub open_accounts: Rc<dyn Fn()>,
    pub open_log: Rc<dyn Fn()>,
}

pub fn open(parent: &impl IsA<gtk::Widget>, ctx: &Ctx, actions: Actions) {
    let s = ctx.ctl.settings();
    let dialog = adw::PreferencesDialog::builder().title("Settings").build();

    // General
    let general = adw::PreferencesPage::builder().title("General").icon_name("preferences-system-symbolic").build();
    let connection = adw::PreferencesGroup::builder().title("Connection").build();
    let login = adw::SwitchRow::builder()
        .title("Launch at login")
        .active(autostart::is_enabled(&autostart::entry_path()))
        .build();
    let reconnect = adw::SwitchRow::builder().title("Reconnect automatically").active(s.auto_reconnect).build();
    let ipv6 = adw::SwitchRow::builder().title("Block IPv6 while connected").active(s.block_ipv6).build();
    let ipv6_captions = [
        "Off: IPv6 only works if the VPN network provides it (a router advertising an IPv6 prefix). Otherwise IPv6 is still captured and dropped, so nothing leaks.",
        "On: IPv6 is captured and dropped, which prevents IPv6 leaks; dual-stack sites fall back to IPv4 through the VPN.",
    ];
    ipv6.set_subtitle(ipv6_captions[usize::from(s.block_ipv6)]);
    for r in [&login, &reconnect, &ipv6] {
        connection.add(r);
    }
    let mode_group = adw::PreferencesGroup::builder().title("Mode").build();
    let mode = crate::combo::row("Use the VPN as", &["Full tunnel (whole computer)", "SOCKS5 proxy only"]);
    mode.set_selected(u32::from(s.tunnel_mode == TunnelMode::SocksProxy));
    let socks_port = adw::SpinRow::with_range(1024.0, 65535.0, 1.0);
    socks_port.set_title("SOCKS port");
    socks_port.set_value(s.socks_port as f64);
    let mode_caption = gtk::Label::builder().xalign(0.0).wrap(true).css_classes(["dim-label"]).build();
    mode_group.add(&mode);
    mode_group.add(&socks_port);
    mode_group.add(&mode_caption);
    let update_mode = {
        let (mode, socks_port, caption) = (mode.clone(), socks_port.clone(), mode_caption.clone());
        move || {
            let socks = mode.selected() == 1;
            socks_port.set_visible(socks);
            caption.set_text(&if socks {
                format!("Serves a SOCKS5 proxy on 127.0.0.1:{}. Name lookups happen remotely; routing rules and IPv6 blocking do not apply. Applies to the next connection.", socks_port.value() as i64)
            } else {
                "All traffic of this computer goes through the VPN. Applies to the next connection.".into()
            });
        }
    };
    update_mode();
    let accounts_group = adw::PreferencesGroup::builder().title("VPN connections").build();
    let open_accounts = adw::ActionRow::builder()
        .title("Open VPN Connection Settings…")
        .subtitle("Manage your own SoftEther servers and accounts in a separate window.")
        .activatable(true)
        .build();
    accounts_group.add(&open_accounts);
    let component = adw::PreferencesGroup::builder().title("VPN component").build();
    let running = ctx.ctl.read(|m| m.service_running);
    component.add(
        &adw::ActionRow::builder()
            .title(if running { "Running" } else { "Not running" })
            .subtitle("The vpngate service runs as root to create the VPN interface, routes and DNS. Manage it with systemctl.")
            .build(),
    );
    for g in [&connection, &mode_group, &accounts_group, &component] {
        general.add(g);
    }

    // Proxy
    let proxy = adw::PreferencesPage::builder().title("Proxy").icon_name("network-server-symbolic").build();
    let proxy_group = adw::PreferencesGroup::builder()
        .title("Connect through")
        .description("If you are using a proxy server, you might not be able to use VPN Relay Servers which don't support the TCP port 443 as “SSL-VPN Connection” from such a proxy-mandated network.")
        .build();
    let kind = crate::combo::row("Proxy", &["No proxy (direct)", "HTTP proxy (CONNECT)", "SOCKS5 proxy"]);
    kind.set_selected(match s.proxy_kind {
        ProxyKind::None => 0,
        ProxyKind::Http => 1,
        ProxyKind::Socks5 => 2,
    });
    let host = adw::EntryRow::builder().title("Proxy host").text(&s.proxy_host).build();
    let port = adw::SpinRow::with_range(0.0, 65535.0, 1.0);
    port.set_title("Proxy port");
    port.set_value(s.proxy_port as f64);
    let user = adw::EntryRow::builder().title("Username (optional)").text(&s.proxy_username).build();
    let pass =
        adw::PasswordEntryRow::builder().title("Password").text(ctx.ctl.proxy_password().unwrap_or_default()).build();
    for r in
        [kind.upcast_ref::<gtk::Widget>(), host.upcast_ref(), port.upcast_ref(), user.upcast_ref(), pass.upcast_ref()]
    {
        proxy_group.add(r);
    }
    proxy.add(&proxy_group);
    let update_proxy = {
        let (kind, host, port, user, pass) = (kind.clone(), host.clone(), port.clone(), user.clone(), pass.clone());
        move || {
            let on = kind.selected() != 0;
            for w in [host.upcast_ref::<gtk::Widget>(), port.upcast_ref(), user.upcast_ref(), pass.upcast_ref()] {
                w.set_sensitive(on);
            }
        }
    };
    update_proxy();

    // Routing
    let routing = adw::PreferencesPage::builder().title("Routing").icon_name("network-workgroup-symbolic").build();
    let cfg = Rc::new(RefCell::new(s.routing.clone()));
    let c = ctx.clone();
    let cfg2 = cfg.clone();
    for g in routing_editor::groups(
        cfg,
        Rc::new(move || {
            let r = cfg2.borrow().clone();
            c.ctl.update_settings(|s| s.routing = r);
        }),
    ) {
        routing.add(&g);
    }

    // Advanced
    let advanced =
        adw::PreferencesPage::builder().title("Advanced").icon_name("applications-engineering-symbolic").build();
    let list_group = adw::PreferencesGroup::builder().title("Server list").build();
    let mirror = adw::EntryRow::builder().title("Mirror URL (optional)").text(&s.mirror_url).build();
    mirror.set_tooltip_text(Some("Used first when set, e.g. if vpngate.net is blocked."));
    list_group.add(&mirror);
    list_group.set_description(Some("Used first when set, e.g. if vpngate.net is blocked."));
    let log_group = adw::PreferencesGroup::builder().title("Log").build();
    let show_log = adw::ActionRow::builder().title("Show Log…").activatable(true).build();
    log_group.add(&show_log);
    advanced.add(&list_group);
    advanced.add(&log_group);
    for p in [&general, &proxy, &routing, &advanced] {
        dialog.add(p);
    }

    // wiring
    let toast_target = dialog.clone();
    login.connect_active_notify(move |r| {
        let want = r.is_active();
        let exec = std::env::current_exe().map_or("vpngate-gtk".into(), |p| p.display().to_string());
        if let Err(e) = autostart::set_enabled(&autostart::entry_path(), want, &exec) {
            // The OS refused: revert and say so (UI-SPEC 8).
            r.set_active(!want);
            toast_target.add_toast(adw::Toast::new(&format!("Could not change launch at login: {e}")));
        }
    });
    let c = ctx.clone();
    reconnect.connect_active_notify(move |r| c.ctl.update_settings(|s| s.auto_reconnect = r.is_active()));
    let c = ctx.clone();
    ipv6.connect_active_notify(move |r| {
        r.set_subtitle(ipv6_captions[usize::from(r.is_active())]);
        c.ctl.update_settings(|s| s.block_ipv6 = r.is_active());
    });
    let (c, u) = (ctx.clone(), update_mode.clone());
    mode.connect_selected_notify(move |r| {
        c.ctl.update_settings(|s| {
            s.tunnel_mode = if r.selected() == 1 { TunnelMode::SocksProxy } else { TunnelMode::FullTunnel }
        });
        u();
    });
    let (c, u) = (ctx.clone(), update_mode);
    socks_port.connect_value_notify(move |r| {
        c.ctl.update_settings(|s| s.socks_port = r.value() as i64);
        u();
    });
    let (c, u) = (ctx.clone(), update_proxy);
    kind.connect_selected_notify(move |r| {
        c.ctl.update_settings(|s| {
            s.proxy_kind = match r.selected() {
                1 => ProxyKind::Http,
                2 => ProxyKind::Socks5,
                _ => ProxyKind::None,
            }
        });
        u();
    });
    let c = ctx.clone();
    host.connect_changed(move |r| c.ctl.update_settings(|s| s.proxy_host = r.text().to_string()));
    let c = ctx.clone();
    port.connect_value_notify(move |r| c.ctl.update_settings(|s| s.proxy_port = r.value() as i64));
    let c = ctx.clone();
    user.connect_changed(move |r| c.ctl.update_settings(|s| s.proxy_username = r.text().to_string()));
    let (c, d) = (ctx.clone(), dialog.clone());
    pass.connect_changed(move |r| {
        if !c.ctl.set_proxy_password(&r.text()) {
            d.add_toast(adw::Toast::new("The keyring refused the password."));
        }
    });
    let c = ctx.clone();
    mirror.connect_changed(move |r| c.ctl.update_settings(|s| s.mirror_url = r.text().to_string()));
    let (f, d) = (actions.open_accounts, dialog.clone());
    open_accounts.connect_activated(move |_| {
        d.close();
        f();
    });
    let f = actions.open_log;
    show_log.connect_activated(move |_| f());
    dialog.present(Some(parent));
}
