# VPN Gate for Linux (GTK4)

GTK4 + libadwaita front end for the `vpngate` daemon. State and daemon logic are in `crates/vpngate-app-model`; this
directory is widgets, the tray and glue. It is its own Cargo workspace because the root one also builds on macOS and Windows.

```
sudo apt install libgtk-4-dev libadwaita-1-dev   # Ubuntu 24.04+ / Debian 13+ (libadwaita 1.5)
cd apps/linux && cargo run
```

`VPNGATE_SOCKET` overrides the daemon socket (default `/run/vpngate.sock`). Your user must be root or in the `vpngate`
group. Settings live in `~/.config/vpngate/settings.json`.

**Tray.** The icon is a StatusNotifierItem. KDE, XFCE and Cinnamon show it; GNOME needs the *AppIndicator and
KStatusNotifierItem Support* extension. Without a watcher the tray is simply absent. Closing the window quits the app.
