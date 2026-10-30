# Platform checklists

Manual checks that need a real machine. The agent cannot run these; the user does, and reports the result in STATUS.md.

## Windows (U20) — clean Windows 10/11 x64 VM, administrator account

**Automated in CI** (the `rust (windows-latest)` and `msi` jobs on disposable admin runners):
- `scripts/test-msi.ps1`: steps 1-4, the IPC status check, service restart after a kill, uninstall.
- `scripts/test-msi-upgrade.ps1`: upgrade over an older MSI (data kept, new service process), downgrade refused, uninstall.
- `crates/vpngate-daemon/tests/tunnel_windows.rs`: a real Wintun adapter, routes and DNS through the real `Session` against a
  fake relay (ping through the tunnel, only 192.0.2.0/24 captured, relay bypass, IPv6 block, restore on disconnect), SOCKS5-only
  mode (proxy answers, no system route change), and a killed process whose stale routes the next start removes.
- `VPNGate.Tests/WindowsIntegrationTests.cs`: real Credential Manager (incl. chunking) and the run-at-login registry value.

Only the rest needs a human: the look of the UI (5), a connection to a real relay with full-tunnel capture of the default
route (6), a real TCP flow through SOCKS5, tray, upgrade of a running app window.

Get `vpn-gate-msi` from the latest green `msi` CI job (unsigned: SmartScreen "More info" > "Run anyway").

1. **Install.** `msiexec /i VPN-Gate.msi /l*v install.log`. Expect no errors; Start menu has "VPN Gate".
2. **Service.** `sc query VPNGate` is RUNNING; `sc qc VPNGate` shows AUTO_START, `--service`; `sc qfailure VPNGate` shows restart x3.
3. **Files.** `C:\Program Files\VPN Gate` has `vpngate-daemon.exe`, `wintun.dll`, `VPNGate.dat`, `VPNGate.exe`.
4. **State folder.** `icacls C:\ProgramData\VPNGate` lists only SYSTEM and Administrators (full control).
5. **App.** Launch as a normal (non-admin) user: window renders; compare against UI-SPEC.md section by section
   (disclaimer, list, filter, sort, columns, Details, accounts editor, routing editor, Settings, History, tray menu).
   The list is filled (bundled list or sync); the status shows the service is reachable.
6. **Connect.** Connect to a relay. Verify: "VPNGate" adapter present, public IP changes, DNS resolves, IPv6 blocked
   (when set), `route print` shows the split default routes and the relay bypass. Disconnect restores routes and DNS.
7. **Crash recovery.** While connected: `taskkill /F /IM vpngate-daemon.exe`. The service restarts within ~5 s and the
   stale routes/DNS are cleaned (no leftover `0.0.0.0/1`, `128.0.0.0/1`).
8. **SOCKS5-only mode** works and does not change the default route.
9. **Run at login, tray, Credential Manager** (accounts survive restart, secrets not in `accounts.json`).
10. **Upgrade** by installing a newer MSI over it; **uninstall** removes the service, adapter, program folder and
    `C:\ProgramData\VPNGate`.

Report anything that fails with the log (`install.log`, `%LocalAppData%\VPNGate`, `sc query`).

## Linux (U24) — clean Ubuntu 24.04 / Debian 13 desktop VM, systemd, a normal user with sudo

**Automated in CI** (the `deb` job, ubuntu-latest): `scripts/build-deb.sh` builds `vpn-gate_<version>_<arch>.deb`;
`scripts/test-deb.sh` installs it, checks the `vpngate` group, the enabled and active unit, the installed files, a `status`
reply over `/run/vpngate.sock`, the restart after `kill -9`, `remove` (unit gone, group kept) and `purge` (state and group gone).
The group membership of the installing user in a fresh login session, socket access for members and refusal for others, and a real keyring round trip are covered too. A tun device and routes are covered by the `softether-netns` job. Not covered: the GTK window, the tray.

Get `vpn-gate-deb` from the latest green `deb` CI job.

1. **Install.** `sudo apt install ./vpn-gate_*.deb`. It prints that your user was added to the `vpngate` group; log out and in.
   `id` lists `vpngate`; `systemctl status vpngate` is active.
2. **App.** Start "VPN Gate" from the application menu (icon present). The window opens, the list is filled, the status shows
   the daemon is reachable. Compare against UI-SPEC.md. On GNOME the tray needs the AppIndicator extension.
3. **Connect.** Connect to a relay: `ip route` shows `0.0.0.0/1` and `128.0.0.0/1` via `vpngate0`, the public IP changes,
   `resolvectl status` shows the VPN resolver with `~.`, IPv6 is blocked. Disconnect restores routes and DNS.
4. **Command line.** `sudo scripts/e2e-tunnel-linux.sh <server-ip>` (get a live one from the app or `vpngate-daemon --probe`) prints
   `E2E PASSED`: traffic, DNS, the IPv6 block, and exact restore after SIGINT, SIGTERM and kill -9 + restart.
5. **Secrets.** With `libsecret-tools` and a keyring: an account's password survives an app restart and is not in
   `~/.config/vpngate/accounts.json`.
6. **Uninstall.** `sudo apt remove vpn-gate` leaves no `vpngate0`, routes or DNS changes; `purge` removes `/var/lib/vpngate`.

Report anything that fails with `journalctl -u vpngate` and the output of the script.

## Android (U28) — a real phone, Android 7.0 or newer

**Automated in CI** (`android-app` and `android-emulator`, ubuntu-latest): JVM tests, the debug APK, the release APK and AAB
(`vpn-gate-release-apk`, `vpn-gate-release-aab`), and an x86_64 emulator (API 34) smoke test: launch, agree to the disclaimer, the bundled list shows.
Without secrets the release build is signed with the debug key (installable, not for distribution). For a real key set
`VPNGATE_KEYSTORE` (path relative to `apps/android`), `VPNGATE_KEYSTORE_PASSWORD`, `VPNGATE_KEY_ALIAS`, `VPNGATE_KEY_PASSWORD`.
Not covered: the VPN consent, a tunnel, always-on, the notification.

1. **Install.** Sideload the APK from `vpn-gate-release-apk`. Launch, agree, the list shows.
2. **Connect.** Accept the VPN consent. The key icon appears, the public IP changes, DNS works, IPv6 does not leak.
3. **Drop.** Toggle airplane mode on and off: it reconnects.
4. **Always-on.** Settings > VPN > VPN Gate > Always-on, plus "Block connections without VPN": it starts after a reboot.
5. **Compare** the screens with UI-SPEC.md. This is also the first run of U26/U27 on a device.
