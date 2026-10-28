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
