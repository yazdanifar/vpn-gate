# Platform checklists

Manual checks that need a real machine. The agent cannot run these; the user does, and reports the result in STATUS.md.

## Windows (U20) — clean Windows 10/11 x64 VM, administrator account

**Automated in CI** (`scripts/test-msi.ps1`, the `msi` job on a Windows runner): steps 1-4, the IPC status check, the crash
recovery of step 7 (service restart; the route cleanup part is not covered) and the uninstall part of step 10. Only the
rest below needs a human: UI look (5), a real connection (6), SOCKS mode, login/tray/Credential Manager, upgrade.

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
