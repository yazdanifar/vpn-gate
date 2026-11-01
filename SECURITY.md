# Security policy

## Reporting
Please report vulnerabilities privately to the maintainer (mohammadreza.yazdanifar75@gmail.com) rather than opening a
public issue. Include the affected version (`VERSION`), your OS and its version, and reproduction steps.

## Trust model
- The tunnel is owned by one privileged process per desktop OS, and it only accepts requests from local users who may use it:
  - macOS: `vpngate-helper` runs as root (LaunchDaemon) on a Unix socket restricted to the console user.
  - Windows: the `VPNGate` service runs as SYSTEM on the named pipe `\\.\pipe\VPNGate`, whose ACL admits SYSTEM, Administrators and
    the interactive user; remote clients are refused and the client's token SIDs are checked. `%ProgramData%\VPNGate` is
    limited to SYSTEM and Administrators.
  - Linux: a systemd unit (`CAP_NET_ADMIN`, `CAP_NET_RAW`) on a Unix socket that admits root and the `vpngate` group (checked
    with `SO_PEERCRED`); the installer adds the installing user to that group.
  - Android: there is no privileged process; the app's `VpnService` runs the engine in-process after the system's VPN
    consent.

  Changes to `crates/vpngate-daemon` (the IPC server), `crates/vpngate-platform` (routes, DNS, tun) or the installer
  scripts in `packaging/` need particular care.
- Secrets (passwords, private keys, proxy passwords) live in the platform store, never in `accounts.json`: the Keychain
  (macOS), Credential Manager (Windows), the Secret Service through `secret-tool` (Linux) or the Android Keystore (AES-GCM).
- Builds are not notarized or store-signed: the macOS package is ad-hoc signed, the MSI is unsigned, and the Android release
  APK is signed with the project's release key (the release workflow refuses a debug-signed APK).
- VPN Gate relays are volunteer-run public servers; do not send sensitive traffic through them.
