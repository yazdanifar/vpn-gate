# Security policy

## Reporting
Please report vulnerabilities privately to the maintainer (mohammadreza.yazdanifar75@gmail.com) rather than opening a
public issue. Include the affected version (`VERSION`), macOS version and reproduction steps.

## Trust model
- `vpngate-helper` runs as root (LaunchDaemon) and accepts requests on a local socket restricted to the console user.
  Changes to `IPCServer`, `NetConfig` or the installer scripts in `packaging/` need particular care.
- Secrets (passwords, private keys, proxy passwords) live in the Keychain, never in `accounts.json`.
- Builds are ad-hoc signed and not notarized.
- VPN Gate relays are volunteer-run public servers; do not send sensitive traffic through them.
