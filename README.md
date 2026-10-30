# VPN Gate for macOS

Unofficial native macOS client for [VPN Gate](https://www.vpngate.net) and other SoftEther VPN servers, written from the
protocol as implemented by the Windows SoftEther VPN Client / VPN Gate plugin (v4.44 build 9807). It is not affiliated
with VPN Gate or SoftEther and does not claim full parity with the Windows client.

> **Verification status:** nothing has been run against a real VPN Gate server or a live tunnel yet; everything is
> tested with in-memory fakes and loopback sockets. See [docs/FEATURES.md](docs/FEATURES.md#what-has-and-has-not-been-verified).

## Documentation
| Document | Contents |
|---|---|
| [docs/FEATURES.md](docs/FEATURES.md) | What is implemented, known limits, telemetry, IPv6, routing rules, SOCKS5 mode |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Targets, process model, repository layout |
| [docs/cross-platform/PLAN.md](docs/cross-platform/PLAN.md) | Multi-session plan for the Rust core + Windows/Linux/Android ports; progress in [STATUS.md](docs/cross-platform/STATUS.md) |
| [docs/research/](docs/research/) | Reverse-engineering notes on the Windows client (not part of the build) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test and change workflow |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, trust model |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [LICENSE](LICENSE) | Apache-2.0 |
| [NOTICE](NOTICE) | Third-party notices |

## Install
Release builds are attached to each [GitHub release](../../releases) (tag `v*`): `VPN Gate.pkg`, `VPN-Gate.msi`,
`vpn-gate_<version>_<arch>.deb`, and an `.apk` and `.aab`. None is notarized or store-signed (see the notes per platform).

| OS | Install | Uninstall |
|---|---|---|
| macOS | open `VPN Gate.pkg` (details below) | Settings → Uninstall…, then trash the app |
| Windows 10/11 x64 | run `VPN-Gate.msi` as administrator; installs the `VPNGate` service and the app (Start menu) | Apps & features → VPN Gate |
| Debian/Ubuntu (systemd) | `sudo apt install ./vpn-gate_<version>_<arch>.deb`, then log out and in so the `vpngate` group applies | `sudo apt remove vpn-gate` (`purge` also deletes state) |
| Android 7.0+ | sideload the `.apk` (allow installs from unknown sources) | remove the app |

The Windows installer and Android APK are signed only with test keys unless the release secrets were set. Build from
source on macOS as follows.

### macOS
```
scripts/build-pkg.sh           # -> build/VPN Gate.pkg (Universal installer)
open "build/VPN Gate.pkg"      # standard macOS installer: asks for your password once
```
The installer puts `VPN Gate.app` in /Applications and starts the privileged helper (a LaunchDaemon). After that the
app never asks for anything: the helper accepts requests from whoever is logged in at the console. If the helper is
missing or outdated, **Connect** shows a one-time setup alert, opens the same installer and connects by itself when it
finishes. The package version is the `VERSION` file (currently 1.0.0). The app and package are ad-hoc signed only:
no Developer ID, no hardened runtime, **not notarizable** as built, so macOS shows an "unidentified developer" notice
the first time (right-click → Open). Notarizing would need a Developer ID, hardened-runtime signing and a rebuild.

Uninstall: Settings → Uninstall…, then drag the app to the Trash.

## Build
Only the Command Line Tools are needed (`make help` lists the shortcuts) (SwiftPM is not required; `Package.swift` is provided for machines where it works).

```
scripts/build.sh all           # -> Universal binaries in build/bin/ (arm64 + x86_64)
scripts/build-app.sh           # -> build/VPN Gate.app (ad-hoc signed, bundled VPNGate.dat)
```

Without root you can check a server's handshake and DHCP only:
```
build/bin/vpngate-helper --probe 219.100.37.7 --port 443
```
Foreground tunnel for debugging: `sudo build/bin/vpngate-helper --connect <ip> [--port N]` (Ctrl-C restores routes/DNS).

## Tests
```
cargo test --workspace           # engine + daemon (Rust): no network or root
scripts/test.sh                  # macOS app tests (Swift), no network or root
scripts/test.sh --each           # every test in its own process (crashes are reported per test)
scripts/test.sh --tsan | --asan  # app tests under ThreadSanitizer / AddressSanitizer
cargo test -p vpngate-daemon --test live -- --ignored   # real VPN Gate servers (network)
scripts/coverage-rs.sh           # cargo-llvm-cov; fails below 90% (core) / 80% (engine files)
sudo -E cargo test -p vpngate-daemon --test tunnel_hermetic -- --ignored   # real utun + routes vs a fake relay
sudo scripts/e2e-tunnel.sh <ip>  # real tunnel: traffic, DNS, IPv6 block, SIGINT/SIGTERM/kill -9 cleanup
```
The Rust suite uses an in-memory SoftEther server (real wire format), a fake hub that answers DHCP/ARP, and
recording doubles for `route`/DNS/utun, so the session, bridge, network configuration and IPC are tested
without privileges. Fuzz tests are property tests (`PROPTEST_CASES`).

## Notes / Security
- If the helper crashes, stale routes/DNS are cleaned on its next start (only routes it added).
- `scripts/gen-watermark.sh` regenerates the SoftEther signature image (Apache-2.0, © SoftEther VPN Project).
- `docs/research/` holds reverse-engineering notes: Ghidra pseudocode of the Windows client and plugin plus a `VPNGate.dat`
  decoder, used to understand the protocol (not part of the build). `NOTICE` has the third-party notices.
- Not affiliated with VPN Gate or SoftEther. VPN Gate relays are volunteer-run public servers: don't send
  sensitive traffic through them unless you trust the operator.
