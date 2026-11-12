# VPN Gate

Unofficial client for [VPN Gate](https://www.vpngate.net) and other SoftEther VPN servers for **macOS, Windows, Linux and
Android**, written from the protocol as implemented by the Windows SoftEther VPN Client / VPN Gate plugin (v4.44 build 9807).
The engine and the privileged daemon are one Rust code base shared by all four apps. It is not affiliated with VPN Gate or
SoftEther and does not claim full parity with the Windows client.

> **Verification status:** tunnels have been run against real public VPN Gate relays on macOS, Linux and Windows (the weekly
> `Tunnel e2e (real relay)` workflow connects from a GitHub-hosted runner of each OS and checks that traffic leaves through the
> relay, DNS, the IPv6 block and the exact restore after a kill). The Android app is tested against a real SoftEther server in an
> emulator, not against a public relay. Public relays come and go, relays that insist on the "knock" are not supported, and some
> list-API behaviour is unconfirmed. See [docs/FEATURES.md](docs/FEATURES.md#what-has-and-has-not-been-verified).

## Documentation
| Document | Contents |
|---|---|
| [docs/FEATURES.md](docs/FEATURES.md) | What is implemented per platform, known limits, verification status, telemetry, IPv6, routing rules, SOCKS5 mode |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, process model, repository layout |
| [docs/cross-platform/PLAN.md](docs/cross-platform/PLAN.md) | Multi-session plan for the Rust core + Windows/Linux/Android ports; progress in [STATUS.md](docs/cross-platform/STATUS.md), decisions in [DECISIONS.md](docs/cross-platform/DECISIONS.md) |
| [docs/cross-platform/PLATFORMS.md](docs/cross-platform/PLATFORMS.md) | Per platform: what CI covers and what still needs a human |
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
| macOS 14+ | open `VPN Gate.pkg` (details below) | Settings → Uninstall…, then trash the app |
| Windows 10/11 x64 | run `VPN-Gate.msi` as administrator; installs the `VPNGate` service and the app (Start menu) | Apps & features → VPN Gate |
| Debian/Ubuntu (systemd) | `sudo apt install ./vpn-gate_<version>_<arch>.deb`, then log out and in so the `vpngate` group applies | `sudo apt remove vpn-gate` (`purge` also deletes state) |
| Android 7.0+ | sideload the `.apk` (allow installs from unknown sources) | remove the app |

The Windows installer is unsigned (SmartScreen: "More info" → "Run anyway"). The Android APK of a release is signed with the
project's release key; one you build yourself is signed with the debug key unless you set `VPNGATE_KEYSTORE*` (see below).

### macOS
The installer puts `VPN Gate.app` in /Applications and starts the privileged helper (a LaunchDaemon). After that the
app never asks for anything: the helper accepts requests from whoever is logged in at the console. If the helper is
missing or outdated, **Connect** shows a one-time setup alert, opens the same installer and connects by itself when it
finishes. The package version is the `VERSION` file (currently 1.2.0). The app and package are ad-hoc signed only:
no Developer ID, no hardened runtime, **not notarizable** as built, so macOS shows an "unidentified developer" notice
the first time (right-click → Open). Notarizing would need a Developer ID, hardened-runtime signing and a rebuild.

Uninstall: Settings → Uninstall…, then drag the app to the Trash.

## Build from source
The Rust toolchain is pinned by `rust-toolchain.toml` (rustup installs it on first use). Each platform builds its installer
with one script:

| OS | Needs | Command | Output |
|---|---|---|---|
| macOS | Command Line Tools (SwiftPM is not required; `Package.swift` is provided for machines where it works) | `scripts/build-pkg.sh` (`make help` lists the shortcuts) | `build/VPN Gate.pkg` (Universal installer) |
| Windows | .NET 8 SDK, the WiX CLI (`dotnet tool install --global wix --version 4.0.5`) | `scripts/build-msi.ps1` | `build/VPN-Gate.msi` |
| Linux | `sudo apt install libgtk-4-dev libadwaita-1-dev jq` | `scripts/build-deb.sh` | `build/vpn-gate_<version>_<arch>.deb` |
| Android | Android SDK and NDK (`$ANDROID_NDK_HOME`) | `scripts/build-android-engine.sh`, then in `apps/android`: `./gradlew :app:assembleRelease :app:bundleRelease` | `.apk` and `.aab` under `apps/android/app/build/outputs` |

On macOS the pieces separately: `scripts/build.sh all` (Universal binaries in `build/bin/`, arm64 + x86_64) and
`scripts/build-app.sh` (`build/VPN Gate.app`, ad-hoc signed, bundled VPNGate.dat).

The daemon is `vpngate-helper` in `build/bin` on macOS and `vpngate-daemon` elsewhere (`cargo build --release -p vpngate-daemon`).
Without root you can check a server's handshake and DHCP only:
```
build/bin/vpngate-helper --probe 219.100.37.7 --port 443
```
Foreground tunnel for debugging (root, or Administrator on Windows): `sudo build/bin/vpngate-helper --connect <ip> [--port N]`
(Ctrl-C restores routes/DNS).

## Tests
```
cargo test --workspace           # engine, daemon, platform backends (Rust): no network or root
scripts/test.sh                  # macOS app tests (Swift), no network or root
scripts/test.sh --each           # every test in its own process (crashes are reported per test)
scripts/test.sh --tsan | --asan  # app tests under ThreadSanitizer / AddressSanitizer
scripts/test-ui.sh               # macOS: renders the SwiftUI views and diffs them with Tests/Fixtures/screenshots
(cd apps/linux && cargo test)    # GTK app; its window tests need a display: VPNGATE_UI_TESTS=1 xvfb-run -a cargo test --test ui
dotnet test apps/windows/VPNGate.Tests          # Windows app logic (WinUI UI tests: apps/windows/VPNGate.UiTests)
(cd apps/android && ./gradlew :core:test :app:verifyPaparazziDebug)   # Android logic and screenshots
cargo test -p vpngate-daemon --test live -- --ignored   # real VPN Gate servers (network)
scripts/coverage-rs.sh           # cargo-llvm-cov; fails below 90% (core) / 80% (engine files)
sudo -E cargo test -p vpngate-daemon --test tunnel_hermetic -- --ignored   # macOS: real utun + routes vs a fake relay
sudo scripts/e2e-tunnel.sh <ip>  # macOS: real tunnel: traffic, DNS, IPv6 block, SIGINT/SIGTERM/kill -9 cleanup
```
`scripts/e2e-tunnel-linux.sh` and `scripts/e2e-tunnel.ps1` are the Linux and Windows versions of the real-tunnel check. The Rust
suite uses an in-memory SoftEther server (real wire format), a fake hub that answers DHCP/ARP, and recording doubles for
`route`/DNS/utun, so the session, bridge, network configuration and IPC are tested without privileges. Fuzz tests are
property tests (`PROPTEST_CASES`). CI also runs every installer, the UI tests and a tunnel against a real SoftEther server
in a network namespace; [docs/cross-platform/PLATFORMS.md](docs/cross-platform/PLATFORMS.md) lists what each platform covers.

## Notes / Security
- If the daemon (the helper on macOS) crashes or is killed, stale routes/DNS are undone on its next start (only what it
  changed); the weekly real-relay e2e checks this on macOS, Linux and Windows.
- `scripts/gen-watermark.sh` regenerates the SoftEther signature image (Apache-2.0, © SoftEther VPN Project).
- `docs/research/` holds reverse-engineering notes: Ghidra pseudocode of the Windows client and plugin plus a `VPNGate.dat`
  decoder, used to understand the protocol (not part of the build). `NOTICE` has the third-party notices.
- Not affiliated with VPN Gate or SoftEther. VPN Gate relays are volunteer-run public servers: don't send
  sensitive traffic through them unless you trust the operator.
