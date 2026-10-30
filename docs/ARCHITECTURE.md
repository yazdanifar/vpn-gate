# Architecture

The engine and the privileged daemon are Rust (Cargo workspace in `crates/`); the macOS app is Swift (`Package.swift`, one
target). `scripts/build.sh` builds both into `build/bin` (universal binaries).

| Component | Path | Role |
|---|---|---|
| `vpngate-core` | `crates/vpngate-core` | Pure protocol and logic: SoftEther pack/packet codecs, `VPNGate.dat` parsing and RSA check, server list/filter, routing rules, IPC message types, input validation |
| `vpngate-net` | `crates/vpngate-net` | SoftEther client, connection pool, Ethernet bridge, DNS proxy, SOCKS5 server, UDP acceleration, session, list fetcher (no OS calls) |
| `vpngate-platform` | `crates/vpngate-platform` | OS backends behind traits: macOS utun, routes, configd DNS, bound sockets |
| `vpngate-daemon` | `crates/vpngate-daemon` | Root LaunchDaemon binary (installed as `vpngate-helper`): IPC server, engine, stale-state undo list |
| `VPNGateMac` | `Sources/VPNGateMac` | SwiftUI menu-bar app. `Model/`: UI-free logic (`AppModel`, accounts + Keychain, helper client/installer, mirrors of the daemon's JSON types), compiled into the tests by glob. `UI/`: views, not unit-tested |

The app never touches the network configuration itself: it sends requests (connect, disconnect, settings, list, probe) to the
daemon over a uid-restricted Unix socket; the protocol is specified in `docs/cross-platform/IPC.md`.

## Repository layout
```
crates/       Rust engine, daemon and platform backends
Sources/      the macOS app
Tests/        app tests (App, Support fakes, Harness custom runner) and Fixtures (golden vectors shared with the Rust tests)
scripts/      build, test, coverage, packaging and e2e scripts
packaging/    LaunchDaemon plist and pkg pre/postinstall scripts
assets/       bundled VPNGate.dat, app icon, third-party notices
docs/         FEATURES, ARCHITECTURE, research/ (Windows client analysis, not built)
.github/      CI
```
Swift tests use a custom harness (`Tests/Harness`) compiled by `scripts/test.sh`, not XCTest; Rust tests use `cargo test`.
