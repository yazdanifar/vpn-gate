# Architecture

The engine and the privileged daemon are Rust (Cargo workspace in `crates/`) and shared by all platforms; each platform has its own
app: Swift/SwiftUI on macOS (`Package.swift`, one target), WinUI 3 (C#) on Windows, GTK4/libadwaita (Rust) on Linux and
Kotlin/Jetpack Compose on Android. On macOS `scripts/build.sh` builds the daemon and the app into `build/bin` (universal binaries);
the other platforms build through their installer scripts (see the README).

| Component | Path | Role |
|---|---|---|
| `vpngate-core` | `crates/vpngate-core` | Pure protocol and logic: SoftEther pack/packet codecs, `VPNGate.dat` parsing and RSA check, server list/filter, routing rules, IPC message types, input validation |
| `vpngate-net` | `crates/vpngate-net` | SoftEther client, connection pool, Ethernet bridge, DNS proxy, SOCKS5 server, UDP acceleration, session, list fetcher (no OS calls) |
| `vpngate-platform` | `crates/vpngate-platform` | OS backends behind traits (tun device, routes, DNS, bound sockets): macOS utun/`route`/configd, Windows Wintun/IP Helper/DNS API, Linux tun/iproute2/systemd-resolved, Android tunnel plan and socket protector |
| `vpngate-daemon` | `crates/vpngate-daemon` | Privileged daemon binary: IPC server, engine, stale-state undo list. Runs as a LaunchDaemon (installed as `vpngate-helper`), a Windows service or a systemd unit |
| `vpngate-ipc-client` | `crates/vpngate-ipc-client` | Rust client of the daemon's IPC (reconnect on demand, id-matched replies) |
| `vpngate-app-model` | `crates/vpngate-app-model` | Toolkit-free state and controller of the main window, used by the Linux app (tested on every OS) |
| `vpngate-uniffi` | `crates/vpngate-uniffi` | The in-process engine for Android, exposed to Kotlin through UniFFI (`AndroidEngine.send(json)`) |
| `vpngate-testkit` | `crates/vpngate-testkit` | Test fakes (daemon, platform doubles) and the golden-vector loader |
| `VPNGateMac` | `Sources/VPNGateMac` | SwiftUI menu-bar app. `Model/`: UI-free logic (`AppModel`, accounts + Keychain, helper client/installer, mirrors of the daemon's JSON types), compiled into the tests by glob. `UI/`: views, not unit-tested |
| Windows app | `apps/windows` | WinUI 3 (unpackaged, self-contained): `VPNGate.Core` (IPC client, view models), `VPNGate.App` (windows, tray), tests, UI tests and a FlaUI smoke test |
| Linux app | `apps/linux/vpngate-gtk` | GTK4/libadwaita app with a `ksni` tray icon (own Cargo workspace) |
| Android app | `apps/android` | Kotlin/Compose; a `VpnService` hosts the Rust engine in-process; `:core` is the plain-JVM logic module |

The desktop apps never touch the network configuration themselves: they send requests (connect, disconnect, settings, list, probe)
to the daemon over a restricted local channel (a Unix socket limited to the console user on macOS and to root and the `vpngate`
group on Linux, the named pipe `\\.\pipe\VPNGate` on Windows); the protocol is specified in `docs/cross-platform/IPC.md`. On Android
the app owns the tunnel (`VpnService`) and sends the same requests to the in-process engine.

## Repository layout
```
crates/       Rust engine, daemon and platform backends
Sources/      the macOS app
apps/         the Windows (WinUI), Linux (GTK) and Android (Compose) apps
Tests/        app tests (App, Support fakes, Harness custom runner) and Fixtures (golden vectors shared with the Rust tests)
scripts/      build, test, coverage, packaging and e2e scripts
packaging/    LaunchDaemon plist and pkg scripts (macOS), WiX package (Windows), systemd unit and deb scripts (Linux)
assets/       bundled VPNGate.dat, app icon, third-party notices
docs/         FEATURES, ARCHITECTURE, cross-platform/ (plan, status, decisions, IPC, platform checklists), research/ (Windows client analysis, not built)
.github/      CI
```
Swift tests use a custom harness (`Tests/Harness`) compiled by `scripts/test.sh`, not XCTest; Rust tests use `cargo test`.
