# Architecture

Three SwiftPM targets (`Package.swift`); `scripts/` builds the same sources with `swiftc` for universal binaries.

| Target | Path | Role |
|---|---|---|
| `VPNGateCore` | `Sources/VPNGateCore` | Platform-light library: SoftEther pack/packet codecs, `VPNGate.dat` parsing and RSA check, server list/filter/probe, routing rules, IPC message types, input validation |
| `vpngate-helper` | `Sources/vpngate-helper` | Root LaunchDaemon: SoftEther client session, Ethernet bridge, utun, routes/DNS (`NetConfig`), DNS proxy, SOCKS5 server, UDP acceleration, IPC server |
| `VPNGateMac` | `Sources/VPNGateMac` | SwiftUI menu-bar app. `Model/`: UI-free logic (`AppModel`, `VGDatFetcher`, accounts + Keychain, helper client/installer), compiled into the tests by glob. `UI/`: views, not unit-tested |

The app never touches the network configuration itself: it sends requests (connect, disconnect, settings) to the helper
over a uid-restricted Unix socket (`IPCMessages` in Core, `IPCServer`/`HelperClient` on each side).

## Repository layout
```
Sources/      production code (three targets above)
Tests/        Unit, Behaviour (fakes), Fuzz, Live (network), Support (fakes), Fixtures, Harness (custom runner)
scripts/      build, test, coverage, packaging and e2e scripts
packaging/    LaunchDaemon plist and pkg pre/postinstall scripts
assets/       bundled VPNGate.dat, app icon, third-party notices
docs/         FEATURES, ARCHITECTURE, research/ (Windows client analysis, not built)
.github/      CI
```
Tests use a custom harness (`Tests/Harness`) compiled by `scripts/test.sh`, not XCTest.
