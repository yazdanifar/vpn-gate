# Cross-platform VPN Gate — multi-session plan

## Context
VPN Gate for macOS is a working SoftEther client written in Swift. It has three parts:
- `Sources/VPNGateCore`, about 3k lines.
- The root helper, `Sources/vpngate-helper`, about 3.7k lines.
- A SwiftUI app, about 3.4k lines.

There are 430 tests. They use a custom harness, fakes and an in-memory SoftEther server. About 85% of the core and helper
is pure byte logic. The Apple-only parts are:
- TLS: `Network.framework` in `TLSStream`.
- `Security` RSA: `VGDat` and `CertAuth`.
- CryptoKit and Compression.
- utun: `Utun.swift`.
- route, ifconfig and SCDynamicStore: `NetConfig.swift`.
- `IP_BOUND_IF`, `getpeereid` together with `/dev/console`, and launchd.

**Goal:** ship on **macOS, Windows, Linux and Android** from one Rust core, with a **native GUI on each OS**. The work is
delivered over many Claude Code sessions. Each unit of work (U-nn) below fits one session and leaves the branch green.

## Decisions (made with the user, 2026-10-25)
| Topic | Decision | Why / rejected |
|---|---|---|
| Core + daemon language | **Rust** workspace, used on all 4 platforms. macOS is the *first* backend. The Swift core and helper are deleted once it reaches parity. | Best TUN/Wintun/netlink/TLS ecosystem, no GC, and it cross-compiles everywhere. Rejected: Swift everywhere (immature Windows/Android toolchains) and Go (clunkier mobile FFI, GC). |
| Architecture | **Thick engine, thin UIs.** The engine owns the protocol, the tunnel, server-list and VGDat sync, and probing. On desktop the engine is a privileged daemon, and the UIs speak the existing newline-delimited JSON IPC. On Android the engine runs in-process. | No logic is duplicated across the four UIs. The SwiftUI app doesn't care what language the helper is written in, so switching mac over is cheap. |
| GUIs | **Native per OS:** macOS uses SwiftUI (existing). Windows uses **WinUI 3 + C#**. Linux uses **GTK4/libadwaita in Rust** (relm4). Android uses **Kotlin + Jetpack Compose**. | Native feel on each platform. Replaces the earlier Flutter choice. The Linux UI can reuse the Rust IPC types directly. |
| Android ↔ Rust | **UniFFI**: one Rust API definition generates Kotlin bindings. | Rejected: hand-written JNI (verbose and error-prone). |
| Platform secrets/login | These stay in each UI: Keychain + SMAppService on mac, Credential Manager/DPAPI + a startup task on Windows, libsecret + XDG autostart on Linux, Android Keystore. | The mac code keeps working unchanged. |
| TLS | **rustls** with a custom verifier (accepts self-signed certificates and pins the leaf DER). When "system trust" is on, it uses **rustls-platform-verifier**. | The OS trust store gives the verdict, with only one TLS implementation. Rejected: native-tls and per-OS stacks. |
| Parity safety net | **Golden vectors** exported from the Swift code, which Rust must reproduce byte-for-byte, **plus** a port of every Swift test file. | Catches a test and its code being translated wrongly together. |
| Platform order | macOS, then **Windows**, then **Linux**, then **Android**. | Largest audience first after mac. |
| Packaging | mac: the existing .pkg. Windows: **MSI via WiX**, unsigned at first, with a Windows Service, a bundled signed `wintun.dll` and a self-contained WinUI app. Linux: **.deb** with a systemd unit. Android: APK/AAB. | |
| Build | Cargo for Rust. `scripts/build.sh` keeps building the Swift app and calls `cargo` (two arches + `lipo`) for the daemon. `dotnet` builds Windows and Gradle builds Android. | |

These defaults were chosen without asking. Record them in DECISIONS.md so they can be revisited:
- tokio as the async runtime.
- The IPC stays newline-delimited JSON, with `ipcVersion` bumped to 9 for the additive requests.
- WinUI is unpackaged and self-contained, with the CommunityToolkit.Mvvm and H.NotifyIcon libraries.
- relm4 for GTK.
- Compose with a ViewModel + StateFlow.

Accepted risk: in the desktop daemon, untrusted server CSV/`.dat` parsing runs as root/SYSTEM. This is mitigated by Rust
memory safety, the existing input validation and fuzz tests (U15).

## Target layout
```
Cargo.toml                 # workspace
crates/
  vpngate-core/            # pure: pack, packets, rc4, sha0, vgdat, serverlist, routing rules, ipc msgs, dataphase, udpaccel pkt
  vpngate-net/             # tls+proxy dialers, softether client, conn pool, bridge, dns, socks, udp accel, session, dat sync (no OS calls)
  vpngate-platform/        # traits: TunDevice, NetConfigurator, DnsConfigurator, SocketBinder, IpcListener, PeerAuth, ServiceHost
                           #   + backends: macos/, windows/, linux/, android/ (#[cfg(target_os)])
  vpngate-daemon/          # bin: --probe / --connect / --daemon / --version; IPC server; stale-state recovery
  vpngate-ipc-client/      # Rust IPC client (used by the GTK app and the integration tests)
  vpngate-uniffi/          # UniFFI API for Android (in-process engine)
  vpngate-testkit/         # fake SoftEther server, fake hub (DHCP/ARP), recording platform fakes, golden loader, fake daemon
apps/
  windows/                 # WinUI 3 + C# (VPNGate.Windows.sln, VPNGate.App, VPNGate.Core [IPC+models], VPNGate.Tests)
  linux/                   # GTK4/libadwaita + relm4 (Rust crate in the workspace)
  android/                 # Gradle project: Kotlin, Compose, VpnService, UniFFI bindings
Sources/VPNGateMac/        # SwiftUI app (thin client after U14)
Tests/Fixtures/golden/     # JSON vectors exported from Swift (U01a/b), consumed by Rust, C#, Swift and Kotlin tests
docs/cross-platform/       # PLAN.md, STATUS.md, DECISIONS.md, IPC.md, PLATFORMS.md, UI-SPEC.md
```

The Swift-to-Rust mapping is reused one-to-one:
- The `Protocols.swift` seams (`VPNTransport`, `TunDevice`, `CommandRunner`, `DNSConfigurator`, `NetConfiguring`,
  `SessionControlling`) become Rust traits.
- So do `ByteStream`/`StreamFactory` (`TLSStream.swift:5-47`), `DNSUpstream` (`DNSProxy.swift:7`) and `SocksConnector`
  (`SocksServer.swift:6`).
- The `Tests/Support` fakes (`FakeSoftEtherServer`, `Fakes.swift`, `FakeNetwork`, `LocalHTTPServer`) move into
  `vpngate-testkit`.

Crates, with versions pinned in U02:
- Async and serialization: tokio, serde/serde_json.
- TLS: rustls, rustls-platform-verifier, and rcgen for tests.
- Crypto and compression: sha1, sha2, chacha20poly1305, rsa (PKCS#1 v1.5 SHA-1 verify and sign) and flate2.
- System: libc, wintun, windows, windows-service, rtnetlink, zbus and system-configuration.
- UI and bindings: uniffi, gtk4, libadwaita and relm4.
- Testing: proptest (seeded fuzz) and cargo-llvm-cov.

## Session protocol (every unit)
1. Read this unit in `docs/cross-platform/PLAN.md`, and read `STATUS.md`. Confirm that the units it depends on are ✅.
   Use Sonnet `Explore` subagents to read the Swift sources being ported. If the unit hits an open decision, ask the user,
   giving the options with pros and cons, before coding. Log the answer in DECISIONS.md.
2. Work on branch `xp/U-nn-<slug>`. Keep commits small and imperative, and end each one with the attribution line.
3. "Done when" must pass locally. That means `cargo fmt --check && cargo clippy -D warnings && cargo test` and/or the
   platform's own build and tests (`scripts/test.sh`, `dotnet test`, `./gradlew test`). Run `scripts/lint.sh` if Swift was
   touched.
4. Commands that touch a live tunnel, routes or relays (e2e and live tests) are **handed to the user to run**. Claude runs the
   offline tests.
5. At the end of the session:
   - Update `STATUS.md`: mark the unit ✅, and add notes and any follow-ups found.
   - Add an entry under "Unreleased" in `CHANGELOG.md`.
   - Push and open a PR.
   - If the unit turned out too big, split the remainder into `U-nn.b` in PLAN.md rather than overrunning.

---
## Units of work

### Phase 0 — Foundation
**U00 Plan docs.**
- Write `docs/cross-platform/{PLAN,STATUS,DECISIONS}.md` from this file.
- Write `UI-SPEC.md`: a screen-by-screen spec of the current SwiftUI app, which the three native UIs must match. Cover the
  disclaimer, the server list (filter and sort), connect, accounts and the editor, cert import, routing rules, settings
  (SOCKS5, proxy, telemetry, launch at login), history, statistics, the log and the tray/menu bar.
- Add the plan to the README docs table, and add a `CLAUDE.md` pointer to the session protocol.

**U01a Golden vectors: pure codecs (Swift).**
- Add `Tests/Golden/Export.swift` and a `scripts/gen-golden.sh` that compiles it the way `scripts/test.sh` does and writes
  `Tests/Fixtures/golden/*.json`. Each vector is an input and its expected bytes or struct, with bytes in hex.
- Cover:
  - Pack, HTTPHead, InputValidation and SoftEtherError.
  - RC4/SHA0 and the VGDat decode of `Tests/Fixtures/VPNGate.dat`.
  - ServerList over `vpngate-snapshot.csv`, ServerFilter and RoutingRule.
  - DataPhase, and UdpAccelPacket with a fixed key and nonce.
  - CertPin, ClientAccount JSON, and every `HelperRequest`/`HelperEvent` case.
- *Done when:* the vectors are committed, and a Swift test checks that regenerating them changes nothing.

**U01b Golden transcripts: protocol exchanges.**
- Inject the randomness in `SoftEtherClient`, `HostUniqueId` and the bridge, for tests only.
- Record byte transcripts against `FakeSoftEtherServer` for:
  - Signature upload, password login, cert login, redirect and welcome.
  - DHCP, ARP, IPv6 RS/RA and the DNS proxy rewrite.
- Save them to `golden/transcripts/`.

**U02 Rust workspace scaffold.**
- Add the workspace and the empty crates, `rust-toolchain.toml`, rustfmt, clippy lints and the testkit golden loader.
- Add a `rust` job to `ci.yml` that runs on a macos-15, windows-latest and ubuntu-latest matrix.
- Add the Makefile targets `rust-test` and `rust-lint`, and a Rust section in CONTRIBUTING.
- *Done when:* CI is green on all 3 OSes.

### Phase 1 — Pure core (`vpngate-core`)
Each unit ports its modules and their Swift unit tests, and must pass all golden vectors for those modules.
Phase 1 units only depend on U02, so they can run in any order.

- **U03** ByteBuffer, Pack, HTTPHead, SoftEtherError, InputValidation (PackTests, ValidationTests).
- **U04** RC4, SHA0, VGDat (`rsa` verify against the embedded PEM, then `flate2` inflate with a hand-checked Adler-32) and
  CertPin (VGDatTests).
- **U05** Packets (Ethernet, IPv4, IPv6, ARP, DHCP, ICMPv6), DataPhase, UdpAccelPacket (PacketTests, DataPhaseTests,
  IPv6Tests).
- **U06** ServerList parse, ServerFilter, RoutingRule, ClientAccount, IPC messages (ServerListTests, RoutingRuleTests,
  AccountTests, TelemetryTests).
  - The IPC messages use serde. Their JSON must match the Swift Codable output, *including the
    default-on-missing-field behaviour*.

### Phase 2 — Network engine (`vpngate-net`, no OS calls)
- **U07 Streams + TLS + probe.**
  - A `ByteStream` trait with TCP dialing, plus HTTP CONNECT and SOCKS5 client dialers.
  - rustls with a custom `ServerCertVerifier` that has three modes: self-signed, leaf pin (SHA-1/SHA-256) and platform
    verifier. Also SNI, a TLS 1.2 minimum and reporting the remote IPv4 address.
  - `ServerProbe`.
  - Port TLSPinTests and ProbeTests, using rcgen certs and a ported `LocalHTTPServer`.
- **U08a SoftEther handshake + login.** `SoftEtherClient.swift` is 790 lines, so its port is split across U08a and U08b.
  - This unit covers the signature upload (WaterMark), and password, ticket and cert login. Cert login uses an `rsa`
    PKCS#1 v1.5 SHA-1 signature plus the PKCS#8 unwrap from `CertAuth.swift`.
  - Also welcome validation and `HostUniqueId`.
  - Port `FakeSoftEtherServer` into the testkit.
  - Port HandshakeTests and LoginParityTests, and replay the U01b login transcripts.
- **U08b Redirects + ConnectionPool.** Cluster redirects, additional connections and multi-TCP (ParityTests, the redirect
  and pool cases).
- **U09 Bridge + DNS.** EthernetBridge (ARP, DHCP, RA, SLAAC), DNSMessage, DNSProxy logic through a `DnsUpstream` trait,
  and the fake hub (BridgeTests, DNSProxyTests).
- **U10a Session.**
  - The state machine, retry/reconnect (8 retries for the user's own accounts), counters, and applying dynamic routing
    rules.
  - Built on the `vpngate-platform` traits, with recording fakes that record *structured* route and DNS operations rather
    than argv (SessionTests).
- **U10b UDP acceleration + SOCKS5 server.** tokio UDP/TCP code that binds sockets through the `SocketBinder` trait
  (SocksTests, ProtocolFixTests).

### Phase 3 — Daemon + macOS cutover
- **U11 Daemon binary + IPC server.**
  - The CLI modes, and newline-delimited JSON with a 1 MiB line cap.
  - Validation, ported from `IPCServer.swift:164-190`.
  - A bounded outbox (256 events, 2 s stall) and the `PeerAuth` trait.
  - The stale-state undo list, and shutdown on a signal or a service stop.
  - Port IPCTests.
- **U12 Thick-engine features.**
  - Move the `VGDatFetcher.swift` logic into `vpngate-net`: HTTP API first, then relays, then the cache, plus the
    HTTPS→HTTP fallback.
  - New IPC v9 requests: `listServers`, `refreshServers`, `syncDat`, `probe` and `validateAccount`.
  - A Rust `vpngate-ipc-client`, and a fake daemon in the testkit.
  - Write `docs/cross-platform/IPC.md`, the full spec for the Swift, C# and Rust clients.
  - Port AppFixTests where they apply.
- **U13 macOS backend.**
  - utun via `PF_SYSTEM`/`CTLIOCGINFO` (`Utun.swift:106-136`), detecting each packet's family from the IP version nibble.
  - Routes: add, delete, get, blackhole and ifscope. Keep the `/sbin/route` and `ifconfig` commands behind the structured
    trait, for parity.
  - SCDynamicStore DNS with `OverridePrimary` (`NetConfig.swift:29-79`).
  - `IP_BOUND_IF`, `getpeereid` together with the console UID, and the existing paths.
  - Port NetConfigTests and SystemTests.
- **U14 SwiftUI app becomes a thin client.**
  - Replace `import VPNGateCore` in `Sources/VPNGateMac` with Codable mirrors in `Model/IPCTypes.swift`, tested against
    the golden IPC JSON.
  - Route the list, dat-sync and probe calls through `HelperClient`.
  - Adapt AppModelTests and PackagingTests.
  - `build.sh` runs `cargo build` for `{aarch64,x86_64}-apple-darwin`, then `lipo`. `build-pkg.sh` ships the result as
    `vpngate-helper`, so the plist and the pkg scripts stay unchanged.
- **U15a macOS parity: Rust tests + CI (offline).** Fuzz (proptest), live tests, `cargo-llvm-cov` thresholds, `live.yml`, `probe-sample.sh`, `gen-watermark.sh`.
- **U15b Swift deletion + 2.0.0** (after the user ran the live commands below). Remaining items of the old U15:
  - Port the Fuzz tests (seeded proptest) and the Live tests.
  - Add `cargo-llvm-cov` thresholds equal to today's (≥90% core, ≥80% client, bridge, session, netconfig and ipc).
  - Point `live.yml` and `probe-sample.sh` at the Rust daemon, and make `gen-watermark.sh` emit Rust.
  - **The user runs** `sudo scripts/e2e-tunnel.sh <ip>` and `scripts/test.sh --live`.
  - Then delete `Sources/VPNGateCore` and `Sources/vpngate-helper`, and the Swift tests the Rust tests now cover.
  - Trim `Package.swift`, `test.sh` and `coverage.sh`.
  - Update ARCHITECTURE, README and FEATURES, and release 2.0.0 (VERSION, CHANGELOG, tag).

### Phase 4 — Windows
- **U16 Windows backend I: tunnel + routes.**
  - A Wintun adapter.
  - Address and MTU via the IP Helper API (`CreateUnicastIpAddressEntry`, `SetIpInterfaceEntry`).
  - Routes via `CreateIpForwardEntry2`, `DeleteIpForwardEntry2` and `GetBestRoute2`: the split default route, the relay
    bypass and the IPv6 block.
  - Unit tests against a recording fake of the API layer.
- **U17 Windows backend II: DNS, IPC, service.**
  - DNS via `SetInterfaceDnsSettings` plus the interface metric.
  - `IP_UNICAST_IF` for socket binding.
  - A named-pipe `IpcListener` with an ACL (SYSTEM, Administrators, Interactive), and a check of the client's SID.
  - A `windows-service` host that does the stale cleanup on start, and data under `%ProgramData%\VPNGate`.
- **U18 WinUI app I: scaffold + connect flow.**
  - Create `apps/windows`: WinUI 3, unpackaged and self-contained, using CommunityToolkit.Mvvm.
  - `VPNGate.Core` is a C# library with the named-pipe JSON client and the models, which are tested against the golden IPC
    JSON with xUnit.
  - Screens: the disclaimer gate, the server list (filter and sort), connect/disconnect and the log.
  - A tray icon (H.NotifyIcon), and ViewModel tests against a fake pipe server.
- **U19 WinUI app II: parity.**
  - Accounts and the editor, with secrets in Credential Manager.
  - Cert import (PEM, DER, p12), routing rules, settings (SOCKS5, proxy, telemetry opt-in, run at login through a startup
    task), history and statistics.
  - App icons from `assets/AppIcon-256.png`.
  - Check against UI-SPEC.md.
- **U20 Windows packaging + CI.**
  - A WiX MSI (`cargo-wix`/WiX v4). It installs the service (auto-start, restart on failure), `wintun.dll` and the WinUI
    app, and removes the service and its state on uninstall.
  - A CI job that runs `dotnet test` and builds the MSI as an artifact.
  - **The user runs** the manual e2e checklist on a Windows VM. Add the checklist to `PLATFORMS.md`.

### Phase 5 — Linux
- **U21 Linux backend.**
  - The tunnel through `/dev/net/tun` (`IFF_TUN|IFF_NO_PI`).
  - rtnetlink for addresses, routes and blackhole routes, plus a policy-routing table that replaces `-ifscope`.
  - DNS through systemd-resolved over D-Bus with zbus (`SetLinkDNS`, `SetLinkDomains ~.`, `SetLinkDefaultRoute`). The
    fallback backs up and restores `/etc/resolv.conf`.
  - `SO_BINDTODEVICE`.
  - For `PeerAuth`, `SO_PEERCRED` plus a `vpngate` group.
  - A systemd unit with `CAP_NET_ADMIN CAP_NET_RAW` and `Restart=always`.
- **U22 GTK app I: scaffold + connect flow.**
  - Create `apps/linux`: GTK4, libadwaita and relm4, using `vpngate-ipc-client` and the core types directly.
  - Screens: the disclaimer, the server list, connect/disconnect and the log.
  - A tray via StatusNotifierItem (ksni). Note that GNOME needs the AppIndicator extension; document this.
  - Component tests against the fake daemon.
- **U23 GTK app II: parity.** Accounts and the editor (secrets in libsecret through oo7 or secret-service), cert import,
  routing rules, settings (XDG autostart), history and statistics. Check against UI-SPEC.md.
- **U24 Linux packaging + CI.**
  - A `.deb` built with cargo-deb, containing the daemon, the unit, the GTK app, a `.desktop` file and icons.
  - The postinst creates the group, adds the installing user to it and enables the unit.
  - Build the deb in ubuntu CI.
  - Port `e2e-tunnel.sh` to Linux. **The user runs** it.

### Phase 6 — Android (in-process engine, no daemon)
- **U25 Rust Android engine.**
  - `vpngate-uniffi` exposes these operations: list, refresh and dat sync; probe; validate an account; connect and
    disconnect; and an event stream callback.
  - Build it with `cargo-ndk` for arm64-v8a, armeabi-v7a and x86_64.
  - The `android` backend has three parts:
    - `TunDevice` comes from the VpnService fd.
    - `SocketBinder` calls a Kotlin `protect(fd)` callback for the relay, UDP-accel and direct-DNS sockets.
    - `NetConfigurator` returns a *plan* (addresses, routes, excluded routes, DNS, MTU) that Kotlin applies through
      `VpnService.Builder`.
- **U26 Android app I: VpnService + connect flow.**
  - Create the Gradle project in `apps/android`, with the UniFFI-generated bindings.
  - The Kotlin `VpnService` has a foreground notification, the consent flow, and always-on/lockdown support.
  - Compose screens: the disclaimer, the server list and connect/disconnect, built on a ViewModel and StateFlow.
  - Unit tests with a fake engine.
- **U27 Android app II: parity.**
  - Accounts and the editor (secrets in Android Keystore), cert import (SAF picker), settings, history, statistics and the
    log.
  - Routing rules map to `excludeRoute` on API 33+, and to computed route splitting below that.
  - **Ask the user** whether SOCKS5 mode should be hidden on Android. The proposed default is to hide it.
  - Check against UI-SPEC.md.
- **U28 Android packaging + CI.**
  - A Gradle build of the APK/AAB.
  - Signing: the debug key in CI, and the release key from secrets.
  - A CI job, and an emulator smoke test (launch, then fetch the server list against a fixture).

### Phase 7 — Unified release
- **U29 Release workflow.**
  - Change `release.yml` so that a `v*` tag builds the mac .pkg, the Windows MSI, the .deb and the APK, and attaches all of
    them to the GitHub release.
  - Gate it on every platform's lint and test jobs.
  - Add a per-platform feature matrix to FEATURES.md, and per-OS install instructions to the README.

## Dependency graph
```
U00 → U01a → U01b → U02 → {U03, U04, U05, U06} → U07 → U08a → U08b → U09 → U10a → U10b → U11 → U12 → U13 → U14 → U15
U12 → U18 → U19          (WinUI UI work can start against the fake daemon before the Windows backend exists)
U15 → U16 → U17 → U20    (U20 also needs U19)
U12 → U22 → U23          (GTK UI likewise)
U17 → U21 → U24          (U24 also needs U23)
U12 → U25 → U26 → U27 → U28
All → U29
```
The main line follows the agreed order: mac, then Windows, then Linux, then Android. Each UI unit only needs U12 (the IPC v9
spec and the fake daemon), so the UI units can be interleaved with backend units.

## Verification
- **Per unit:** the golden vectors pass, the ported or new tests pass, and lint is clean on the CI OSes. For the native UIs,
  ViewModel/component tests run against the fake daemon or engine, and the model tests run against the golden IPC JSON.
- **mac cutover (U15):** the full Rust suite, the Swift app tests, the e2e tunnel (traffic, DNS, the IPv6 block, cleanup
  after SIGINT, SIGTERM and kill -9) and the live relay checks all pass on the Rust daemon. The user runs the live and
  tunnel parts.
- **Each new platform:** CI builds and tests it, and produces the installer artifact. The user then runs the manual e2e
  checklist in PLATFORMS.md:
  - Connect, browse and DNS.
  - The IPv6 block and a routing rule.
  - Reconnect after a network drop.
  - Uninstall leaves no routes or DNS changes behind.
  - The UI matches UI-SPEC.md.

## Critical files (existing)
- Seams: `Sources/vpngate-helper/Protocols.swift`, `Sources/VPNGateCore/TLSStream.swift` and
  `Sources/VPNGateCore/IPCMessages.swift`.
- Platform code to reimplement: `Sources/vpngate-helper/{Utun,NetConfig,IPCServer,DNSProxy,SocksServer,CertAuth,HostUniqueId,Shutdown}.swift`.
- App coupling to the core: `Sources/VPNGateMac/Model/{AppModel,VGDatFetcher,HelperClient,AccountManager}.swift`. The UI
  reference for UI-SPEC is `Sources/VPNGateMac/UI/*.swift`.
- Test fakes to port: `Tests/Support/{FakeSoftEtherServer,Fakes,FakeNetwork,LocalHTTPServer}.swift`.
- Build and CI: `scripts/{build,build-pkg,test,coverage,lint}.sh`, `.github/workflows/{ci,release,live}.yml` and
  `Package.swift`.
