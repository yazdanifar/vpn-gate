# Changelog
Format follows [Keep a Changelog](https://keepachangelog.com/); versions come from the `VERSION` file.

## [Unreleased]
### Fixed
- Rust daemon: the tun reader thread panicked ("no reactor running") on the first outgoing packet, so a connected tunnel carried no traffic. Packets are now handed to the engine inside the Tokio runtime.

### Added
- U15a: Rust property tests (`proptest`, port of the Swift fuzz suite) for pack, data phase, packet parsers, server list,
  validation and the bridge; ignored live-relay tests (`cargo test -p vpngate-daemon --test live -- --ignored`);
  `scripts/coverage-rs.sh` (cargo-llvm-cov, same thresholds as the Swift script) and a `coverage` CI job. `live.yml` now runs
  the Rust live tests and `gen-watermark.sh` emits `crates/vpngate-net/src/watermark.rs`.
- Golden vectors (`Tests/Fixtures/golden/*.json`, `scripts/gen-golden.sh`): Swift-exported input/output pairs for the pure
  codecs, which the cross-platform ports must reproduce byte for byte; a test fails when they go stale.
- `Live relay checks` workflow (weekly + manual) and `scripts/probe-sample.sh`: real-relay handshake/DHCP/list-sync
  checks with a pass rate per server build; relays come from the bundled list, not hard-coded addresses.
- Golden transcripts (`Tests/Fixtures/golden/transcripts/`): login/redirect/welcome exchanges, DHCP/ARP/IPv6 bridge frames and DNS proxy
  rewrites recorded with injected randomness, for byte-level replay by the ports. `SoftEtherClient` and `EthernetBridge` take an
  injectable `Entropy` (default: system random, behaviour unchanged).
- Rust workspace scaffold (`crates/vpngate-{core,net,platform,daemon,ipc-client,uniffi,testkit}`), pinned toolchain, `rust` CI job on
  macOS/Windows/Linux, `make rust-test` / `make rust-lint`, and the golden-vector loader in `vpngate-testkit`. No behaviour change.
- `vpngate-core`: Rust ports of ByteBuffer, Pack, HTTPHead, SoftEtherError and InputValidation, passing the golden vectors. No behaviour change.
- `vpngate-core`: Rust ports of RC4, SHA-0, VGDat (RSA signature check, inflate, probe, tunables) and CertPin/ServerCertPolicy, passing the golden vectors. No behaviour change.
- `vpngate-core`: Rust ports of Packets (Ethernet, ARP, IPv4, UDP, DHCP, IPv6, ICMPv6), DataPhase and UdpAccelPacket (hand-written ChaCha20-Poly1305), passing the golden vectors. No behaviour change.
- `vpngate-core`: Rust ports of ServerList (CSV parse, ports, list text), ServerFilter, RoutingRule/RoutingMatcher, ClientAccount and the IPC messages (serde, same JSON and missing-field defaults as the Swift Codable output), passing the golden vectors. No behaviour change.
- `vpngate-net`: Rust `ByteStream` trait, `TlsStream` (rustls; accept-any, leaf pin and platform-verifier modes; SNI; remote IPv4), HTTP CONNECT and SOCKS5 client dialers, and `ServerProbe`, tested against a loopback rcgen TLS server. No behaviour change.
- `vpngate-net`: Rust SoftEther handshake and login (`SoftEtherClient::connect_once`: watermark/plain signature, anonymous, password, certificate and ticket auth, welcome and redirect validation), `HostUniqueId`, certificate signing, an in-memory `FakeSoftEtherServer` (`testing` feature), replaying the 10 golden login transcripts byte for byte. No behaviour change.
- `vpngate-net`: Rust `SoftEtherClient::connect` (up to 5 cluster redirects), `ConnectionPool` (least-loaded sends, half-connection directions, idle-read watchdog) and the session services: additional connections with replenish/backoff, keep-alives, capped send queue; `FakeSoftEtherServer` now speaks additional_connect and the data phase. UDP acceleration stays for U10b. No behaviour change.
- `vpngate-net`: Rust `EthernetBridge` (DHCP acquire/renew, ARP resolve/queue, IPv4 framing, IPv6 neighbour discovery and SLAAC with Router Solicitation backoff), `DnsMessage` and the `DnsProxy` routing decision behind `DnsUpstream`/`DynamicRuleSink` traits, plus an in-memory `FakeNetworkServer` (DHCP/ARP hub, `testing` feature); replays the 5 bridge and 6 DNS proxy golden transcripts byte for byte. No behaviour change.
- `vpngate-net`: Rust `Session` (generation-guarded connect/disconnect, port fallback, 8-attempt reconnect with per-account override, bridge/tun wiring, DNS proxy and SOCKS lifecycle, bypass routes, SLAAC address, lease renewal, 1 s counters) built on the new `vpngate-platform` traits (`TunDevice`, `NetConfiguring`, `DnsConfigurator`), with structured recording fakes in `vpngate-testkit`; ports all of `SessionTests`. No behaviour change.
- `vpngate-net`: Rust UDP acceleration (`udp_accel`, wired into `SoftEtherClient::connect`: UDP first once ~10 s stable, TCP otherwise, endpoint in the bypass hosts), SOCKS5 server and `TunnelConnector`, DNS UDP client and loopback listener (`DnsProxyServer`), and the `SocketBinder` platform trait; ports the UdpAccel tests of `ProtocolFixTests` and `SocksTests`. No behaviour change.
- `vpngate-daemon`: Rust daemon binary (`--daemon [--uid] [--socket]`, `--connect`, `--probe [--watch-udp]`, `--version`) with the IPC server (newline-delimited JSON over a Unix socket, 1 MiB line cap, bounded 256-event outbox with a 2 s stall drop, `PeerAuth` by uid/console user, connect-request validation), a stale-state undo list and SIGINT/SIGTERM shutdown; ports `IPCTests`. No platform backend yet, so a connect stops at tun creation. No behaviour change.
- `vpngate-net`/`vpngate-daemon`/`vpngate-ipc-client`: thick engine (IPC v9). `DatFetcher` ports `VGDatFetcher` (HTTP API, last-good-relay P2P download with ack, cache/bundle, CSV mirror, DynList tunables and poll intervals); `vgdat::parse_inner_servers` turns a verified list into servers (matches the 200 golden servers). New request/reply commands `listServers`, `refreshServers`, `syncDat`, `probe` and `validateAccount`, `ipcVersion` in snapshots, daemon options `--bundle`/`--cache`. A Rust `IpcClient` (reconnect on demand, id-matched replies) and a scriptable `FakeDaemon` in the testkit. Spec in `docs/cross-platform/IPC.md`. v8 clients are unaffected.
- macOS app is a thin client (U14): it no longer links `VPNGateCore`. `Model/IPCTypes.swift`, `ClientAccount.swift`, `RoutingRule.swift`, `ServerModel.swift` mirror the daemon's JSON (checked against the golden vectors in `Tests/App/MirrorTests.swift`); `HelperClient` gains the IPC v9 request/reply calls (`listServers`, `refreshServers`, `probe`, `validateAccount`). The server list, the dat sync and "Test from this Mac" now run in the daemon; the app owns only the poll timer (the daemon returns `nextPollSeconds`). `VGDatFetcher.swift` is deleted from the app.
- `scripts/build.sh` builds the Rust daemon (`cargo` per architecture + `lipo`) as `vpngate-helper` and the app with swiftc alone; the LaunchDaemon plist passes `--bundle` (the list shipped in the app). The tests run in two binaries (`tests`, `tests-app`); CI installs the Rust toolchain for the build and package jobs.

### Changed
- An installed helper that does not report `ipcVersion` 9 (the old Swift one) is treated as outdated: Connect offers the reinstall, which installs the Rust daemon. Before a v9 helper is running the app shows the list it saved last time (no list is parsed in the app any more).

### Fixed
- CI: run on `macos-15` (Swift 6 toolchain; `macos-14` has 5.10, which rejects `swift-tools-version:6.0`), and split
  `ARPPacket.encode` so it type-checks quickly on any compiler.

### Changed
- Repository restructured: feature documentation moved to `docs/`, reverse-engineering notes to `docs/research/`,
- `vpngate-platform`/`vpngate-daemon`: macOS backend in Rust (utun via `PF_SYSTEM`, `/sbin/route` + `ifconfig` behind a `CommandRunner`, configd DNS with `OverridePrimary`, `IP_BOUND_IF` sockets, undo list recorded as changes are made and replayed at daemon start). The daemon is now a working tunnel on macOS; the Swift helper is still the shipped one. Live tunnel checks are left to the user.
  added CI workflow, Makefile and contributor/security documents.

## [1.0.0]
- Menu-bar client with VPN Gate list sync, Client Manager, full tunnel, SOCKS5 proxy mode, routing rules with DNS proxy,
  live download/upload speed display.
