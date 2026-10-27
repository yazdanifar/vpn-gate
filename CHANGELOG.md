# Changelog
Format follows [Keep a Changelog](https://keepachangelog.com/); versions come from the `VERSION` file.

## [Unreleased]
### Added
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

### Fixed
- CI: run on `macos-15` (Swift 6 toolchain; `macos-14` has 5.10, which rejects `swift-tools-version:6.0`), and split
  `ARPPacket.encode` so it type-checks quickly on any compiler.

### Changed
- Repository restructured: feature documentation moved to `docs/`, reverse-engineering notes to `docs/research/`,
  added CI workflow, Makefile and contributor/security documents.

## [1.0.0]
- Menu-bar client with VPN Gate list sync, Client Manager, full tunnel, SOCKS5 proxy mode, routing rules with DNS proxy,
  live download/upload speed display.
