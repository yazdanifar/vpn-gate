# Changelog
Format follows [Keep a Changelog](https://keepachangelog.com/); versions come from the `VERSION` file.

## [Unreleased]
### Added
- `Live relay checks` workflow (weekly + manual) and `scripts/probe-sample.sh`: real-relay handshake/DHCP/list-sync
  checks with a pass rate per server build; relays come from the bundled list, not hard-coded addresses.

### Fixed
- CI: run on `macos-15` (Swift 6 toolchain; `macos-14` has 5.10, which rejects `swift-tools-version:6.0`), and split
  `ARPPacket.encode` so it type-checks quickly on any compiler.

### Changed
- Repository restructured: feature documentation moved to `docs/`, reverse-engineering notes to `docs/research/`,
  added CI workflow, Makefile and contributor/security documents.

## [1.0.0]
- Menu-bar client with VPN Gate list sync, Client Manager, full tunnel, SOCKS5 proxy mode, routing rules with DNS proxy,
  live download/upload speed display.
