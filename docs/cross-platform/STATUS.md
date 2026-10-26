# Status

Update at the end of every session (see the session protocol in [PLAN.md](PLAN.md)). ⬜ todo · 🔄 in progress · ✅ done.

| Unit | Title | State | Branch / PR | Notes |
|---|---|---|---|---|
| U00 | Plan docs | ✅ | | PLAN/STATUS/DECISIONS/UI-SPEC, README row, CLAUDE.md. Found: mac app has no statistics screen (only opt-in diagnostics). |
| U01a | Golden vectors: pure codecs (Swift) | ✅ | xp/U01a-golden-vectors | 14 files in `Tests/Fixtures/golden/` (~590 KB), exporter `Tests/Golden/Export.swift`, `scripts/gen-golden.sh`, staleness test in `GoldenTests.swift`. Deterministic (verified by double run). |
| U01b | Golden transcripts: protocol exchanges | ✅ | xp/U01b-golden-transcripts | 4 files in `Tests/Fixtures/golden/transcripts/` (login x10, host id, bridge x5, DNS proxy x6); exporter `Tests/Golden/ExportTranscripts.swift`; `Entropy`/`ClientEnvironment` injection in `SoftEtherClient` and `EthernetBridge`. Deterministic (3 runs). |
| U02 | Rust workspace scaffold | ✅ | xp/U02-rust-scaffold | 7 crates in `crates/`, toolchain pinned 1.98.1, `rust` CI matrix job, `make rust-test/rust-lint`, `vpngate-testkit::golden` (load/unhex) with a test that every golden file parses and none is unlisted. Windows/Linux legs verified only by CI. |
| U03 | Pure core: Pack, ByteBuffer, HTTPHead, errors, validation | ✅ | xp/U03-core-pack | `byte_buffer`, `pack`, `http_head`, `softether_error`, `validation` in `vpngate-core`; golden vectors pass. Only dependency added: serde (unused yet, for U06). |
| U04 | Pure core: RC4, SHA0, VGDat, CertPin | ✅ | xp/U04-crypto-vgdat | `rc4`, `sha0`, `cert_pin`, `vgdat` in `vpngate-core`; golden vectors pass (28 tests). Added deps: sha1, sha2, rsa 0.9 (verify only), flate2 (rust_backend), base64. Verified offline only (`--offline`); CI will resolve fresh. |
| U05 | Pure core: Packets, DataPhase, UdpAccelPacket | ✅ | xp/U05-packets | `packets`, `data_phase`, `udp_accel` (+ private `chacha_poly`) in `vpngate-core`; golden vectors pass. No new dependencies. |
| U06 | Pure core: ServerList, ServerFilter, RoutingRule, ClientAccount, IPC messages | ✅ | xp/U06-serverlist-routing | `server_list` (+ `list_format`), `server_filter`, `routing_rule`, `client_account`, `ipc` in `vpngate-core`; golden vectors pass (54 tests). New deps: regex, uuid (v4, serde), serde_json (now a normal dep); `vpngate-testkit::golden::json_eq` (3 == 3.0). Verified offline only. |
| U07 | Streams + TLS + probe | ⬜ | | |
| U08a | SoftEther handshake + login | ⬜ | | |
| U08b | Redirects + ConnectionPool | ⬜ | | |
| U09 | Bridge + DNS | ⬜ | | |
| U10a | Session | ⬜ | | |
| U10b | UDP acceleration + SOCKS5 server | ⬜ | | |
| U11 | Daemon binary + IPC server | ⬜ | | |
| U12 | Thick-engine features | ⬜ | | |
| U13 | macOS backend | ⬜ | | |
| U14 | SwiftUI app becomes a thin client | ⬜ | | |
| U15 | macOS parity + Swift deletion | ⬜ | | |
| U16 | Windows backend I: tunnel + routes | ⬜ | | |
| U17 | Windows backend II: DNS, IPC, service | ⬜ | | |
| U18 | WinUI app I: scaffold + connect flow | ⬜ | | |
| U19 | WinUI app II: parity | ⬜ | | |
| U20 | Windows packaging + CI | ⬜ | | |
| U21 | Linux backend | ⬜ | | |
| U22 | GTK app I: scaffold + connect flow | ⬜ | | |
| U23 | GTK app II: parity | ⬜ | | |
| U24 | Linux packaging + CI | ⬜ | | |
| U25 | Rust Android engine | ⬜ | | |
| U26 | Android app I: VpnService + connect flow | ⬜ | | |
| U27 | Android app II: parity | ⬜ | | |
| U28 | Android packaging + CI | ⬜ | | |
| U29 | Release workflow | ⬜ | | |

## Follow-ups found during implementation

- UI-SPEC: routing regex flavour differs between NSRegularExpression and Rust `regex`; pin the supported subset in U01a/U06.
- UI-SPEC: PKCS#12 import on mac uses Security.framework; decide in U08a/U19 whether the Rust engine parses .p12 for all UIs.
- Plan wording: "statistics" in U17b/U19/U23/U27 means the opt-in diagnostics upload plus traffic counters; there is no statistics screen.
- U01a: compressed outputs (`DataPhase.compressFrame`) are marked `"byteExact": false`; Rust must check them by round trip, not bytes.
- U01a: `ServerFilter` search uses `localizedCaseInsensitiveContains` (`MÜLLER` finds `Müller`, `elodie` does NOT find `ÉLODIE`); U06 must reproduce exactly this (Unicode case folding, no diacritic folding) or log a deliberate change.
- U01a: JSON `Date` fields use Swift's default (seconds since 2001-01-01 as a number); the Rust/C#/Kotlin account codecs must read and write that.
- U01a: vectors for `VGDat` use `Tests/Fixtures/VPNGate.dat` (symlink to `assets/`), referenced by name, plus mutation recipes (`truncate:`, `xor:`, `set:`) instead of embedded copies.
- U01a: not covered (internal or non-pure, left to later units): `ServerList.openVPNEndpoint` directly (covered through `parse`), `ClientAccount` store, `RC4`/`SHA1` streaming APIs.
- U01b: transcripts record every random draw (`entropy`: `bytes n` / `below n` with the value) in call order; ports replay the recorded values instead of reimplementing the generator, and must make the same sequence of calls.
- U01b: the data-phase keep-alive jitter/junk stays on the system generator (timing-driven, outside the injected `Entropy`); keep-alive bytes are not in any transcript.
- U01b: not covered, left to U08b/U10b: additional_connect / multi-TCP transcripts (concurrent, order not deterministic), UDP acceleration login (binds a real socket whose port goes in the login pack), the 4 s DHCP/RS retry timers.
- U01b: the login pack carries `ClientOsName`/`ClientOsVer`/`ClientHostname`; the transcripts pin them (`macOS` / `14.5.0` / `golden-host`) and list them under `config.environment`.
- U01b: the watermark upload is recorded as `watermark: true` plus the random padding after the constant image (`softEtherWaterMark`), not as ~8 KB of hex.
- U02: crates have no dependencies beyond serde/serde_json (testkit); the plan's crate list (tokio, rustls, ...) is pinned by the unit that first uses each. `rust-version` is 1.85 while the toolchain is 1.98.1.
- U02: `Tests/Fixtures/VPNGate.dat` is a symlink; Windows checkouts need `core.symlinks=true` (or a copy) before U04 reads it. Check the Windows CI leg then.
- U03: `validation::is_ip_literal` has its own IPv4/IPv6 parser because the Swift one reuses `CIDRMatcher` (RoutingRule, U06); U06 should share one parser.
- U03: Pack name matching uses Unicode lowercase comparison (Swift `caseInsensitiveCompare` is not byte-identical for exotic names); `HttpHead` headers are a `BTreeMap`.
- U04: `vgdat::parse` stops at the inner Pack (`VgDatFile.inner`); turning it into servers (`parseInnerServers`) belongs to U06 `server_list`. The test checks element names and the host count only.
- U04: the API certificate PEM is embedded; the SPKI is extracted with a small DER walk (no x509 crate) and verified with `rsa` PKCS#1 v1.5/SHA-1. `parse` takes `now_ms` instead of a `Date`.
- U04: Rust inflates raw deflate with `flate2` and checks the zlib header and Adler-32 by hand, like Swift. Trailing bytes after the deflate stream are not covered by any vector; Swift/Apple behaviour there is untested.
- U04: `CertPin::parse` accepts ASCII hex only (Swift `isHexDigit` also accepts full-width digits, which would then crash its `UInt8(radix:)!`); not a behaviour worth porting.
- U04: crates.io was unreachable from the sandbox, so Cargo.lock was resolved offline from the local registry cache (rsa 0.9.10, sha1/sha2 0.10, flate2 1.1.x, base64 0.22). Run `cargo update --dry-run` once online if newer patch versions matter.
- U05: crates.io was unreachable again, so ChaCha20-Poly1305 (RFC 8439, empty AAD) is hand-written in `chacha_poly.rs` (checked by the RFC ChaCha/Poly1305 vectors and the golden packets) instead of the `chacha20poly1305` crate. Swap it for the crate when online if an audited implementation is preferred; the module is private, so only `udp_accel` changes.
- U05: `DataPhase.compressFrame` output is not byte-identical to Apple zlib (flate2 rust_backend); vectors check round trip and that Swift's bytes inflate. `uncompress_frame` caps output at `max_len` and, unlike C `uncompress`, ignores bytes after the stream end.
- U05: the Swift `packIPValue` golden `back` is computed from reversed octets by the exporter (byte-swapped value); the Rust test mirrors that. `pack_ip_value` itself takes dotted-order octets.
- U05: the Swift unit-test files (PacketTests, DataPhaseTests, IPv6Tests) were not ported one by one; the golden vectors (52 packet, 34 data-phase, 25 UDP-accel cases) cover the same behaviour.
- U06: IDs are `uuid::Uuid`; Rust writes them lowercase, Swift writes uppercase. Both read either, so files round-trip, but a byte diff of an accounts file would show case changes.
- U06: whole-number Doubles (`reconnectInterval`, dates) are written as `3.0`, Swift writes `3`; both decode either. The golden tests compare with `json_eq`.
- U06: non-Optional fields with a default (e.g. `ConnectConfig.ports`) fall back only when the key is missing; an explicit `null` is an error in Rust, while Swift's `decodeIfPresent` treats it as missing. Swift never writes such nulls.
- U06: `ClientAccount` missing `createdAt`/`updatedAt` default to now (system clock) inside `Deserialize`; tests only check they are within 60 s of now.
- U06: IPv6 groups in `CidrMatcher` reject a leading `+` that Swift's `UInt16(_, radix: 16)` would accept (`+1::`); not worth porting.
- U06: `ServerFilter` search uses Unicode lower-casing of both sides, which matches the golden vectors but is not ICU's locale-aware compare (e.g. Turkish dotted I).
- U06: routing regexes use the Rust `regex` crate (no look-around or back-references); the golden vectors only cover the common subset. The UI should warn on patterns the engine rejects, which `validation_error` already reports.
- U06: `ServerList.fetch` (HTTP) and `ServerProbe` are not ported here; they belong to U07 with the network layer.
