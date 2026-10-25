# Status

Update at the end of every session (see the session protocol in [PLAN.md](PLAN.md)). ⬜ todo · 🔄 in progress · ✅ done.

| Unit | Title | State | Branch / PR | Notes |
|---|---|---|---|---|
| U00 | Plan docs | ✅ | | PLAN/STATUS/DECISIONS/UI-SPEC, README row, CLAUDE.md. Found: mac app has no statistics screen (only opt-in diagnostics). |
| U01a | Golden vectors: pure codecs (Swift) | ✅ | xp/U01a-golden-vectors | 14 files in `Tests/Fixtures/golden/` (~590 KB), exporter `Tests/Golden/Export.swift`, `scripts/gen-golden.sh`, staleness test in `GoldenTests.swift`. Deterministic (verified by double run). |
| U01b | Golden transcripts: protocol exchanges | ✅ | xp/U01b-golden-transcripts | 4 files in `Tests/Fixtures/golden/transcripts/` (login x10, host id, bridge x5, DNS proxy x6); exporter `Tests/Golden/ExportTranscripts.swift`; `Entropy`/`ClientEnvironment` injection in `SoftEtherClient` and `EthernetBridge`. Deterministic (3 runs). |
| U02 | Rust workspace scaffold | ⬜ | | |
| U03 | Pure core: Pack, ByteBuffer, HTTPHead, errors, validation | ⬜ | | |
| U04 | Pure core: RC4, SHA0, VGDat, CertPin | ⬜ | | |
| U05 | Pure core: Packets, DataPhase, UdpAccelPacket | ⬜ | | |
| U06 | Pure core: ServerList, ServerFilter, RoutingRule, ClientAccount, IPC messages | ⬜ | | |
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
