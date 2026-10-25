# Status

Update at the end of every session (see the session protocol in [PLAN.md](PLAN.md)). ⬜ todo · 🔄 in progress · ✅ done.

| Unit | Title | State | Branch / PR | Notes |
|---|---|---|---|---|
| U00 | Plan docs | ✅ | | PLAN/STATUS/DECISIONS/UI-SPEC, README row, CLAUDE.md. Found: mac app has no statistics screen (only opt-in diagnostics). |
| U01a | Golden vectors: pure codecs (Swift) | ⬜ | | |
| U01b | Golden transcripts: protocol exchanges | ⬜ | | |
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
