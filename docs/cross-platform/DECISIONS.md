# Decisions

Log of decisions. Add a dated entry whenever a unit asks the user something; never silently change one.

## Initial decisions (made with the user, 2026-10-25)
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


## Later decisions

- **U12, IPC v9 wire shape (2026-10-27).** New commands are request/reply: a request carries an `id`, and the answer is a
  separate line `{"reply":"<cmd>","id":N,"ok":bool,"error"?,"result"?}`. Reply lines have no `state`, so a v8 client's
  `HelperEvent` decoder fails on them and ignores them. `HELPER_VERSION` stays 8 (the Swift app compares it to decide
  on a reinstall, and the golden constants pin it); the new `IPC_VERSION` is 9 and travels as `ipcVersion` in every snapshot
  event, which is how a client detects a v9 daemon. Rejected: bumping `helperVersion` (forces a reinstall for nothing),
  and answering as events (a v8 client would show them as state changes).
- **U12, who fetches the list (2026-10-27).** The daemon does (`DatFetcher` in `vpngate-net`), including the CSV mirror,
  with its own minimal HTTP/1.0 client instead of `reqwest`: no new dependency, no chunked bodies, and `https://` goes through
  the existing rustls stack with system trust. The cache is `--cache` (default per OS, `backend::default_cache_path`), the
  shipped fallback is `--bundle`.
- **U14, the Swift app mirrors the JSON instead of sharing code (2026-10-27).** `Sources/VPNGateMac/Model` carries its own
  Codable copies of the daemon's types (copied from `VPNGateCore`, minus the matching/parsing logic) and does not import the
  engine; golden-vector tests in `Tests/App/MirrorTests.swift` keep them honest. Rejected: keeping `VPNGateCore` linked into
  the app (U15 deletes it) and generating the Swift types from the Rust ones (a codegen step for ~10 structs).
- **U14, two Swift test binaries (2026-10-27).** The app tests compile `Model/` without `VPNGateCore`, because the mirrored
  names would otherwise shadow the engine's; the engine/helper tests stay in the old binary until U15. The app tests talk to a
  scripted `FakeHelperServer` that speaks the daemon's JSON, not to a real daemon.
- **U15b, golden vectors become frozen fixtures (2026-10-27).** With the Swift engine deleted nothing regenerates `Tests/Fixtures/golden`; they stay as the reference contract for Rust, the app mirrors, and the ports in U18-U28. Rejected: porting the exporter to Rust (it would test Rust against itself).
- **U15b, release (2026-10-27).** `VERSION` is 2.0.0 and the changelog has the 2.0.0 section; the `v2.0.0` tag (which triggers the Release workflow) is left to the user.

