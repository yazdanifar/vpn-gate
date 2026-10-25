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

(none yet)
