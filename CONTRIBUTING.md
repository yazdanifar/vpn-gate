# Contributing

## Requirements
macOS 14+, Xcode Command Line Tools (Swift 6 toolchain, language mode 5) and rustup (the daemon is Rust; `rust-toolchain.toml` pins it). SwiftPM is optional.

## Workflow
```
make build     # universal binaries in build/bin: the Rust daemon (installed as vpngate-helper) and the app
make test      # macOS app tests (Swift); engine and daemon: make rust-test
make test-tsan # before touching concurrency code
make lint      # swift-format check (make format fixes in place)
make rust-coverage # thresholds: 90% core, 80% engine files
```
The golden vectors in `Tests/Fixtures/golden/*.json` were exported from the Swift engine before it was deleted; they are now fixed
reference data that the Rust tests (and the app's mirror tests) must keep reproducing. Change one only together with the behaviour it
pins, by hand. Run a subset of the app tests with `scripts/test.sh <name-substring>`. Network checks: `make rust-live` and
`scripts/e2e-tunnel.sh` (root). `scripts/probe-sample.sh [count]` probes a random sample of real relays; the weekly `Live relay checks` and
`Tunnel e2e` workflows are informational (never gate a merge).

## Rust (cross-platform port)
The workspace in `crates/` is pinned by `rust-toolchain.toml` (rustup installs it on first use).
```
make rust-test   # cargo test --workspace
make rust-lint   # cargo fmt --check + clippy -D warnings
```
`vpngate-testkit::golden` loads the golden vectors from `Tests/Fixtures/golden`; port code must reproduce them. CI runs the
`rust` job on macOS, Windows and Linux. See `docs/cross-platform/PLAN.md` for the unit plan.

## Conventions
- `crates/vpngate-core` is pure protocol/logic with no I/O or privileged code; keep it that way. New engine behaviour needs a Rust test (fakes in `vpngate-testkit` and `vpngate-net`'s `testing` feature).
- In the Mac app, anything testable goes in `Sources/VPNGateMac/Model/` (compiled into the app tests by glob); `UI/` holds SwiftUI views only. The app does not link the engine: `Model/IPCTypes.swift`, `ClientAccount.swift`, `ServerModel.swift`... mirror the daemon's JSON and `Tests/App/MirrorTests.swift` checks them against the golden vectors.
- `scripts/test.sh` builds one test binary: `Model/` + `Tests/App`, against `FakeHelperServer` in `Tests/Support/FakeHelper.swift`.
- `scripts/test-ui.sh` builds a second binary (`UI/` + `Model/` + `Tests/UI`) that renders the SwiftUI views off-screen and diffs them with `Tests/Fixtures/screenshots/*.png` (CI job `screenshots`). Goldens depend on the macOS version, so never record them on your Mac: run the `Record screenshot goldens` workflow (or take `actual/` from the failed job's `screenshot-actual-and-diff` artifact), look at the images, copy them into `Tests/Fixtures/screenshots/` and commit. A new view state = a new `test("ui/...")` in `Tests/UI/ScreenshotTests.swift`. `scripts/test-ui.sh` locally is still useful to see that views render (it fails on a golden mismatch, expected on a different macOS).
- `Package.swift` and `scripts/build.sh` must both build; CI runs `swift build` as a drift check.
- Releases: bump `VERSION`, update the changelog, push tag `v<VERSION>`; the Release workflow publishes the pkg.
- `git config blame.ignoreRevsFile .git-blame-ignore-revs` hides the formatting commit from blame.
- Bump `VERSION` and update `CHANGELOG.md` for releases. The helper's IPC version is a separate number.
- Commit messages: imperative, one-line summary describing the user-visible change.
