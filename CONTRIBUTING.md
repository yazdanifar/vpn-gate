# Contributing

## Requirements
macOS 14+, Xcode Command Line Tools (Swift 6 toolchain, language mode 5) and rustup (the daemon is Rust; `rust-toolchain.toml` pins it). SwiftPM is optional.

## Workflow
```
make build     # universal binaries in build/bin: the Rust daemon (installed as vpngate-helper) and the app
make test      # full suite, no network or root (~100 s)
make test-tsan # before touching concurrency code
make lint      # swift-format check (make format fixes in place)
make coverage  # thresholds: 90% core, 80% key helper files
```
If you change core behaviour on purpose (`Sources/VPNGateCore`), run `scripts/gen-golden.sh` and commit the updated `Tests/Fixtures/golden/*.json`; `golden/committed-vectors-are-current` fails otherwise. Run a subset with `scripts/test.sh <name-substring>`; `--live` and `scripts/e2e-tunnel.sh` need network (and root). `scripts/probe-sample.sh [count]` probes a random sample of real relays; the weekly
`Live relay checks` workflow runs both and is informational (never gates a merge).

## Rust (cross-platform port)
The workspace in `crates/` is pinned by `rust-toolchain.toml` (rustup installs it on first use).
```
make rust-test   # cargo test --workspace
make rust-lint   # cargo fmt --check + clippy -D warnings
```
`vpngate-testkit::golden` loads the Swift-exported vectors from `Tests/Fixtures/golden`; port code must reproduce them. CI runs the
`rust` job on macOS, Windows and Linux. See `docs/cross-platform/PLAN.md` for the unit plan.

## Conventions
- `Sources/VPNGateCore` is pure protocol/logic with no UI or privileged code; keep it that way.
- New behaviour needs a test in `Tests/Unit` (pure logic) or `Tests/Behaviour` (fakes in `Tests/Support`).
- In the Mac app, anything testable goes in `Sources/VPNGateMac/Model/` (compiled into the app tests by glob); `UI/` holds SwiftUI views only. The app does not import `VPNGateCore`: `Model/IPCTypes.swift`, `ClientAccount.swift`, `ServerModel.swift`... mirror the daemon's JSON and `Tests/App/MirrorTests.swift` checks them against the golden vectors.
- `scripts/test.sh` builds two test binaries: `tests` (Core + the Swift helper, until U15 deletes them) and `tests-app` (`Model/` + `Tests/App`, against `FakeHelperServer` in `Tests/Support/FakeHelper.swift`). Files used by both live in `Tests/Support/Shared.swift`.
- `Package.swift` and `scripts/build.sh` must both build; CI runs `swift build` as a drift check.
- Releases: bump `VERSION`, update the changelog, push tag `v<VERSION>`; the Release workflow publishes the pkg.
- `git config blame.ignoreRevsFile .git-blame-ignore-revs` hides the formatting commit from blame.
- Bump `VERSION` and update `CHANGELOG.md` for releases. The helper's IPC version is a separate number.
- Commit messages: imperative, one-line summary describing the user-visible change.
