# Contributing

## Requirements
macOS 14+, Xcode Command Line Tools (Swift 6 toolchain, language mode 5). SwiftPM is optional.

## Workflow
```
make build     # universal binaries in build/bin
make test      # full suite, no network or root (~100 s)
make test-tsan # before touching concurrency code
make lint      # swift-format check (make format fixes in place)
make coverage  # thresholds: 90% core, 80% key helper files
```
Run a subset with `scripts/test.sh <name-substring>`; `--live` and `scripts/e2e-tunnel.sh` need network (and root).

## Conventions
- `Sources/VPNGateCore` is pure protocol/logic with no UI or privileged code; keep it that way.
- New behaviour needs a test in `Tests/Unit` (pure logic) or `Tests/Behaviour` (fakes in `Tests/Support`).
- In the Mac app, anything testable goes in `Sources/VPNGateMac/Model/` (compiled into the tests by glob); `UI/` holds SwiftUI views only.
- `Package.swift` and `scripts/build.sh` must both build; CI runs `swift build` as a drift check.
- Releases: bump `VERSION`, update the changelog, push tag `v<VERSION>`; the Release workflow publishes the pkg.
- `git config blame.ignoreRevsFile .git-blame-ignore-revs` hides the formatting commit from blame.
- Bump `VERSION` and update `CHANGELOG.md` for releases. The helper's IPC version is a separate number.
- Commit messages: imperative, one-line summary describing the user-visible change.
