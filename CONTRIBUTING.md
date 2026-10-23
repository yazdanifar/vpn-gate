# Contributing

## Requirements
macOS 14+, Xcode Command Line Tools (Swift 6 toolchain, language mode 5). SwiftPM is optional.

## Workflow
```
make build     # universal binaries in build/bin
make test      # full suite, no network or root (~100 s)
make test-tsan # before touching concurrency code
make coverage  # thresholds: 90% core, 80% key helper files
```
Run a subset with `scripts/test.sh <name-substring>`; `--live` and `scripts/e2e-tunnel.sh` need network (and root).

## Conventions
- `Sources/VPNGateCore` is pure protocol/logic with no UI or privileged code; keep it that way.
- New behaviour needs a test in `Tests/Unit` (pure logic) or `Tests/Behaviour` (fakes in `Tests/Support`).
- `scripts/test.sh` lists the app files it compiles explicitly: add new non-UI app files there (UI-only files such as views are not compiled by the tests, so keep testable types out of them).
- Bump `VERSION` and update `CHANGELOG.md` for releases. The helper's IPC version is a separate number.
- Commit messages: imperative, one-line summary describing the user-visible change.
