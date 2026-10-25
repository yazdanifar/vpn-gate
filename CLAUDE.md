# VPN Gate

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test and conventions.

## Cross-platform port (multi-session)
The port to Rust + Windows/Linux/Android is planned in [docs/cross-platform/PLAN.md](docs/cross-platform/PLAN.md).
Each session implements ONE unit (U-nn). Before starting, read that unit, the "Session protocol" section and
[STATUS.md](docs/cross-platform/STATUS.md); at the end, update STATUS.md and CHANGELOG.md. Log new user decisions in
[DECISIONS.md](docs/cross-platform/DECISIONS.md). Commands that touch live tunnels/routes/relays are handed to the user.
