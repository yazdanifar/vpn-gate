#!/bin/bash
# Builds build/vpn-gate_<version>_<arch>.deb (daemon + GTK app + unit + desktop file). Linux with the GTK dev packages
# and jq:
#   sudo apt install libgtk-4-dev libadwaita-1-dev jq
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${1:-$(cat VERSION)}
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked --version 3.8.0
# apps/linux is its own workspace. Building both into the root workspace's target dir (wherever cargo puts it, so
# CARGO_TARGET_DIR and build.target-dir are respected) puts vpngate-gtk next to vpngate-daemon, where cargo-deb
# resolves the target/release/ assets.
CARGO_TARGET_DIR=$(cargo metadata --format-version 1 --no-deps --locked | jq -r .target_directory)
export CARGO_TARGET_DIR
cargo build --release --locked -p vpngate-daemon
(cd apps/linux && cargo build --release --locked)
mkdir -p build
(cd apps/linux && cargo deb -p vpngate-gtk --no-build --deb-version "$VERSION" -o "../../build/")
ls -l build/*.deb
