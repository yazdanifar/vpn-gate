#!/bin/bash
# Builds build/vpn-gate_<version>_<arch>.deb (daemon + GTK app + unit + desktop file). Linux with the GTK dev packages:
#   sudo apt install libgtk-4-dev libadwaita-1-dev
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${1:-$(cat VERSION)}
command -v cargo-deb >/dev/null || cargo install cargo-deb --locked --version 3.6.1
cargo build --release --locked -p vpngate-daemon
(cd apps/linux && cargo build --release --locked)
mkdir -p build
(cd apps/linux && cargo deb -p vpngate-gtk --no-build --deb-version "$VERSION" -o "../../build/")
ls -l build/*.deb
