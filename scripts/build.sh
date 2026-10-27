#!/bin/bash
# Builds the macOS binaries into build/bin:
#   vpngate-helper  the Rust daemon (crates/vpngate-daemon), universal (arm64 + x86_64) via cargo + lipo
#   VPNGateMac      the SwiftUI app, universal, with swiftc directly (it does not link the engine; it speaks the daemon's JSON)
# Usage: scripts/build.sh [helper|app|all]     (tests: scripts/test.sh)
# ARCHS="arm64" limits the build to one architecture (the tests only need the host's).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=build/bin; mkdir -p "$OUT"
what=${1:-all}
read -r -a ARCHS <<< "${ARCHS:-arm64 x86_64}"

# App sources live in exactly Model/ (unit-tested) and UI/; anything else would be built by one tool and not the other.
bad=$(find Sources/VPNGateMac -mindepth 1 -maxdepth 1 ! -name Model ! -name UI)
[[ -z $bad ]] || { echo "error: Sources/VPNGateMac may only contain Model/ and UI/, found: $bad" >&2; exit 1; }

rust_triple() { case $1 in arm64) echo aarch64-apple-darwin ;; x86_64) echo x86_64-apple-darwin ;; esac; }

build_helper() {
  local slices=()
  for arch in "${ARCHS[@]}"; do
    local triple; triple=$(rust_triple "$arch")
    rustup target add "$triple" >/dev/null 2>&1 || true
    cargo build --release --locked -p vpngate-daemon --target "$triple"
    slices+=("target/$triple/release/vpngate-daemon")
  done
  lipo -create -output "$OUT/vpngate-helper" "${slices[@]}"
}

build_app() {
  mkdir -p "$OUT/arm64" "$OUT/x86_64"
  local slices=()
  for arch in "${ARCHS[@]}"; do
    swiftc -swift-version 5 -O -target "${arch}-apple-macos14.0" -parse-as-library -o "$OUT/$arch/VPNGateMac" Sources/VPNGateMac/*/*.swift
    slices+=("$OUT/$arch/VPNGateMac")
  done
  lipo -create -output "$OUT/VPNGateMac" "${slices[@]}"
}

[[ $what == helper || $what == all ]] && build_helper
[[ $what == app || $what == all ]] && build_app
exit 0
