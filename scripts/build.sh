#!/bin/bash
# Builds with swiftc directly (works even when SwiftPM is unavailable).
# Usage: scripts/build.sh [core|helper|app|all]     (tests: scripts/test.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=build/bin; mkdir -p "$OUT"
FLAGS=(-swift-version 5 -O -target arm64-apple-macos14.0)
CORE=(Sources/VPNGateCore/*.swift)
what=${1:-all}
if [[ $what == core || $what == all ]]; then
  swiftc "${FLAGS[@]}" -parse-as-library -emit-library -emit-module -module-name VPNGateCore \
    -static -o "$OUT/libVPNGateCore.a" -emit-module-path "$OUT/VPNGateCore.swiftmodule" "${CORE[@]}"
fi
if [[ $what == helper || $what == all ]]; then
  swiftc "${FLAGS[@]}" -I "$OUT" -o "$OUT/vpngate-helper" Sources/vpngate-helper/*.swift "$OUT/libVPNGateCore.a"
fi
if [[ $what == app || $what == all ]]; then
  swiftc "${FLAGS[@]}" -I "$OUT" -parse-as-library -o "$OUT/VPNGateMac" Sources/VPNGateMac/*.swift "$OUT/libVPNGateCore.a"
fi
