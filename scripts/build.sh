#!/bin/bash
# Builds universal binaries (arm64 + x86_64) with swiftc directly.
# Usage: scripts/build.sh [core|helper|app|all]     (tests: scripts/test.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=build/bin; mkdir -p "$OUT" "$OUT/arm64" "$OUT/x86_64"
VERSION=$(cat VERSION 2>/dev/null || echo "1.0.0")
ARCHS=(arm64 x86_64)
CORE=(Sources/VPNGateCore/*.swift)
what=${1:-all}

# App sources live in exactly Model/ (unit-tested) and UI/; anything else would be built by one tool and not the other.
bad=$(find Sources/VPNGateMac -mindepth 1 -maxdepth 1 ! -name Model ! -name UI)
[[ -z $bad ]] || { echo "error: Sources/VPNGateMac may only contain Model/ and UI/, found: $bad" >&2; exit 1; }

build_arch() {
  local arch=$1
  local aout="$OUT/$arch"
  local flags=(-swift-version 5 -O -target "${arch}-apple-macos14.0")

  if [[ $what == core || $what == all ]]; then
    swiftc "${flags[@]}" -parse-as-library -emit-library -emit-module -module-name VPNGateCore \
      -static -o "$aout/libVPNGateCore.a" -emit-module-path "$aout/VPNGateCore.swiftmodule" "${CORE[@]}"
  fi
  if [[ $what == helper || $what == all ]]; then
    swiftc "${flags[@]}" -I "$aout" -o "$aout/vpngate-helper" Sources/vpngate-helper/*.swift "$aout/libVPNGateCore.a"
  fi
  if [[ $what == app || $what == all ]]; then
    swiftc "${flags[@]}" -I "$aout" -parse-as-library -o "$aout/VPNGateMac" Sources/VPNGateMac/*/*.swift "$aout/libVPNGateCore.a"
  fi
}

for arch in "${ARCHS[@]}"; do
  build_arch "$arch"
done

# Create fat universal binaries using lipo
cp -f "$OUT/arm64/VPNGateCore.swiftmodule" "$OUT/VPNGateCore.swiftmodule"
if [[ $what == core || $what == all ]]; then
  lipo -create -output "$OUT/libVPNGateCore.a" "$OUT/arm64/libVPNGateCore.a" "$OUT/x86_64/libVPNGateCore.a"
fi
if [[ $what == helper || $what == all ]]; then
  lipo -create -output "$OUT/vpngate-helper" "$OUT/arm64/vpngate-helper" "$OUT/x86_64/vpngate-helper"
fi
if [[ $what == app || $what == all ]]; then
  lipo -create -output "$OUT/VPNGateMac" "$OUT/arm64/VPNGateMac" "$OUT/x86_64/VPNGateMac"
fi
