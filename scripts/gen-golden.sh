#!/bin/bash
# Regenerates the golden vectors in Tests/Fixtures/golden/ from the Swift implementation.
#   scripts/gen-golden.sh
# The Rust, C# and Kotlin ports must reproduce these byte for byte. Commit the result when the Swift behaviour
# changed on purpose; Tests/Unit/GoldenTests.swift fails when the committed files are stale.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=build/golden; mkdir -p "$OUT"
FLAGS=(-swift-version 5 -Onone -g -target arm64-apple-macos14.0)
swiftc "${FLAGS[@]}" -parse-as-library -emit-library -static -emit-module -module-name VPNGateCore \
  Sources/VPNGateCore/*.swift -o "$OUT/libVPNGateCore.a" -emit-module-path "$OUT/VPNGateCore.swiftmodule" 2> "$OUT/compile-core.log" || {
  grep -E "error:" -A3 "$OUT/compile-core.log" | head -40; echo "CORE COMPILE FAILED"; exit 2; }
swiftc "${FLAGS[@]}" -I "$OUT" Tests/Golden/Export.swift Tests/Golden/main.swift "$OUT/libVPNGateCore.a" -o "$OUT/gen-golden" 2> "$OUT/compile.log" || {
  grep -E "error:" -A3 "$OUT/compile.log" | head -40; echo "EXPORTER COMPILE FAILED"; exit 2; }
"$OUT/gen-golden" Tests/Fixtures Tests/Fixtures/golden
