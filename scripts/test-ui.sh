#!/bin/bash
# Screenshot tests of the macOS app's SwiftUI views (Sources/VPNGateMac/UI) against Tests/Fixtures/screenshots/*.png.
#   scripts/test-ui.sh [--record] [name-substring ...]
# --record writes the rendered images as the new goldens instead of comparing. Goldens depend on the OS version and
# font rendering, so record them on the CI runner ("Record screenshot goldens" workflow), not on a developer's Mac.
# Failures leave actual/ and diff/ images in build/screenshots (CI uploads them).
# A separate binary from scripts/test.sh: that one compiles only Sources/VPNGateMac/Model.
set -uo pipefail
cd "$(dirname "$0")/.."
PASS=()
for a in "$@"; do
  case $a in
    --record) export SNAPSHOT_RECORD=1 ;;
    *) PASS+=("$a") ;;
  esac
done
OUT=build/test-ui; mkdir -p "$OUT"
export SNAPSHOT_OUT="${SNAPSHOT_OUT:-$PWD/build/screenshots}"
rm -rf "$SNAPSHOT_OUT"
# VPNGateApp.swift holds @main, which the test binary replaces with Tests/UI/main.swift; it is not rendered.
SRC=(Tests/Harness/Harness.swift Tests/Support/Shared.swift Tests/Support/Snapshot.swift Tests/UI/ScreenshotTests.swift
     Sources/VPNGateMac/Model/*.swift $(ls Sources/VPNGateMac/UI/*.swift | grep -v '/VPNGateApp.swift'))
swiftc -swift-version 5 -Onone -g -target arm64-apple-macos14.0 "${SRC[@]}" Tests/UI/main.swift Tests/UI/Stubs.swift -o "$OUT/tests-ui" 2> "$OUT/compile.log" || {
  grep -E "error:" -A3 "$OUT/compile.log" | head -80; echo "UI COMPILE FAILED (full log: $OUT/compile.log)"; exit 2; }
# Fixed zone (the harness treats every argument as a test filter, so no -AppleLocale; runners are en_US).
TZ=UTC "$OUT/tests-ui" ${PASS[@]+"${PASS[@]}"}
