#!/bin/bash
# Launch test of the real macOS app: starts `build/VPN Gate.app` against a fake helper and clicks through it with the
# accessibility API (Tests/Launch/main.swift). CI only: it needs Accessibility permission for the terminal/runner, a GUI
# session, and it takes over the mouse. On a developer's Mac set VPNGATE_LAUNCH_TEST_OK=1 to run it deliberately.
#   scripts/test-app-launch.sh [--no-build] [name-substring ...]
# Failure evidence (accessibility trees, screenshots) goes to build/launch-test.
set -uo pipefail
cd "$(dirname "$0")/.."
if [ -z "${CI:-}" ] && [ -z "${VPNGATE_LAUNCH_TEST_OK:-}" ]; then
  echo "Refusing to run: this test controls the mouse and keyboard. Set VPNGATE_LAUNCH_TEST_OK=1 to run it here."; exit 2
fi
BUILD=1; PASS=()
for a in "$@"; do case $a in --no-build) BUILD=0 ;; *) PASS+=("$a") ;; esac; done
[ "$BUILD" = 1 ] && { scripts/build-app.sh > build/launch-build.log 2>&1 || { tail -30 build/launch-build.log; echo "APP BUILD FAILED"; exit 2; }; }
if [ -n "${CI:-}" ]; then
  # Fresh profile on the disposable runner, so the disclaimer appears and nothing is left over.
  defaults delete com.yazdanifar.VPNGateMac 2>/dev/null || true
fi
OUT=build/test-launch; mkdir -p "$OUT" build/launch-test
SRC=(Tests/Harness/Harness.swift Tests/Support/Shared.swift Tests/Support/FakeHelper.swift Sources/VPNGateMac/Model/*.swift)
swiftc -swift-version 5 -Onone -g -target arm64-apple-macos14.0 "${SRC[@]}" Tests/Launch/main.swift -o "$OUT/tests-launch" 2> "$OUT/compile.log" || {
  grep -E "error:" -A3 "$OUT/compile.log" | head -80; echo "LAUNCH TEST COMPILE FAILED (full log: $OUT/compile.log)"; exit 2; }
export VPNGATE_APP="$PWD/build/VPN Gate.app" VPNGATE_SHOTS="$PWD/build/launch-test"
"$OUT/tests-launch" ${PASS[@]+"${PASS[@]}"}
