#!/bin/bash
# "Test Connection" against real relays from the emulator (ProbeLiveTest), run from apps/android inside
# android-emulator-runner's booted emulator. Needs the internet; used by the Test Connection workflow only.
set -uo pipefail
OUT=${OUT_DIR:-/tmp/android-probe-logs}
PKG=com.yazdanifar.vpngate
mkdir -p "$OUT"
./gradlew --no-daemon -q :app:installDebug :app:installDebugAndroidTest || { echo "install failed"; exit 2; }
adb shell pm grant $PKG android.permission.POST_NOTIFICATIONS
adb shell am instrument -w -r -e class "$PKG.app.ProbeLiveTest" -e liveRelays true -e liveCount "${LIVE_COUNT:-24}" \
  "$PKG.test/androidx.test.runner.AndroidJUnitRunner" > "$OUT/instrument.txt" 2>&1
adb logcat -d -s ProbeLive > "$OUT/probe-live.txt" 2>&1
adb logcat -d > "$OUT/logcat.txt" 2>&1
echo "== Test Connection from Android"
cat "$OUT/probe-live.txt"
# `am instrument` exits 0 whatever happens: pass only with exactly one passed test, no failure or skip, and a clean end.
passed=$(grep -cE '^INSTRUMENTATION_STATUS_CODE: 0\s*$' "$OUT/instrument.txt")
if grep -qE '^INSTRUMENTATION_STATUS_CODE: -[1234]\s*$' "$OUT/instrument.txt" || [[ $passed != 1 ]] ||
   ! grep -qE '^INSTRUMENTATION_CODE: -1\s*$' "$OUT/instrument.txt"; then
  echo "FAILED"; grep -A40 -E 'INSTRUMENTATION_STATUS: stack=' "$OUT/instrument.txt" | head -60
  exit 1
fi
echo "PASSED"
