#!/bin/bash
# The Android emulator tests of CI (U35), run from apps/android inside android-emulator-runner's booted emulator.
#
#   emulator --10.0.2.2--> runner:443 --docker--> SoftEther container (hub VPNGATE, anonymous user "vpn", SecureNAT)
#   emulator --172.17.0.1:8080--> runner's web server (answers with the caller's address)
#
# Phases: (1) smoke, manifest and the VPN consent dialog, (2) connect/always-on/airplane against the container,
# (3) the real process death: kill -9 the app and see the system restart the sticky VPN service, which reconnects.
# The container setup mirrors scripts/test-tunnel-netns.sh. Logs go to $OUT.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT_DIR:-/tmp/android-emulator-logs}
PKG=com.yazdanifar.vpngate
RUNNER=$PKG.test/androidx.test.runner.AndroidJUnitRunner
T=$PKG.app
CONTAINER=vpngate-android-softether
WEB_PORT=8080
FAILS=0
mkdir -p "$OUT"
ok()  { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAILS=$((FAILS+1)); }

cleanup() {
  adb logcat -d > "$OUT/logcat.txt" 2>&1
  [[ -n ${WEB_PID:-} ]] && kill "$WEB_PID" 2>/dev/null
  docker logs "$CONTAINER" > "$OUT/softether.log" 2>&1
  docker rm -f "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

echo "== SoftEther server on the runner"
docker rm -f "$CONTAINER" >/dev/null 2>&1
docker run -d --name "$CONTAINER" -p 443:443 softethervpn/vpnserver:stable >/dev/null || { echo "cannot start the container"; exit 2; }
VPNCMD=$(docker exec "$CONTAINER" sh -c 'command -v vpncmd || find / -name vpncmd -type f 2>/dev/null | head -1')
[[ -n $VPNCMD ]] || { echo "vpncmd not found in the image"; exit 2; }
vpncmd() { timeout 30 docker exec "$CONTAINER" "$VPNCMD" localhost /SERVER /PASSWORD: "$@" </dev/null; }
for _ in $(seq 1 60); do vpncmd /CMD ServerStatusGet >/dev/null 2>&1 && break; sleep 1; done
vpncmd /CMD ServerStatusGet >/dev/null || { echo "server did not come up"; docker logs "$CONTAINER"; exit 2; }
vpncmd /CMD HubCreate VPNGATE /PASSWORD:hubpw >/dev/null || { echo "HubCreate failed"; exit 2; }
for c in "SecureNatEnable" "UserCreate vpn /GROUP:none /REALNAME:none /NOTE:none" "UserAnonymousSet vpn"; do
  # shellcheck disable=SC2086   # $c is a command line to split
  vpncmd /ADMINHUB:VPNGATE /CMD $c >/dev/null || { echo "vpncmd $c failed"; exit 2; }
done
DOCKER_GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
python3 "$ROOT/scripts/ci-web-peer.py" "$WEB_PORT" > "$OUT/web.log" 2>&1 &
WEB_PID=$!
sleep 1
WEB_URL="http://$DOCKER_GW:$WEB_PORT/"
echo "server ready; docker0 address $DOCKER_GW; web answer on the host: $(curl -s -m 5 "$WEB_URL")"

echo "== install"
./gradlew --no-daemon -q :app:installDebug :app:installDebugAndroidTest || { echo "install failed"; exit 2; }
adb shell pm grant $PKG android.permission.POST_NOTIFICATIONS

# run_instr NAME CLASSES [am args]: one instrumentation run; `am instrument` exits 0 whatever happens, so read its raw output.
run_instr() {
  local name=$1 classes=$2; shift 2
  echo "== $name"
  adb shell am instrument -w -r -e class "$classes" "$@" "$RUNNER" > "$OUT/$name.txt" 2>&1
  awk '
    /^INSTRUMENTATION_STATUS: class=/ { c=$0; sub(/.*class=/,"",c) }
    /^INSTRUMENTATION_STATUS: test=/  { t=$0; sub(/.*test=/,"",t) }
    /^INSTRUMENTATION_STATUS_CODE:/ {
      if ($2==0) print "  ok   " c "#" t
      else if ($2==-1 || $2==-2) print "  FAIL " c "#" t
      else if ($2==-3 || $2==-4) print "  skip " c "#" t
    }' "$OUT/$name.txt"
  local failed passed
  failed=$(grep -cE '^INSTRUMENTATION_STATUS_CODE: -[12]\s*$' "$OUT/$name.txt")
  passed=$(grep -cE '^INSTRUMENTATION_STATUS_CODE: 0\s*$' "$OUT/$name.txt")
  if [[ $failed != 0 ]] || ! grep -q '^INSTRUMENTATION_CODE: -1' "$OUT/$name.txt" || [[ $passed == 0 ]]; then
    bad "$name ($passed passed, $failed failed)"
    head -150 "$OUT/$name.txt"
    return 1
  fi
  ok "$name ($passed passed)"
}

run_instr smoke-manifest-consent "$T.SmokeTest,$T.ManifestTest,$T.ConsentTest"
run_instr tunnel "$T.TunnelTest" -e hermeticWeb "$WEB_URL" -e hermeticServer 10.0.2.2

echo "== the system restarts the sticky VPN service after the process is killed"
# From the app's own uid (debug build), so the request takes the VPN's path like the app's traffic does.
peer() { adb shell "run-as $PKG sh -c 'printf \"GET / HTTP/1.0\n\n\" | toybox nc -w 5 $DOCKER_GW $WEB_PORT'" 2>/dev/null | tr -d '\r' | tail -1; }
await_peer() {   # $1 = what; waits for an answer that differs from the direct one
  for _ in $(seq 1 90); do
    got=$(peer)
    [[ -n $got && $got != "$DIRECT" ]] && { ok "$1: the web server saw $got (direct: $DIRECT)"; return 0; }
    sleep 2
  done
  bad "$1: no tunnelled answer (last '$got', direct '$DIRECT')"; return 1
}
DIRECT=$(peer)
[[ -n $DIRECT ]] && ok "direct answer from the web server: $DIRECT" || bad "no direct answer from the web server"
adb shell am start-foreground-service -a android.net.VpnService -n $PKG/$T.VpnEngineService
await_peer "always-on start with no UI"
PID=$(adb shell pidof $PKG | tr -d '\r')
echo "killing pid $PID"
adb shell run-as $PKG kill -9 "$PID"
for _ in $(seq 1 30); do
  NEW=$(adb shell pidof $PKG | tr -d '\r'); [[ -n $NEW && $NEW != "$PID" ]] && break; sleep 1
done
[[ -n ${NEW:-} && $NEW != "$PID" ]] && ok "the system restarted the service in a new process ($PID -> $NEW)" || bad "the VPN service was not restarted after kill -9"
await_peer "reconnected after the restart"

adb shell dumpsys activity services $PKG | head -40 > "$OUT/services.txt"
echo
[[ $FAILS == 0 ]] && echo "ANDROID EMULATOR TESTS PASSED" || echo "ANDROID EMULATOR TESTS FAILED ($FAILS)"
exit $((FAILS>0))
