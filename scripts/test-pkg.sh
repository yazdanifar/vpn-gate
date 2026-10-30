#!/bin/bash
# Smoke test of "build/VPN Gate.pkg" on a disposable macOS machine (CI runner with passwordless sudo): install, files,
# the LaunchDaemon, IPC over the helper socket, KeepAlive restart after a kill, reinstall over a running helper, and the
# removal of everything it put there. Do NOT run on a machine you care about (it installs a privileged helper).
set -uo pipefail
cd "$(dirname "$0")/.."
PKG=${1:-build/VPN Gate.pkg}
LABEL=com.yazdanifar.vpngate.helper
HELPER=/Library/PrivilegedHelperTools/vpngate-helper
PLIST=/Library/LaunchDaemons/$LABEL.plist
APP="/Applications/VPN Gate.app"
SOCK=/var/run/vpngate-mac.sock
FAILS=0
ok()  { echo "ok: $*"; }
bad() { echo "FAILED: $*"; FAILS=$((FAILS+1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
wait_for() { local what=$1; shift; for _ in $(seq 1 60); do "$@" >/dev/null 2>&1 && { ok "$what"; return; }; sleep 1; done; bad "(timeout) $what"; }
helper_pid() { sudo launchctl print "system/$LABEL" 2>/dev/null | awk '/^[[:space:]]*pid = /{print $3; exit}'; }
status() {
  sudo python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
s.connect("/var/run/vpngate-mac.sock")
s.sendall(b'{"cmd":"status"}\n')
line = s.makefile().readline().replace(' ', '')
print(line.strip())
sys.exit(0 if '"state":"disconnected"' in line and '"ipcVersion":9' in line else 1)
PY
}

sudo installer -pkg "$PKG" -target / || { echo "install failed"; exit 1; }

for f in "$APP/Contents/MacOS/VPNGateMac" "$APP/Contents/Resources/VPNGate.dat" "$APP/Contents/Resources/VPN Gate Helper.pkg" "$HELPER" "$PLIST"; do
  check "installed $f" test -e "$f"
done
check "helper is owned by root:wheel" bash -c "[ \"\$(stat -f '%Su:%Sg' '$HELPER')\" = root:wheel ]"
check "plist is a valid property list" plutil -lint "$PLIST"
check "app bundle signature is intact" codesign --verify --deep "$APP"
wait_for "launchd job is running" bash -c "$(declare -f helper_pid); LABEL=$LABEL; p=\$(helper_pid); [ -n \"\$p\" ] && [ \"\$p\" != 0 ]"
wait_for "socket answers status (disconnected, ipcVersion 9)" bash -c "$(declare -f status); status"

# KeepAlive: a hard kill must bring the helper back as a new process that answers again.
PID1=$(helper_pid)
sudo kill -9 "$PID1"
wait_for "helper restarted with a new process" bash -c "$(declare -f helper_pid); LABEL=$LABEL; p=\$(helper_pid); [ -n \"\$p\" ] && [ \"\$p\" != 0 ] && [ \"\$p\" != $PID1 ]"
wait_for "socket answers again after the restart" bash -c "$(declare -f status); status"

# Reinstall over a running helper (what an update does): preinstall boots the old job out, postinstall starts a new one.
PID2=$(helper_pid)
sudo installer -pkg "$PKG" -target / >/dev/null || bad "reinstall failed"
wait_for "reinstall started a new helper process" bash -c "$(declare -f helper_pid); LABEL=$LABEL; p=\$(helper_pid); [ -n \"\$p\" ] && [ \"\$p\" != 0 ] && [ \"\$p\" != $PID2 ]"
wait_for "socket answers after the reinstall" bash -c "$(declare -f status); status"
check "exactly one job is loaded" bash -c "[ \$(sudo launchctl list | grep -c $LABEL) = 1 ]"

# There is no uninstaller yet: remove what the pkg installed the way a user would by hand, and check nothing keeps running.
sudo launchctl bootout "system/$LABEL"
sudo rm -rf "$APP" "$HELPER" "$PLIST"
check "job is gone after bootout" bash -c "! sudo launchctl print system/$LABEL"
wait_for "socket is gone" test ! -e "$SOCK"
check "no helper process left" bash -c "! pgrep -f vpngate-helper"

[ "$FAILS" = 0 ] && echo "PKG TEST PASSED" || echo "PKG TEST FAILED ($FAILS)"
exit $((FAILS>0))
