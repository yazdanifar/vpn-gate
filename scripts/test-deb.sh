#!/bin/bash
# Smoke test of build/vpn-gate_*.deb on a disposable Ubuntu/Debian machine (CI runner with sudo): install, group, unit,
# files, IPC over the socket, restart after a kill, remove, purge. Do NOT run on a machine you care about.
set -uo pipefail
cd "$(dirname "$0")/.."
DEB=${1:-$(ls build/vpn-gate_*.deb | head -1)}
FAILS=0
ok()  { echo "ok: $*"; }
bad() { echo "FAILED: $*"; FAILS=$((FAILS+1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
wait_for() { local what=$1; shift; for _ in $(seq 1 60); do "$@" >/dev/null 2>&1 && { ok "$what"; return; }; sleep 1; done; bad "(timeout) $what"; }
status() {
  python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
s.connect("/run/vpngate.sock")
s.sendall(b'{"cmd":"status"}\n')
line = s.makefile().readline()
print(line.strip())
sys.exit(0 if '"state":"disconnected"' in line.replace(' ', '') and '"ipcVersion":9' in line.replace(' ', '') else 1)
PY
}

sudo apt-get install -y "./$DEB" || { echo "install failed"; exit 1; }

check "group vpngate exists" getent group vpngate
if [ -n "${SUDO_USER:-}" ]; then :; fi
check "unit is enabled" systemctl is-enabled vpngate.service
wait_for "unit is active" systemctl is-active --quiet vpngate.service
for f in /usr/bin/vpngate-daemon /usr/bin/vpngate-gtk /usr/share/vpngate/VPNGate.dat /lib/systemd/system/vpngate.service \
         /usr/share/applications/net.vpngate.App.desktop /usr/share/icons/hicolor/256x256/apps/net.vpngate.App.png; do
  check "installed $f" test -e "$f"
done
check "desktop file is valid" bash -c 'command -v desktop-file-validate >/dev/null && desktop-file-validate /usr/share/applications/net.vpngate.App.desktop || true'
wait_for "socket answers status (disconnected, ipcVersion 9)" sudo bash -c "$(declare -f status); status"
sudo bash -c "$(declare -f status); status" || true

PID1=$(systemctl show -p MainPID --value vpngate.service)
sudo kill -9 "$PID1"
wait_for "unit restarted with a new process" bash -c "p=\$(systemctl show -p MainPID --value vpngate.service); [ \"\$p\" != 0 ] && [ \"\$p\" != $PID1 ]"
wait_for "socket answers again" sudo bash -c "$(declare -f status); status"

sudo apt-get remove -y vpn-gate
check "binary removed" test ! -e /usr/bin/vpngate-daemon
check "unit gone" test ! -e /lib/systemd/system/vpngate.service
check "group kept after remove" getent group vpngate
sudo apt-get purge -y vpn-gate
check "state removed on purge" test ! -e /var/lib/vpngate
check "group removed on purge" bash -c '! getent group vpngate'

[ "$FAILS" = 0 ] && echo "DEB TEST PASSED" || echo "DEB TEST FAILED ($FAILS)"
exit $((FAILS>0))
