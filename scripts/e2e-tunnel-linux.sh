#!/bin/bash
# End-to-end tunnel test for Linux. Needs root (tun, routes, DNS) and network. Run:  sudo scripts/e2e-tunnel-linux.sh <server-ip> [port]
# Checks that traffic really goes through the VPN and that SIGINT, SIGTERM and kill -9 + restart all leave the routing
# tables, policy rules and DNS exactly as they were. Port of scripts/e2e-tunnel.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
[[ $EUID == 0 ]] || { echo "run with sudo"; exit 2; }
SERVER=${1:?usage: sudo scripts/e2e-tunnel-linux.sh <server-ip> [port]}
PORT=${2:-}
HELPER=${VPNGATE_DAEMON:-$(command -v vpngate-daemon || echo target/release/vpngate-daemon)}
[[ -x $HELPER ]] || cargo build --release -p vpngate-daemon >/dev/null || exit 2
[[ -x $HELPER ]] || HELPER=target/release/vpngate-daemon
LOG=/tmp/vpngate-e2e.log
FAILS=0
ok()   { echo "  ok   $*"; }
bad()  { echo "  FAIL $*"; FAILS=$((FAILS+1)); }
# Neighbour-cache entries change on their own; tunnel routes go away with the interface.
snap() {
  { ip -4 route show table all; ip -6 route show table all; ip -4 rule show; ip -6 rule show
    if command -v resolvectl >/dev/null && systemctl is-active -q systemd-resolved; then resolvectl status; else cat /etc/resolv.conf; fi
  } 2>/dev/null | grep -v -E "^(broadcast|local|multicast|anycast) |tun[0-9]*|vpngate|expires|fe80::|Current Scopes|DNSSEC|Protocols:" | sed -E 's/ +/ /g; s/ (pref|metric) [0-9]+//' | sort
}
pubip() { curl -4 -s -m 10 https://api.ipify.org || echo "?"; }
wait_for() { for _ in $(seq 1 40); do grep -q "$1" $LOG 2>/dev/null && return 0; sleep 0.5; done; return 1; }

BASE_IP=$(pubip); snap > /tmp/vpngate-e2e.before
echo "baseline public IPv4: $BASE_IP"

run_case() {   # $1 = how to stop: INT | TERM | KILL
  echo "== connect, then stop with $1"
  : > $LOG
  $HELPER --connect "$SERVER" ${PORT:+--port $PORT} > $LOG 2>&1 &
  PID=$!
  if ! wait_for "\[connected\]"; then bad "never connected"; cat $LOG; kill -9 $PID 2>/dev/null; return; fi
  ok "connected: $(grep '\[connected\]' $LOG | head -1)"
  sleep 2
  VIA=$(pubip)
  [[ $VIA == "$SERVER" || ( $VIA != "$BASE_IP" && $VIA != "?" ) ]] && ok "public IPv4 through the tunnel: $VIA" || bad "public IPv4 unchanged ($VIA)"
  ROUTES=$(ip -4 route show)
  grep -q "^0.0.0.0/1 " <<< "$ROUTES" && grep -q "^128.0.0.0/1 " <<< "$ROUTES" && ok "0.0.0.0/1 and 128.0.0.0/1 routes present" || bad "default-capture routes missing"
  V6=$(curl -6 -s -m 5 https://api64.ipify.org 2>&1)
  if [[ $V6 == *:* ]]; then
    bad "IPv6 reachable while connected (leak): $V6"
    echo "    inet6 routes:"; ip -6 route show | sed 's/^/      /'
  else ok "IPv6 blocked"; fi
  VPNDNS=$(grep -o 'gateway [0-9.]*' $LOG | head -1 | awk '{print $2}')
  if command -v resolvectl >/dev/null && systemctl is-active -q systemd-resolved; then
    DNSCONF=$(resolvectl dns)
    if [[ -n $VPNDNS ]] && grep -q "$VPNDNS" <<< "$DNSCONF" && [[ $(resolvectl domain | grep -c '~\.') -ge 1 ]]; then ok "VPN resolver ($VPNDNS) set with the ~. routing domain"
    else bad "resolvectl does not show the VPN resolver ${VPNDNS:-?} with ~."; echo "$DNSCONF" | sed 's/^/      /'; fi
  else
    FIRST_NS=$(grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
    [[ -n $VPNDNS && $FIRST_NS == "$VPNDNS" ]] && ok "VPN resolver ($VPNDNS) is first in resolv.conf" || bad "first nameserver is ${FIRST_NS:-none}, expected ${VPNDNS:-?}"
  fi
  (getent hosts example.com || dig +short +time=3 example.com) >/dev/null 2>&1 && ok "DNS resolves through the tunnel" || bad "DNS lookup failed"
  case $1 in
    INT) kill -INT $PID ;; TERM) kill -TERM $PID ;; KILL) kill -9 $PID ;;
  esac
  wait $PID 2>/dev/null
  if [[ $1 == KILL ]]; then
    echo "  (daemon killed hard; stale state must be cleaned by the next start)"
    [[ -s /run/vpngate.state ]] && ok "state file left for recovery" || bad "no state file after kill -9"
    $HELPER --daemon --socket /tmp/vpngate-e2e.sock --uid "$(id -u "${SUDO_USER:-root}")" > /tmp/vpngate-e2e-daemon.log 2>&1 & DPID=$!
    sleep 2; kill -TERM $DPID 2>/dev/null; wait $DPID 2>/dev/null
  fi
  sleep 1
  snap > /tmp/vpngate-e2e.after
  if diff -q /tmp/vpngate-e2e.before /tmp/vpngate-e2e.after >/dev/null; then ok "routes, rules and DNS restored exactly"
  else bad "routing/DNS differ after $1:"; diff /tmp/vpngate-e2e.before /tmp/vpngate-e2e.after | head -20; fi
  [[ $(pubip) == "$BASE_IP" ]] && ok "public IPv4 back to $BASE_IP" || bad "public IPv4 did not return to baseline"
}

run_case INT
run_case TERM
run_case KILL
echo
[[ $FAILS == 0 ]] && echo "E2E PASSED" || echo "E2E FAILED ($FAILS)"
exit $((FAILS>0))
