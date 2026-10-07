#!/bin/bash
# End-to-end tunnel test. Needs root (utun, routes, DNS) and network. Run:  sudo scripts/e2e-tunnel.sh <server-ip> [port]
# Checks that traffic really goes through the VPN and that SIGINT, SIGTERM and kill -9 + restart all leave the
# routing table and DNS exactly as they were.
set -uo pipefail
cd "$(dirname "$0")/.."
[[ $EUID == 0 ]] || { echo "run with sudo"; exit 2; }
SERVER=${1:?usage: sudo scripts/e2e-tunnel.sh <server-ip> [port]}
PORT=${2:-}
HELPER=build/bin/vpngate-helper
[[ -x $HELPER ]] || scripts/build.sh all >/dev/null
FAILS=0
ok()   { echo "  ok   $*"; }
bad()  { echo "  FAIL $*"; FAILS=$((FAILS+1)); }
# ARP/neighbour cache entries (lines with a MAC address) change on their own and are not routes we manage.
snap() { { netstat -rn -f inet; netstat -rn -f inet6; scutil --dns; } 2>/dev/null | grep -v -E "utun|Expire|Refs|Use |([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}" | sed -E 's/ +/ /g' | sort; }
pubip() { curl -4 -s -m 10 https://api.ipify.org || echo "?"; }
wait_for() { for _ in $(seq 1 40); do grep -q "$1" /tmp/vpngate-e2e.log 2>/dev/null && return 0; sleep 0.5; done; return 1; }

BASE_IP=$(pubip); snap > /tmp/vpngate-e2e.before
echo "baseline public IPv4: $BASE_IP"
# a loopback route that teardown must never touch (regression guard for the bypass-route bug)
LO_BEFORE=$(netstat -rn -f inet | grep -c "^127")

run_case() {   # $1 = how to stop: INT | TERM | KILL
  echo "== connect, then stop with $1"
  : > /tmp/vpngate-e2e.log
  $HELPER --connect "$SERVER" ${PORT:+--port $PORT} > /tmp/vpngate-e2e.log 2>&1 &
  PID=$!
  if ! wait_for "\[connected\]"; then bad "never connected"; cat /tmp/vpngate-e2e.log; kill -9 $PID 2>/dev/null; return; fi
  ok "connected: $(grep '\[connected\]' /tmp/vpngate-e2e.log | head -1)"
  sleep 2
  VIA=$(pubip)
  [[ $VIA == "$SERVER" || ( $VIA != "$BASE_IP" && $VIA != "?" ) ]] && ok "public IPv4 through the tunnel: $VIA" || bad "public IPv4 unchanged ($VIA)"
  # Capture first: with pipefail, `cmd | grep -q` fails when grep exits early and cmd gets SIGPIPE.
  ROUTES=$(netstat -rn -f inet)
  grep -q "^0/1" <<< "$ROUTES" && grep -q "^128.0/1" <<< "$ROUTES" && ok "0/1 and 128.0/1 routes present" || bad "default-capture routes missing"
  V6=$(curl -6 -s -m 5 https://api64.ipify.org 2>&1)
  if [[ $V6 == *:* ]]; then
    bad "IPv6 reachable while connected (leak): $V6"
    echo "    inet6 routes into the tunnel:"; netstat -rn -f inet6 | grep -E "^(::/1|8000::/1|0|8000)" | sed 's/^/      /'
    echo "    helper log:"; grep -i -E "route|inet6" /tmp/vpngate-e2e.log | sed 's/^/      /'
  else ok "IPv6 blocked"; fi
  VPNDNS=$(grep -o 'gateway [0-9.]*' /tmp/vpngate-e2e.log | head -1 | awk '{print $2}')
  DNSCONF=$(scutil --dns)
  FIRST_NS=$(grep -m1 "nameserver\[0\]" <<< "$DNSCONF" | awk '{print $3}')
  if [[ -n $VPNDNS && $FIRST_NS == "$VPNDNS" ]]; then ok "VPN resolver ($VPNDNS) is the primary resolver"
  else
    bad "primary resolver is ${FIRST_NS:-none}, expected the VPN's ${VPNDNS:-?}"
    if [[ ${DIAG_DONE:-0} == 0 ]]; then
      DIAG_DONE=1
      echo "    --- diagnostics (shown once) ---"
      echo "    helper output:"; sed 's/^/      /' /tmp/vpngate-e2e.log
      echo "    our keys in the dynamic store:"
      printf 'show State:/Network/Service/VPNGateMac/IPv4\nshow State:/Network/Service/VPNGateMac/DNS\nquit\n' | scutil | sed 's/^/      /'
      echo "    primary service / interface:"
      printf 'show State:/Network/Global/IPv4\nquit\n' | scutil | sed 's/^/      /'
      echo "    scutil --nwi:"; scutil --nwi 2>&1 | head -25 | sed 's/^/      /'
      echo "    scutil --dns (first 40 lines):"; scutil --dns 2>&1 | head -40 | sed 's/^/      /'
      echo "    ---"
    fi
  fi
  dig +short +time=3 example.com >/dev/null 2>&1 && ok "DNS resolves through the tunnel" || bad "DNS lookup failed"
  case $1 in
    INT) kill -INT $PID ;; TERM) kill -TERM $PID ;; KILL) kill -9 $PID ;;
  esac
  wait $PID 2>/dev/null
  if [[ $1 == KILL ]]; then
    echo "  (helper killed hard; stale state must be cleaned by the next start)"
    ls /var/run/vpngate-mac.state >/dev/null 2>&1 && ok "state file left for recovery" || bad "no state file after kill -9"
    $HELPER --daemon --uid "$(id -u ${SUDO_USER:-root})" > /tmp/vpngate-e2e-daemon.log 2>&1 & DPID=$!
    sleep 2; kill -TERM $DPID 2>/dev/null; wait $DPID 2>/dev/null
  fi
  sleep 1
  snap > /tmp/vpngate-e2e.after
  if diff -q /tmp/vpngate-e2e.before /tmp/vpngate-e2e.after >/dev/null; then ok "routes and DNS restored exactly"
  else bad "routing/DNS differ after $1:"; diff /tmp/vpngate-e2e.before /tmp/vpngate-e2e.after | head -20; fi
  [[ $(netstat -rn -f inet | grep -c "^127") == "$LO_BEFORE" ]] && ok "loopback routes intact" || bad "loopback routes changed"
  [[ $(pubip) == "$BASE_IP" ]] && ok "public IPv4 back to $BASE_IP" || bad "public IPv4 did not return to baseline"
}

run_case INT
run_case TERM
run_case KILL
echo
[[ $FAILS == 0 ]] && echo "E2E PASSED" || echo "E2E FAILED ($FAILS)"
exit $((FAILS>0))
