#!/bin/bash
# Full-tunnel test on Linux against a real SoftEther server (the official container), with the daemon in a network
# namespace so the runner's own routes and DNS are never touched. Needs root and docker. Run:  sudo scripts/test-tunnel-netns.sh
#
#   namespace vgtest (10.200.0.2) --veth-- host (10.200.0.1) --docker0-- container (SoftEther, SecureNAT)
#
# The daemon connects to 10.200.0.1:443 (the published container port), captures 0.0.0.0/1 and 128.0.0.0/1 inside the
# namespace and must reach a web server on the docker0 address *through* SecureNAT: the server then sees the
# container's address, not the namespace's. SIGINT, SIGTERM and kill -9 + restart must leave routes, rules and
# resolv.conf of the namespace exactly as they were.
set -uo pipefail
cd "$(dirname "$0")/.."
[[ $EUID == 0 ]] || { echo "run with sudo"; exit 2; }
DAEMON=${VPNGATE_DAEMON:-target/release/vpngate-daemon}
[[ -x $DAEMON ]] || { echo "$DAEMON not found: cargo build --release -p vpngate-daemon"; exit 2; }
NS=vgtest HOST_IP=10.200.0.1 NS_IP=10.200.0.2
CONTAINER=vgtest-softether
WEB_PORT=8080
LOG=/tmp/vpngate-netns.log
WEB_LOG=/tmp/vpngate-netns-web.log
FAILS=0
ok()   { echo "  ok   $*"; }
bad()  { echo "  FAIL $*"; FAILS=$((FAILS+1)); }
nsx()  { ip netns exec "$NS" "$@"; }

cleanup() {
  [[ -n ${WEB_PID:-} ]] && kill "$WEB_PID" 2>/dev/null
  pkill -f "$DAEMON --connect $HOST_IP" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  ip link del vg-host 2>/dev/null
  rm -rf "/etc/netns/$NS"
  docker logs "$CONTAINER" > /tmp/vpngate-netns-softether.log 2>&1
  docker rm -f "$CONTAINER" >/dev/null 2>&1
}
trap cleanup EXIT

echo "== SoftEther server"
docker rm -f "$CONTAINER" >/dev/null 2>&1
docker run -d --name "$CONTAINER" -p 443:443 softethervpn/vpnserver:stable >/dev/null || { echo "cannot start the container"; exit 2; }
VPNCMD=$(docker exec "$CONTAINER" sh -c 'command -v vpncmd || find / -name vpncmd -type f 2>/dev/null | head -1')
[[ -n $VPNCMD ]] || { echo "vpncmd not found in the image"; exit 2; }
# The image sets no admin password (the server password is blank). stdin is /dev/null and a timeout bounds each call,
# because vpncmd prompts forever when it is unhappy.
vpncmd() { timeout 30 docker exec "$CONTAINER" "$VPNCMD" localhost /SERVER /PASSWORD: "$@" </dev/null; }
for _ in $(seq 1 60); do vpncmd /CMD ServerStatusGet >/dev/null 2>&1 && break; sleep 1; done
vpncmd /CMD ServerStatusGet || { echo "server did not come up"; docker logs "$CONTAINER"; exit 2; }
vpncmd /CMD HubCreate VPNGATE /PASSWORD:hubpw || { echo "HubCreate failed"; exit 2; }
for c in "SecureNatEnable" "UserCreate vpn /GROUP:none /REALNAME:none /NOTE:none" "UserAnonymousSet vpn"; do
  # shellcheck disable=SC2086   # $c is a command line to split
  vpncmd /HUB:VPNGATE /CMD $c || { echo "vpncmd $c failed"; exit 2; }
done
DOCKER_GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
echo "server ready; docker0 address $DOCKER_GW"

echo "== namespace and web server"
ip netns add "$NS"
ip link add vg-host type veth peer name vg-ns
ip link set vg-ns netns "$NS"
ip addr add "$HOST_IP/24" dev vg-host && ip link set vg-host up
nsx ip addr add "$NS_IP/24" dev vg-ns
nsx ip link set vg-ns up; nsx ip link set lo up
nsx ip route add default via "$HOST_IP"
mkdir -p "/etc/netns/$NS" && echo "nameserver $HOST_IP" > "/etc/netns/$NS/resolv.conf"
python3 -m http.server "$WEB_PORT" --bind 0.0.0.0 -d /tmp > "$WEB_LOG" 2>&1 &
WEB_PID=$!
sleep 1

# Routes, rules and the namespace's resolv.conf without the volatile parts.
snap() {
  { nsx ip -4 route show table all; nsx ip -6 route show table all; nsx ip -4 rule show; nsx ip -6 rule show
    nsx cat /etc/resolv.conf
  } 2>/dev/null | grep -v -E "^(broadcast|local|multicast|anycast) |tun[0-9]*|vpngate|expires|fe80::" | sed -E 's/ +/ /g; s/ (pref|metric) [0-9]+//' | sort
}
# The namespace has no systemd-resolved: mask its sockets so `resolvectl` cannot touch the host's links, whose
# interface indexes differ from the namespace's. The daemon then takes its resolv.conf fallback.
in_ns() { nsx bash -c 'mount -t tmpfs tmpfs /run/dbus 2>/dev/null; mount -t tmpfs tmpfs /run/systemd/resolve 2>/dev/null; exec "$@"' _ "$@"; }
web_source() {   # who the web server saw for the request named $1
  sleep 1; grep "GET /$1 " "$WEB_LOG" | tail -1 | awk '{print $1}'
}

curl_ns() { nsx curl -s -m 10 -o /dev/null "http://$DOCKER_GW:$WEB_PORT/$1"; }
snap > /tmp/vpngate-netns.before
curl_ns control && [[ $(web_source control) == "$NS_IP" ]] && ok "control: without the tunnel the server sees $NS_IP" || bad "control request failed (saw '$(web_source control)')"

run_case() {   # $1 = how to stop: INT | TERM | KILL
  echo "== connect, then stop with $1"
  : > "$LOG"
  in_ns "$DAEMON" --connect "$HOST_IP" --port 443 > "$LOG" 2>&1 &
  PID=$!
  for _ in $(seq 1 60); do grep -q "\[connected\]" "$LOG" && break; kill -0 $PID 2>/dev/null || break; sleep 0.5; done
  if ! grep -q "\[connected\]" "$LOG"; then bad "never connected"; cat "$LOG"; kill -9 $PID 2>/dev/null; return; fi
  ok "connected: $(grep '\[connected\]' "$LOG" | head -1)"
  sleep 2
  ROUTES=$(nsx ip -4 route show)
  grep -q "^0.0.0.0/1 " <<< "$ROUTES" && grep -q "^128.0.0.0/1 " <<< "$ROUTES" && ok "0.0.0.0/1 and 128.0.0.0/1 routes present" || { bad "default-capture routes missing"; echo "$ROUTES"; }
  if curl_ns "tunnel-$1"; then
    SRC=$(web_source "tunnel-$1")
    [[ -n $SRC && $SRC != "$NS_IP" ]] && ok "traffic goes through the tunnel (the server saw $SRC)" || bad "server saw '$SRC', not the SecureNAT address"
  else bad "request through the tunnel failed"; fi
  FIRST_NS=$(nsx grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
  [[ -n $FIRST_NS && $FIRST_NS != "$HOST_IP" ]] && ok "resolv.conf points at the VPN resolver ($FIRST_NS)" || bad "resolv.conf still has '$FIRST_NS'"
  case $1 in
    INT) kill -INT $PID ;; TERM) kill -TERM $PID ;; KILL) kill -9 $PID ;;
  esac
  wait $PID 2>/dev/null
  if [[ $1 == KILL ]]; then
    echo "  (daemon killed hard; stale state must be cleaned by the next start)"
    [[ -s /run/vpngate.state ]] && ok "state file left for recovery" || bad "no state file after kill -9"
    in_ns "$DAEMON" --daemon --socket /tmp/vpngate-netns.sock --uid 0 > /tmp/vpngate-netns-daemon.log 2>&1 & DPID=$!
    sleep 2; kill -TERM $DPID 2>/dev/null; wait $DPID 2>/dev/null
  fi
  sleep 1
  snap > /tmp/vpngate-netns.after
  if diff -q /tmp/vpngate-netns.before /tmp/vpngate-netns.after >/dev/null; then ok "routes, rules and resolv.conf restored exactly"
  else bad "routing/DNS differ after $1:"; diff /tmp/vpngate-netns.before /tmp/vpngate-netns.after | head -20; fi
  curl_ns "after-$1" && [[ $(web_source "after-$1") == "$NS_IP" ]] && ok "traffic is direct again" || bad "traffic did not return to the direct path"
}

run_case INT
run_case TERM
run_case KILL
echo
[[ $FAILS == 0 ]] && echo "NETNS E2E PASSED" || echo "NETNS E2E FAILED ($FAILS)"
exit $((FAILS>0))
