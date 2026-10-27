#!/bin/bash
# Probes a random sample of real relays (handshake + DHCP, no root, no routes) and prints the pass rate per server
# build. Relays come from the CSV snapshot of the signed list, never from hard-coded addresses.
#   scripts/probe-sample.sh [count] [csv]
# The per-build split shows whether relays that need the Windows client's "knock" (builds above 9074) refuse us.
set -u
cd "$(dirname "$0")/.."
COUNT="${1:-20}"
CSV="${2:-docs/research/VPNGate_dat_hosts.csv}"
HELPER=build/bin/vpngate-helper   # the Rust daemon (scripts/build.sh helper)
TO=$(command -v timeout || command -v gtimeout || true)
[ -x "$HELPER" ] || { echo "build first: scripts/build.sh all" >&2; exit 2; }

# columns: IP(1) ... SslPorts(10) ... Build(16); take the first SSL port of rows that have one.
rows=$(awk -F, 'NR>1 && $10!="" {split($10,p," "); print $1, p[1], $16}' "$CSV" | sort -R | head -n "$COUNT")
[ -n "$rows" ] || { echo "no relays in $CSV" >&2; exit 2; }

results=$(mktemp); trap 'rm -f "$results"' EXIT
while read -r ip port build; do
  if ${TO:+$TO 40} "$HELPER" --probe "$ip" --port "$port" >/dev/null 2>&1; then r=ok; else r=fail; fi
  echo "$ip:$port build=$build $r"
  echo "$build $r" >>"$results"
done <<<"$rows"

echo; echo "== pass rate by server build =="
awk '{t[$1]++; if ($2=="ok") o[$1]++} END {for (b in t) printf "build %s: %d/%d\n", b, o[b], t[b]}' "$results" | sort
awk '{t++; if ($2=="ok") o++} END {printf "total: %d/%d\n", o, t}' "$results"
# Informational: relays come and go, so a low rate must not fail the workflow unless nothing at all worked.
grep -q ' ok$' "$results"
