#!/bin/bash
# Runs the Rust workspace tests under cargo-llvm-cov and fails if a per-file line-coverage threshold is missed.
# Same thresholds as the Swift scripts/coverage.sh: core >= 90%, client, bridge, session, netconfig and ipc >= 80%
# (session is held at 75% until its gap is closed, see docs/cross-platform/STATUS.md U15a).
#   scripts/coverage-rs.sh            needs: cargo install cargo-llvm-cov --locked  (and the llvm-tools-preview component)
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=target/coverage; mkdir -p "$OUT"
cargo llvm-cov --workspace --locked --json --summary-only --output-path "$OUT/coverage.json" || exit 1
python3 -I - "$OUT/coverage.json" <<'PY'
import json, sys
rows = {}
for f in json.load(open(sys.argv[1]))["data"][0]["files"]:
    rows[f["filename"].split("/crates/")[-1]] = f["summary"]["lines"]["percent"]
core = [f"vpngate-core/src/{n}.rs" for n in (
    "pack packets server_list byte_buffer http_head data_phase validation server_filter "
    "rc4 sha0 cert_pin vgdat routing_rule client_account udp_accel").split()]
engine = {
    "vpngate-net/src/softether_client.rs": 80,   # client
    "vpngate-net/src/ethernet_bridge.rs": 80,    # bridge
    "vpngate-net/src/session.rs": 75,            # session (target 80)
    "vpngate-platform/src/macos/net_config.rs": 80,  # netconfig
    "vpngate-daemon/src/ipc_server.rs": 80,      # ipc
    "vpngate-core/src/ipc.rs": 80,
}
bad = [(f, rows.get(f), 90) for f in core if rows.get(f, 0) < 90]
bad += [(f, rows.get(f), t) for f, t in engine.items() if rows.get(f, 0) < t]
for f, c, t in bad:
    print(f"BELOW THRESHOLD {f}: {c}% < {t}%")
print("coverage thresholds:", "FAILED" if bad else "OK")
sys.exit(1 if bad else 0)
PY
