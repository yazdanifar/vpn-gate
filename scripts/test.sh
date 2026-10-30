#!/bin/bash
# Compiles and runs the test suite.
#   scripts/test.sh [--tsan|--asan] [--each] [name-substring ...]
# Swift tests cover the macOS app only; the engine and daemon are tested with `cargo test` (make rust-test).
# --each runs every test in its own process (a crashing test is reported, the rest still run).
set -uo pipefail
cd "$(dirname "$0")/.."
SAN=(); EACH=0; PASS=()
for a in "$@"; do
  case $a in
    --tsan) SAN=(-sanitize=thread) ;;
    --asan) SAN=(-sanitize=address) ;;
    --each) EACH=1 ;;
    *) PASS+=("$a") ;;
  esac
done
# Sanitized binaries are several times slower: stretch the harness's waits (Tests/Harness/Harness.swift).
[[ ${#SAN[@]} -gt 0 ]] && export VPNGATE_TEST_SLOWDOWN=4
OUT=build/test; mkdir -p "$OUT"
FLAGS=(-swift-version 5 -Onone -g -target arm64-apple-macos14.0)

compile_app() {
  local SRC=(Tests/Harness/Harness.swift Tests/Support/Shared.swift Tests/Support/CertFixtures.swift Tests/Support/LocalHTTPServer.swift Tests/Support/FakeHelper.swift
       $(ls Tests/App/*.swift | grep -v '/main.swift') Sources/VPNGateMac/Model/*.swift)
  swiftc "${FLAGS[@]}" ${SAN[@]+"${SAN[@]}"} "${SRC[@]}" Tests/App/main.swift -o "$OUT/tests-app" 2> "$OUT/compile-app.log" || {
    grep -E "error:" -A3 "$OUT/compile-app.log" | head -80; echo "APP COMPILE FAILED (full log: $OUT/compile-app.log). Model/ is compiled without UI/: Model code must not use it."; exit 2; }
}
compile_app

rc=0
for BIN in "$OUT/tests-app"; do
  if [[ $EACH == 1 ]]; then
    fails=0; total=0
    while IFS= read -r name; do
      if [[ ${#PASS[@]} -gt 0 ]]; then
        match=0; for f in "${PASS[@]}"; do [[ $name == *$f* ]] && match=1; done
        [[ $match == 0 ]] && continue
      fi
      total=$((total+1))
      out=$("$BIN" --exact "$name" 2>&1); r=$?
      if [[ $r != 0 ]]; then
        fails=$((fails+1)); echo "FAIL $name (exit $r)"
        echo "$out" | grep -E "^    |Fatal error|WARNING: ThreadSanitizer|ERROR: AddressSanitizer|Crash|Illegal|Trace" | head -6
      else echo "PASS $name"; fi
    done < <("$BIN" --list)
    echo; echo "$(basename "$BIN"): $((total-fails)) passed, $fails failed (isolated runs)"
    [[ $fails == 0 ]] || rc=1
  else
    "$BIN" ${PASS[@]+"${PASS[@]}"} || rc=1
  fi
done
exit $rc
