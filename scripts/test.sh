#!/bin/bash
# Compiles and runs the test suite.
#   scripts/test.sh [--tsan|--asan] [--live] [--each] [--list] [name-substring ...]
# --each runs every test in its own process (a crashing test is reported, the rest still run).
set -uo pipefail
cd "$(dirname "$0")/.."
SAN=(); COV=0; EACH=0; PASS=()
for a in "$@"; do
  case $a in
    --tsan) SAN=(-sanitize=thread) ;;
    --asan) SAN=(-sanitize=address) ;;
    --coverage) COV=1 ;;
    --each) EACH=1 ;;
    *) PASS+=("$a") ;;
  esac
done
OUT=build/test; mkdir -p "$OUT"
# The daemon test runs the real helper binary: rebuild it when any source is newer.
if [[ ! -x build/bin/vpngate-helper ]] || [[ -n $(find Sources -name '*.swift' -newer build/bin/vpngate-helper | head -1) ]]; then
  scripts/build.sh all > "$OUT/build-all.log" 2>&1 || { grep -E "error:" -A3 "$OUT/build-all.log" | head -30; echo "HELPER BUILD FAILED"; exit 2; }
fi
BIN="$OUT/tests"
FLAGS=(-swift-version 5 -Onone -g -target arm64-apple-macos14.0)
[[ $COV == 1 ]] && FLAGS+=(-profile-generate -profile-coverage-mapping)
CORE_FLAGS=(-swift-version 5 -Onone -g -target arm64-apple-macos14.0 -parse-as-library -emit-library -static -emit-module -module-name VPNGateCore)
[[ $COV == 1 ]] && CORE_FLAGS+=(-profile-generate -profile-coverage-mapping)
swiftc "${CORE_FLAGS[@]}" ${SAN[@]+"${SAN[@]}"} Sources/VPNGateCore/*.swift -o "$OUT/libVPNGateCore.a" \
  -emit-module-path "$OUT/VPNGateCore.swiftmodule" 2> "$OUT/compile-core.log" || {
  grep -E "error:" -A3 "$OUT/compile-core.log" | head -40; echo "CORE COMPILE FAILED"; exit 2; }
SRC=(Tests/Harness/Harness.swift Tests/Support/*.swift Tests/Unit/*.swift Tests/Behaviour/*.swift
     Tests/Fuzz/*.swift Tests/Live/*.swift
     $(ls Sources/vpngate-helper/*.swift | grep -v '/main.swift')
     Sources/VPNGateMac/HelperClient.swift Sources/VPNGateMac/HelperInstaller.swift
     Sources/VPNGateMac/AppModel.swift Sources/VPNGateMac/Keychain.swift)
# main.swift must be the only top-level-code file
swiftc "${FLAGS[@]}" ${SAN[@]+"${SAN[@]}"} -I "$OUT" "${SRC[@]}" Tests/Harness/main.swift "$OUT/libVPNGateCore.a" -o "$BIN" 2> "$OUT/compile.log" || {
  grep -E "error:" -A3 "$OUT/compile.log" | head -80; echo "COMPILE FAILED (full log: $OUT/compile.log)"; exit 2; }
export LLVM_PROFILE_FILE="$PWD/$OUT/cov-%p.profraw"
if [[ $EACH == 1 ]]; then
  fails=0; total=0
  while IFS= read -r name; do
    if [[ ${#PASS[@]} -gt 0 ]]; then
      match=0; for f in "${PASS[@]}"; do [[ $name == *$f* ]] && match=1; done
      [[ $match == 0 ]] && continue
    fi
    total=$((total+1))
    out=$("$BIN" --exact "$name" 2>&1); rc=$?
    if [[ $rc != 0 ]]; then
      fails=$((fails+1)); echo "FAIL $name (exit $rc)"
      echo "$out" | grep -E "^    |Fatal error|WARNING: ThreadSanitizer|ERROR: AddressSanitizer|Crash|Illegal|Trace" | head -6
    else echo "PASS $name"; fi
  done < <("$BIN" --list)
  echo; echo "$((total-fails)) passed, $fails failed (isolated runs)"
  [[ $fails == 0 ]]
else
  "$BIN" ${PASS[@]+"${PASS[@]}"}
fi
