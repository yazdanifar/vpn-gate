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
# The daemon test runs the real daemon (the Rust binary the app installs): rebuild it when any source is newer.
if [[ ! -x build/bin/vpngate-helper ]] || [[ -n $(find crates Cargo.toml Cargo.lock \( -name '*.rs' -o -name Cargo.toml -o -name Cargo.lock \) -newer build/bin/vpngate-helper | head -1) ]]; then
  ARCHS="$(uname -m | sed 's/aarch64/arm64/')" scripts/build.sh helper > "$OUT/build-helper.log" 2>&1 || { tail -30 "$OUT/build-helper.log"; echo "DAEMON BUILD FAILED"; exit 2; }
fi
FLAGS=(-swift-version 5 -Onone -g -target arm64-apple-macos14.0)
[[ $COV == 1 ]] && FLAGS+=(-profile-generate -profile-coverage-mapping)
export LLVM_PROFILE_FILE="$PWD/$OUT/cov-%p.profraw"

# Two binaries: the engine/helper tests link VPNGateCore; the app tests compile Model/ alone (it mirrors the daemon's JSON
# and does not import the engine), so same-named types never meet.
compile_core() {
  CORE_FLAGS=(-swift-version 5 -Onone -g -target arm64-apple-macos14.0 -parse-as-library -emit-library -static -emit-module -module-name VPNGateCore)
  [[ $COV == 1 ]] && CORE_FLAGS+=(-profile-generate -profile-coverage-mapping)
  swiftc "${CORE_FLAGS[@]}" ${SAN[@]+"${SAN[@]}"} Sources/VPNGateCore/*.swift -o "$OUT/libVPNGateCore.a" \
    -emit-module-path "$OUT/VPNGateCore.swiftmodule" 2> "$OUT/compile-core.log" || {
    grep -E "error:" -A3 "$OUT/compile-core.log" | head -40; echo "CORE COMPILE FAILED"; exit 2; }
  local SRC=(Tests/Harness/Harness.swift $(ls Tests/Support/*.swift | grep -v FakeHelper) Tests/Unit/*.swift Tests/Behaviour/*.swift
       Tests/Fuzz/*.swift Tests/Live/*.swift Tests/Golden/Export.swift Tests/Golden/ExportTranscripts.swift
       $(ls Sources/vpngate-helper/*.swift | grep -v '/main.swift'))
  # main.swift must be the only top-level-code file
  swiftc "${FLAGS[@]}" ${SAN[@]+"${SAN[@]}"} -I "$OUT" "${SRC[@]}" Tests/Harness/main.swift "$OUT/libVPNGateCore.a" -o "$OUT/tests" 2> "$OUT/compile.log" || {
    grep -E "error:" -A3 "$OUT/compile.log" | head -80; echo "COMPILE FAILED (full log: $OUT/compile.log)."; exit 2; }
}
compile_app() {
  local SRC=(Tests/Harness/Harness.swift Tests/Support/Shared.swift Tests/Support/CertFixtures.swift Tests/Support/LocalHTTPServer.swift Tests/Support/FakeHelper.swift
       $(ls Tests/App/*.swift | grep -v '/main.swift') Sources/VPNGateMac/Model/*.swift)
  swiftc "${FLAGS[@]}" ${SAN[@]+"${SAN[@]}"} "${SRC[@]}" Tests/App/main.swift -o "$OUT/tests-app" 2> "$OUT/compile-app.log" || {
    grep -E "error:" -A3 "$OUT/compile-app.log" | head -80; echo "APP COMPILE FAILED (full log: $OUT/compile-app.log). Model/ is compiled without UI/ and without VPNGateCore: Model code must not use either."; exit 2; }
}
compile_core; compile_app

rc=0
for BIN in "$OUT/tests" "$OUT/tests-app"; do
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
