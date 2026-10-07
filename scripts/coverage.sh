#!/bin/bash
# Builds the tests with coverage instrumentation, runs them, prints llvm-cov per-file line coverage and
# fails if a threshold is missed.  Thresholds (lines): VPNGateCore >= 90%, key helper files >= 80%.
set -uo pipefail
cd "$(dirname "$0")/.."
rm -f build/test/*.profraw build/test/cov.profdata
scripts/test.sh --coverage || exit 1
xcrun llvm-profdata merge -sparse build/test/cov-*.profraw -o build/test/cov.profdata
xcrun llvm-cov report build/test/tests -instr-profile=build/test/cov.profdata \
  -ignore-filename-regex='Tests/|\.build/|WaterMark' > build/test/coverage.txt
cat build/test/coverage.txt
python3 -I - <<'PY'
import re,sys
rows={}
for l in open('build/test/coverage.txt'):
    p=l.split()
    if len(p)>=10 and p[0].endswith('.swift'):
        # name regions miss cover% funcs miss exec% lines miss cover% ...
        rows[p[0].split('/')[-1]]=float(p[9].rstrip('%'))
core=["Pack.swift","Packets.swift","ServerList.swift","ByteBuffer.swift","HTTPHead.swift","DataPhase.swift","InputValidation.swift","ServerFilter.swift"]
helper=["SoftEtherClient.swift","EthernetBridge.swift","Session.swift","NetConfig.swift","IPCServer.swift"]
bad=[]
for f in core:
    if rows.get(f,0)<90: bad.append((f,rows.get(f),90))
for f in helper:
    if rows.get(f,0)<80: bad.append((f,rows.get(f),80))
print()
for f,c,t in bad: print(f"BELOW THRESHOLD {f}: {c}% < {t}%")
print("coverage thresholds:", "FAILED" if bad else "OK")
sys.exit(1 if bad else 0)
PY
