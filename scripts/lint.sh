#!/bin/bash
# Style check with the toolchain's swift-format (config: .swift-format).
#   scripts/lint.sh          report violations (non-zero exit if any)
#   scripts/lint.sh --fix    rewrite files in place
set -euo pipefail
cd "$(dirname "$0")/.."
SF=$(xcrun --find swift-format)
if [[ ${1:-} == --fix ]]; then "$SF" format -i -r Sources Tests; else "$SF" lint --strict -r Sources Tests; fi
