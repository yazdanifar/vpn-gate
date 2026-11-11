#!/bin/bash
# CI only: lets the launch test control the app through the accessibility API. Grants Accessibility to the programs a
# GitHub-hosted macOS runner starts the test from (the TCC database of a disposable runner is writable with sudo).
set -uo pipefail
[ -n "${CI:-}" ] || { echo "CI only"; exit 2; }
DB="/Library/Application Support/com.apple.TCC/TCC.db"
for c in /bin/bash /bin/sh /bin/zsh /usr/bin/env /usr/libexec/sshd-keygen-wrapper "$PWD/build/test-launch/tests-launch" \
         "$(cd "$(dirname "$0")/.." && pwd)/build/test-launch/tests-launch" /usr/bin/osascript /usr/bin/swift; do
  sudo sqlite3 "$DB" "INSERT OR REPLACE INTO access (service,client,client_type,auth_value,auth_reason,auth_version,indirect_object_identifier,flags,last_modified) VALUES ('kTCCServiceAccessibility','$c',1,2,4,1,'UNUSED',0,strftime('%s','now'));" 2>&1 | head -2
done
sudo sqlite3 "$DB" "select client,auth_value from access where service='kTCCServiceAccessibility';" 2>&1 | head -20
