#!/bin/bash
# Builds build/VPN\ Gate.pkg: installs /Applications/VPN Gate.app and the privileged helper (LaunchDaemon).
# The app also carries "VPN Gate Helper.pkg" so it can re-run the same installer for updates/repairs.
set -euo pipefail
cd "$(dirname "$0")/.."
export COPYFILE_DISABLE=1          # no ._AppleDouble stubs for extended attributes in the payload
# pkgbuild tries to chown payload files to root as a normal user; the recorded ownership is still root:wheel.
quiet() { "$@" 2> >(grep -v "^write: Permission denied$" >&2); }
# The release version (VERSION file); the helper's IPC version (helperVersion) is a separate number.
VERSION=$(tr -d '[:space:]' < VERSION)
STAGE=build/pkg; rm -rf "$STAGE"; mkdir -p "$STAGE/helper-root/Library/PrivilegedHelperTools" \
  "$STAGE/helper-root/Library/LaunchDaemons" "$STAGE/app-root/Applications"

scripts/build-app.sh >/dev/null    # runs scripts/build.sh all, then assembles build/VPN Gate.app
# 1. helper component: binary + LaunchDaemon plist, scripts restart the daemon
cp build/bin/vpngate-helper "$STAGE/helper-root/Library/PrivilegedHelperTools/vpngate-helper"
cp packaging/com.yazdanifar.vpngate.helper.plist "$STAGE/helper-root/Library/LaunchDaemons/"
codesign --force -s - "$STAGE/helper-root/Library/PrivilegedHelperTools/vpngate-helper"
xattr -cr "$STAGE/helper-root"
quiet pkgbuild --root "$STAGE/helper-root" --identifier com.yazdanifar.vpngate.helper --version "$VERSION" \
  --install-location / --scripts packaging/scripts --ownership recommended "$STAGE/helper.pkg" >/dev/null

# 2. app (with the helper installer inside it), signed after everything is in place
APP="build/VPN Gate.app"
cp "$STAGE/helper.pkg" "$APP/Contents/Resources/VPN Gate Helper.pkg"
codesign --force -s - "$APP"
cp -R "$APP" "$STAGE/app-root/Applications/"
xattr -cr "$STAGE/app-root"
# Not relocatable: otherwise the installer updates any other copy of the bundle it finds (a stray one in Downloads, the
# build directory) and leaves /Applications untouched.
pkgbuild --analyze --root "$STAGE/app-root" "$STAGE/app-components.plist" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO "$STAGE/app-components.plist"
quiet pkgbuild --root "$STAGE/app-root" --component-plist "$STAGE/app-components.plist" --identifier com.yazdanifar.VPNGateMac \
  --version "$VERSION" --install-location / --ownership recommended "$STAGE/app.pkg" >/dev/null

# 3. one installer for both
cat > "$STAGE/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>VPN Gate</title>
  <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" title="VPN Gate">
    <pkg-ref id="com.yazdanifar.VPNGateMac"/><pkg-ref id="com.yazdanifar.vpngate.helper"/>
  </choice>
  <pkg-ref id="com.yazdanifar.VPNGateMac" version="$VERSION">app.pkg</pkg-ref>
  <pkg-ref id="com.yazdanifar.vpngate.helper" version="$VERSION">helper.pkg</pkg-ref>
</installer-gui-script>
XML
productbuild --distribution "$STAGE/distribution.xml" --package-path "$STAGE" "build/VPN Gate.pkg" >/dev/null

# self-check: the installer must contain exactly what the app expects to find
LIST=$(pkgutil --payload-files "$STAGE/helper.pkg")
for f in ./Library/PrivilegedHelperTools/vpngate-helper ./Library/LaunchDaemons/com.yazdanifar.vpngate.helper.plist; do
  grep -qx "$f" <<< "$LIST" || { echo "helper.pkg is missing $f"; exit 1; }
done
pkgutil --payload-files "$STAGE/app.pkg" | grep -q "VPN Gate Helper.pkg" || { echo "app lacks the helper installer"; exit 1; }
SIG=$(pkgutil --check-signature "build/VPN Gate.pkg" 2>&1 || true); echo "$(head -1 <<< "$SIG")  (unsigned: macOS shows a one-time \"unidentified developer\" notice; right-click → Open)"
echo "Built build/VPN Gate.pkg (version $VERSION)"
