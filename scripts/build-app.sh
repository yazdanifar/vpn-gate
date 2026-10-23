#!/bin/bash
# Assembles build/VPN\ Gate.app (ad-hoc signed) containing the app and the privileged helper.
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/build.sh all
VERSION=$(cat VERSION 2>/dev/null || echo "1.0.0")
APP="build/VPN Gate.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp build/bin/VPNGateMac "$APP/Contents/MacOS/VPNGateMac"
cp build/bin/vpngate-helper "$APP/Contents/Resources/vpngate-helper"
cp assets/VPNGate.dat "$APP/Contents/Resources/VPNGate.dat"
# app icon: the SoftEther VPN Client Manager icon (see NOTICE), rendered with the standard margin
swift scripts/make-icon.swift assets/AppIcon-256.png build/AppIcon.iconset
iconutil -c icns build/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>VPN Gate</string>
  <key>CFBundleDisplayName</key><string>VPN Gate</string>
  <key>CFBundleIdentifier</key><string>com.yazdanifar.VPNGateMac</string>
  <key>CFBundleExecutable</key><string>VPNGateMac</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSAppTransportSecurity</key><dict>
    <key>NSExceptionDomains</key><dict>
      <key>vpngate.net</key><dict>
        <key>NSIncludesSubdomains</key><true/>
        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
      </dict>
      <key>vpngate2.jp</key><dict>
        <key>NSIncludesSubdomains</key><true/>
        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
      </dict>
    </dict>
  </dict>
</dict></plist>
PLIST
codesign --force -s - "$APP/Contents/Resources/vpngate-helper"
codesign --force -s - "$APP"
echo "Built $APP"
