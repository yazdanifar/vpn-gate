#!/usr/bin/env python3
"""Checks the merged Android manifest (after every library has contributed) for the always-on VPN contract.

Usage: check-android-manifest.py apps/android   (after `./gradlew :app:processDebugMainManifest`)
The system offers "Always-on VPN" and "Block connections without VPN" only for a service that is bound with
BIND_VPN_SERVICE, answers the android.net.VpnService action and declares SUPPORTS_ALWAYS_ON."""
import pathlib
import sys
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
root = pathlib.Path(sys.argv[1])
found = sorted(root.glob("app/build/intermediates/**/processDebugMainManifest/AndroidManifest.xml"))
if not found:
    sys.exit(f"no merged manifest under {root}/app/build/intermediates (run :app:processDebugMainManifest first)")
manifest = ET.parse(found[0]).getroot()
services = [s for s in manifest.iter("service") if s.get(ANDROID + "name", "").endswith("VpnEngineService")]
errors = []
if len(services) != 1:
    sys.exit(f"{found[0]}: expected one VpnEngineService, found {len(services)}")
service = services[0]
if service.get(ANDROID + "permission") != "android.permission.BIND_VPN_SERVICE":
    errors.append("the service is not protected by android.permission.BIND_VPN_SERVICE")
if service.get(ANDROID + "exported") != "true":
    errors.append("the service is not exported, so the system cannot start it")
actions = [a.get(ANDROID + "name") for a in service.iter("action")]
if "android.net.VpnService" not in actions:
    errors.append(f"no android.net.VpnService intent filter (actions: {actions})")
meta = {m.get(ANDROID + "name"): m.get(ANDROID + "value") for m in service.iter("meta-data")}
if meta.get("android.net.VpnService.SUPPORTS_ALWAYS_ON") != "true":
    errors.append(f"android.net.VpnService.SUPPORTS_ALWAYS_ON is not true (meta-data: {meta})")
if errors:
    sys.exit(f"{found[0]}:\n  " + "\n  ".join(errors))
print(f"{found[0]}: VpnEngineService declares BIND_VPN_SERVICE, the android.net.VpnService action and SUPPORTS_ALWAYS_ON")
