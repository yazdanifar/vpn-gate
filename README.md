# VPN Gate for macOS

Unofficial native macOS client for [VPN Gate](https://www.vpngate.net). It speaks SoftEther's own
SSL-VPN protocol directly (no OpenVPN/L2TP), like the Windows client does.

- **App** (SwiftUI): server list (sort, search, country filter, favorites, latency test), menu-bar status
  item with connect/disconnect, proxy (HTTP CONNECT / SOCKS5), auto-reconnect, list mirror URL.
- **Helper** (`vpngate-helper`, runs as root via a LaunchDaemon): SoftEther session over TLS, a userspace
  L2 stack (DHCP + ARP) bridging the hub to a `utun` interface, routes, and DNS.
- The app and helper talk over `/var/run/vpngate-mac.sock` (JSON lines, restricted to your uid).

## Install
```
scripts/build-pkg.sh           # -> build/VPN Gate.pkg
open "build/VPN Gate.pkg"      # standard macOS installer: asks for your password once
```
The installer puts `VPN Gate.app` in /Applications and starts the privileged helper (a LaunchDaemon). After that the
app never asks for anything: the helper accepts requests from whoever is logged in at the console. If the helper is
missing or outdated, **Connect** shows a one-time setup alert, opens the same installer and connects by itself when it
finishes. The package is unsigned, so macOS shows an "unidentified developer" notice the first time (right-click →
Open); signing it needs an Apple Developer ID.

Uninstall: Settings → Uninstall…, then drag the app to the Trash.

## Build
Only the Command Line Tools are needed (SwiftPM is not required; `Package.swift` is provided for machines where it works).

```
scripts/build-app.sh           # -> build/VPN Gate.app (ad-hoc signed); no helper installer inside, for development
```

Without root you can check a server's handshake and DHCP only:
```
build/bin/vpngate-helper --probe 219.100.37.7 --port 443
```
Foreground tunnel for debugging: `sudo build/bin/vpngate-helper --connect <ip> [--port N]` (Ctrl-C restores routes/DNS).

## Tests
```
scripts/test.sh                  # 170 tests, no network or root, ~25 s
scripts/test.sh --each           # every test in its own process (crashes are reported per test)
scripts/test.sh --tsan | --asan  # same suite under ThreadSanitizer / AddressSanitizer
scripts/test.sh --live live/     # real VPN Gate servers: list download + handshake + DHCP
scripts/coverage.sh              # llvm-cov report; fails below 90% (core) / 80% (key helper files)
sudo scripts/e2e-tunnel.sh <ip>  # real tunnel: traffic, DNS, IPv6 block, SIGINT/SIGTERM/kill -9 cleanup
```
The suite uses an in-memory SoftEther server (real wire format), a fake hub that answers DHCP/ARP, and
recording doubles for `route`/DNS/utun, so the session, bridge, network configuration and IPC are tested
without privileges. Fuzz tests are seeded (`FUZZ_SEED`, `FUZZ_ITERATIONS`).

## Notes / limitations (v1)
- Single TCP connection, no compression, no UDP acceleration, IPv4 only. While connected IPv6 is routed into
  the tunnel and dropped (Settings → "Block IPv6"), so dual-stack sites fall back to IPv4 through the VPN.
- Cluster redirects are not supported (VPN Gate relays don't use them).
- No kill switch. If the helper crashes, stale routes/DNS are cleaned on its next start (only routes it added).
- Whether the DNS override wins over the system resolver on every network setup is only verified by the E2E script.
- `scripts/gen-watermark.sh` regenerates the SoftEther signature image (Apache-2.0, © SoftEther VPN Project).
- Not affiliated with VPN Gate or SoftEther. VPN Gate relays are volunteer-run public servers: don't send
  sensitive traffic through them unless you trust the operator.
