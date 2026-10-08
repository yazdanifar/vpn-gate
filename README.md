# VPN Gate for macOS

Unofficial native macOS client for [VPN Gate](https://www.vpngate.net) with full feature and protocol
parity with the Windows SoftEther VPN Client and VPN Gate plugin (v4.44 build 9807).

- **VPN Gate Relay Directory**: RSA-verified P2P `VPNGate.dat` relay synchronization (over 200 relays with exact SSL-VPN ports), bundled bootstrap file, local cache, and CSV mirror fallback. Full 15-column server details view, academic experiment disclaimer, search, filter, and ping latency tester.
- **SoftEther Client Manager**: Dedicated Connection Settings manager supporting custom SoftEther servers, virtual hubs, multiple authentication methods (Anonymous, Standard SHA-0 Password, Plain Password, Client Certificate, Ticket), and Keychain secrets storage.
- **Protocol Parity**:
  - **Multi-TCP Connection Pool**: Automatically multiplexes frames across multiple TCP streams (up to 8, Windows default) for maximum throughput.
  - **zlib Data Compression**: Full wire-level zlib deflate/inflate compression framing.
  - **UDP Acceleration v2**: Ultra-low latency UDP transport with ChaCha20-Poly1305 AEAD encryption and automatic TCP failover.
  - **Cluster Redirects**: Handles farm/cluster redirects with 20-byte tickets and automatic reconnection.
  - **Client Identity**: Reports as SoftEther VPN Client v4.44 Build 9807.
- **Tunnel & Network**:
  - Full IPv4 + IPv6 dual-stack support with SLAAC and NDP neighbour discovery.
  - Configurable IPv6 leak protection (route blackhole or full tunnel forwarding).
  - DHCP Option 26 MTU/MSS negotiation.
  - Read-idle connection watchdog with automatic auto-reconnect.
- **App & Daemon Architecture**:
  - Native SwiftUI app with menu-bar extra and connection history log.
  - Universal binary (`arm64` Apple Silicon + `x86_64` Intel).
  - Privileged root helper LaunchDaemon (`vpngate-helper`) with IPC v5.
  - Launch at login via macOS `SMAppService`.
  - Anonymous academic statistics telemetry (matching Windows client, with user opt-out in Settings).

## Install
```
scripts/build-pkg.sh           # -> build/VPN Gate.pkg (Universal installer)
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
scripts/build.sh all           # -> Universal binaries in build/bin/ (arm64 + x86_64)
scripts/build-app.sh           # -> build/VPN Gate.app (ad-hoc signed, bundled VPNGate.dat)
```

Without root you can check a server's handshake and DHCP only:
```
build/bin/vpngate-helper --probe 219.100.37.7 --port 443
```
Foreground tunnel for debugging: `sudo build/bin/vpngate-helper --connect <ip> [--port N]` (Ctrl-C restores routes/DNS).

## Tests
```
scripts/test.sh                  # 198 tests, no network or root, ~25 s
scripts/test.sh --each           # every test in its own process (crashes are reported per test)
scripts/test.sh --tsan | --asan  # same suite under ThreadSanitizer / AddressSanitizer
scripts/test.sh --live live/     # real VPN Gate servers: list download + handshake + DHCP
scripts/coverage.sh              # llvm-cov report; fails below 90% (core) / 80% (key helper files)
sudo scripts/e2e-tunnel.sh <ip>  # real tunnel: traffic, DNS, IPv6 block, SIGINT/SIGTERM/kill -9 cleanup
```
The suite uses an in-memory SoftEther server (real wire format), a fake hub that answers DHCP/ARP, and
recording doubles for `route`/DNS/utun, so the session, bridge, network configuration and IPC are tested
without privileges. Fuzz tests are seeded (`FUZZ_SEED`, `FUZZ_ITERATIONS`).

## Notes / Security
- If the helper crashes, stale routes/DNS are cleaned on its next start (only routes it added).
- `scripts/gen-watermark.sh` regenerates the SoftEther signature image (Apache-2.0, © SoftEther VPN Project).
- Not affiliated with VPN Gate or SoftEther. VPN Gate relays are volunteer-run public servers: don't send
  sensitive traffic through them unless you trust the operator.
