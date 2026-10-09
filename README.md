# VPN Gate for macOS

Unofficial native macOS client for [VPN Gate](https://www.vpngate.net) and other SoftEther VPN servers, written from the
protocol as implemented by the Windows SoftEther VPN Client / VPN Gate plugin (v4.44 build 9807). It is not affiliated
with VPN Gate or SoftEther and does not claim full parity with the Windows client.

## What is implemented
- **Relay directory**: RSA-verified `VPNGate.dat` synchronisation, bundled bootstrap file, local cache, CSV mirror
  fallback, server details, search/filter, TCP ping measurement. The list table follows the Windows client's columns:
  DDNS name (Fqdn), ping to Google and to Japan, SSL ports in the client's priority order (443, 992, 995, 465, 585,
  993, 22, then the rest), a UDP flag, uptime as minutes (up to 1 h), hours (up to 24 h) or days. The status line says
  the list is OK within 24 h of its timestamp and "stale" after that (a download is still accepted up to 36 h, as in the
  original). The column titles are this app's own English wording: the Windows client's titles are not in the decompile.
- **List sync (same order as the Windows client)**: the project's HTTP API first, then relays, then the cached or
  bundled list.
  - *HTTP API*: `http://x<a>.x<b>.client.api.vpngate2.jp/api/?session_id=<random u64>` (`<a>` and `<b>` are random hex
    digits; the original takes them from a machine hash). The reply is the same signed `.dat`: it is used only if the
    RSA signature verifies and it is fresh, otherwise it is ignored. The original's `X-Transaction` header (an
    RC4-obscured OS name and LAN address) is not sent; if the server insists on it this step simply fails and the relays
    are used. Skipped when an app proxy is configured (URLSession would bypass it). A hidden `alternativeMode`
    default (`defaults write <app id> alternativeMode -bool YES`) adds the original's https retry.
  - *Relays* (peer to peer, over TLS): the relay that delivered the last list is tried first (remembered across
    launches), then up to 13 hosts offering port 443, then up to 13 others on the first port of their priority order.
  - *Tunables*: a verified list may carry a signed `DynList` that overrides client timers. It is parsed as the
    original does (names are case-insensitive, a value of 0 means "unset", values are clamped to [default/5,
    default*50]). Honoured: `VGC_HTTP_POLL_INTERVAL_OK` / `_ERROR`, `VGC_UDP_POLL_INTERVAL_ERROR`,
    `VGC_NUM_TCP_TARGET_HOSTS`, `VGC_TCP_POLL_CONNECT_TIMEOUT`, `VGC_TCP_POLL_SSL_TIMEOUT`, `VGC_HTTP_CONNECT_TIMEOUT`,
    `VGC_HTTP_DATA_TIMEOUT`. The shipped list sets the OK interval to 2 h. Not honoured: the UDP-poll and relay-hosting
    tunables, and `VG_ALLOW_TIME_DIFF` (the 36 h freshness rule is fixed).
  - *Schedule*: the next poll is now + a uniformly random time in [0, interval) (the original's `Rand % interval`), so
    the average is half the interval.
- **Client Manager**: saved connection settings for your own SoftEther servers (host, ports, virtual hub, user,
  Anonymous / Standard (SHA-0) password / Plain password / User certificate authentication). Passwords, certificates,
  private keys and proxy passwords are stored in the Keychain only, never in `accounts.json`. A damaged or newer
  `accounts.json` is never overwritten (it is kept as `accounts.json.corrupt-<date>`). Ticket authentication is not
  selectable in the app (the helper only uses tickets handed out by a cluster redirect).
- **Connections to VPN Gate servers** use the Windows client's account: hub `VPNGATE`, anonymous, **one TCP
  connection**, **QoS off**, no compression, UDP acceleration allowed, ports in the priority order above (the extra
  fallback ports 992, 5555 and 1194 are a deviation: Windows retries one port only). A custom account has its own
  settings instead: "Max TCP Connections" (default 1, up to 32) and a **"Use QoS"** option (on by default, as in the
  SoftEther Client Manager; for VPN Gate connections QoS is always off).
- **Reconnect**: for a connection you start from the server list, with "Reconnect automatically" on (Settings), the app
  retries forever, every 15 s (the stock account's `NumRetry` infinite, `RetryInterval` 15 s), until you disconnect or
  connect elsewhere. The helper is asked to make a single attempt and the app does the waiting, so the interval is
  exactly 15 s and shows as "Reconnecting…". The retry lives in the app: if you quit the app, the helper does not keep
  retrying. For your own accounts the helper retries up to 8 times, 3 s apart, then gives up.
- **Certificate login**: import a PEM or DER certificate with its **RSA** private key (PKCS#1 or PKCS#8, not
  passphrase-protected), or a `.p12` file (passphrase asked). Caveat: macOS 14 reads only the older-encoding `.p12`
  files; if a `.p12` is refused, convert it to PEM (the PEM/DER path is the safe choice there). The `.p12` path has
  not been tried on macOS 14. EC keys and encrypted PEM keys are rejected with an explanation. The key is kept in the
  Keychain and sent to the root helper over the uid-restricted local socket for each connection; the helper signs the
  server challenge.
- **Server certificate checking**: a configured SHA-1 or SHA-256 fingerprint is enforced (tested against a loopback TLS
  server: right pin connects, wrong pin fails with a pin-mismatch error); "Verify Server Certificate" without a
  fingerprint uses the system trust store; the default accepts any certificate (VPN Gate relays commonly use
  self-signed certificates).
- **Tunnel**: utun interface, DHCP over the SoftEther virtual hub, routes and DNS, IPv6 handling (below), connection
  history (last 100 connections, stored locally in `connection_history.json`), optional proxy (HTTP CONNECT / SOCKS5),
  launch at login (the toggle reverts and shows the reason if macOS refuses).
- **Protocol features**: additional TCP connections when an account allows more than one (replenished when they
  drop), per-block zlib compression, cluster redirects, UDP acceleration v2 (opportunistic, TCP fallback if UDP is not
  stable for 10 s; honours the compress flag; no NAT traversal, so only servers given as an IPv4 address, host-name
  servers use TCP only).
- Universal binary (arm64 + x86_64), privileged helper LaunchDaemon (`vpngate-helper`, IPC version 6), menu-bar extra.

### IPv6
- **Block IPv6 on (default)**: `::/1` and `8000::/1` are routed into the tunnel and all IPv6 is dropped, so nothing leaks
  around the VPN; dual-stack sites fall back to IPv4.
- **Block IPv6 off**: IPv6 works only if the VPN network advertises an IPv6 prefix by Router Advertisement (SLAAC
  EUI-64 address, router solicitation retries, NDP). Otherwise IPv6 is still captured and dropped (no leak).
- Not implemented: privacy/stable addresses, DHCPv6, DNS over IPv6/RDNSS, router reachability tracking. When an address
  lifetime expires it is only no longer used; it stays on the utun until disconnect.

### What has and has not been verified
**Nothing has run against a real VPN Gate server, the real list API, or a live tunnel yet.** Everything is tested with
in-memory fakes and loopback sockets: a fake SoftEther server (real wire format), a fake hub for DHCP/ARP, recording
doubles for `route`/DNS/utun, fake relay streams and a fake HTTP client for the list sync (the default HTTP client is
exercised only against a loopback server), a fake helper behind the real IPC socket, and a loopback TLS server for
certificate pinning. Whether the real list API answers a request without `X-Transaction`, and whether every relay
accepts a client without the "knock" below, are therefore open. The opt-in live checks (`--live`, `--probe`,
`scripts/e2e-tunnel.sh`) need network access and are not part of the normal test run. One earlier end-to-end log shows
a connection to a build-9729 relay without the knock; that is one data point, not proof for all relays.

### Not implemented
- **"Knock"**: the Windows client sends servers with a build above 9074 that publish a `HostUniqueKey` a pre-connect
  blob (a signed, RC4-wrapped packet) before the TLS connection. This app does not. Official SoftEther clients connect
  without it and one relay is known to accept that, but relays that require it would refuse this app. The blob's pack
  key names are not recoverable from the decompile, so it cannot be reproduced exactly.
- **NAT-T / R-UDP**: neither the VPN transport nor the list download over R-UDP (the UDP-poll path of the original).
- **Half-connection** (never requested). The account field is stored and ignored.
- UDP-acceleration public-IP discovery through a relay; the original's "alt mode" decoys.

### Telemetry (opt-in, Mac app only)
Off by default; nothing is scheduled or sent until you turn it on (the first-run dialog and Settings both show the
switch). The Windows VPN Gate client does **not** send this for an ordinary client (it uploads relay logs only when the
PC hosts a relay); this upload is specific to this app. When on, every 10 minutes it POSTs `HostKey` (a random ID
generated on this Mac, resettable in Settings; not derived from the machine name), `Build` and `ClientBuild` (9807),
`ClientVer` (444), `ClientOsName` ("macOS") and `IsClient` (1) to the statistics host of the VPN Gate project
(`x<c>.x<d>.statistics.api.vpngate2.jp`, where `<c>` and `<d>` are the third and fourth characters of the HostKey, as in
the original). Settings lists the exact fields. No traffic, addresses or personal data are sent.

### Settings that are stored but not used
`halfConnection`, `reconnectInterval`, `reconnectCount`, `virtualMacAddress` and `mtu` exist in the account file for
SoftEther compatibility but the helper ignores them (the MTU comes from DHCP option 26). They are not shown in the
editor. (An older `hideFromVpnGateList` key, which the Windows client never had, is ignored on load and no longer written.)

### First-run disclaimer
The academic-use disclaimer must be accepted before any connection starts, from any screen (server list, Client Manager,
menu bar). Declining quits the app.

## Install
```
scripts/build-pkg.sh           # -> build/VPN Gate.pkg (Universal installer)
open "build/VPN Gate.pkg"      # standard macOS installer: asks for your password once
```
The installer puts `VPN Gate.app` in /Applications and starts the privileged helper (a LaunchDaemon). After that the
app never asks for anything: the helper accepts requests from whoever is logged in at the console. If the helper is
missing or outdated, **Connect** shows a one-time setup alert, opens the same installer and connects by itself when it
finishes. The package version is the `VERSION` file (currently 1.0.0). The app and package are ad-hoc signed only:
no Developer ID, no hardened runtime, **not notarizable** as built, so macOS shows an "unidentified developer" notice
the first time (right-click → Open). Notarizing would need a Developer ID, hardened-runtime signing and a rebuild.

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
scripts/test.sh                  # 360 tests, no network or root, ~100 s
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
- `decompiled/` holds reverse-engineering notes: Ghidra pseudocode of the Windows client and plugin plus a `VPNGate.dat`
  decoder, used to understand the protocol (not part of the build). `assets/NOTICE.md` has the third-party notices.
- Not affiliated with VPN Gate or SoftEther. VPN Gate relays are volunteer-run public servers: don't send
  sensitive traffic through them unless you trust the operator.
