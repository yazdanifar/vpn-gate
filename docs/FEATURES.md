# Features, limits and verification status

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
- Universal binary (arm64 + x86_64), privileged helper LaunchDaemon (`vpngate-helper`, the Rust daemon; IPC version 9), menu-bar extra.

### SOCKS5 proxy mode
Settings → General → Mode lets you use the VPN as a **SOCKS5 proxy only** instead of a full tunnel. The system's default
route, DNS and IPv6 are left alone: the tunnel interface gets its DHCP address and an interface-scoped default route
(`route add -ifscope utunN default <gw>`), and the helper listens on `127.0.0.1:<port>` (default 1080, 1024–65535).
Each proxied connection is a socket bound to the tunnel interface (`IP_BOUND_IF`), so only apps you point at the proxy
use the VPN. Supported: SOCKS5 CONNECT, no authentication, IPv4 and host-name destinations (names are resolved through
the VPN's own DNS, so use the app's "remote DNS" option). Not supported: UDP ASSOCIATE, BIND, IPv6 destinations,
proxy authentication. Any local process can use the port while connected. Routing rules and IPv6 blocking do not apply
in this mode. The mode is app-wide (not per connection setting) and takes effect on the next connection. Like the rest
of the tunnel code, this is covered by loopback tests only (the interface binding is exercised on `lo0`); it has not
been run over a live VPN Gate tunnel.

### Routing rules
Settings → Routing (and, per connection setting, its own editor) lets you send specific domains, IP addresses or
CIDR ranges **through the tunnel** (`Proxy`), **around it** (`Direct`, the original default route), or drop them
(`Block`) — the same idea as V2rayN's routing rules. Domain rules match by suffix, exact name, keyword or regular
expression; IP/CIDR rules match IPv4 and IPv6 literals and ranges. Rules are checked top to bottom, first match
wins; "Bypass private networks" adds the RFC 1918/CGNAT/link-local ranges as low-priority `Direct` rules. A
connection setting can use its own rules instead of the app-wide list (its editor's "Routing" section).

- **How it stays safe to use somewhere that censors by domain**: a rule's domain is resolved by a small DNS proxy
  the helper runs on `127.0.0.1` (published as the system resolver while one is needed). A domain matched `Direct`
  is looked up through the physical network's own resolver, captured before the tunnel overrides it — never the
  tunnel's resolver. Every other domain (the default, and anything matched `Proxy`) is looked up only through the
  tunnel, so nothing but an explicitly `Direct` domain's name is ever exposed to an ISP-controlled resolver. A
  lookup that cannot be answered safely (no usable resolver, a timeout, an unparsable query) gets SERVFAIL, never a
  guess that could leak. IP/CIDR rules need no DNS proxy; they are plain routes (or a blackhole route, for `Block`).
- **Known limits**: resolution is UDP only (no TCP DNS fallback yet); an app that does its own DNS (DNS-over-HTTPS,
  a hardcoded resolver) bypasses domain matching, though IP/CIDR rules still apply to its traffic once connected;
  there is no bundled country IP/domain list (V2rayN-style "bypass mainland China" equivalents) — build one with
  custom CIDR/domain rules if you need it; V2rayN rule-set import/export is not implemented.

### IPv6
- **Block IPv6 on (default)**: `::/1` and `8000::/1` are routed into the tunnel and all IPv6 is dropped, so nothing leaks
  around the VPN; dual-stack sites fall back to IPv4.
- **Block IPv6 off**: IPv6 works only if the VPN network advertises an IPv6 prefix by Router Advertisement (SLAAC
  EUI-64 address, router solicitation retries, NDP). Otherwise IPv6 is still captured and dropped (no leak).
- Not implemented: privacy/stable addresses, DHCPv6, DNS over IPv6/RDNSS, router reachability tracking. When an address
  lifetime expires it is only no longer used; it stays on the utun until disconnect.

### Per-platform features
The engine is the same Rust code everywhere; the table shows what each app offers. Only macOS has had a live tunnel run
(see [verification](#what-has-and-has-not-been-verified)); the other platforms are verified by CI and the checklists in
[PLATFORMS.md](cross-platform/PLATFORMS.md).

| Feature | macOS | Windows | Linux | Android |
|---|---|---|---|---|
| Server list, search, filter, sort, favorites | yes | yes | yes | yes |
| Test Connection (handshake probe column) | yes | not yet | yes | yes |
| Saved connection settings (accounts), all auth types | yes | yes | yes | yes |
| Certificate import | PEM/DER/PKCS#12 | PEM/DER/PKCS#12 | PEM/DER/PKCS#12 | PEM/DER/PKCS#12 |
| Secrets stored in | Keychain | Credential Manager | Secret Service (`secret-tool`) | Keystore (AES-GCM) |
| Routing rules | all kinds | all kinds | all kinds | IPv4 IP/CIDR bypass only |
| SOCKS5-only mode | yes | yes | yes | no |
| IPv6 block, proxy, auto-reconnect | yes | yes | yes | yes (always-on VPN too) |
| Connection history, server details, log | yes | yes | yes | yes |
| Run at login | yes | yes | yes | always-on VPN |
| Privileged process | LaunchDaemon | Windows service | systemd unit | in-process (`VpnService`) |
| Installer | `.pkg` | `.msi` | `.deb` | `.apk` / `.aab` |
| Opt-in diagnostics upload | yes | no | no | no |

### What has and has not been verified
**Nothing has run against a real VPN Gate server, the real list API, or a live tunnel yet.** Everything is tested with
in-memory fakes and loopback sockets: a fake SoftEther server (real wire format), a fake hub for DHCP/ARP, recording
doubles for `route`/DNS/utun, fake relay streams and a fake HTTP client for the list sync (the default HTTP client is
exercised only against a loopback server), a fake helper behind the real IPC socket, and a loopback TLS server for
certificate pinning. Whether the real list API answers a request without `X-Transaction`, and whether every relay
accepts a client without the "knock" below, are therefore open. The opt-in live checks (`make rust-live`, `--probe`,
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
`halfConnection`, `virtualMacAddress` and `mtu` exist in the account file for SoftEther compatibility but the helper
ignores them (the tunnel MTU comes from DHCP option 26). They are not shown in the editor. (An older
`hideFromVpnGateList` key, which the Windows client never had, is ignored on load and no longer written.)

Each connection setting's own `reconnectInterval` (default 3 s) and `reconnectCount` (default 8), editable in the
account editor, control the helper's own retry loop — matching the stock Client Manager's per-connection retry
policy. VPN Gate connections ignore both: the app retries those itself, forever, every 15 s, like the real VPN Gate
account does.

### First-run disclaimer
The academic-use disclaimer must be accepted before any connection starts, from any screen (server list, Client Manager,
menu bar). Declining quits the app.
