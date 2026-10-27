# Daemon IPC (version 9)

The protocol between a UI (Swift, C#, Rust, Kotlin) and the privileged daemon `vpngate-daemon`. This is the spec for
every client. The source of truth for the JSON is `crates/vpngate-core/src/ipc.rs`; the golden vectors in
`Tests/Fixtures/golden/ipc.json` pin the v8 messages.

## Transport

- macOS and Linux: a Unix stream socket (default `/var/run/vpngate-mac.sock` on macOS, `/run/vpngate.sock` on Linux; the
  daemon takes `--socket`). Windows: a named pipe (U17).
- One JSON object per line, UTF-8, `\n` terminated. A line over 1 MiB drops the client.
- Access is by the peer's uid: root, the daemon's `--uid` user, or the console user. Anybody else is closed without a byte.
- A client may send at any time; the daemon never waits on a slow client (256-event outbox, 2 s write stall, then dropped).

## Lines from the daemon

| Kind | Recognised by | Meaning |
|---|---|---|
| Event | has `state` | A snapshot of the VPN session. Sent once on connect, then on every change and every second while connected. |
| Reply | has `reply` | The answer to one v9 request. |

A client that only knows events (v8) fails to decode a reply as an event and must ignore the line; the Swift
`HelperClient` already does (`try? decode`).

### Event (`HelperEvent`)

`{"state","server"?,"virtualIP"?,"bytesIn","bytesOut","log"?,"error"?,"helperVersion"?,"ipcVersion"?}`

`state` is one of `disconnected connecting authenticating dhcp connected reconnecting`. Snapshots carry `helperVersion`
(8) and, from a v9 daemon, `ipcVersion` (9). **A client uses the v9 commands only after it has seen `ipcVersion >= 9`.**

### Reply (`HelperReply`)

`{"reply":"<cmd>","id":N?,"ok":true|false,"error"?,"result"?}`

`id` echoes the request's. `ok:false` carries `error`, a human-readable reason; no work was done unless stated.

## Requests (`HelperRequest`)

`{"cmd", ...}`. Unknown keys are ignored, and unknown `cmd`s are answered like `status`.

### Session commands (v8, answered by events, not replies)

| `cmd` | Fields | Effect |
|---|---|---|
| `connect` | `config` (`ConnectConfig`), or the legacy `host`, `port`, `ports`, `proxy`, `autoReconnect`, `blockIPv6`, `routing`, `tunnelMode`, `socksPort` | Starts a session. A request that fails validation is answered by an event with `error: "Rejected connect request: ..."`. |
| `disconnect` | | Ends the session. |
| `status` | | Sends a snapshot to this client. |

### v9 commands (answered by one reply each)

Send an integer `id` (any value unique among your open requests); the reply echoes it. Replies may arrive in any order
and interleaved with events.

| `cmd` | Request fields | `result` |
|---|---|---|
| `listServers` | | `ServerListResult` from the cache or the shipped list; **no network**. `ok:false` if there is none. |
| `refreshServers` | `proxy`?, `mirror`? | Runs the sync pipeline below and returns `ServerListResult`. |
| `syncDat` | `proxy`?, `mirror`? | The same sync, returning `SyncResult` (no servers). |
| `probe` | `targets` (1-200 of `{host, ports?}`), `proxy`?, `timeout`? (seconds per relay, clamped 1-60, default 8) | `{"results":[ProbeEntry]}` in request order. |
| `validateAccount` | `account` (`ClientAccount`) | `{"valid":bool,"error"?}`: would `connect` accept this account. |

Validation failures (bad host or port, no targets, more than 200 targets, a bad proxy) answer `ok:false` before any socket
is opened. A daemon started without an engine answers the network commands `ok:false` with "This daemon has no server engine".

#### Sync pipeline (`refreshServers`, `syncDat`)

1. The project's HTTP API (skipped when `proxy.kind` is not `none`).
2. Peer-to-peer download of the signed `VPNGate.dat` from relays of the last list (the last relay that worked first).
3. The newer of the cached and the shipped `VPNGate.dat` (`--cache`, `--bundle`).
4. The CSV mirror, only when no verified list exists.

A list is accepted only if its RSA signature verifies and it is under 36 h old (stored lists older than that are still
returned, with `isFresh:false`). One sync runs at a time.

#### `ServerListResult`

`{"servers":[VpnServer],"source","timestampMs"?,"isFresh","outcome","nextPollSeconds"?}`

- `source`: `"HTTP API"`, `"Relay P2P"`, `"Cached"`, `"Built-in"` or `"CSV Mirror"`.
- `timestampMs`: Unix milliseconds of the signed list; absent for the CSV mirror or no list.
- `outcome`: `synced` (a fresh list arrived), `relaysFailed` (relays were asked and none answered) or `noRelays`.
- `nextPollSeconds` (refresh only): when to sync again, a random point in the outcome's interval (about 1 h after a
  success, 10 min after a failure; the list's DynList can change both). The UI owns the timer.
- `VpnServer` is the JSON of `ServerList.swift`'s `VPNServer` (camelCase keys).

#### `SyncResult`

`{"source","timestampMs"?,"isFresh","outcome","serverCount","nextPollSeconds"}`

#### `ProbeEntry`

`{"host","ok","port"?,"connectMs"?,"helloMs"?,"build"?,"error"?}`. `ok` means a SoftEther server answered the protocol
hello on `port`; `connectMs` is TCP+TLS, `helloMs` the whole test. Without `ports` the relay's own SSL ports are tried
(at most 3, in the Windows client's priority order), then 443.

## Client rules

- Connect lazily and reconnect on the next send after the connection drops; report the drop to the UI. Never let a write to
  a closed socket kill the process (no SIGPIPE).
- Keep one reader: dispatch lines with `reply` to the waiting request by `id`, everything else is an event.
- Time out requests (the sync pipeline can take over a minute) and fail them when the connection drops.
- Secrets (`password`, `certDer`, `privateKeyDer`, `ticket`) live only in `connect`'s `config`; the daemon never logs them.

Implementations: Rust `vpngate-ipc-client::IpcClient` (with the scriptable `vpngate_testkit::fake_daemon::FakeDaemon`);
Swift `HelperClient` (U14); C# and Kotlin clients follow in U17/U26.
