import Darwin
import Foundation
import VPNGateCore

// Usage:
//   vpngate-helper --daemon [--uid <uid>]      run as the LaunchDaemon, serve the app over a Unix socket
//                                              (without --uid: whoever is logged in at the console may connect)
//   vpngate-helper --connect <host> [--port N] connect once in the foreground (debugging; needs sudo)

setvbuf(stdout, nil, _IOLBF, 0)

// --probe <host> [--port N] [--watch-udp [N]]: handshake + DHCP only, no utun/routes, so it runs without root.
// --watch-udp keeps the session open for N seconds (default 20) afterwards, polling whether UDP acceleration
// (opportunistic; the client always falls back to TCP) actually became usable against this real server.
if let (host, port) = parseProbeArgs(CommandLine.arguments) {
    let watchSeconds = parseWatchUdpSeconds(CommandLine.arguments)
    Task {
        let c = SoftEtherClient(host: host, port: UInt16(port), proxy: ProxySettings())
        let b = EthernetBridge()
        b.sendFrame = { c.sendFrame($0) }
        c.onFrame = { b.fromHub($0) }
        do {
            let w = try await c.connect { print("  \($0)") }
            print("OK session \(w.sessionName) timeout \(w.timeoutMs)ms")
            let l = try await b.acquireLease()
            print("OK lease ip \(ipString(l.ip)) mask \(ipString(l.mask)) gw \(ipString(l.router)) dns \(l.dns.map(ipString)) \(l.seconds)s")
            if let seconds = watchSeconds {
                print("  UDP negotiated: \(c.udpAccelNegotiated) — watching for \(seconds)s (needs ~10s stable receive before it carries data)")
                var becameUsableAt: Int? = nil
                for elapsed in 1...seconds {
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                    if c.udpAccelUsable && becameUsableAt == nil {
                        becameUsableAt = elapsed
                        print("  UDP became usable after \(elapsed)s")
                    }
                }
                if let t = becameUsableAt {
                    print("OK udp usable after \(t)s (still usable: \(c.udpAccelUsable))")
                } else if c.udpAccelNegotiated {
                    print(
                        "FAIL udp negotiated by the server but never became usable in \(seconds)s (likely blocked/dropped on this network; TCP fallback is what carries traffic instead)"
                    )
                } else {
                    print("OK udp not negotiated by this server; nothing to watch (TCP only)")
                }
            }
            c.close(nil); exit(0)
        } catch { print("FAIL \(error.localizedDescription)"); exit(1) }
    }
    dispatchMain()
}

let isConnectMode = CommandLine.arguments.contains("--connect")
// Only creating the tunnel needs root; the daemon itself starts anywhere (the LaunchDaemon runs it as root).
guard getuid() == 0 || !isConnectMode else {
    FileHandle.standardError.write(Data("vpngate-helper must run as root (use sudo)\n".utf8))
    exit(1)
}
let args = CommandLine.arguments
if args.contains("--version") { print(helperVersion); exit(0) }
func opt(_ name: String) -> String? {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    return args[i + 1]
}

var ipcServer: IPCServer?
NetConfig.cleanupStale()
let session = VPNSession()

let socketPath = opt("--socket") ?? helperSocketPath
let shutdownHandlers = ShutdownCoordinator(signals: [SIGINT, SIGTERM]) {
    session.disconnect()
    unlink(socketPath)
}
signal(SIGPIPE, SIG_IGN)

if let host = opt("--connect") {
    session.emit = { e in
        if let l = e.log { print("[\(e.state.rawValue)] \(l)") }
        if let err = e.error { print("[error] \(err)") }
        if e.state == .connected, e.bytesIn == 0, e.bytesOut == 0 { print("[connected] virtual IP \(e.virtualIP ?? "?")") }
    }
    guard InputValidation.isValidHost(host) else { print("invalid host"); exit(2) }
    session.connect(
        host: host, port: opt("--port").flatMap(Int.init), proxy: ProxySettings(),
        autoReconnect: false, blockIPv6: !args.contains("--allow-ipv6"))
} else if args.contains("--daemon") {
    // Kept in a global: a local here is released when this block ends, which silently stopped IPC.
    let fixedUID = opt("--uid").flatMap { uid_t($0) }
    ipcServer = IPCServer(
        path: socketPath, allowedUID: fixedUID,
        consoleUID: fixedUID == nil ? currentConsoleUID : { nil }, session: session)
    do { try ipcServer!.start() } catch { print("IPC: \(error)"); exit(1) }
    print("vpngate-helper listening on \(socketPath)")
} else {
    print("usage: vpngate-helper --daemon --uid <uid> | --connect <host> [--port N]")
    exit(2)
}
dispatchMain()
