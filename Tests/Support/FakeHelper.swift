import Darwin
import Foundation

/// What the app tests need from a helper: records the requests the app sends and answers the v9 ones from scripted
/// results. The real daemon is the Rust `vpngate-daemon`; the app only ever sees its JSON, so this speaks that JSON.
final class FakeHelperSession: @unchecked Sendable {
    /// Broadcasts an event line to every connected client.
    var emit: ((HelperEvent) -> Void)?
    var snapshot = HelperEvent(state: .disconnected)
    /// Reported in every snapshot unless the test sets `nil` (a v8 helper).
    var reportedIPCVersion: Int? = ipcVersion

    /// Scripted answers; nil = `ok:false`.
    var listResult: ServerListResult?
    var refreshResult: ServerListResult?
    var refreshDelay: TimeInterval = 0
    var probeReply: (([ProbeTarget]) -> [ProbeEntry])?

    private let state = Locked(
        (
            connects: [(host: String, port: Int?)](), disconnects: 0, blockIPv6: [Bool](), configs: [ConnectConfig](), autoReconnects: [Bool](),
            portLists: [[Int]?](), commands: [String](), probes: [[ProbeTarget]](), refreshes: [(proxy: ProxySettings?, mirror: String?)]()
        ))
    var connects: [(host: String, port: Int?)] { state.value.connects }
    var blockIPv6Flags: [Bool] { state.value.blockIPv6 }
    var autoReconnects: [Bool] { state.value.autoReconnects }
    var portLists: [[Int]?] { state.value.portLists }
    var disconnects: Int { state.value.disconnects }
    var configs: [ConnectConfig] { state.value.configs }
    var commands: [String] { state.value.commands }
    var probes: [[ProbeTarget]] { state.value.probes }
    var refreshes: [(proxy: ProxySettings?, mirror: String?)] { state.value.refreshes }

    fileprivate func record(_ r: HelperRequest) {
        state.update {
            $0.commands.append(r.cmd)
            switch r.cmd {
            case "connect":
                if let c = r.config {
                    $0.connects.append((c.host, c.ports.first)); $0.blockIPv6.append(c.blockIPv6); $0.configs.append(c)
                } else {
                    $0.connects.append((r.host ?? "", r.port)); $0.blockIPv6.append(r.blockIPv6 ?? true)
                    $0.autoReconnects.append(r.autoReconnect ?? true); $0.portLists.append(r.ports)
                }
            case "disconnect": $0.disconnects += 1
            case "probe": $0.probes.append(r.targets ?? [])
            case "refreshServers": $0.refreshes.append((r.proxy, r.mirror))
            default: break
            }
        }
    }

    fileprivate func snapshotEvent() -> HelperEvent {
        var s = snapshot; s.ipcVersion = reportedIPCVersion; return s
    }

    fileprivate func reply(to r: HelperRequest) -> HelperReply? {
        guard let id = r.id else { return nil }
        func ok<T: Encodable>(_ v: T) -> HelperReply {
            HelperReply(reply: r.cmd, id: id, ok: true, error: nil, result: try? JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(v)))
        }
        func fail(_ m: String) -> HelperReply { HelperReply(reply: r.cmd, id: id, ok: false, error: m, result: nil) }
        switch r.cmd {
        case "listServers": return listResult.map(ok) ?? fail("No server list")
        case "refreshServers":
            if refreshDelay > 0 { Thread.sleep(forTimeInterval: refreshDelay) }
            return refreshResult.map(ok) ?? fail("No server list")
        case "probe":
            guard let f = probeReply else { return fail("no probe") }
            return ok(ProbeResultList(results: f(r.targets ?? [])))
        default: return nil
        }
    }
}

/// A Unix socket server speaking the daemon's line protocol, for `AppModel` tests.
final class FakeHelperServer: @unchecked Sendable {
    private let path: String
    private let session: FakeHelperSession
    private var listener: Int32 = -1
    private let clients = Locked([Int32]())

    init(path: String, session: FakeHelperSession) { self.path = path; self.session = session }

    func start() throws {
        unlink(path)
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0, listen(listener, 8) == 0 else { throw POSIXError(.EADDRINUSE) }
        session.emit = { [weak self] e in self?.broadcast(e) }
        let l = listener
        Thread.detachNewThread { [weak self] in
            while true {
                let c = accept(l, nil, nil)
                if c < 0 { break }
                self?.serve(c)
            }
        }
    }

    func stop() {
        let l = listener; listener = -1
        if l >= 0 { Darwin.close(l) }
        for c in clients.value { Darwin.close(c) }
        clients.update { $0 = [] }
        unlink(path)
    }

    private func send(_ fd: Int32, _ line: Data) {
        var d = line; d.append(10)
        _ = d.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, d.count) }
    }

    private func broadcast(_ e: HelperEvent) {
        guard let d = try? JSONEncoder().encode(e) else { return }
        for c in clients.value { send(c, d) }
    }

    private func serve(_ fd: Int32) {
        clients.update { $0.append(fd) }
        if let d = try? JSONEncoder().encode(session.snapshotEvent()) { send(fd, d) }
        Thread.detachNewThread { [weak self] in
            var buf = Data(); var chunk = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = read(fd, &chunk, chunk.count)
                if n <= 0 { break }
                buf.append(contentsOf: chunk[0..<n])
                while let nl = buf.firstIndex(of: 10) {
                    let line = buf[buf.startIndex..<nl]
                    buf = Data(buf[buf.index(after: nl)...])
                    guard let self, let r = try? JSONDecoder().decode(HelperRequest.self, from: line) else { continue }
                    self.session.record(r)
                    if r.cmd == "status", let d = try? JSONEncoder().encode(self.session.snapshotEvent()) { self.send(fd, d) }
                    // Each v9 request is answered on its own thread so a slow one does not block the others.
                    if r.id != nil {
                        Thread.detachNewThread {
                            if let rep = self.session.reply(to: r), let d = try? JSONEncoder().encode(rep) { self.send(fd, d) }
                        }
                    }
                }
            }
            self?.clients.update { $0.removeAll { $0 == fd } }
            Darwin.close(fd)
        }
    }
}

/// One server as the list parser would have produced it for a CSV line with an OpenVPN `remote <ip> <port>`.
func parsedServer(_ host: String = "vpn1", ip: String = "1.2.3.4", port: Int = 443) -> VPNServer {
    VPNServer(
        hostName: host, ip: ip, score: 1, ping: 1, speed: 1, countryLong: "Japan", countryShort: "JP", sessions: 1, uptimeMs: 1,
        totalUsers: 1, totalTraffic: 1, logType: "2weeks", operatorName: "Op", message: "msg", listedPort: port, listedProto: "tcp")
}
