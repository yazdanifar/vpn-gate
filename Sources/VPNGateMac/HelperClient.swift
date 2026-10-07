import Foundation
import Darwin
import VPNGateCore

/// Talks to the privileged helper over its Unix socket.
final class HelperClient {
    private var fd: Int32 = -1
    private let path: String

    init(path: String = helperSocketPath) { self.path = path }
    private let lock = NSLock()
    var onEvent: ((HelperEvent) -> Void)?
    var onDisconnect: (() -> Void)?

    var isConnected: Bool { lock.lock(); defer { lock.unlock() }; return fd >= 0 }

    func connect() -> Bool {
        if isConnected { return true }
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return false }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { Darwin.close(s); return false }
        lock.lock(); fd = s; lock.unlock()
        Thread.detachNewThread { [weak self] in self?.readLoop(s) }
        return true
    }

    private func readLoop(_ s: Int32) {
        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = read(s, &chunk, chunk.count)
            if n <= 0 { break }
            buf.append(contentsOf: chunk[0..<n])
            while let nl = buf.firstIndex(of: 10) {
                let line = buf[buf.startIndex..<nl]
                buf = Data(buf[buf.index(after: nl)...])
                if let e = try? JSONDecoder().decode(HelperEvent.self, from: line) { onEvent?(e) }
            }
        }
        lock.lock(); if fd == s { fd = -1 }; lock.unlock()
        Darwin.close(s)
        onDisconnect?()
    }

    func send(_ req: HelperRequest) {
        guard connect(), var d = try? JSONEncoder().encode(req) else { return }
        d.append(10)
        lock.lock(); let s = fd; lock.unlock()
        _ = d.withUnsafeBytes { write(s, $0.baseAddress, d.count) }
    }
}
