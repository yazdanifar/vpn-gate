import Foundation
import Darwin

/// Tiny one-route HTTP/1.1 server on 127.0.0.1 for tests of network clients.
final class LocalHTTPServer {
    private let fd: Int32
    let port: UInt16
    private let lock = NSLock()
    private var running = true
    private(set) var requests = 0
    var url: URL { URL(string: "http://127.0.0.1:\(port)/list")! }

    init(status: Int = 200, body: Data) {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        var one: Int32 = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, 4)
        var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        listen(s, 8)
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
        fd = s; port = UInt16(bigEndian: a.sin_port)
        Thread.detachNewThread { [weak self] in
            while true {
                let c = accept(s, nil, nil)
                guard let self = self, c >= 0 else { return }
                self.lock.lock(); self.requests += 1; self.lock.unlock()
                var buf = [UInt8](repeating: 0, count: 4096); _ = read(c, &buf, buf.count)
                let head = Array("HTTP/1.1 \(status) X\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
                _ = (head + [UInt8](body)).withUnsafeBytes { write(c, $0.baseAddress, head.count + body.count) }
                Darwin.close(c)
            }
        }
    }

    func stop() { Darwin.shutdown(fd, SHUT_RDWR); Darwin.close(fd) }
}
