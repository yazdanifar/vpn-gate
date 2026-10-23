import Darwin
import Foundation

/// Tiny one-route HTTP/1.1 server on 127.0.0.1 for tests of network clients.
final class LocalHTTPServer {
    private let fd: Int32
    let port: UInt16
    private let lock = NSLock()
    private var running = true
    private(set) var requests = 0
    /// The raw bytes of every request received, in order, for tests that need to inspect what a client actually sent.
    private(set) var captured: [Data] = []
    var url: URL { URL(string: "http://127.0.0.1:\(port)/list")! }
    /// The method, path and body of the most recent request (nil until one arrives).
    var lastRequest: (method: String, path: String, headers: [String: String], body: Data)? {
        guard let raw = captured.last else { return nil }
        return Self.parse(raw)
    }

    /// Splits a raw HTTP/1.1 request into its parts. Header lookups are case-insensitive, as HTTP requires.
    private static func parse(_ raw: Data) -> (method: String, path: String, headers: [String: String], body: Data) {
        let sep = Data("\r\n\r\n".utf8)
        guard let headEnd = raw.range(of: sep) else { return ("", "", [:], Data()) }
        let headText = String(decoding: raw[..<headEnd.lowerBound], as: UTF8.self)
        var lines = headText.split(separator: "\r\n", omittingEmptySubsequences: true).map(String.init)
        let requestLine = lines.isEmpty ? "" : lines.removeFirst()
        let parts = requestLine.split(separator: " ")
        let method = parts.count > 0 ? String(parts[0]) : ""
        let path = parts.count > 1 ? String(parts[1]) : ""
        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }
        let body = raw[headEnd.upperBound...]
        return (method, path, headers, Data(body))
    }

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
                let raw = Self.readRequest(c)
                self.lock.lock(); self.requests += 1; self.captured.append(raw); self.lock.unlock()
                let head = Array("HTTP/1.1 \(status) X\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
                _ = (head + [UInt8](body)).withUnsafeBytes { write(c, $0.baseAddress, head.count + body.count) }
                Darwin.close(c)
            }
        }
    }

    /// Reads a full HTTP/1.1 request off `c`: the header block, then exactly `Content-Length` more bytes.
    /// A single 4096-byte read is enough on loopback almost always, but a request can legitimately span more
    /// than one TCP segment, so this loops instead of assuming it all arrives at once.
    private static func readRequest(_ c: Int32) -> Data {
        var raw = Data()
        let sep = Data("\r\n\r\n".utf8)
        var buf = [UInt8](repeating: 0, count: 4096)
        while raw.range(of: sep) == nil {
            let n = read(c, &buf, buf.count)
            guard n > 0 else { return raw }
            raw.append(buf, count: n)
        }
        guard let headEnd = raw.range(of: sep) else { return raw }
        let (_, _, headers, _) = parse(raw)
        let want = headers["content-length"].flatMap(Int.init) ?? 0
        var have = raw.count - headEnd.upperBound
        while have < want {
            let n = read(c, &buf, min(buf.count, want - have))
            guard n > 0 else { break }
            raw.append(buf, count: n)
            have += n
        }
        return raw
    }

    func stop() { Darwin.shutdown(fd, SHUT_RDWR); Darwin.close(fd) }
}
