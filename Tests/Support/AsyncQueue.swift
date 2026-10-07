import Foundation
import Darwin

/// Async byte-chunk queue used by the in-memory stream.
final class AsyncQueue {
    private let lock = NSLock()
    private var items: [Data] = []
    private var waiter: CheckedContinuation<Data, Error>?
    private var finished: Error?

    func push(_ d: Data) {
        lock.lock()
        if let w = waiter { waiter = nil; lock.unlock(); w.resume(returning: d) }
        else { items.append(d); lock.unlock() }
    }

    func finish(_ e: Error = StreamError.closed) {
        lock.lock()
        if finished == nil { finished = e }
        let w = waiter; waiter = nil
        lock.unlock()
        w?.resume(throwing: e)
    }

    func next() async throws -> Data {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, Error>) in
            lock.lock()
            if !items.isEmpty { let d = items.removeFirst(); lock.unlock(); c.resume(returning: d) }
            else if let e = finished { lock.unlock(); c.resume(throwing: e) }
            else { waiter = c; lock.unlock() }
        }
    }
}

/// Simple thread-safe box for values mutated from callbacks.
final class Locked<T> {
    private let lock = NSLock()
    private var v: T
    init(_ v: T) { self.v = v }
    var value: T { lock.lock(); defer { lock.unlock() }; return v }
    func update(_ f: (inout T) -> Void) { lock.lock(); f(&v); lock.unlock() }
}

/// Gate that blocks async callers until opened.
final class Gate {
    private let q = AsyncQueue()
    private let lock = NSLock()
    private var open = false
    func wait() async {
        lock.lock(); let o = open; lock.unlock()
        if o { return }
        _ = try? await q.next()
    }
    func release() {
        lock.lock(); open = true; lock.unlock()
        q.finish()
    }
}

/// Unix-socket server that accepts connections and never says anything.
final class SilentUnixListener {
    private let fd: Int32
    private let path: String
    init(path: String) {
        self.path = path
        unlink(path)
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        listen(fd, 4)
    }
    func close() { Darwin.close(fd); unlink(path) }
}
