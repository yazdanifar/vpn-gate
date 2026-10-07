import Foundation
import VPNGateCore

/// Manages multiple TCP connections for a single SoftEther session (Protocol.c ConnectionPool).
/// Sockets multiplex received Ethernet frames and balance outgoing frame batches.
final class ConnectionPool {
    struct SocketEntry {
        let id: Int
        let stream: ByteStream
        var bytesOut: UInt64 = 0
        var readerTask: Task<Void, Never>?
    }

    private let lock = NSLock()
    private var sockets: [Int: SocketEntry] = [:]
    private var nextId = 1
    private var roundRobinIndex = 0
    private var isClosed = false

    var onFrame: (([UInt8]) -> Void)?
    var onClose: ((Error?) -> Void)?
    var onByteCount: ((_ bytesIn: Int, _ bytesOut: Int) -> Void)?

    init() {}

    var activeCount: Int {
        lock.lock(); defer { lock.unlock() }
        return sockets.count
    }

    /// Adds an established socket to the pool and starts reading frames from it.
    func add(stream: ByteStream, useCompress: Bool, timeoutMs: Int) {
        lock.lock()
        if isClosed {
            lock.unlock()
            stream.cancel()
            return
        }
        let id = nextId
        nextId += 1
        var entry = SocketEntry(id: id, stream: stream)

        let rxLock = NSLock()
        var lastRxDate = Date()
        func touchRx() { rxLock.lock(); lastRxDate = Date(); rxLock.unlock() }
        func idleMs() -> Double { rxLock.lock(); let t = -lastRxDate.timeIntervalSinceNow * 1000; rxLock.unlock(); return t }

        let reader = Task.detached { [weak self] in
            do {
                var decoder = DataPhaseDecoder(useCompress: useCompress)
                var chunk = stream.buffer.takeAll()
                while true {
                    for item in try decoder.feed(chunk) {
                        if case .frame(let d) = item {
                            self?.onByteCount?(d.count, 0)
                            self?.onFrame?(d)
                        }
                    }
                    chunk = [UInt8](try await stream.readChunk())
                    touchRx()
                }
            } catch {
                self?.remove(id: id, error: error)
            }
        }

        let watchdog = Task.detached { [weak self] in
            let pollNs = UInt64(max(timeoutMs / 2, 50)) * 1_000_000
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: pollNs)
                guard !Task.isCancelled else { return }
                if idleMs() >= Double(timeoutMs) {
                    self?.remove(id: id, error: StreamError.protocolError("Read idle timeout (\(timeoutMs) ms)"))
                    return
                }
            }
        }

        entry.readerTask = Task.detached {
            _ = await reader.result
            watchdog.cancel()
        }

        sockets[id] = entry
        lock.unlock()
    }

    /// Selects the least-loaded socket and sends the encoded data.
    func send(data: Data, byteCount: Int) async throws {
        let stream: ByteStream? = lock.withLock {
            guard !isClosed, !sockets.isEmpty else { return nil }
            // Pick least-loaded by bytesOut
            let sorted = sockets.values.sorted { $0.bytesOut < $1.bytesOut }
            guard let chosen = sorted.first else { return nil }
            sockets[chosen.id]?.bytesOut += UInt64(byteCount)
            return chosen.stream
        }

        guard let stream = stream else {
            throw StreamError.closed
        }

        try await stream.send(data)
        onByteCount?(0, byteCount)
    }

    /// Broadcasts a keep-alive packet to all active sockets.
    func broadcastKeepAlive(_ data: Data) async {
        let list: [ByteStream] = lock.withLock {
            guard !isClosed else { return [] }
            return sockets.values.map(\.stream)
        }
        for s in list {
            try? await s.send(data)
        }
    }

    private func remove(id: Int, error: Error?) {
        let shouldCloseSession: Bool = lock.withLock {
            guard let removed = sockets.removeValue(forKey: id) else { return false }
            removed.readerTask?.cancel()
            removed.stream.cancel()
            return sockets.isEmpty && !isClosed
        }

        if shouldCloseSession {
            close(error)
        }
    }

    func close(_ error: Error? = nil) {
        let entries: [SocketEntry] = lock.withLock {
            if isClosed { return [] }
            isClosed = true
            let list = Array(sockets.values)
            sockets.removeAll()
            return list
        }

        for e in entries {
            e.readerTask?.cancel()
            e.stream.cancel()
        }

        onClose?(error)
    }
}
