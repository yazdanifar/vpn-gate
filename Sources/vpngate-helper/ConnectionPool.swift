import Foundation
import VPNGateCore

/// Manages multiple TCP connections for a single SoftEther session (Protocol.c ConnectionPool).
/// Sockets multiplex received Ethernet frames and balance outgoing frame batches.
final class ConnectionPool {
    /// Which way a half-connection socket may carry application data (Connection.c:109-113's IsSendDirection /
    /// IsRecvDirection, from the client's point of view). A normal (non-half-connection) session only ever uses
    /// `.both`, which keeps every socket eligible to send and receive exactly as before this existed.
    enum SocketDirection {
        case both, serverToClient, clientToServer
        var canSend: Bool { self == .both || self == .clientToServer }
        var canReceive: Bool { self == .both || self == .serverToClient }

        /// The server's `direction` field on an additional_connect reply (0 both, 1 server->client, 2 client->server,
        /// Protocol.c:5257); anything else (including absent, the normal case) is `.both`.
        init(wireValue: UInt32?) {
            switch wireValue {
            case 1: self = .serverToClient
            case 2: self = .clientToServer
            default: self = .both
            }
        }
    }

    struct SocketEntry {
        let id: Int
        let stream: ByteStream
        let direction: SocketDirection
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

    /// Adds an established socket to the pool and starts reading frames from it. `direction` is `.both` for a
    /// normal session; under half connection, a client-to-server-only socket is never expected to receive
    /// application data, so the idle-read watchdog is skipped for it (silence there is correct, not a stall).
    func add(stream: ByteStream, useCompress: Bool, timeoutMs: Int, direction: SocketDirection = .both) {
        lock.lock()
        if isClosed {
            lock.unlock()
            stream.cancel()
            return
        }
        let id = nextId
        nextId += 1
        var entry = SocketEntry(id: id, stream: stream, direction: direction)

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
            guard direction.canReceive else { return }   // send-only: never receiving is expected, not a timeout
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

    /// Selects the least-loaded socket eligible to send (every socket, in a normal session) and sends the data.
    func send(data: Data, byteCount: Int) async throws {
        let stream: ByteStream? = lock.withLock {
            guard !isClosed, !sockets.isEmpty else { return nil }
            // Pick least-loaded by bytesOut, among sockets this direction allows us to send on.
            let sorted = sockets.values.filter { $0.direction.canSend }.sorted { $0.bytesOut < $1.bytesOut }
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

    /// Broadcasts a keep-alive packet to every socket eligible to send (receive-only sockets never send anything,
    /// Connection.c's keepalive loop is itself gated by IsSendDirection).
    func broadcastKeepAlive(_ data: Data) async {
        let list: [ByteStream] = lock.withLock {
            guard !isClosed else { return [] }
            return sockets.values.filter { $0.direction.canSend }.map(\.stream)
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
