import Darwin
import Foundation
import VPNGateCore

/// Async byte-chunk queue used by the in-memory stream.
final class AsyncQueue {
    private let lock = NSLock()
    private var items: [Data] = []
    private var waiter: CheckedContinuation<Data, Error>?
    private var finished: Error?

    func push(_ d: Data) {
        lock.lock()
        if let w = waiter { waiter = nil; lock.unlock(); w.resume(returning: d) } else { items.append(d); lock.unlock() }
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
            if !items.isEmpty {
                let d = items.removeFirst(); lock.unlock(); c.resume(returning: d)
            } else if let e = finished {
                lock.unlock(); c.resume(throwing: e)
            } else {
                waiter = c; lock.unlock()
            }
        }
    }
}

/// Gate that blocks async callers until opened.
final class Gate {
    private let q = AsyncQueue()
    private let lock = NSLock()
    private var open = false
    func wait() async {
        if lock.withLock({ open }) { return }
        _ = try? await q.next()
    }
    func release() {
        lock.lock(); open = true; lock.unlock()
        q.finish()
    }
}
