import Foundation

/// Growable FIFO byte buffer with O(1) amortised consumption (no copy of the remainder per read).
public struct ByteBuffer {
    private var storage: [UInt8] = []
    private var head = 0

    public init() {}
    public var count: Int { storage.count - head }

    public mutating func append(_ d: Data) { storage.append(contentsOf: d) }
    public mutating func append(_ b: [UInt8]) { storage.append(contentsOf: b) }

    /// Removes and returns exactly `n` bytes, or nil if fewer are buffered.
    public mutating func take(_ n: Int) -> [UInt8]? {
        guard n >= 0, count >= n else { return nil }
        let out = Array(storage[head..<head + n])
        head += n
        compactIfNeeded()
        return out
    }

    public mutating func takeAll() -> [UInt8] { take(count) ?? [] }

    /// Removes everything up to and including `marker`; returns the bytes before it.
    public mutating func take(upTo marker: [UInt8]) -> [UInt8]? {
        guard !marker.isEmpty, count >= marker.count else { return nil }
        var i = head
        let last = storage.count - marker.count
        while i <= last {
            if storage[i] == marker[0] && storage[i..<i + marker.count].elementsEqual(marker) {
                let out = Array(storage[head..<i])
                head = i + marker.count
                compactIfNeeded()
                return out
            }
            i += 1
        }
        return nil
    }

    private mutating func compactIfNeeded() {
        if head == storage.count { storage.removeAll(keepingCapacity: true); head = 0 }
        else if head > 1 << 16 && head * 2 > storage.count { storage.removeFirst(head); head = 0 }
    }
}
