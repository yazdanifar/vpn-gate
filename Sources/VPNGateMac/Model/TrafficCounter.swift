import Foundation

final class TrafficCounter: ObservableObject {
    @Published private(set) var bytesIn: UInt64 = 0
    @Published private(set) var bytesOut: UInt64 = 0
    /// Bytes per second, smoothed over recent samples.
    @Published private(set) var speedIn: Double = 0
    @Published private(set) var speedOut: Double = 0
    private var sample: (at: Date, i: UInt64, o: UInt64)?

    func set(_ i: UInt64, _ o: UInt64) {
        if bytesIn != i { bytesIn = i }
        if bytesOut != o { bytesOut = o }
        let now = Date()
        guard let prev = sample else { sample = (now, i, o); return }
        let dt = now.timeIntervalSince(prev.at)
        guard dt >= 1 else { return }  // wait for a long enough window; events may arrive faster
        sample = (now, i, o)
        if i < prev.i || o < prev.o { speedIn = 0; speedOut = 0; return }  // counters restarted (new session)
        let alpha = 0.5
        let newIn = Double(i - prev.i) / dt, newOut = Double(o - prev.o) / dt
        speedIn = speedIn * (1 - alpha) + newIn * alpha
        speedOut = speedOut * (1 - alpha) + newOut * alpha
        if speedIn < 1 { speedIn = 0 }
        if speedOut < 1 { speedOut = 0 }
    }
}
