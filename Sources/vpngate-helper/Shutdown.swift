import Foundation

/// Runs `cleanup` and then `finish` when one of `signals` arrives. The handler runs on a dispatch queue, not
/// in signal context, so cleanup may take locks, spawn processes and allocate (a raw `signal()` handler may not).
final class ShutdownCoordinator {
    private var sources: [DispatchSourceSignal] = []
    private let once = NSLock()
    private var done = false

    init(signals: [Int32], cleanup: @escaping () -> Void, finish: @escaping () -> Void = { exit(0) }) {
        for sig in signals {
            signal(sig, SIG_IGN)  // the dispatch source takes over delivery
            let s = DispatchSource.makeSignalSource(signal: sig, queue: DispatchQueue(label: "vpngate.shutdown.\(sig)"))
            s.setEventHandler { [weak self] in
                guard let self = self else { return }
                self.once.lock()
                let first = !self.done; self.done = true
                self.once.unlock()
                if first { cleanup(); finish() }
            }
            s.resume()
            sources.append(s)
        }
    }
}
