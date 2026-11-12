import Foundation

/// What the list window's toolbar shows, kept apart from `AppModel` so the toolbar's open menus are not rebuilt (and
/// closed by macOS) every time something unrelated changes: probe results, log lines, traffic, helper polling.
/// Every setter assigns only when the value really changes, because assigning a `@Published` value republishes even
/// when it is equal.
@MainActor
final class ListFacets: ObservableObject {
    /// "All" followed by the countries of the current list, sorted.
    @Published private(set) var countries: [String] = ["All"]
    /// Logging-policy filter in weeks (-1 = any).
    @Published private(set) var maxLogWeeks = -1
    @Published private(set) var loading = false

    func setCountries(from servers: [VPNServer]) {
        let next = ["All"] + Set(servers.map(\.countryLong)).sorted()
        if next != countries { countries = next }
    }
    func setMaxLogWeeks(_ v: Int) { if v != maxLogWeeks { maxLogWeeks = v } }
    func setLoading(_ v: Bool) { if v != loading { loading = v } }
}

/// Results of Test Connection, kept out of `AppModel` so a run (one update per relay) only redraws the table.
/// Updates from the workers are gathered and published together at most every `flushInterval`.
@MainActor
final class ProbeStore: ObservableObject {
    @Published private(set) var outcomes: [String: ProbeOutcome] = [:]
    /// Locked rather than relying on the main actor alone: under `dispatchMain()` (the test runner) main-actor jobs
    /// run on GCD worker threads, which ThreadSanitizer reports as a race.
    private let lock = NSLock()
    private var pending: [String: ProbeOutcome] = [:]
    private var flushScheduled = false
    nonisolated static let flushMilliseconds = 250

    /// Replaces everything at once (a new run's "queued" state, or a test's fixture).
    func replace(_ next: [String: ProbeOutcome]) {
        lock.withLock { pending = [:] }
        outcomes = next
    }

    /// Puts `outcome` on every id now, keeping the other rows; drops updates of an earlier run still waiting.
    func setAll(_ ids: [String], _ outcome: ProbeOutcome) {
        lock.withLock { pending = [:] }
        var next = outcomes
        for id in ids { next[id] = outcome }
        outcomes = next
    }

    /// One relay's new state; published with the others that arrive in the same interval.
    func set(_ id: String, _ outcome: ProbeOutcome) {
        let schedule = lock.withLock { () -> Bool in
            pending[id] = outcome
            if flushScheduled { return false }
            flushScheduled = true
            return true
        }
        guard schedule else { return }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(Self.flushMilliseconds) * 1_000_000)
            self?.flush()
        }
    }

    private func flush() {
        let batch = lock.withLock { () -> [String: ProbeOutcome] in
            flushScheduled = false
            defer { pending = [:] }
            return pending
        }
        guard !batch.isEmpty else { return }
        var next = outcomes
        for (id, o) in batch { next[id] = o }
        outcomes = next
    }
}
