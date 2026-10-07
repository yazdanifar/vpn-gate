import Foundation

/// Minimal test registry/runner (XCTest is not available with the Command Line Tools alone).
struct TestCase {
    let name: String
    let live: Bool
    let timeout: Double
    let body: () async throws -> Void
}

nonisolated(unsafe) var registry: [TestCase] = []
private let failLock = NSLock()
nonisolated(unsafe) private var failures: [String] = []

func test(_ name: String, timeout: Double = 20, _ body: @escaping () async throws -> Void) {
    registry.append(TestCase(name: name, live: false, timeout: timeout, body: body))
}

func liveTest(_ name: String, timeout: Double = 60, _ body: @escaping () async throws -> Void) {
    registry.append(TestCase(name: name, live: true, timeout: timeout, body: body))
}

func fail(_ msg: String, file: StaticString = #file, line: UInt = #line) {
    failLock.lock(); defer { failLock.unlock() }
    failures.append("    \((String(describing: file) as NSString).lastPathComponent):\(line): \(msg)")
}

func expect(_ cond: @autoclosure () -> Bool, _ msg: String = "expectation failed",
            file: StaticString = #file, line: UInt = #line) {
    if !cond() { fail(msg, file: file, line: line) }
}

func expectA(_ cond: @autoclosure () async -> Bool, _ msg: String = "expectation failed",
            file: StaticString = #file, line: UInt = #line) async {
    if !(await cond()) { fail(msg, file: file, line: line) }
}

func expectEqual<T: Equatable>(_ a: @autoclosure () -> T, _ b: @autoclosure () -> T, _ msg: String = "",
                               file: StaticString = #file, line: UInt = #line) {
    let (x, y) = (a(), b())
    if x != y { fail("\(msg) expected \(y), got \(x)", file: file, line: line) }
}

func expectThrows<T>(_ body: @autoclosure () throws -> T, _ msg: String = "expected an error",
                     file: StaticString = #file, line: UInt = #line) {
    do { _ = try body(); fail(msg, file: file, line: line) } catch {}
}

/// Polls until `cond` holds (or `timeout` elapses).
@discardableResult
func eventually(_ timeout: Double = 3, _ cond: () -> Bool) async -> Bool {
    let end = Date().addingTimeInterval(timeout)
    while Date() < end {
        if cond() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return cond()
}

/// Like `eventually`, for conditions that must hop to another actor (e.g. read @MainActor state).
@discardableResult
func eventuallyA(_ timeout: Double = 3, _ cond: () async -> Bool) async -> Bool {
    let end = Date().addingTimeInterval(timeout)
    while Date() < end {
        if await cond() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return await cond()
}

struct SeededRNG: RandomNumberGenerator {
    private var s: UInt64
    init(_ seed: UInt64) { s = seed == 0 ? 0x9E3779B97F4A7C15 : seed }
    mutating func next() -> UInt64 {      // xorshift64*
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27
        return s &* 2685821657736338717
    }
}

/// Usage: tests [--list] [--live] [--seed N] [substring...]
func runAllTests(args: [String]) async -> Int32 {
    var filters = args.filter { !$0.hasPrefix("--") }
    if let i = args.firstIndex(of: "--seed"), i + 1 < args.count { filters.removeAll { $0 == args[i + 1] } }
    let live = args.contains("--live")
    var selected = registry.filter { t in (live || !t.live) && (filters.isEmpty || filters.contains { t.name.contains($0) }) }
    if args.contains("--exact") { selected = registry.filter { filters.contains($0.name) } }
    if args.contains("--list") { registry.forEach { print($0.name) }; return 0 }

    var passed = 0, failed = 0
    var failedNames: [String] = []
    for t in selected {
        failLock.lock(); failures = []; failLock.unlock()
        let start = Date()
        let finished = await withTaskGroup(of: Bool.self) { g -> Bool in
            g.addTask { do { try await t.body(); return true } catch { fail("threw \(error)"); return true } }
            g.addTask { try? await Task.sleep(nanoseconds: UInt64(t.timeout * 1e9)); return false }
            let r = await g.next() ?? false
            g.cancelAll()
            return r
        }
        if !finished { fail("timed out after \(t.timeout)s") }
        failLock.lock(); let f = failures; failLock.unlock()
        let ms = Int(Date().timeIntervalSince(start) * 1000)
        if f.isEmpty { passed += 1; print("PASS \(t.name) (\(ms)ms)") }
        else { failed += 1; failedNames.append(t.name); print("FAIL \(t.name) (\(ms)ms)"); f.forEach { print($0) } }
    }
    print("\n\(passed) passed, \(failed) failed, \(selected.count) run")
    if failed > 0 { print("failed: \(failedNames.joined(separator: ", "))") }
    return failed == 0 ? 0 : 1
}
