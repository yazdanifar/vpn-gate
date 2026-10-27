import Darwin
import Foundation

// Used by the app test binary (scripts/test.sh).

func tempPath(_ name: String) -> String {
    let dir = NSTemporaryDirectory() + "vpngate-tests-\(getpid())"
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    return dir + "/" + name
}

func fixture(_ name: String, file: String = #filePath) -> String {
    let root = URL(fileURLWithPath: file).deletingLastPathComponent().deletingLastPathComponent()
    return (try? String(contentsOf: root.appendingPathComponent("Fixtures/" + name), encoding: .utf8)) ?? ""
}

func fixtureData(_ name: String, file: String = #filePath) -> Data {
    let root = URL(fileURLWithPath: file).deletingLastPathComponent().deletingLastPathComponent()
    return (try? Data(contentsOf: root.appendingPathComponent("Fixtures/" + name))) ?? Data()
}

// UserDefaults is documented thread-safe but older SDKs do not say so; the tests hand throwaway suites to @Sendable closures.
extension UserDefaults: @unchecked @retroactive Sendable {}

/// Simple thread-safe box for values mutated from callbacks.
final class Locked<T>: @unchecked Sendable {  // every access goes through `lock`
    private let lock = NSLock()
    private var v: T
    init(_ v: T) { self.v = v }
    var value: T { lock.lock(); defer { lock.unlock() }; return v }
    func update(_ f: (inout T) -> Void) { lock.lock(); f(&v); lock.unlock() }
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
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        listen(fd, 4)
    }
    func close() { Darwin.close(fd); unlink(path) }
}
