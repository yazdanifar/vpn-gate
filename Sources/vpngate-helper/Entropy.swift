import Foundation

/// Every random value the protocol layer draws (login padding, UDP keys, DHCP xid, MAC). Production uses the system
/// generator; the golden transcripts inject a recording one so the exchanges are byte-reproducible in other languages.
struct Entropy {
    var bytes: (Int) -> Data
    /// Uniform in `0..<n` (n > 0).
    var below: (Int) -> Int

    static let system = Entropy(bytes: HostUniqueId.secureRandom, below: { Int.random(in: 0..<$0) })

    /// Uniform in `range` (non-empty), drawn through `below` so a recorder sees one draw per call.
    func int(in range: ClosedRange<Int>) -> Int { range.lowerBound + below(range.count) }
}

/// What the login pack says about the machine it runs on (the golden transcripts pin it).
struct ClientEnvironment {
    var osName: String
    var osVersion: String
    var hostname: String

    static var current: ClientEnvironment {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return ClientEnvironment(
            osName: "macOS", osVersion: "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            hostname: ProcessInfo.processInfo.hostName)
    }
}
