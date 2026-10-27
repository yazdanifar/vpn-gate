// Mirrors of the engine's JSON types (crates/vpngate-core). The engine owns the logic; the app only needs the
// shapes, the editors' validation and the list formatting. Golden JSON in Tests/Fixtures/golden pins them.
import Foundation

public struct VPNServer: Identifiable, Codable, Hashable {
    /// The DDNS host name is the only unique key: the same IP can appear several times on different ports.
    public var id: String { hostName }
    public var hostName: String
    public var ip: String
    public var score: Int
    public var ping: Int
    public var speed: Int  // bits per second
    public var countryLong: String
    public var countryShort: String
    public var sessions: Int
    public var uptimeMs: Int
    public var totalUsers: Int
    public var totalTraffic: Int  // bytes
    public var logType: String
    public var operatorName: String
    public var message: String
    /// Port from the server's OpenVPN config (tcp or udp); 0 if unknown. SoftEther listens for SSL-VPN on
    /// the ports it advertises, so it is the best first guess even for udp entries.
    public var listedPort: Int
    public var listedProto: String

    // Full parity fields from VPNGate.dat and Cedar
    public var fqdn: String
    public var sslPorts: [UInt16]
    public var udpPort: UInt16?
    public var openVpnUdpPorts: [UInt16]
    public var l2tp: Bool
    public var os: String?
    public var soft: String?
    public var build: Int?
    public var owner: String?
    public var abuse: String?
    public var numLogin: Int64?
    public var noLog: Bool
    public var logPermanent: Bool
    /// More VPNGate.dat host fields (client_exe.c host record, 9122-9230); 0 / nil for CSV-sourced servers.
    public var name: String?
    public var pingToGoogle: Int
    public var sendSize: UInt64
    public var recvSize: UInt64
    public var isKernelModeNAT: Bool
    /// Not stored or sent anywhere: the "Test from this Mac" result as a sort key (see `ProbeOutcome.sortRank`),
    /// filled in by the list view just before sorting.
    public var testRank = 0

    public init(
        hostName: String, ip: String, score: Int = 0, ping: Int = 0, speed: Int = 0,
        countryLong: String = "", countryShort: String = "", sessions: Int = 0,
        uptimeMs: Int = 0, totalUsers: Int = 0, totalTraffic: Int = 0,
        logType: String = "", operatorName: String = "", message: String = "",
        listedPort: Int = 0, listedProto: String = "",
        fqdn: String = "", sslPorts: [UInt16] = [], udpPort: UInt16? = nil,
        openVpnUdpPorts: [UInt16] = [], l2tp: Bool = false, os: String? = nil,
        soft: String? = nil, build: Int? = nil, owner: String? = nil, abuse: String? = nil,
        numLogin: Int64? = nil, noLog: Bool = false, logPermanent: Bool = false,
        name: String? = nil, pingToGoogle: Int = 0, sendSize: UInt64 = 0, recvSize: UInt64 = 0,
        isKernelModeNAT: Bool = false
    ) {
        self.hostName = hostName.isEmpty ? fqdn : hostName
        self.ip = ip; self.score = score; self.ping = ping; self.speed = speed
        self.countryLong = countryLong; self.countryShort = countryShort; self.sessions = sessions
        self.uptimeMs = uptimeMs; self.totalUsers = totalUsers; self.totalTraffic = totalTraffic
        self.logType = logType; self.operatorName = operatorName; self.message = message
        self.listedPort = listedPort; self.listedProto = listedProto
        self.fqdn = fqdn.isEmpty ? hostName : fqdn
        self.sslPorts = sslPorts; self.udpPort = udpPort; self.openVpnUdpPorts = openVpnUdpPorts
        self.l2tp = l2tp; self.os = os; self.soft = soft; self.build = build
        self.owner = owner; self.abuse = abuse; self.numLogin = numLogin
        self.noLog = noLog; self.logPermanent = logPermanent
        self.name = name; self.pingToGoogle = pingToGoogle; self.sendSize = sendSize; self.recvSize = recvSize
        self.isKernelModeNAT = isKernelModeNAT
    }

    private enum CodingKeys: String, CodingKey {
        case hostName, ip, score, ping, speed, countryLong, countryShort, sessions, uptimeMs, totalUsers,
            totalTraffic, logType, operatorName, message, listedPort, listedProto
        case tcpPort  // written by the first app version, before ports/protocols were recorded
        case fqdn, sslPorts, udpPort, openVpnUdpPorts, l2tp, os, soft, build, owner, abuse, numLogin,
            noLog, logPermanent, name, pingToGoogle, sendSize, recvSize, isKernelModeNAT
    }

    /// Caches written by older versions must still load (otherwise the table is empty until the download ends).
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        let rawHost = try c.decodeIfPresent(String.self, forKey: .hostName) ?? ""
        let rawFqdn = try c.decodeIfPresent(String.self, forKey: .fqdn) ?? ""
        hostName = rawHost.isEmpty ? rawFqdn : rawHost
        fqdn = rawFqdn.isEmpty ? rawHost : rawFqdn
        ip = try c.decode(String.self, forKey: .ip)
        score = try c.decodeIfPresent(Int.self, forKey: .score) ?? 0
        ping = try c.decodeIfPresent(Int.self, forKey: .ping) ?? 0
        speed = try c.decodeIfPresent(Int.self, forKey: .speed) ?? 0
        countryLong = try c.decodeIfPresent(String.self, forKey: .countryLong) ?? ""
        countryShort = try c.decodeIfPresent(String.self, forKey: .countryShort) ?? ""
        sessions = try c.decodeIfPresent(Int.self, forKey: .sessions) ?? 0
        uptimeMs = try c.decodeIfPresent(Int.self, forKey: .uptimeMs) ?? 0
        totalUsers = try c.decodeIfPresent(Int.self, forKey: .totalUsers) ?? 0
        totalTraffic = try c.decodeIfPresent(Int.self, forKey: .totalTraffic) ?? 0
        logType = try c.decodeIfPresent(String.self, forKey: .logType) ?? ""
        operatorName = try c.decodeIfPresent(String.self, forKey: .operatorName) ?? ""
        message = try c.decodeIfPresent(String.self, forKey: .message) ?? ""
        listedPort =
            try c.decodeIfPresent(Int.self, forKey: .listedPort)
            ?? c.decodeIfPresent(Int.self, forKey: .tcpPort) ?? 0
        listedProto = try c.decodeIfPresent(String.self, forKey: .listedProto) ?? ""

        sslPorts = try c.decodeIfPresent([UInt16].self, forKey: .sslPorts) ?? []
        udpPort = try c.decodeIfPresent(UInt16.self, forKey: .udpPort)
        openVpnUdpPorts = try c.decodeIfPresent([UInt16].self, forKey: .openVpnUdpPorts) ?? []
        l2tp = try c.decodeIfPresent(Bool.self, forKey: .l2tp) ?? false
        os = try c.decodeIfPresent(String.self, forKey: .os)
        soft = try c.decodeIfPresent(String.self, forKey: .soft)
        build = try c.decodeIfPresent(Int.self, forKey: .build)
        owner = try c.decodeIfPresent(String.self, forKey: .owner)
        abuse = try c.decodeIfPresent(String.self, forKey: .abuse)
        numLogin = try c.decodeIfPresent(Int64.self, forKey: .numLogin)
        noLog = try c.decodeIfPresent(Bool.self, forKey: .noLog) ?? false
        logPermanent = try c.decodeIfPresent(Bool.self, forKey: .logPermanent) ?? false
        name = try c.decodeIfPresent(String.self, forKey: .name)
        pingToGoogle = try c.decodeIfPresent(Int.self, forKey: .pingToGoogle) ?? 0
        sendSize = try c.decodeIfPresent(UInt64.self, forKey: .sendSize) ?? 0
        recvSize = try c.decodeIfPresent(UInt64.self, forKey: .recvSize) ?? 0
        isKernelModeNAT = try c.decodeIfPresent(Bool.self, forKey: .isKernelModeNAT) ?? false
    }

    public func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(hostName, forKey: .hostName); try c.encode(ip, forKey: .ip)
        try c.encode(score, forKey: .score); try c.encode(ping, forKey: .ping); try c.encode(speed, forKey: .speed)
        try c.encode(countryLong, forKey: .countryLong); try c.encode(countryShort, forKey: .countryShort)
        try c.encode(sessions, forKey: .sessions); try c.encode(uptimeMs, forKey: .uptimeMs)
        try c.encode(totalUsers, forKey: .totalUsers); try c.encode(totalTraffic, forKey: .totalTraffic)
        try c.encode(logType, forKey: .logType); try c.encode(operatorName, forKey: .operatorName)
        try c.encode(message, forKey: .message)
        try c.encode(listedPort, forKey: .listedPort); try c.encode(listedProto, forKey: .listedProto)
        try c.encode(fqdn, forKey: .fqdn); try c.encode(sslPorts, forKey: .sslPorts)
        try c.encode(udpPort, forKey: .udpPort); try c.encode(openVpnUdpPorts, forKey: .openVpnUdpPorts)
        try c.encode(l2tp, forKey: .l2tp); try c.encode(os, forKey: .os)
        try c.encode(soft, forKey: .soft); try c.encode(build, forKey: .build)
        try c.encode(owner, forKey: .owner); try c.encode(abuse, forKey: .abuse)
        try c.encode(numLogin, forKey: .numLogin); try c.encode(noLog, forKey: .noLog)
        try c.encode(logPermanent, forKey: .logPermanent)
        try c.encodeIfPresent(name, forKey: .name); try c.encode(pingToGoogle, forKey: .pingToGoogle)
        try c.encode(sendSize, forKey: .sendSize); try c.encode(recvSize, forKey: .recvSize)
        try c.encode(isKernelModeNAT, forKey: .isKernelModeNAT)
    }

    /// The Windows client's port order (client_exe.c FUN_004117c0, 7569-7640): 443, 992, 995, 465, 585, 993, 22
    /// (only those the host offers), then the host's other ports in their original order.
    public static let preferredPorts: [UInt16] = [443, 992, 995, 465, 585, 993, 22]

    public static func portPriority(_ ports: [UInt16]) -> [UInt16] {
        var out = preferredPorts.filter { ports.contains($0) }
        for p in ports where !out.contains(p) { out.append(p) }
        return out
    }

    /// SSL ports in the Windows priority order.
    public var prioritizedSslPorts: [UInt16] { Self.portPriority(sslPorts) }

    /// Port to try first when connecting: the first SSL port in priority order, then listedPort.
    public var connectPort: Int? {
        if let first = prioritizedSslPorts.first, InputValidation.isValidPort(Int(first)) {
            return Int(first)
        }
        return InputValidation.isValidPort(listedPort) ? listedPort : nil
    }

    public var flag: String {
        let base: UInt32 = 127397
        return countryShort.uppercased().unicodeScalars.compactMap { Unicode.Scalar(base + $0.value) }
            .map(String.init).joined()
    }
}

/// Text of the list table, following the Windows client (client_exe.c FUN_00525490 / FUN_00525da0 / FUN_00525490's
/// status line, 149575-149860).
public enum ListFormat {
    /// Uptime: up to 1 h in minutes, up to 24 h in hours, beyond that in days. The cut-offs are the original's
    /// `< 3,600,001 ms` and `< 86,400,001 ms`; the words are the client string table's VGC_UPTIME_MIN / _HOUR / _DAY
    /// ("%u mins" / "%u hours" / "%u days"), with the singular for exactly one.
    public static func uptime(ms: Int) -> String {
        let ms = max(0, ms)
        func unit(_ n: Int, _ word: String) -> String { "\(n) \(word)\(n == 1 ? "" : "s")" }
        if ms < 3_600_001 { return unit(ms / 60_000, "min") }
        if ms < 86_400_001 { return unit(ms / 3_600_000, "hour") }
        return unit(ms / 86_400_000, "day")
    }

    /// VGC_NUM_VPN: "%u sessions".
    public static func sessions(_ n: Int) -> String { "\(n) session\(n == 1 ? "" : "s")" }

    /// VGC_NUM_LOGIN: "%S logins" (the count is printed with thousands separators).
    public static func logins(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal; f.locale = Locale(identifier: "en_US")
        return "\(f.string(from: NSNumber(value: n)) ?? String(n)) login\(n == 1 ? "" : "s")"
    }

    /// Logging policy column: VGC_LOG_PERMANENT / VGC_LOG_2WEEKS / VGC_LOG_NONE ("Permanent" / "2 Weeks" / "No Logs").
    /// Anything the list does not classify is shown as the server sent it.
    public static func logging(_ logType: String) -> String {
        let t = logType.lowercased()
        if t.hasPrefix("no") { return "No Logs" }
        if t.contains("2") && t.contains("week") { return "2 Weeks" }
        if t.hasPrefix("perm") { return "Permanent" }
        return logType.isEmpty ? "-" : logType
    }

    /// "<PingToGoogle>, <PingToJapan>", each as "<n> ms" or "-" when 0 (the original prints "-" for 0).
    public static func pings(google: Int, japan: Int) -> String {
        func one(_ v: Int) -> String { v == 0 ? "-" : "\(v) ms" }
        return "\(one(google)), \(one(japan))"
    }

    /// UDP column: VGC_UDP_AVAILABLE ("UDP OK") when the host has a UDP port, else "-".
    public static func udp(_ port: UInt16?) -> String { port == nil ? "-" : "UDP OK" }

    /// List age as the original's status line classifies it: within 24 h (inclusive of the original's
    /// `< 86,400,001 ms`) the list is OK, older it is "stale". (Accepting a download uses 36 h; the UI uses 24 h.)
    public static func isListOK(timestamp: Date, now: Date) -> Bool {
        abs(now.timeIntervalSince(timestamp)) * 1000 < 86_400_001
    }
}

public enum ServerProbe {
    /// How many of a relay's ports are tried before giving up (in the Windows client's priority order).
    public static let maxPorts = 3

    public static func ports(for server: VPNServer) -> [UInt16] {
        var out = server.prioritizedSslPorts
        if out.isEmpty, let p = server.connectPort { out = [UInt16(p)] }
        if out.isEmpty { out = [443] }
        return Array(out.prefix(maxPorts))
    }
}
