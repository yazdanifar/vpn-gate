import Foundation

public struct VPNServer: Identifiable, Codable, Hashable {
    /// The DDNS host name is the only unique key: the same IP can appear several times on different ports.
    public var id: String { hostName }
    public var hostName: String
    public var ip: String
    public var score: Int
    public var ping: Int
    public var speed: Int          // bits per second
    public var countryLong: String
    public var countryShort: String
    public var sessions: Int
    public var uptimeMs: Int
    public var totalUsers: Int
    public var totalTraffic: Int   // bytes
    public var logType: String
    public var operatorName: String
    public var message: String
    /// Port from the server's OpenVPN config (tcp or udp); 0 if unknown. SoftEther listens for SSL-VPN on
    /// the ports it advertises, so it is the best first guess even for udp entries.
    public var listedPort: Int
    public var listedProto: String

    public init(hostName: String, ip: String, score: Int, ping: Int, speed: Int, countryLong: String,
                countryShort: String, sessions: Int, uptimeMs: Int, totalUsers: Int, totalTraffic: Int,
                logType: String, operatorName: String, message: String, listedPort: Int, listedProto: String) {
        self.hostName = hostName; self.ip = ip; self.score = score; self.ping = ping; self.speed = speed
        self.countryLong = countryLong; self.countryShort = countryShort; self.sessions = sessions
        self.uptimeMs = uptimeMs; self.totalUsers = totalUsers; self.totalTraffic = totalTraffic
        self.logType = logType; self.operatorName = operatorName; self.message = message
        self.listedPort = listedPort; self.listedProto = listedProto
    }

    private enum CodingKeys: String, CodingKey {
        case hostName, ip, score, ping, speed, countryLong, countryShort, sessions, uptimeMs, totalUsers,
             totalTraffic, logType, operatorName, message, listedPort, listedProto
        case tcpPort            // written by the first app version, before ports/protocols were recorded
    }

    /// Caches written by older versions must still load (otherwise the table is empty until the download ends).
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        hostName = try c.decode(String.self, forKey: .hostName)
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
        listedPort = try c.decodeIfPresent(Int.self, forKey: .listedPort)
            ?? c.decodeIfPresent(Int.self, forKey: .tcpPort) ?? 0
        listedProto = try c.decodeIfPresent(String.self, forKey: .listedProto) ?? ""
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
    }

    /// Port to try first when connecting (nil = use the defaults only).
    public var connectPort: Int? { InputValidation.isValidPort(listedPort) ? listedPort : nil }

    public var flag: String {
        let base: UInt32 = 127397
        return countryShort.uppercased().unicodeScalars.compactMap { Unicode.Scalar(base + $0.value) }
            .map(String.init).joined()
    }
}

public enum ServerListError: Error { case badResponse }

public enum ServerList {
    public static let defaultURLs = [
        URL(string: "https://www.vpngate.net/api/iphone/")!,
        URL(string: "http://www.vpngate.net/api/iphone/")!,
    ]

    public static func fetch(mirror: URL? = nil) async throws -> [VPNServer] {
        var last: Error = ServerListError.badResponse
        for url in (mirror.map { [$0] } ?? []) + defaultURLs {
            do {
                var req = URLRequest(url: url, timeoutInterval: 60)
                req.setValue("VPNGateMac/1.0", forHTTPHeaderField: "User-Agent")
                let (data, _) = try await URLSession.shared.data(for: req)
                let servers = parse(String(decoding: data, as: UTF8.self))
                if !servers.isEmpty { return servers }
            } catch { last = error }
        }
        throw last
    }

    public static func parse(_ csv: String) -> [VPNServer] {
        var out: [VPNServer] = []
        for raw in csv.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            if line.hasPrefix("*") || line.hasPrefix("#") || line.isEmpty { continue }
            let f = line.components(separatedBy: ",")
            guard f.count >= 15 else { continue }
            // The config blob is always the last column; a stray comma in the message must not shift it.
            let config = f[f.count - 1]
            let message = f[13..<(f.count - 1)].joined(separator: ",")
            guard InputValidation.isIPv4Literal(f[1]) else { continue }
            var port = 0, proto = ""
            if let cfg = Data(base64Encoded: config).map({ String(decoding: $0, as: UTF8.self) }) {
                (port, proto) = openVPNEndpoint(cfg)
            }
            out.append(VPNServer(
                hostName: f[0], ip: f[1], score: Int(f[2]) ?? 0, ping: Int(f[3]) ?? 0,
                speed: Int(f[4]) ?? 0, countryLong: f[5], countryShort: f[6],
                sessions: Int(f[7]) ?? 0, uptimeMs: Int(f[8]) ?? 0, totalUsers: Int(f[9]) ?? 0,
                totalTraffic: Int(f[10]) ?? 0, logType: f[11], operatorName: f[12],
                message: message, listedPort: port, listedProto: proto))
        }
        return out
    }

    /// (port, "tcp"/"udp") from `proto` and `remote` lines of an OpenVPN config; port 0 if absent or invalid.
    static func openVPNEndpoint(_ cfg: String) -> (Int, String) {
        var proto = ""
        var port = 0
        for l in cfg.split(whereSeparator: \.isNewline) {
            let w = l.split(separator: " ")
            if w.first == "proto", w.count > 1 { proto = w[1].hasPrefix("tcp") ? "tcp" : "udp" }
            if w.first == "remote", w.count > 2, let p = Int(w[2]), InputValidation.isValidPort(p) { port = p }
        }
        return (port, proto)
    }
}
