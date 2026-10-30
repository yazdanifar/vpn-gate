import Foundation

public struct ServerFilter: Equatable {
    public var search = ""
    public var country = "All"
    public var favoritesOnly = false
    public var favorites: Set<String> = []
    /// Hide servers that keep logs longer than this many weeks (nil = show all).
    public var maxLogWeeks: Int?

    public init() {}

    public func apply(_ servers: [VPNServer]) -> [VPNServer] {
        servers.filter { s in
            if country != "All" && s.countryLong != country { return false }
            if favoritesOnly && !favorites.contains(s.id) { return false }
            if let max = maxLogWeeks {
                // unknown retention is treated as "too long"
                guard let w = Self.logWeeks(s.logType), w <= max else { return false }
            }
            if !search.isEmpty {
                let hit = [s.hostName, s.ip, s.countryLong, s.operatorName]
                    .contains { $0.localizedCaseInsensitiveContains(search) }
                if !hit { return false }
            }
            return true
        }
    }

    /// "2weeks" → 2, "3months" → 13, "1year" → 52, "no" / "none" / "0" → 0, unparseable → nil.
    public static func logWeeks(_ s: String) -> Int? {
        let t = s.lowercased().trimmingCharacters(in: .whitespaces)
        if ["no", "none", "nolog", "0"].contains(t) { return 0 }
        let digits = t.prefix { $0.isNumber }
        guard let n = Int(digits), !digits.isEmpty else { return nil }
        let unit = t.dropFirst(digits.count).trimmingCharacters(in: .whitespaces)
        switch unit {
        case "day", "days": return (n + 6) / 7
        case "week", "weeks": return n
        case "month", "months": return n * 52 / 12 + (n * 52 % 12 == 0 ? 0 : 1)
        case "year", "years": return n * 52
        default: return nil
        }
    }
}
