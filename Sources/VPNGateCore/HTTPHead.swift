import Foundation

public struct HTTPHead: Equatable {
    public var status: String
    public var headers: [String: String]  // names lowercased

    public var statusCode: Int? {
        let p = status.split(separator: " ")
        return p.count >= 2 ? Int(p[1]) : nil
    }

    public static let terminator: [UInt8] = [13, 10, 13, 10]
    public static let maxSize = 16384

    /// Parses the header block (without the blank-line terminator).
    public static func parse(_ head: [UInt8]) -> HTTPHead {
        var lines = String(decoding: head, as: UTF8.self).components(separatedBy: "\r\n")
        let status = lines.removeFirst()
        var h: [String: String] = [:]
        for l in lines {
            if let i = l.firstIndex(of: ":") {
                h[l[..<i].lowercased()] = l[l.index(after: i)...].trimmingCharacters(in: .whitespaces)
            }
        }
        return HTTPHead(status: status, headers: h)
    }
}
