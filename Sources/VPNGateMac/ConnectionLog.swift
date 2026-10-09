import Foundation

public struct ConnectionLogEntry: Identifiable, Codable, Equatable {
    public var id: UUID
    public var serverName: String
    public var serverIP: String
    public var connectedAt: Date
    public var disconnectedAt: Date?
    public var durationSeconds: TimeInterval?
    public var bytesIn: UInt64
    public var bytesOut: UInt64
    public var error: String?

    public init(
        id: UUID = UUID(),
        serverName: String,
        serverIP: String,
        connectedAt: Date = Date(),
        disconnectedAt: Date? = nil,
        durationSeconds: TimeInterval? = nil,
        bytesIn: UInt64 = 0,
        bytesOut: UInt64 = 0,
        error: String? = nil
    ) {
        self.id = id
        self.serverName = serverName
        self.serverIP = serverIP
        self.connectedAt = connectedAt
        self.disconnectedAt = disconnectedAt
        self.durationSeconds = durationSeconds
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.error = error
    }
}

@MainActor
public final class ConnectionLogStore: ObservableObject {
    @Published public var entries: [ConnectionLogEntry] = []

    public static var logFileURL: URL {
        AppPaths.supportFile("connection_history.json")
    }

    private let fileURL: URL

    public init(fileURL: URL? = nil) {
        self.fileURL = fileURL ?? Self.logFileURL
        load()
    }

    public func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let list = try? JSONDecoder().decode([ConnectionLogEntry].self, from: data) else {
            entries = []
            return
        }
        entries = list
    }

    public func save() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    public func recordStart(serverName: String, serverIP: String) -> UUID {
        let entry = ConnectionLogEntry(serverName: serverName, serverIP: serverIP)
        entries.insert(entry, at: 0)
        if entries.count > 100 { entries.removeLast(entries.count - 100) }
        save()
        return entry.id
    }

    public func recordEnd(id: UUID, bytesIn: UInt64, bytesOut: UInt64, error: String?) {
        guard let idx = entries.firstIndex(where: { $0.id == id }) else { return }
        var entry = entries[idx]
        let now = Date()
        entry.disconnectedAt = now
        entry.durationSeconds = now.timeIntervalSince(entry.connectedAt)
        entry.bytesIn = bytesIn
        entry.bytesOut = bytesOut
        entry.error = error
        entries[idx] = entry
        save()
    }

    public func clear() {
        entries.removeAll()
        save()
    }
}
