import SwiftUI
import VPNGateCore

/// Past connections (kept locally in connection_history.json, newest first, at most 100).
struct HistoryView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Connection history").font(.headline)
                Spacer()
                Button("Clear") { model.connectionLog.clear() }.disabled(model.connectionLog.entries.isEmpty)
            }.padding(10)
            Divider()
            if model.connectionLog.entries.isEmpty {
                Text("No connections yet.").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(model.connectionLog.entries) {
                    TableColumn("Server", value: \.serverName)
                    TableColumn("Address", value: \.serverIP)
                    TableColumn("Connected") { e in Text(e.connectedAt, format: .dateTime.month().day().hour().minute()) }
                    TableColumn("Duration") { e in
                        Text(e.durationSeconds.map { Fmt.duration(Date().addingTimeInterval(-$0)) } ?? "active")
                    }
                    TableColumn("Traffic") { e in Text("↓ \(Fmt.bytes(e.bytesIn))  ↑ \(Fmt.bytes(e.bytesOut))").monospacedDigit() }
                    TableColumn("Result") { e in Text(e.error ?? (e.disconnectedAt == nil ? "" : "ended")).foregroundStyle(e.error == nil ? Color.secondary : Color.red) }
                }
            }
        }
    }
}
