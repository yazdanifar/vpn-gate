import SwiftUI
import VPNGateCore

final class ListState: ObservableObject {
    @Published var search = ""
    @Published var country = "All"
    @Published var favoritesOnly = false
    @Published var selection: VPNServer.ID?
    @Published var sortOrder = [KeyPathComparator(\VPNServer.score, order: .reverse)]
}

private let logChoices: [(label: String, weeks: Int)] = [("Any logging", -1), ("≤ 2 weeks", 2), ("≤ 1 month", 5), ("No logs", 0)]

struct ServerListView: View {
    @EnvironmentObject var model: AppModel
    // @State is a macro whose plugin only ships with full Xcode, so view state lives in an ObservableObject.
    @StateObject private var ui = ListState()
    private var search: String { ui.search }
    private var country: String { ui.country }
    private var favoritesOnly: Bool { ui.favoritesOnly }
    private var sortOrder: [KeyPathComparator<VPNServer>] { ui.sortOrder }

    private var countries: [String] {
        ["All"] + Set(model.servers.map(\.countryLong)).sorted()
    }

    private var rows: [VPNServer] {
        var f = ServerFilter()
        f.search = search; f.country = country; f.favoritesOnly = favoritesOnly; f.favorites = model.favorites
        f.maxLogWeeks = model.maxLogWeeks >= 0 ? model.maxLogWeeks : nil
        return f.apply(model.servers).sorted(using: sortOrder)
    }

    private var statusText: String {
        if let e = model.loadError { return "Could not load the server list: \(e). Press Refresh to retry." }
        if model.loading { return model.servers.isEmpty ? "Loading server list… (about 1 MB, can take 10–20 s)" : "Updating server list…" }
        if model.servers.isEmpty { return "No servers yet. Press Refresh." }
        return "\(rows.count) servers — double-click a server to connect"
    }

    private var setupTitle: String { model.setupPrompt == .update ? "Update the VPN component?" : "One-time setup" }

    private var selected: VPNServer? { rows.first { $0.id == ui.selection } }

    /// Left side of the bottom bar: the server being used while connected, otherwise the selection or list status.
    @ViewBuilder private var bottomInfo: some View {
        if model.event.state != .disconnected {
            let s = model.connectedServer
            VStack(alignment: .leading, spacing: 2) {
                Text(s.map { "\($0.flag) \($0.hostName) — \($0.ip)" } ?? (model.event.server ?? "")).font(.headline)
                Text(model.event.state.title).font(.caption).foregroundStyle(.secondary)
            }
        } else if let s = selected {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(s.flag) \(s.hostName) — \(s.ip)").font(.headline)
                if !s.message.isEmpty { Text(s.message).font(.caption).foregroundStyle(.secondary).lineLimit(2) }
            }
        } else {
            if model.loading { ProgressView().controlSize(.small) }
            Text(statusText).foregroundStyle(model.loadError == nil ? Color.secondary : Color.red)
        }
    }

    /// One button for both directions: Connect (to the selected server) when disconnected, otherwise
    /// Disconnect — or Cancel while a connection is still being established.
    @ViewBuilder private var connectionButton: some View {
        switch model.event.state {
        case .disconnected:
            Button("Connect") { if let s = selected { model.connect(s) } }
                .keyboardShortcut(.defaultAction)
                .disabled(selected == nil)
                .help(selected == nil ? "Select a server first" : "Connect to the selected server")
        case .connected:
            Button("Disconnect") { model.disconnect() }
                .keyboardShortcut(.defaultAction)
        default:
            Button("Cancel") { model.disconnect() }
                .keyboardShortcut(.defaultAction)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            StatusBar()
            Divider()
            HStack {
                TextField("Search host, IP, country, operator", text: $ui.search)
                    .textFieldStyle(.roundedBorder)
                Picker("Country", selection: $ui.country) {
                    ForEach(countries, id: \.self) { Text($0).tag($0) }
                }.frame(width: 200)
                Picker("Logs", selection: $model.maxLogWeeks) {
                    ForEach(logChoices, id: \.weeks) { Text($0.label).tag($0.weeks) }
                }.frame(width: 150)
                Toggle("Favorites", isOn: $ui.favoritesOnly).toggleStyle(.checkbox)
                Button { model.measure(rows) } label: { Label("Test latency", systemImage: "speedometer") }
                Button { model.refresh() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .disabled(model.loading)
            }.padding(8)

            Table(rows, selection: $ui.selection, sortOrder: $ui.sortOrder) {
                TableColumn("★") { s in
                    Button { model.toggleFavorite(s) } label: {
                        Image(systemName: model.favorites.contains(s.id) ? "star.fill" : "star")
                    }.buttonStyle(.plain)
                }.width(24)
                TableColumn("Country", value: \.countryLong) { Text("\($0.flag) \($0.countryLong)") }.width(min: 110, ideal: 130)
                TableColumn("Host / IP", value: \.hostName) { s in
                    VStack(alignment: .leading, spacing: 0) {
                        Text(s.hostName)
                        Text(s.ip).font(.caption).foregroundStyle(.secondary).monospacedDigit()
                    }
                }.width(min: 120, ideal: 140)
                TableColumn("Score", value: \.score) { Text("\($0.score)").monospacedDigit() }.width(60)
                TableColumn("Speed", value: \.speed) { Text(Fmt.speed($0.speed)).monospacedDigit() }.width(90)
                TableColumn("Ping", value: \.ping) { s in
                    VStack(alignment: .leading, spacing: 0) {
                        Text("\(s.ping) ms").monospacedDigit()
                        if let ms = model.pings[s.id] {
                            Text(ms < 0 ? "unreachable" : "\(ms) ms here").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }.width(80)
                TableColumn("Sessions", value: \.sessions) { Text("\($0.sessions)").monospacedDigit() }.width(65)
                TableColumn("Uptime", value: \.uptimeMs) { Text(Fmt.uptime($0.uptimeMs)) }.width(70)
                TableColumn("Users / Traffic", value: \.totalTraffic) { s in
                    VStack(alignment: .leading, spacing: 0) {
                        Text("\(s.totalUsers) users").monospacedDigit()
                        Text(Fmt.traffic(s.totalTraffic)).font(.caption).foregroundStyle(.secondary)
                    }
                }.width(100)
                TableColumn("Operator / Logs", value: \.operatorName) { s in
                    VStack(alignment: .leading, spacing: 0) {
                        Text(s.operatorName).lineLimit(1)
                        Text("logs: \(s.logType)").font(.caption).foregroundStyle(.secondary)
                    }
                }.width(min: 140)
            }
            .contextMenu(forSelectionType: VPNServer.ID.self) { ids in
                if let s = model.servers.first(where: { ids.contains($0.id) }) {
                    if model.event.state == .disconnected { Button("Connect") { model.connect(s) } }
                    Button(model.favorites.contains(s.id) ? "Remove favorite" : "Add favorite") { model.toggleFavorite(s) }
                }
            } primaryAction: { ids in
                // Double-click connects only when idle; to switch servers, disconnect first.
                if model.event.state == .disconnected, let s = model.servers.first(where: { ids.contains($0.id) }) { model.connect(s) }
            }

            Divider()
            HStack {
                bottomInfo
                Spacer()
                connectionButton
            }.padding(8)
        }
        .frame(minWidth: 980, minHeight: 520)
        .alert(setupTitle, isPresented: Binding(get: { model.setupPrompt != nil }, set: { if !$0 { model.cancelSetup() } })) {
            Button("Continue") { model.beginSetup() }
            Button("Not Now", role: .cancel) { model.cancelSetup() }
        } message: {
            Text("VPN Gate needs a small background component to create the VPN connection. macOS will open its standard installer and ask for your password once. After that, VPN Gate connects by itself.")
        }
        .onAppear { if model.servers.isEmpty { model.refresh() } }
    }
}

struct StatusBar: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: model.event.state.symbol)
                .foregroundStyle(model.event.state == .connected ? Color.green : Color.secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(model.event.state.title).font(.headline)
                if let s = model.event.server {
                    Text(model.event.virtualIP.map { "\(s) · \($0)" } ?? s).font(.caption).foregroundStyle(.secondary)
                }
            }
            if model.event.state == .connected {
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    Text("\(Fmt.duration(model.connectedAt))  ↓ \(Fmt.bytes(model.event.bytesIn))  ↑ \(Fmt.bytes(model.event.bytesOut))")
                        .monospacedDigit().font(.caption)
                }
            }
            Spacer()
            if let n = model.notice { Text(n).font(.caption).foregroundStyle(.red).lineLimit(1) }
        }.padding(10)
    }
}
