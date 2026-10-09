import SwiftUI
import VPNGateCore

final class ListState: ObservableObject {
    @Published var search = ""
    @Published var country = "All"
    @Published var favoritesOnly = false
    @Published var selection: VPNServer.ID?
    @Published var sortOrder = [KeyPathComparator(\VPNServer.score, order: .reverse)]
    @Published var showingDetails = false
    @Published var selectedServerForDetails: VPNServer? = nil
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
        let age = model.listTimestamp.map { " — list \(ListFormat.isListOK(timestamp: $0, now: Date()) ? "OK" : "stale")" } ?? ""
        return "\(rows.count) servers\(age) — double-click a server to connect"
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
        HStack(spacing: 8) {
            Button("Details") {
                if let s = selected {
                    ui.selectedServerForDetails = s
                    ui.showingDetails = true
                }
            }
            .disabled(selected == nil)

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
    }

    // The table's columns are split in two builders: one big Table expression is too slow to type-check.
    @TableColumnBuilder<VPNServer, KeyPathComparator<VPNServer>>
    private var identityColumns: some TableColumnContent<VPNServer, KeyPathComparator<VPNServer>> {
                TableColumn("★") { (s: VPNServer) in
                    Button { model.toggleFavorite(s) } label: {
                        Image(systemName: model.favorites.contains(s.id) ? "star.fill" : "star")
                    }.buttonStyle(.plain)
                }.width(24)
                TableColumn("Country", value: \.countryLong) { (s: VPNServer) in CountryCell(server: s) }.width(min: 110, ideal: 130)
                TableColumn("Host / IP", value: \.hostName) { (s: VPNServer) in HostCell(server: s) }.width(min: 120, ideal: 140)
                TableColumn("DDNS name", value: \.fqdn) { (s: VPNServer) in FqdnCell(server: s) }.width(min: 120, ideal: 170)
                TableColumn("Score", value: \.score) { (s: VPNServer) in NumberCell(text: "\(s.score)") }.width(60)
                TableColumn("Speed", value: \.speed) { (s: VPNServer) in NumberCell(text: Fmt.speed(s.speed)) }.width(90)
                TableColumn("Ping Google, Japan", value: \.ping) { (s: VPNServer) in
                    PingCell(server: s, measured: model.pings[s.id])
                }.width(min: 100, ideal: 120)
                TableColumn("Sessions", value: \.sessions) { (s: VPNServer) in NumberCell(text: "\(s.sessions)") }.width(65)
    }

    @TableColumnBuilder<VPNServer, KeyPathComparator<VPNServer>>
    private var statColumns: some TableColumnContent<VPNServer, KeyPathComparator<VPNServer>> {
                TableColumn("Uptime", value: \.uptimeMs) { (s: VPNServer) in Text(ListFormat.uptime(ms: s.uptimeMs)) }.width(70)
                TableColumn("SSL ports") { (s: VPNServer) in PortsCell(server: s) }.width(min: 90, ideal: 130)
                TableColumn("UDP") { (s: VPNServer) in Text(ListFormat.udp(s.udpPort)) }.width(40)
                TableColumn("Users / Traffic", value: \.totalTraffic) { (s: VPNServer) in TrafficCell(server: s) }.width(100)
                TableColumn("Operator / Logs", value: \.operatorName) { (s: VPNServer) in OperatorCell(server: s) }.width(min: 140)
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

            // Column titles are this app's own English wording: the Windows client's VGC_COLUMN_0..14 texts live in an
            // external string table that is not part of the decompile. The cells follow client_exe.c FUN_00525490.
            Table(rows, selection: $ui.selection, sortOrder: $ui.sortOrder) {
                identityColumns
                statColumns
            }
            .contextMenu(forSelectionType: VPNServer.ID.self) { ids in
                if let s = model.servers.first(where: { ids.contains($0.id) }) {
                    if model.event.state == .disconnected { Button("Connect") { model.connect(s) } }
                    Button("View Details…") {
                        ui.selectedServerForDetails = s
                        ui.showingDetails = true
                    }
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
        .sheet(isPresented: $ui.showingDetails) {
            if let s = ui.selectedServerForDetails {
                ServerDetailsSheet(server: s)
            }
        }
        .alert(setupTitle, isPresented: Binding(get: { model.setupPrompt != nil }, set: { if !$0 { model.cancelSetup() } })) {
            Button("Continue") { model.beginSetup() }
            Button("Not Now", role: .cancel) { model.cancelSetup() }
        } message: {
            Text("VPN Gate needs a small background component to create the VPN connection. macOS will open its standard installer and ask for your password once. After that, VPN Gate connects by itself.")
        }
        .onAppear {
            if model.servers.isEmpty { model.refresh() }
        }
    }
}

// Table cells, kept as small views so the Table expression stays cheap to type-check.
private struct CountryCell: View { let server: VPNServer; var body: some View { Text("\(server.flag) \(server.countryLong)") } }
private struct NumberCell: View { let text: String; var body: some View { Text(text).monospacedDigit() } }
private struct FqdnCell: View { let server: VPNServer; var body: some View { Text(server.fqdn).lineLimit(1).textSelection(.enabled) } }
private struct HostCell: View {
    let server: VPNServer
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(server.hostName)
            Text(server.ip).font(.caption).foregroundStyle(.secondary).monospacedDigit()
        }
    }
}
private struct PingCell: View {
    let server: VPNServer
    let measured: Int?
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(ListFormat.pings(google: server.pingToGoogle, japan: server.ping)).monospacedDigit()
            if let ms = measured {
                Text(ms < 0 ? "unreachable" : "\(ms) ms here").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
private struct PortsCell: View {
    let server: VPNServer
    var body: some View { Text(server.prioritizedSslPorts.map(String.init).joined(separator: ", ")).monospacedDigit().lineLimit(1) }
}
private struct TrafficCell: View {
    let server: VPNServer
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(server.totalUsers) users").monospacedDigit()
            Text(Fmt.traffic(server.totalTraffic)).font(.caption).foregroundStyle(.secondary)
        }
    }
}
private struct OperatorCell: View {
    let server: VPNServer
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(server.operatorName.isEmpty ? "Anonymous" : server.operatorName).lineLimit(1)
            Text("logs: \(server.logType)").font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct DetailRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(title).font(.subheadline).foregroundColor(.secondary).frame(width: 140, alignment: .leading)
            Text(value).font(.subheadline).textSelection(.enabled)
            Spacer()
        }
    }
}

struct ServerDetailsSheet: View {
    let server: VPNServer
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("\(server.flag) \(server.hostName)")
                    .font(.title2).bold()
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    DetailRow(title: "DDNS Hostname:", value: server.fqdn)
                    DetailRow(title: "IP Address:", value: server.ip)
                    DetailRow(title: "Country:", value: "\(server.countryLong) (\(server.countryShort))")
                    DetailRow(title: "Line Speed:", value: Fmt.speed(server.speed))
                    DetailRow(title: "Score:", value: "\(server.score)")
                    DetailRow(title: "Ping to Japan:", value: "\(server.ping) ms")
                    DetailRow(title: "Ping to Google:", value: server.pingToGoogle == 0 ? "-" : "\(server.pingToGoogle) ms")
                    DetailRow(title: "UDP port:", value: server.udpPort.map(String.init) ?? "-")
                    DetailRow(title: "SSL-VPN Ports:", value: server.sslPorts.isEmpty ? "Default (443)" : server.prioritizedSslPorts.map(String.init).joined(separator: ", "))
                    DetailRow(title: "OpenVPN UDP Ports:", value: server.openVpnUdpPorts.isEmpty ? "None" : server.openVpnUdpPorts.map(String.init).joined(separator: ", "))
                    DetailRow(title: "L2TP / IPsec:", value: server.l2tp ? "Supported" : "Not supported")
                    DetailRow(title: "Logging Policy:", value: server.logType)
                    DetailRow(title: "Operator / Owner:", value: server.operatorName.isEmpty ? "Anonymous" : server.operatorName)
                    if let abuse = server.abuse, !abuse.isEmpty {
                        DetailRow(title: "Abuse Contact:", value: abuse)
                    }
                    if let os = server.os {
                        DetailRow(title: "Operating System:", value: os)
                    }
                    if let build = server.build {
                        DetailRow(title: "SoftEther Build:", value: "\(build)")
                    }
                    if !server.message.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Server Message:").font(.headline).padding(.top, 4)
                            Text(server.message)
                                .font(.body)
                                .textSelection(.enabled)
                                .padding(8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color(NSColor.controlBackgroundColor))
                                .cornerRadius(6)
                        }
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(20)
        .frame(minWidth: 480, minHeight: 460)
    }
}

/// Shown from the app root (any tab, menu-bar connects too) until accepted; connecting is blocked until then.
struct AcademicDisclaimerSheet: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "graduationcap.fill")
                .font(.system(size: 44))
                .foregroundColor(.accentColor)
            Text("VPN Gate Academic Experiment Service")
                .font(.title2).bold()
            Text("VPN Gate is an academic research project of the Graduate School of University of Tsukuba, Japan.\n\nPublic VPN relay servers are hosted by volunteers around the world. Anyone can connect through these servers to achieve anonymity and bypass censorship.\n\nBy clicking “Agree and Continue”, you confirm that you will use this service in compliance with local laws.")
                .font(.body)
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .padding(.horizontal)
            Divider()
            Toggle("Send Mac-only diagnostics (off by default)", isOn: $model.statistics.isEnabled)
            Text("This app’s own opt-in upload, not something the Windows client does for ordinary users. You can change it any time in Settings, where the exact contents are listed.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            HStack {
                Button("Disagree & Quit") {
                    NSApplication.shared.terminate(nil)
                }
                Spacer()
                Button("Agree and Continue") { model.agreeToDisclaimer() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 480)
        .interactiveDismissDisabled()
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
            // Server list age and source status
            HStack(spacing: 6) {
                Text(model.listSource.rawValue)
                    .font(.caption)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.15))
                    .cornerRadius(4)
                if let ts = model.listTimestamp {
                    // The original's status line: OK within 24 h of the list's timestamp, otherwise the "stale" wording.
                    let ok = ListFormat.isListOK(timestamp: ts, now: Date())
                    Text(ts, style: .relative)
                        .font(.caption)
                        .foregroundColor(ok ? .secondary : .orange)
                    if !ok { Text("stale").font(.caption).foregroundColor(.orange) }
                }
            }
            if let n = model.notice { Text(n).font(.caption).foregroundStyle(.red).lineLimit(1) }
        }.padding(10)
    }
}
