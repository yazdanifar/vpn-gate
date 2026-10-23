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
    /// Which of the 15 columns are shown and in what order; right-click the table header to change it.
    @Published var columns: TableColumnCustomization<VPNServer> {
        didSet {
            if let d = try? JSONEncoder().encode(columns) { UserDefaults.standard.set(d, forKey: Self.columnsKey) }
        }
    }
    private static let columnsKey = "listColumns.v1"

    init() {
        if let d = UserDefaults.standard.data(forKey: Self.columnsKey),
            let c = try? JSONDecoder().decode(TableColumnCustomization<VPNServer>.self, from: d)
        {
            columns = c
        } else {
            columns = TableColumnCustomization<VPNServer>()
        }
    }
}

private let logChoices: [(label: String, weeks: Int)] = [("Any logging policy", -1), ("2 weeks or less", 2), ("Up to 1 month", 5), ("No logs only", 0)]

/// "duration ↓ in ↑ out"; observes only the counters.
struct TrafficText: View {
    @ObservedObject var traffic: TrafficCounter
    var since: Date? = nil
    var body: some View {
        let io = "↓ \(Fmt.bytes(traffic.bytesIn))  ↑ \(Fmt.bytes(traffic.bytesOut))"
        let rate = "↓ \(Fmt.rate(traffic.speedIn))  ↑ \(Fmt.rate(traffic.speedOut))"
        VStack(alignment: .leading, spacing: 2) {
            Text(since == nil ? io : "\(Fmt.duration(since))  \(io)")
            if since != nil { Text(rate) }
        }
    }
}

/// The toolbar Filter menu. It takes plain values and is Equatable on them (closures are ignored), so model updates
/// that don't change what it shows (log lines, probes, helper polling) don't rebuild it while it is open.
private struct FilterMenu: View, Equatable {
    let countries: [String]
    let country: String
    let maxLogWeeks: Int
    let favoritesOnly: Bool
    let active: Bool
    let setCountry: (String) -> Void
    let setLogWeeks: (Int) -> Void
    let setFavoritesOnly: (Bool) -> Void
    let clear: () -> Void

    static func == (a: FilterMenu, b: FilterMenu) -> Bool {
        a.countries == b.countries && a.country == b.country && a.maxLogWeeks == b.maxLogWeeks
            && a.favoritesOnly == b.favoritesOnly && a.active == b.active
    }

    var body: some View {
        Menu {
            Picker("Country", selection: Binding(get: { country }, set: setCountry)) {
                ForEach(countries, id: \.self) { Text($0 == "All" ? "All countries" : $0).tag($0) }
            }
            Picker("Logging", selection: Binding(get: { maxLogWeeks }, set: setLogWeeks)) {
                ForEach(logChoices, id: \.weeks) { Text($0.label).tag($0.weeks) }
            }
            Toggle("Favorites only", isOn: Binding(get: { favoritesOnly }, set: setFavoritesOnly))
            if active {
                Divider()
                Button("Clear Filters", action: clear)
            }
        } label: {
            Label("Filter", systemImage: active ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle")
        }
    }
}

/// The window of the Windows client's VPN Gate plug-in (D_VGC_LIST): title, intro, the relay list, and the
/// Connect button. Proxy Settings and VPN Connection Settings live in the macOS-native Settings window and the
/// Window menu instead of a button row here; VPN Gate Web Site is in the Help menu.
struct ServerListView: View {
    @EnvironmentObject var model: AppModel
    // @State is a macro whose plugin only ships with full Xcode, so view state lives in an ObservableObject.
    @StateObject private var ui = ListState()

    private var countries: [String] {
        ["All"] + Set(model.servers.map(\.countryLong)).sorted()
    }

    private var rows: [VPNServer] {
        var f = ServerFilter()
        f.search = ui.search; f.country = ui.country; f.favoritesOnly = ui.favoritesOnly; f.favorites = model.favorites
        f.maxLogWeeks = model.maxLogWeeks >= 0 ? model.maxLogWeeks : nil
        return f.apply(model.servers).map { s -> VPNServer in
            var s = s; s.testRank = ProbeOutcome.sortRank(model.probes[s.id]); return s
        }.sorted(using: ui.sortOrder)
    }

    private var filterActive: Bool {
        ui.country != "All" || ui.favoritesOnly || model.maxLogWeeks >= 0
    }

    private var selected: VPNServer? { rows.first { $0.id == ui.selection } }

    private var setupTitle: String { model.setupPrompt == .update ? "Update the VPN component?" : "One-time setup" }

    // MARK: pieces

    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text("VPN Gate Public VPN Relay Servers").font(.title2).bold()
                Text(
                    "Gain freedom access to Internet by using VPN connection via Public VPN Servers provided by volunteers around the world. Bypass your local malfunctioning firewall's packet blocking, and hide your IP address safely."
                )
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            ConnectionCard().frame(width: 260)
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    /// The original's list line: "<n> Public VPN Relay Servers on the Earth! (Updated at <time>)" or its failure text.
    private var listStatus: some View {
        HStack(spacing: 6) {
            if model.loading { ProgressView().controlSize(.small) }
            if let e = model.loadError {
                Text("List update failed (\(e)). Try again.").foregroundStyle(.red)
            } else if model.loading {
                Text(model.servers.isEmpty ? "Refreshing the List… (about 1 MB, can take 10–20 s)" : "Refreshing the List…")
                    .foregroundStyle(.secondary)
            } else if model.servers.isEmpty {
                Text("No servers yet. Press Refresh List.").foregroundStyle(.secondary)
            } else {
                let stale = model.listTimestamp.map { !ListFormat.isListOK(timestamp: $0, now: Date()) } ?? false
                // The time shown is when the list was last downloaded here; the list's own (server-side) stamp is in the tooltip.
                let updated = (model.listFetchedAt ?? model.listTimestamp).map { " (Updated at \($0.formatted(date: .abbreviated, time: .shortened)))" } ?? ""
                let generated = model.listTimestamp.map { "\nList generated by the server: \($0.formatted(date: .abbreviated, time: .shortened))" } ?? ""
                let shown = rows.count == model.servers.count ? "" : " — showing \(rows.count)"
                Text("\(model.servers.count) Public VPN Relay Servers on the Earth!\(updated)\(shown)")
                    .foregroundStyle(stale ? Color.orange : Color.secondary)
                    .help("Source: \(model.listSource.rawValue)\(generated)")
                if stale { Text("The list is old — press Refresh List.").foregroundStyle(.orange) }
            }
            Spacer()
        }
        .font(.callout)
        .padding(.horizontal, 16).padding(.vertical, 6)
    }

    /// One button for every state: Connect (to the selected server), Disconnect, or Cancel while connecting.
    @ViewBuilder private var connectionButton: some View {
        switch model.event.state {
        case .disconnected:
            Button {
                if let s = selected { model.connect(s) }
            } label: {
                Text("Connect to the VPN Server").frame(minWidth: 190)
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent).controlSize(.large)
            .disabled(selected == nil)
            .help(selected == nil ? "Select a server in the list first" : "Connect to the selected server")
        case .connected:
            Button(role: .destructive) {
                model.disconnect()
            } label: {
                Text("Disconnect").frame(minWidth: 190)
            }
            .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).controlSize(.large).tint(.red)
        default:
            Button {
                model.disconnect()
            } label: {
                Text("Cancel").frame(minWidth: 190)
            }
            .keyboardShortcut(.defaultAction).controlSize(.large)
        }
    }

    // The table's columns are split in three builders: one big Table expression is too slow to type-check.
    // Titles are the client's VGC_COLUMN_0..14; cells follow client_exe.c FUN_00525490.
    @TableColumnBuilder<VPNServer, KeyPathComparator<VPNServer>>
    private var mainColumns: some TableColumnContent<VPNServer, KeyPathComparator<VPNServer>> {
        TableColumn("IP Address (Hostname)", value: \.ip) { (s: VPNServer) in HostCell(server: s) }
            .width(min: 130, ideal: 160).customizationID("ip")
        TableColumn("Region", value: \.countryLong) { (s: VPNServer) in CountryCell(server: s) }
            .width(min: 110, ideal: 130).customizationID("region")
        TableColumn("Uptime", value: \.uptimeMs) { (s: VPNServer) in Text(ListFormat.uptime(ms: s.uptimeMs)) }
            .width(min: 60, ideal: 75).customizationID("uptime")
        TableColumn("VPN Sessions", value: \.sessions) { (s: VPNServer) in Text(ListFormat.sessions(s.sessions)).monospacedDigit() }
            .width(min: 75, ideal: 95).customizationID("sessions")
        TableColumn("Line Speed", value: \.speed) { (s: VPNServer) in Text(Fmt.speed(s.speed)).monospacedDigit() }
            .width(min: 75, ideal: 90).customizationID("speed")
    }

    @TableColumnBuilder<VPNServer, KeyPathComparator<VPNServer>>
    private var qualityColumns: some TableColumnContent<VPNServer, KeyPathComparator<VPNServer>> {
        TableColumn("Ping (Google, SE)", value: \.ping) { (s: VPNServer) in PingCell(server: s) }
            .width(min: 110, ideal: 130).customizationID("ping")
        TableColumn("Test from this Mac", value: \.testRank) { (s: VPNServer) in ProbeCell(outcome: model.probes[s.id]) }
            .width(min: 120, ideal: 150).customizationID("probe")
        TableColumn("Logging Policy", value: \.logType) { (s: VPNServer) in Text(ListFormat.logging(s.logType)) }
            .width(min: 80, ideal: 100).customizationID("logging")
        TableColumn("Total Score", value: \.score) { (s: VPNServer) in Text("\(s.score)").monospacedDigit() }
            .width(min: 65, ideal: 80).customizationID("score")
        TableColumn("DDNS Hostname", value: \.fqdn) { (s: VPNServer) in Text(s.fqdn).lineLimit(1).textSelection(.enabled) }
            .width(min: 120, ideal: 170).customizationID("ddns").defaultVisibility(.hidden)
        TableColumn("SSL-VPN (TCP)") { (s: VPNServer) in PortsCell(server: s) }
            .width(min: 90, ideal: 120).customizationID("ssl").defaultVisibility(.hidden)
    }

    @TableColumnBuilder<VPNServer, KeyPathComparator<VPNServer>>
    private var detailColumns: some TableColumnContent<VPNServer, KeyPathComparator<VPNServer>> {
        TableColumn("UDP Support") { (s: VPNServer) in Text(ListFormat.udp(s.udpPort)) }
            .width(min: 70, ideal: 80).customizationID("udp").defaultVisibility(.hidden)
        TableColumn("Cumulative Transfers", value: \.totalTraffic) { (s: VPNServer) in Text(Fmt.traffic(s.totalTraffic)) }
            .width(min: 90, ideal: 110).customizationID("transfers").defaultVisibility(.hidden)
        TableColumn("Cumulative Users", value: \.totalUsers) { (s: VPNServer) in Text(ListFormat.logins(s.totalUsers)) }
            .width(min: 90, ideal: 110).customizationID("users").defaultVisibility(.hidden)
        TableColumn("Operator's Name", value: \.operatorName) { (s: VPNServer) in
            Text(s.operatorName.isEmpty ? "Anonymous" : s.operatorName).lineLimit(1)
        }.width(min: 100, ideal: 140).customizationID("operator").defaultVisibility(.hidden)
        TableColumn("Operator's Message", value: \.message) { (s: VPNServer) in Text(s.message).lineLimit(1) }
            .width(min: 140, ideal: 220).customizationID("message").defaultVisibility(.hidden)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            listStatus

            Table(rows, selection: $ui.selection, sortOrder: $ui.sortOrder, columnCustomization: $ui.columns) {
                mainColumns
                qualityColumns
                detailColumns
            }
            .contextMenu(forSelectionType: VPNServer.ID.self) { ids in
                if let s = model.servers.first(where: { ids.contains($0.id) }) {
                    if model.event.state == .disconnected { Button("Connect to the VPN Server") { model.connect(s) } }
                    Button("Server Details…") {
                        ui.selectedServerForDetails = s; ui.showingDetails = true
                    }
                    Button(model.favorites.contains(s.id) ? "Remove from Favorites" : "Add to Favorites") { model.toggleFavorite(s) }
                }
            } primaryAction: { ids in
                // Double-click connects only when idle; to switch servers, disconnect first.
                if model.event.state == .disconnected, let s = model.servers.first(where: { ids.contains($0.id) }) { model.connect(s) }
            }

            Divider()
            HStack(spacing: 10) {
                Spacer()
                connectionButton
            }
            .padding(.horizontal, 16).padding(.vertical, 10)

            HStack(spacing: 8) {
                Text("Academic project at University of Tsukuba, Japan.")
                Text("·")
                Text("A server with a higher Line Speed and a smaller Ping is usually more comfortable to use.")
                    .lineLimit(1)
                Spacer()
            }
            .font(.caption).foregroundStyle(.secondary)
            .padding(.horizontal, 16).padding(.bottom, 8)
        }
        .frame(minWidth: 860, minHeight: 560)
        .searchable(text: $ui.search, placement: .toolbar, prompt: "Search host, IP, country, operator")
        .toolbar {
            ToolbarItemGroup {
                FilterMenu(
                    countries: countries, country: ui.country, maxLogWeeks: model.maxLogWeeks,
                    favoritesOnly: ui.favoritesOnly, active: filterActive,
                    setCountry: { ui.country = $0 }, setLogWeeks: { model.maxLogWeeks = $0 },
                    setFavoritesOnly: { ui.favoritesOnly = $0 },
                    clear: {
                        ui.country = "All"; ui.favoritesOnly = false; model.maxLogWeeks = -1
                    }
                )
                .equatable()
                Button {
                    if let s = selected { ui.selectedServerForDetails = s; ui.showingDetails = true }
                } label: {
                    Label("Details", systemImage: "info.circle")
                }
                .disabled(selected == nil).help("Server details (⌘I)").keyboardShortcut("i")
                Button {
                    model.measure(rows)
                } label: {
                    Label("Test Connection", systemImage: "speedometer")
                }
                .help("Try a real VPN handshake with the listed servers and show the connect time from this Mac")
                Button {
                    model.refresh()
                } label: {
                    Label("Refresh List", systemImage: "arrow.clockwise")
                }
                .disabled(model.loading).help("Refresh List (⌘R)")
            }
        }
        .sheet(isPresented: $ui.showingDetails) {
            if let s = ui.selectedServerForDetails { ServerDetailsSheet(server: s) }
        }
        .alert(setupTitle, isPresented: Binding(get: { model.setupPrompt != nil }, set: { if !$0 { model.cancelSetup() } })) {
            Button("Continue") { model.beginSetup() }
            Button("Not Now", role: .cancel) { model.cancelSetup() }
        } message: {
            Text(
                "VPN Gate needs a small background component to create the VPN connection. macOS will open its standard installer and ask for your password once. After that, VPN Gate connects by itself."
            )
        }
        .onAppear {
            if model.servers.isEmpty { model.refresh() }
        }
    }
}

/// Top-right card: what the connection is doing right now.
struct ConnectionCard: View {
    @EnvironmentObject var model: AppModel

    private var tint: Color {
        switch model.event.state {
        case .connected: return .green
        case .disconnected: return .secondary
        default: return .orange
        }
    }

    var body: some View {
        let state = model.event.state
        HStack(alignment: .top, spacing: 10) {
            if state == .disconnected || state == .connected {
                Image(systemName: state.symbol).font(.title2).foregroundStyle(tint)
            } else {
                ProgressView().controlSize(.small)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(state == .disconnected ? "Not connected" : state.title).font(.headline)
                if state != .disconnected {
                    let s = model.connectedServer
                    Text(s.map { "\($0.flag) \($0.hostName)" } ?? (model.event.server ?? "")).font(.caption).lineLimit(1)
                    if let ip = model.event.virtualIP { Text("Virtual IP \(ip)").font(.caption).foregroundStyle(.secondary) }
                    if state == .connected {
                        TimelineView(.periodic(from: .now, by: 1)) { _ in
                            TrafficText(traffic: model.traffic, since: model.connectedAt)
                                .monospacedDigit().font(.caption).foregroundStyle(.secondary)
                        }
                    }
                } else if let n = model.notice {
                    Text(n).font(.caption).foregroundStyle(.red).lineLimit(3)
                } else {
                    Text("Select a server and press Connect.").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(tint.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(tint.opacity(0.35)))
    }
}

// Table cells, kept as small views so the Table expression stays cheap to type-check.
private struct CountryCell: View { let server: VPNServer; var body: some View { Text("\(server.flag) \(server.countryLong)") } }
private struct HostCell: View {
    let server: VPNServer
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(server.ip).monospacedDigit()
            Text(server.hostName).font(.caption).foregroundStyle(.secondary).lineLimit(1)
        }
    }
}
private struct PingCell: View {
    let server: VPNServer
    var body: some View { Text(ListFormat.pings(google: server.pingToGoogle, japan: server.ping)).monospacedDigit() }
}
/// Result of "Test Connection": a real SoftEther handshake from this Mac, so "ok" means a connection can be established.
private struct ProbeCell: View {
    let outcome: ProbeOutcome?
    var body: some View {
        switch outcome {
        case nil:
            Text("—").foregroundStyle(.tertiary).help("Not tested yet — press Test Connection")
        case .queued?:
            Text("Waiting…").foregroundStyle(.secondary)
        case .testing?:
            HStack(spacing: 6) {
                ProgressView().controlSize(.small); Text("Testing…").foregroundStyle(.secondary)
            }
        case .ok(let port, let connectMs, let helloMs, _)?:
            VStack(alignment: .leading, spacing: 0) {
                Label("\(connectMs) ms", systemImage: "checkmark.circle.fill").foregroundStyle(.green).monospacedDigit()
                Text("handshake \(helloMs) ms · port \(port)").font(.caption).foregroundStyle(.secondary)
            }
        case .failed(let why)?:
            Label(why, systemImage: "xmark.circle.fill").foregroundStyle(.red).lineLimit(2).help(why)
        }
    }
}
private struct PortsCell: View {
    let server: VPNServer
    var body: some View { Text(server.prioritizedSslPorts.map(String.init).joined(separator: ", ")).monospacedDigit().lineLimit(1) }
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
                    DetailRow(
                        title: "SSL-VPN Ports:",
                        value: server.sslPorts.isEmpty ? "Default (443)" : server.prioritizedSslPorts.map(String.init).joined(separator: ", "))
                    DetailRow(
                        title: "OpenVPN UDP Ports:",
                        value: server.openVpnUdpPorts.isEmpty ? "None" : server.openVpnUdpPorts.map(String.init).joined(separator: ", "))
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
            Text(
                "VPN Gate is an academic research project of the Graduate School of University of Tsukuba, Japan.\n\nPublic VPN relay servers are hosted by volunteers around the world. Anyone can connect through these servers to achieve anonymity and bypass censorship.\n\nBy clicking “Agree and Continue”, you confirm that you will use this service in compliance with local laws."
            )
            .font(.body)
            .multilineTextAlignment(.center)
            .foregroundColor(.secondary)
            .padding(.horizontal)
            Text("Optional diagnostics upload is off and can be turned on in Settings → Advanced.")
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
