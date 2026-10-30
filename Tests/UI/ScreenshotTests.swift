import AppKit
import SwiftUI

// Every view is rendered with fixed data in both color schemes where it matters; see Tests/Support/Snapshot.swift.

private let fixedDate = Date(timeIntervalSince1970: 1_760_000_000)  // 2025-10-09 08:53:20 UTC

private func makeDefaults() -> UserDefaults {
    let name = "vpngate-uitests-\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    d.set(true, forKey: "hasAgreedToDisclaimer")
    return d
}

private func fixtureServers() -> [VPNServer] {
    let rows: [(String, String, String, String, Int, Int, Int, Int, String)] = [
        ("vpn927125019", "183.88.237.254", "Thailand", "TH", 687_114, 7, 581_748_844, 57, "2weeks"),
        ("public-vpn-12", "219.100.37.12", "Japan", "JP", 654_200, 12, 412_000_000, 31, "2weeks"),
        ("vpn482910374", "121.139.62.5", "Korea Republic of", "KR", 598_031, 31, 298_500_000, 14, "nolog"),
        ("vpn1337", "46.19.141.8", "Russian Federation", "RU", 455_870, 88, 120_300_000, 6, "1month"),
        ("vpn771300", "178.62.20.44", "United States", "US", 420_333, 140, 98_000_000, 22, "2weeks"),
        ("vpn0099", "85.203.44.19", "Germany", "DE", 388_902, 55, 87_250_000, 9, "nolog"),
        ("vpn5521", "92.60.12.7", "France", "FR", 301_145, 61, 64_800_000, 4, "2weeks"),
        ("vpn31337", "37.120.200.3", "Netherlands", "NL", 250_010, 49, 51_400_000, 2, "1month"),
    ]
    return rows.enumerated().map { i, r in
        VPNServer(
            hostName: r.0, ip: r.1, score: r.4, ping: r.5, speed: r.6, countryLong: r.2, countryShort: r.3, sessions: r.7,
            uptimeMs: (i + 1) * 86_400_000 * 3 + 3_600_000, totalUsers: 1000 * (i + 3), totalTraffic: 5_000_000_000 * (i + 1),
            logType: r.8, operatorName: i % 3 == 0 ? "" : "Volunteer \(i)", message: "", listedPort: 443, listedProto: "tcp",
            fqdn: r.0 + ".opengw.net", sslPorts: [443, 995], udpPort: i % 2 == 0 ? 1194 : nil)
    }
}

@MainActor private func makeModel(servers: Bool = true) -> AppModel {
    let m = AppModel(
        socketPath: tempPath("ui-\(UUID().uuidString.prefix(6)).sock"), defaults: makeDefaults(), autoStart: false,
        loginItem: StubLoginItem(),
        accountManager: AccountManager(fileURL: URL(fileURLWithPath: tempPath("accounts-\(UUID().uuidString.prefix(6)).json"))),
        connectionLog: ConnectionLogStore(fileURL: URL(fileURLWithPath: tempPath("history-\(UUID().uuidString.prefix(6)).json"))))
    if servers {
        m.servers = fixtureServers()
        m.listFetchedAt = fixedDate
        m.listTimestamp = Date()  // fresh: no "list is old" banner, whatever the fixed date
        m.favorites = [m.servers[1].id]
        m.probes = [:]
    }
    m.helperInstalled = true
    m.helperRunning = true
    return m
}

private struct StubLoginItem: LoginItemControlling {
    var status: LoginItemStatus { .notRegistered }
    func register() throws {}
    func unregister() throws {}
}

private let windowSize = CGSize(width: 1000, height: 640)
private let settingsSize = CGSize(width: 560, height: 480)

@MainActor private func shot<V: View>(_ name: String, _ view: V, size: CGSize, dark: Bool = false) {
    if let problem = Snapshot.check(name, view, size: size, dark: dark) { fail(problem) }
}

func registerScreenshotTests() {
    test("ui/server-list-light", timeout: 60) {
        await onMain {
            let m = makeModel()
            shot("server-list-light", ServerListView().environmentObject(m), size: windowSize)
        }
    }
    test("ui/server-list-dark", timeout: 60) {
        await onMain {
            let m = makeModel()
            shot("server-list-dark", ServerListView().environmentObject(m), size: windowSize, dark: true)
        }
    }
    test("ui/server-list-empty", timeout: 60) {
        await onMain {
            let m = makeModel(servers: false)
            shot("server-list-empty", ServerListView().environmentObject(m), size: windowSize)
        }
    }
    test("ui/server-list-connected", timeout: 60) {
        await onMain {
            let m = makeModel()
            var e = HelperEvent(state: .connected)
            e.server = "183.88.237.254:443"; e.virtualIP = "10.211.254.7"
            m.event = e
            m.lastServerID = m.servers[0].id
            shot("server-list-connected", ServerListView().environmentObject(m), size: windowSize)
        }
    }
    test("ui/server-details", timeout: 60) {
        await onMain {
            shot("server-details", ServerDetailsSheet(server: fixtureServers()[0]), size: CGSize(width: 520, height: 640))
        }
    }
    test("ui/disclaimer", timeout: 60) {
        await onMain {
            let m = makeModel()
            shot("disclaimer", AcademicDisclaimerSheet().environmentObject(m), size: CGSize(width: 560, height: 520))
        }
    }
    test("ui/settings-general", timeout: 60) {
        await onMain { shot("settings-general", GeneralSettings().environmentObject(makeModel()), size: settingsSize) }
    }
    test("ui/settings-general-dark", timeout: 60) {
        await onMain { shot("settings-general-dark", GeneralSettings().environmentObject(makeModel()), size: settingsSize, dark: true) }
    }
    test("ui/settings-proxy", timeout: 60) {
        await onMain {
            let m = makeModel()
            m.proxyKind = .socks5; m.proxyHost = "proxy.example.net"; m.proxyPort = 1080; m.proxyUsername = "alice"
            shot("settings-proxy", ProxyForm().environmentObject(m), size: settingsSize)
        }
    }
    test("ui/settings-routing", timeout: 60) {
        await onMain {
            let m = makeModel()
            m.routingConfig = RoutingConfig(
                rules: [
                    RoutingRule(type: .domainSuffix, value: "example.com", action: .direct),
                    RoutingRule(type: .cidr, value: "10.0.0.0/8", action: .direct),
                    RoutingRule(type: .domainKeyword, value: "ads", action: .block, enabled: false),
                ], defaultAction: .proxy, bypassPrivateNetworks: true)
            shot("settings-routing", RoutingSettings().environmentObject(m), size: settingsSize)
        }
    }
    test("ui/settings-advanced", timeout: 60) {
        await onMain { shot("settings-advanced", AdvancedSettings().environmentObject(makeModel()), size: settingsSize) }
    }
    test("ui/settings-window", timeout: 60) {
        await onMain { shot("settings-window", SettingsView().environmentObject(makeModel()), size: settingsSize) }
    }
    test("ui/accounts-empty", timeout: 60) {
        await onMain {
            let m = makeModel()
            shot("accounts-empty", AccountsView(appModel: m, accountManager: m.accountManager).environmentObject(m), size: CGSize(width: 760, height: 420))
        }
    }
    test("ui/accounts-list", timeout: 60) {
        await onMain {
            let m = makeModel()
            m.accountManager.add(ClientAccount(name: "Office", host: "vpn.office.example", hub: "CORP", username: "alice", authType: .password))
            m.accountManager.add(ClientAccount(name: "Home lab", host: "192.0.2.10", hub: "DEFAULT", username: "bob", authType: .anonymous))
            shot("accounts-list", AccountsView(appModel: m, accountManager: m.accountManager).environmentObject(m), size: CGSize(width: 760, height: 420))
        }
    }
    test("ui/account-editor-new", timeout: 60) {
        await onMain {
            shot("account-editor-new", AccountEditor(onSave: { _, _, _, _ in }), size: CGSize(width: 560, height: 640))
        }
    }
    test("ui/account-editor-edit-dark", timeout: 60) {
        await onMain {
            let acc = ClientAccount(name: "Office", host: "vpn.office.example", hub: "CORP", username: "alice", authType: .password)
            shot(
                "account-editor-edit-dark", AccountEditor(account: acc, initialPassword: "secret", onSave: { _, _, _, _ in }),
                size: CGSize(width: 560, height: 640), dark: true)
        }
    }
    test("ui/log", timeout: 60) {
        await onMain {
            let m = makeModel()
            m.logLines = (1...24).map { "2025-10-09 08:\(String(format: "%02d", $0)):00 [helper] line \($0): connected to 183.88.237.254:443" }
            shot("log", LogView().environmentObject(m), size: CGSize(width: 720, height: 420))
        }
    }
    test("ui/history-empty", timeout: 60) {
        await onMain {
            shot("history-empty", HistoryView().environmentObject(makeModel()), size: CGSize(width: 720, height: 380))
        }
    }
    test("ui/history", timeout: 60) {
        await onMain {
            let m = makeModel()
            m.connectionLog.entries = [
                ConnectionLogEntry(
                    serverName: "vpn927125019", serverIP: "183.88.237.254", connectedAt: fixedDate, disconnectedAt: fixedDate.addingTimeInterval(3725),
                    durationSeconds: 3725, bytesIn: 123_456_789, bytesOut: 4_567_890),
                ConnectionLogEntry(
                    serverName: "public-vpn-12", serverIP: "219.100.37.12", connectedAt: fixedDate.addingTimeInterval(-86_400),
                    disconnectedAt: fixedDate.addingTimeInterval(-86_000), durationSeconds: 400, bytesIn: 1_000, bytesOut: 500, error: "Authentication failed"),
            ]
            shot("history", HistoryView().environmentObject(m), size: CGSize(width: 720, height: 380))
        }
    }
}

/// Runs `body` on the main thread (AppKit insists on it); `MainActor.run` is not enough here because the test
/// harness task group can execute it inline on a pool thread.
private func onMain(_ body: @escaping @MainActor () -> Void) async {
    await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
        DispatchQueue.main.async {
            MainActor.assumeIsolated { body() }
            c.resume()
        }
    }
}
