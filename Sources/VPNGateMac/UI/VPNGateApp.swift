import SwiftUI

let vpngateWebSite = URL(string: "http://www.vpngate.net/")!

@main
struct VPNGateApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        // The VPN Gate relay list is the app's main window, as in the Windows client's plug-in.
        Window("VPN Gate Public VPN Relay Servers", id: "main") {
            ServerListView()
                .environmentObject(model)
                .sheet(isPresented: $model.showingDisclaimer) {
                    AcademicDisclaimerSheet().environmentObject(model)
                }
                .onAppear { if !model.hasAgreedToDisclaimer { model.showingDisclaimer = true } }
        }
        .commands { AppCommands(model: model) }

        // The SoftEther Client Manager (connection settings for your own servers) is a separate, optional window.
        Window("VPN Connection Settings", id: "accounts") {
            AccountsView(appModel: model, accountManager: model.accountManager)
                .environmentObject(model)
        }
        .defaultSize(width: 760, height: 420)

        Window("Connection History", id: "history") {
            HistoryView().environmentObject(model)
        }
        .defaultSize(width: 720, height: 380)

        Window("Connection Log", id: "log") {
            LogView().environmentObject(model)
        }
        .defaultSize(width: 720, height: 420)

        Settings { SettingsView().environmentObject(model) }

        MenuBarExtra {
            let s = model.event
            Text(s.state.title)
            if let server = s.server {
                Text(model.connectedServer.map { "\($0.flag) \($0.hostName) (\(server))" } ?? server)
            }
            if let ip = s.virtualIP { Text("Virtual IP \(ip)") }
            if s.state == .connected {
                TrafficText(traffic: model.traffic)
            }
            Divider()
            if s.state == .disconnected {
                if let last = model.lastServer ?? model.servers.first(where: { model.favorites.contains($0.id) }) {
                    Button("Connect to \(last.hostName)") {
                        model.connect(last)
                        if model.showingDisclaimer { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
                    }
                }
            } else {
                Button("Disconnect") { model.disconnect() }
                if model.lastServer != nil { Button("Reconnect") { model.reconnect() } }
            }
            Button("Show VPN Gate") {
                openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true)
            }
            Button("VPN Connection Settings…") {
                openWindow(id: "accounts"); NSApp.activate(ignoringOtherApps: true)
            }
            SettingsLink { Text("Settings…") }
            Divider()
            Button("Quit") { NSApplication.shared.terminate(nil) }.keyboardShortcut("q")
        } label: {
            Image(systemName: model.event.state.symbol)
        }
    }
}

/// Menu bar commands: window openers and the actions that do not depend on the list selection.
struct AppCommands: Commands {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openURL) private var openURL

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("Refresh List") { model.refresh() }.keyboardShortcut("r").disabled(model.loading)
            Button("Disconnect") { model.disconnect() }.keyboardShortcut("d")
                .disabled(model.event.state == .disconnected)
            Divider()
            // "Show …", not the window's own title: the Window menu already lists open windows by that title
            // (and lets you switch to them), so a same-titled command here would just read as a duplicate. These
            // exist to reopen a window that was fully closed, and to give each one a stable shortcut.
            Button("Show VPN Gate") { openWindow(id: "main") }.keyboardShortcut("1")
            Button("Show VPN Connection Settings") { openWindow(id: "accounts") }.keyboardShortcut("m", modifiers: [.command, .shift])
            Button("Show Connection History") { openWindow(id: "history") }.keyboardShortcut("y")
            Button("Show Connection Log") { openWindow(id: "log") }.keyboardShortcut("l", modifiers: [.command, .shift])
        }
        CommandGroup(replacing: .help) {
            Button("VPN Gate Web Site") { openURL(vpngateWebSite) }
        }
    }
}
