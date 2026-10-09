import SwiftUI
import VPNGateCore

@main
struct VPNGateApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        Window("VPN Gate", id: "main") {
            TabView {
                ServerListView()
                    .tabItem {
                        Label("VPN Gate Relays", systemImage: "globe")
                    }
                AccountsView(appModel: model, accountManager: model.accountManager)
                    .tabItem {
                        Label("Client Manager", systemImage: "network")
                    }
                HistoryView()
                    .tabItem {
                        Label("History", systemImage: "clock")
                    }
            }
            .environmentObject(model)
            .sheet(isPresented: $model.showingDisclaimer) {
                AcademicDisclaimerSheet().environmentObject(model)
            }
            .onAppear { if !model.hasAgreedToDisclaimer { model.showingDisclaimer = true } }
        }
        Settings { SettingsView().environmentObject(model) }

        MenuBarExtra {
            let s = model.event
            Text(s.state.title)
            if let server = s.server {
                Text(model.connectedServer.map { "\($0.flag) \($0.hostName) (\(server))" } ?? server)
            }
            if let ip = s.virtualIP { Text("Virtual IP \(ip)") }
            if s.state == .connected {
                Text("↓ \(Fmt.bytes(s.bytesIn))  ↑ \(Fmt.bytes(s.bytesOut))")
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
            Button("Open VPN Gate") {
                openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true)
            }
            SettingsLink { Text("Settings…") }
            Divider()
            Button("Quit") { NSApplication.shared.terminate(nil) }.keyboardShortcut("q")
        } label: {
            Image(systemName: model.event.state.symbol)
        }
    }
}
