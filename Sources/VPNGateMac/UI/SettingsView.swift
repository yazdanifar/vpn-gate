import SwiftUI

/// Settings window: three small tabs instead of one long form.
struct SettingsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        TabView {
            GeneralSettings()
                .tabItem { Label("General", systemImage: "gearshape") }
            ProxyForm()
                .tabItem { Label("Proxy", systemImage: "network") }
            RoutingSettings()
                .tabItem { Label("Routing", systemImage: "arrow.triangle.branch") }
            AdvancedSettings()
                .tabItem { Label("Advanced", systemImage: "wrench.and.screwdriver") }
        }
        .environmentObject(model)
        .frame(width: 560, height: 480)
    }
}

private struct GeneralSettings: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Form {
            Section("Connection") {
                Toggle("Launch at login", isOn: $model.launchAtLogin)
                Toggle("Reconnect automatically", isOn: $model.autoReconnect)
                Toggle("Block IPv6 while connected", isOn: $model.blockIPv6)
                Text(
                    model.blockIPv6
                        ? "On: IPv6 is captured and dropped, which prevents IPv6 leaks; dual-stack sites fall back to IPv4 through the VPN."
                        : "Off: IPv6 only works if the VPN network provides it (a router advertising an IPv6 prefix). Otherwise IPv6 is still captured and dropped, so nothing leaks."
                )
                .font(.caption).foregroundStyle(.secondary)
            }
            Section("Mode") {
                Picker("Use the VPN as", selection: $model.tunnelMode) {
                    Text("Full tunnel (whole Mac)").tag(TunnelMode.fullTunnel)
                    Text("SOCKS5 proxy only").tag(TunnelMode.socksProxy)
                }
                if model.tunnelMode == .socksProxy {
                    TextField("SOCKS port", value: $model.socksPort, format: .number.grouping(.never))
                    if !(1024...65535).contains(model.socksPort) {
                        Text("Use a port from 1024 to 65535.").font(.caption).foregroundStyle(.red)
                    }
                }
                Text(
                    model.tunnelMode == .fullTunnel
                        ? "All traffic from this Mac goes through the VPN (subject to your routing rules)."
                        : "Your routes and DNS stay untouched. Point an app or browser at SOCKS5 127.0.0.1:\(model.socksPort) and only that app's connections use the VPN; use “remote DNS” in the app so names resolve through the VPN too. Any program on this Mac can use the port while connected. Routing rules and IPv6 blocking do not apply. Applies to the next connection."
                )
                .font(.caption).foregroundStyle(.secondary)
            }
            Section("VPN connections") {
                Button("Open VPN Connection Settings…") { openWindow(id: "accounts") }
                Text("Manage your own SoftEther servers and accounts in a separate window.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("VPN component") {
                LabeledContent("Status", value: model.helperRunning ? "Running" : (model.helperInstalled ? "Installed, not running" : "Not installed"))
                HStack {
                    Button(model.helperInstalled ? "Reinstall…" : "Install…") { model.beginSetup() }
                    Button("Uninstall…") { model.uninstallHelper() }.disabled(!model.helperInstalled)
                }
                Text("It runs as root to create the VPN interface, routes and DNS. The installer asks for your password once.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

/// The proxy fields, shared by the Settings tab and the main window's "Proxy Settings…" sheet.
struct ProxyForm: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Form {
            Section("Proxy") {
                Picker("Connect through", selection: $model.proxyKind) {
                    Text("No proxy (direct)").tag(ProxySettings.Kind.none)
                    Text("HTTP proxy (CONNECT)").tag(ProxySettings.Kind.http)
                    Text("SOCKS5 proxy").tag(ProxySettings.Kind.socks5)
                }
                if model.proxyKind != .none {
                    TextField("Proxy host", text: $model.proxyHost)
                    TextField("Proxy port", value: $model.proxyPort, format: .number.grouping(.never))
                    TextField("Username (optional)", text: $model.proxyUsername)
                    SecureField("Password", text: $model.proxyPassword)
                }
                Text(
                    "If you are using a proxy server, you might not be able to use VPN Relay Servers which don't support the TCP port 443 as “SSL-VPN Connection” from such a proxy-mandated network."
                )
                .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

private struct AdvancedSettings: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Form {
            Section("Server list") {
                TextField("Mirror URL (optional)", text: $model.mirrorURL)
                Text("Used first when set, e.g. if vpngate.net is blocked.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Diagnostics (this Mac app only, opt-in)") {
                Toggle("Send anonymous diagnostics every 10 minutes", isOn: $model.statistics.isEnabled)
                DisclosureGroup("Exactly what is sent") {
                    Text(VGStatistics.payloadDescription.joined(separator: "\n"))
                        .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    Text("HostKey is a random ID created on this Mac (not derived from its name).")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Reset ID") { model.statistics.resetHostKey() }
                }
                Text(
                    "Off by default. The Windows client does not send this for ordinary users; it is specific to this Mac app. No traffic, addresses or personal data are included."
                )
                .font(.caption).foregroundStyle(.secondary)
                if let status = model.statistics.lastStatus {
                    Text(status).font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("Log") {
                Button("Show Log…") { openWindow(id: "log") }
            }
        }
        .formStyle(.grouped)
    }
}
