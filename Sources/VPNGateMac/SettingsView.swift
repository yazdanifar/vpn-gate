import SwiftUI
import VPNGateCore

struct SettingsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Form {
            Section("Helper") {
                LabeledContent("Status", value: model.helperRunning ? "Running" : (model.helperInstalled ? "Installed, not running" : "Not installed"))
                HStack {
                    Button(model.helperInstalled ? "Reinstall helper…" : "Install helper…") { model.beginSetup() }
                    Button("Uninstall…") { model.uninstallHelper() }.disabled(!model.helperInstalled)
                }
                Text("The helper runs as root to create the VPN interface, routes and DNS. The installer asks for your password once.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Connection") {
                Toggle("Reconnect automatically", isOn: $model.autoReconnect)
                Toggle("Block IPv6 while connected (prevents leaks)", isOn: $model.blockIPv6)
                Picker("Proxy", selection: $model.proxyKind) {
                    Text("None").tag(ProxySettings.Kind.none)
                    Text("HTTP (CONNECT)").tag(ProxySettings.Kind.http)
                    Text("SOCKS5").tag(ProxySettings.Kind.socks5)
                }
                if model.proxyKind != .none {
                    TextField("Proxy host", text: $model.proxyHost)
                    TextField("Proxy port", value: $model.proxyPort, format: .number.grouping(.never))
                    TextField("Proxy username (optional)", text: $model.proxyUsername)
                    SecureField("Proxy password", text: $model.proxyPassword)
                }
            }
            Section("Server list") {
                TextField("Mirror URL (optional)", text: $model.mirrorURL)
                Text("Used first when set, e.g. if vpngate.net is blocked.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Academic Research & Telemetry") {
                Toggle("Send anonymous usage statistics", isOn: $model.statistics.isEnabled)
                Text("VPN Gate is an academic research experiment. Transmits client build number, OS name, and an anonymous host hash every 10 minutes. No personal info or traffic contents are ever collected.")
                    .font(.caption).foregroundStyle(.secondary)
                if let status = model.statistics.lastStatus {
                    Text(status).font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("Log") {
                ScrollView {
                    Text(model.logLines.joined(separator: "\n")).font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }.frame(height: 140)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .padding()
    }
}
