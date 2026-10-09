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
                Toggle("Launch at login", isOn: $model.launchAtLogin)
                Toggle("Reconnect automatically", isOn: $model.autoReconnect)
                Toggle("Block IPv6 while connected", isOn: $model.blockIPv6)
                Text(model.blockIPv6
                     ? "On: IPv6 is captured and dropped, which prevents IPv6 leaks; dual-stack sites fall back to IPv4 through the VPN."
                     : "Off: IPv6 only works if the VPN network provides it (a router advertising an IPv6 prefix). Otherwise IPv6 is still captured and dropped, so nothing leaks. Not tested against real servers.")
                    .font(.caption).foregroundStyle(.secondary)
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
            Section("Diagnostics (Mac app only, opt-in)") {
                Toggle("Send anonymous diagnostics every 10 minutes", isOn: $model.statistics.isEnabled)
                Text("Off by default; nothing is sent until you turn this on. The Windows VPN Gate client does not send this for ordinary users (it only uploads relay logs when a PC hosts a relay): this upload is specific to this Mac app. No traffic, addresses or personal data are included. Exactly what is sent:")
                    .font(.caption).foregroundStyle(.secondary)
                Text(VGStatistics.payloadDescription.joined(separator: "\n"))
                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                Text("HostKey is a random ID created on this Mac (not derived from its name).")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Reset ID") { model.statistics.resetHostKey() }
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
