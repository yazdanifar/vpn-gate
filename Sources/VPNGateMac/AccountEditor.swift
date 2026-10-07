import SwiftUI
import VPNGateCore

final class AccountEditorState: ObservableObject {
    @Published var name: String
    @Published var host: String
    @Published var portString: String
    @Published var hub: String
    @Published var username: String
    @Published var authType: AccountAuthType
    @Published var password: String

    @Published var maxConnection: Int
    @Published var compression: Bool
    @Published var udpAcceleration: Bool
    @Published var autoReconnect: Bool
    @Published var reconnectInterval: Double
    @Published var reconnectCount: Int
    @Published var checkServerCert: Bool
    @Published var mtu: Int

    init(account: ClientAccount? = nil, initialPassword: String? = nil) {
        self.name = account?.name ?? "New Connection"
        self.host = account?.host ?? ""
        self.portString = account?.portList.map(String.init).joined(separator: ", ") ?? "443, 992, 5555, 1194"
        self.hub = account?.hub ?? "DEFAULT"
        self.username = account?.username ?? ""
        self.authType = account?.authType ?? .password
        self.password = initialPassword ?? ""
        self.maxConnection = account?.maxConnection ?? 8
        self.compression = account?.compression ?? false
        self.udpAcceleration = account?.udpAcceleration ?? true
        self.autoReconnect = account?.autoReconnect ?? true
        self.reconnectInterval = account?.reconnectInterval ?? 3.0
        self.reconnectCount = account?.reconnectCount ?? 8
        self.checkServerCert = account?.checkServerCert ?? false
        self.mtu = account?.mtu ?? 1500
    }
}

struct AccountEditor: View {
    @Environment(\.dismiss) private var dismiss

    var account: ClientAccount?
    var onSave: (ClientAccount, String?, Data?) -> Void

    @StateObject private var ui: AccountEditorState

    init(account: ClientAccount? = nil, initialPassword: String? = nil, onSave: @escaping (ClientAccount, String?, Data?) -> Void) {
        self.account = account
        self.onSave = onSave
        _ui = StateObject(wrappedValue: AccountEditorState(account: account, initialPassword: initialPassword))
    }

    var body: some View {
        VStack(spacing: 0) {
            Text(account == nil ? "New VPN Connection Setting" : "Edit VPN Connection Setting")
                .font(.headline)
                .padding(.top, 16)
                .padding(.bottom, 12)

            Form {
                Section("General Setting") {
                    TextField("Setting Name:", text: $ui.name)
                }

                Section("Destination VPN Server") {
                    TextField("Host Name / IP Address:", text: $ui.host)
                    TextField("Port Number (comma separated):", text: $ui.portString)
                    TextField("Virtual HUB Name:", text: $ui.hub)
                }

                Section("User Authentication Setting") {
                    Picker("Auth Type:", selection: $ui.authType) {
                        ForEach(AccountAuthType.allCases, id: \.self) { type in
                            Text(type.rawValue).tag(type)
                        }
                    }
                    TextField("User Name:", text: $ui.username)
                    if ui.authType == .password || ui.authType == .plainPassword {
                        SecureField("Password:", text: $ui.password)
                    }
                }

                Section("Advanced Options") {
                    Stepper("Max TCP Connections: \(ui.maxConnection)", value: $ui.maxConnection, in: 1...32)
                    Toggle("Use Data Compression", isOn: $ui.compression)
                    Toggle("Use UDP Acceleration (Fastest)", isOn: $ui.udpAcceleration)
                    Toggle("Verify Server Certificate", isOn: $ui.checkServerCert)
                    Toggle("Auto Reconnect on disconnect", isOn: $ui.autoReconnect)
                    if ui.autoReconnect {
                        Stepper("Reconnect attempts: \(ui.reconnectCount)", value: $ui.reconnectCount, in: 1...50)
                    }
                }
            }
            .formStyle(.grouped)
            .padding(.horizontal, 8)

            Divider()

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    save()
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(ui.name.trimmingCharacters(in: .whitespaces).isEmpty || ui.host.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(16)
        }
        .frame(minWidth: 480, minHeight: 520)
    }

    private func save() {
        let ports = ui.portString
            .split(separator: ",")
            .compactMap { UInt16($0.trimmingCharacters(in: .whitespaces)) }
            .filter { $0 > 0 }

        let acc = ClientAccount(
            id: account?.id ?? UUID(),
            name: ui.name.trimmingCharacters(in: .whitespaces),
            host: ui.host.trimmingCharacters(in: .whitespaces),
            portList: ports.isEmpty ? [443] : ports,
            hub: ui.hub.trimmingCharacters(in: .whitespaces).isEmpty ? "DEFAULT" : ui.hub.trimmingCharacters(in: .whitespaces),
            username: ui.username.trimmingCharacters(in: .whitespaces),
            authType: ui.authType,
            checkServerCert: ui.checkServerCert,
            maxConnection: ui.maxConnection,
            compression: ui.compression,
            udpAcceleration: ui.udpAcceleration,
            autoReconnect: ui.autoReconnect,
            reconnectInterval: ui.reconnectInterval,
            reconnectCount: ui.reconnectCount,
            mtu: ui.mtu
        )

        onSave(acc, ui.password.isEmpty ? nil : ui.password, nil)
    }
}
