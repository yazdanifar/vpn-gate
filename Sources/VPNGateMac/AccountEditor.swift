import AppKit
import SwiftUI
import VPNGateCore

struct AccountEditor: View {
    @Environment(\.dismiss) private var dismiss

    var account: ClientAccount?
    /// (account, password, certificate DER, PKCS#1 private key DER); nil secrets keep what is stored.
    var onSave: (ClientAccount, String?, Data?, Data?) -> Void

    @StateObject private var ui: AccountEditorState

    init(account: ClientAccount? = nil, initialPassword: String? = nil, hasStoredIdentity: Bool = false,
         onSave: @escaping (ClientAccount, String?, Data?, Data?) -> Void) {
        self.account = account
        self.onSave = onSave
        _ui = StateObject(wrappedValue: AccountEditorState(account: account, initialPassword: initialPassword,
                                                           hasStoredIdentity: hasStoredIdentity))
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
                    if ui.authType == .certificate { certificateSection }
                }

                Section {
                    DisclosureGroup("Advanced Options", isExpanded: $ui.showAdvanced) { advancedOptions }
                    if !ui.showAdvanced && (ui.mtuError != nil || ui.macError != nil || ui.fingerprintError != nil) {
                        Text("Something in the Advanced Options needs fixing before you can save.")
                            .font(.caption).foregroundStyle(.red)
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
                .disabled(!ui.canSave)
            }
            .padding(16)
        }
        .frame(minWidth: 480, minHeight: 520)
    }

    @ViewBuilder private var advancedOptions: some View {
        Group {
        Stepper("Max TCP Connections: \(ui.maxConnection)", value: $ui.maxConnection, in: 1...32)
                    Toggle("Use Data Compression", isOn: $ui.compression)
                    Toggle("Use UDP Acceleration (Fastest)", isOn: $ui.udpAcceleration)
                    Toggle("Use QoS", isOn: $ui.useQoS)
                    Toggle("Use Half Connection (separate send/receive sockets)", isOn: $ui.halfConnection)
                    TextField("MTU (blank = automatic):", text: $ui.mtuString)
                    if let e = ui.mtuError { Text(e).font(.caption).foregroundStyle(.red) }
                    TextField("Virtual MAC address (blank = random):", text: $ui.macString)
                    if let e = ui.macError { Text(e).font(.caption).foregroundStyle(.red) }
                    Toggle("Verify Server Certificate", isOn: $ui.checkServerCert)
                    TextField("Server certificate fingerprint (SHA-1 / SHA-256, optional):", text: $ui.fingerprint)
                    if let e = ui.fingerprintError { Text(e).font(.caption).foregroundStyle(.red) }
                    Text("A fingerprint is enforced whenever it is set. Without one, “Verify Server Certificate” uses the system trust store.")
                        .font(.caption).foregroundStyle(.secondary)
                    Toggle("Auto Reconnect on disconnect", isOn: $ui.autoReconnect)
                    if ui.autoReconnect {
                        Stepper("Retry every \(ui.reconnectIntervalSeconds) s", value: $ui.reconnectIntervalSeconds, in: 1...300)
                        Stepper("Give up after \(ui.reconnectCount) attempts", value: $ui.reconnectCount, in: 1...1000)
                    }
        }
    }

    @ViewBuilder private var certificateSection: some View {
        Text(ui.certDer != nil && ui.privateKeyDer != nil ? "Certificate and RSA key ready to save."
             : ui.hasStoredIdentity ? "A certificate and key are stored in the Keychain. Import again to replace them."
             : "No certificate yet. Import a PEM/DER certificate with its RSA key, or a .p12 file.")
            .font(.caption).foregroundStyle(.secondary)
        HStack {
            Button("Certificate + Key (PEM/DER)…") { importPEMPair() }
            Button("PKCS#12 (.p12)…") { importP12() }
        }
        SecureField("Passphrase for the .p12 file:", text: $ui.p12Passphrase)
        if let e = ui.importError { Text(e).font(.caption).foregroundStyle(.red) }
    }

    private func pickFile(_ message: String) -> Data? {
        let panel = NSOpenPanel()
        panel.message = message
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return try? Data(contentsOf: url)
    }

    private func importPEMPair() {
        guard let cert = pickFile("Choose the certificate (PEM or DER)"),
              let key = pickFile("Choose its RSA private key (PEM or DER, not passphrase-protected)") else { return }
        do {
            let id = try CertImport.identity(certificateFile: cert, keyFile: key)
            ui.certDer = id.certDer; ui.privateKeyDer = id.privateKeyDer; ui.importError = nil
        } catch { ui.importError = error.localizedDescription }
    }

    private func importP12() {
        guard let data = pickFile("Choose the PKCS#12 file (.p12 / .pfx)") else { return }
        do {
            let id = try CertImport.importPKCS12(data, passphrase: ui.p12Passphrase)
            ui.certDer = id.certDer; ui.privateKeyDer = id.privateKeyDer; ui.importError = nil
        } catch { ui.importError = error.localizedDescription }
    }

    private func save() {
        let acc = ui.makeAccount(base: account)
        let isCert = acc.authType == .certificate
        onSave(acc, ui.password.isEmpty ? nil : ui.password, isCert ? ui.certDer : nil, isCert ? ui.privateKeyDer : nil)
    }
}
