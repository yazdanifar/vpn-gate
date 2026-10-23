import SwiftUI
import VPNGateCore

final class AccountsViewState: ObservableObject {
    @Published var selectedAccountID: UUID?
    @Published var showingEditor = false
    @Published var editingAccount: ClientAccount?
}

struct AccountsView: View {
    @ObservedObject var appModel: AppModel
    @ObservedObject var accountManager: AccountManager
    @StateObject private var ui = AccountsViewState()
    @Environment(\.openWindow) private var openWindow

    var selectedAccount: ClientAccount? {
        accountManager.accounts.first { $0.id == ui.selectedAccountID }
    }

    private func edit(_ acc: ClientAccount) { ui.editingAccount = acc; ui.showingEditor = true }
    private func addNew() { ui.editingAccount = nil; ui.showingEditor = true }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Button {
                    addNew()
                } label: {
                    Label("New Setting", systemImage: "plus")
                }
                Divider().frame(height: 16)
                Button {
                    if let acc = selectedAccount { appModel.connect(account: acc) }
                } label: {
                    Label("Connect", systemImage: "bolt.fill")
                }
                .disabled(selectedAccount == nil || appModel.event.state != .disconnected)
                Button {
                    appModel.disconnect()
                } label: {
                    Label("Disconnect", systemImage: "power")
                }
                .disabled(appModel.event.state == .disconnected)
                Divider().frame(height: 16)
                Button {
                    if let acc = selectedAccount { edit(acc) }
                } label: {
                    Label("Properties", systemImage: "slider.horizontal.3")
                }
                .disabled(selectedAccount == nil)
                Button(role: .destructive) {
                    if let acc = selectedAccount { accountManager.delete(acc); ui.selectedAccountID = nil }
                } label: {
                    Label("Delete", systemImage: "trash")
                }
                .disabled(selectedAccount == nil)
                Spacer()
            }
            .padding(.horizontal, 12).padding(.vertical, 8)

            Divider()

            // The Windows Client Manager lists "VPN Gate Public VPN Relay Servers" as its first row.
            Button {
                openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true)
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "globe").font(.title3).foregroundStyle(Color.accentColor)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("VPN Gate Public VPN Relay Servers").font(.headline)
                        Text("Free servers run by volunteers — open the list").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                }
                .padding(.horizontal, 14).padding(.vertical, 8).contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            Divider()

            if let notice = accountManager.loadNotice {
                Text(notice).font(.caption).foregroundStyle(.orange).padding(.horizontal, 12).padding(.vertical, 4)
            }
            if accountManager.accounts.isEmpty {
                VStack(spacing: 10) {
                    Text("No VPN connection settings yet").font(.headline).foregroundStyle(.secondary)
                    Text("Add one to connect to your own SoftEther VPN server.")
                        .font(.subheadline).foregroundStyle(.secondary)
                    Button("New Setting…") { addNew() }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(accountManager.accounts, selection: $ui.selectedAccountID) {
                    TableColumn("VPN Connection Setting Name", value: \.name)
                    TableColumn("Status") { acc in statusView(for: acc) }.width(min: 90, ideal: 110)
                    TableColumn("VPN Server Hostname") { acc in Text("\(acc.host):\(acc.portList.first ?? 443)") }
                    TableColumn("Virtual Hub", value: \.hub)
                }
                .contextMenu(forSelectionType: UUID.self) { ids in
                    if let acc = accountManager.accounts.first(where: { ids.contains($0.id) }) {
                        Button("Connect") { appModel.connect(account: acc) }.disabled(appModel.event.state != .disconnected)
                        Button("Properties…") { edit(acc) }
                        Button("Duplicate") { accountManager.duplicate(acc) }
                        Divider()
                        Button("Delete", role: .destructive) {
                            accountManager.delete(acc)
                            if ui.selectedAccountID == acc.id { ui.selectedAccountID = nil }
                        }
                    }
                } primaryAction: { ids in
                    if appModel.event.state == .disconnected, let acc = accountManager.accounts.first(where: { ids.contains($0.id) }) {
                        appModel.connect(account: acc)
                    }
                }
            }
        }
        .frame(minWidth: 620, minHeight: 320)
        .sheet(isPresented: $ui.showingEditor) {
            AccountEditor(
                account: ui.editingAccount,
                initialPassword: ui.editingAccount.flatMap { accountManager.password(for: $0) },
                hasStoredIdentity: ui.editingAccount.map { accountManager.hasCertificateIdentity($0) } ?? false,
                onSave: { updated, pw, cert, key in
                    if ui.editingAccount != nil {
                        accountManager.update(updated, password: pw, certDer: cert, privateKeyDer: key)
                    } else {
                        accountManager.add(updated, password: pw, certDer: cert, privateKeyDer: key)
                    }
                }
            )
        }
    }

    @ViewBuilder
    private func statusView(for acc: ClientAccount) -> some View {
        if appModel.activeAccount?.id == acc.id {
            switch appModel.event.state {
            case .connected:
                HStack(spacing: 4) {
                    Circle().fill(Color.green).frame(width: 8, height: 8)
                    Text("Connected").foregroundColor(.green)
                }
            case .connecting, .authenticating, .dhcp:
                HStack(spacing: 4) {
                    Circle().fill(Color.orange).frame(width: 8, height: 8)
                    Text("Connecting").foregroundColor(.orange)
                }
            case .reconnecting:
                HStack(spacing: 4) {
                    Circle().fill(Color.orange).frame(width: 8, height: 8)
                    Text("Reconnecting…").foregroundColor(.orange)
                }
            case .disconnected:
                Text("Offline").foregroundColor(.secondary)
            }
        } else {
            Text("Offline").foregroundColor(.secondary)
        }
    }
}
