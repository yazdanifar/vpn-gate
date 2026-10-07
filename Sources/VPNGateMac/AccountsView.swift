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

    var selectedAccount: ClientAccount? {
        accountManager.accounts.first { $0.id == ui.selectedAccountID }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack(spacing: 8) {
                Button(action: { ui.editingAccount = nil; ui.showingEditor = true }) {
                    Label("New Connection Setting", systemImage: "plus")
                }

                Divider().frame(height: 16)

                Button(action: {
                    if let acc = selectedAccount {
                        appModel.connect(account: acc)
                    }
                }) {
                    Label("Connect", systemImage: "bolt.fill")
                }
                .disabled(selectedAccount == nil || appModel.isConnected)

                Button(action: { appModel.disconnect() }) {
                    Label("Disconnect", systemImage: "power")
                }
                .disabled(!appModel.isConnected)

                Divider().frame(height: 16)

                Button(action: {
                    if let acc = selectedAccount {
                        ui.editingAccount = acc
                        ui.showingEditor = true
                    }
                }) {
                    Label("Properties", systemImage: "slider.horizontal.3")
                }
                .disabled(selectedAccount == nil)

                Button(action: {
                    if let acc = selectedAccount {
                        accountManager.duplicate(acc)
                    }
                }) {
                    Label("Duplicate", systemImage: "plus.square.on.square")
                }
                .disabled(selectedAccount == nil)

                Button(action: {
                    if let acc = selectedAccount {
                        accountManager.delete(acc)
                        ui.selectedAccountID = nil
                    }
                }) {
                    Label("Delete", systemImage: "trash")
                }
                .disabled(selectedAccount == nil)

                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color(NSColor.windowBackgroundColor))

            Divider()

            // Accounts Table
            if accountManager.accounts.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "network")
                        .font(.system(size: 44))
                        .foregroundColor(.secondary)
                    Text("No VPN Connection Settings")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    Text("Click “New Connection Setting” to configure a SoftEther VPN server connection.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Button("Create New Connection Setting") {
                        ui.editingAccount = nil
                        ui.showingEditor = true
                    }
                    .padding(.top, 4)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(accountManager.accounts, selection: $ui.selectedAccountID) {
                    TableColumn("Setting Name", value: \.name)
                    TableColumn("Status") { acc in
                        statusView(for: acc)
                    }
                    .width(min: 90, ideal: 100)
                    TableColumn("VPN Server Hostname") { acc in
                        Text("\(acc.host):\(acc.portList.first ?? 443)")
                    }
                    TableColumn("Virtual HUB", value: \.hub)
                    TableColumn("Virtual Adapter") { _ in
                        Text("utun (Bridge)")
                            .foregroundColor(.secondary)
                    }
                    TableColumn("Auth Type") { acc in
                        Text(acc.authType.rawValue)
                    }
                }
            }
        }
        .sheet(isPresented: $ui.showingEditor) {
            AccountEditor(
                account: ui.editingAccount,
                initialPassword: ui.editingAccount.flatMap { accountManager.password(for: $0) },
                onSave: { updated, pw, cert in
                    if ui.editingAccount != nil {
                        accountManager.update(updated, password: pw, certDer: cert)
                    } else {
                        accountManager.add(updated, password: pw, certDer: cert)
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
                    Text("Connecting…").foregroundColor(.orange)
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
