import SwiftUI
import VPNGateCore

/// The "Routing" settings tab: an ordered rule list, what unmatched traffic does, and the bypass-LAN preset.
/// Shared with the per-account override editor via `RoutingRulesEditor` (bound to whichever `RoutingConfig` the
/// caller passes in).
struct RoutingSettings: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Form { RoutingRulesEditor(config: $model.routingConfig) }
            .formStyle(.grouped)
    }
}

/// The reusable editor: an ordered list of rules, add/remove/reorder, a default-action picker and the
/// bypass-private-networks toggle. Used for both the app-wide config and an account's own override. Produces
/// `Form` sections, so the caller supplies the surrounding `Form` (the Settings tab has its own; the account
/// editor is already inside one).
/// @State is a macro whose plugin only ships with full Xcode, so view state lives in an ObservableObject
/// (see ServerListView.swift).
private final class RoutingEditorUIState: ObservableObject {
    @Published var editing: RoutingRule?
    @Published var showingNewRule = false
}

struct RoutingRulesEditor: View {
    @Binding var config: RoutingConfig
    @StateObject private var ui = RoutingEditorUIState()

    var body: some View {
        Group {
            Section("Unmatched traffic") {
                Picker("By default", selection: $config.defaultAction) {
                    Text("Proxy (through the tunnel)").tag(RoutingAction.proxy)
                    Text("Direct (bypass the tunnel)").tag(RoutingAction.direct)
                }
                Toggle("Bypass private networks (LAN, link-local, CGNAT)", isOn: $config.bypassPrivateNetworks)
                Text(config.defaultAction == .proxy
                     ? "Everything goes through the tunnel except what the rules below send elsewhere."
                     : "Everything bypasses the tunnel except what the rules below send into it. IPv6 keeps being captured and dropped regardless (see “Block IPv6” in General).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Rules") {
                if config.rules.isEmpty {
                    Text("No custom rules. Traffic follows the default action above.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(config.rules) { rule in
                    RoutingRuleRow(rule: rule)
                        .contentShape(Rectangle())
                        .onTapGesture { ui.editing = rule }
                }
                .onMove { indices, newOffset in config.rules.move(fromOffsets: indices, toOffset: newOffset) }
                .onDelete { indices in config.rules.remove(atOffsets: indices) }
                Button("Add Rule…") { ui.showingNewRule = true }
            }
            Text("Rules are checked in order from top to bottom; the first one that matches wins. Domain rules need "
                 + "the DNS proxy, which only runs while one is configured. A domain marked “Direct” is looked up "
                 + "through your regular network connection, never through the VPN or its DNS — everything else is "
                 + "resolved only through the tunnel.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .sheet(item: $ui.editing) { rule in
            RoutingRuleSheet(rule: rule) { updated in
                if let updated {
                    if let i = config.rules.firstIndex(where: { $0.id == rule.id }) { config.rules[i] = updated }
                } else {
                    config.rules.removeAll { $0.id == rule.id }
                }
            }
        }
        .sheet(isPresented: $ui.showingNewRule) {
            RoutingRuleSheet(rule: nil) { newRule in
                if let newRule { config.rules.append(newRule) }
            }
        }
    }
}

private struct RoutingRuleRow: View {
    let rule: RoutingRule

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(rule.value).font(.system(.body, design: .monospaced))
                Text(rule.type.label).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Text(rule.action.label)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 8).padding(.vertical, 2)
                .background(color(for: rule.action).opacity(0.18), in: Capsule())
                .foregroundStyle(color(for: rule.action))
            if !rule.enabled { Text("Off").font(.caption).foregroundStyle(.secondary) }
        }
        .opacity(rule.enabled ? 1 : 0.5)
    }

    private func color(for action: RoutingAction) -> Color {
        switch action {
        case .proxy: return .blue
        case .direct: return .green
        case .block: return .red
        }
    }
}

/// @State is a macro whose plugin only ships with full Xcode, so view state lives in an ObservableObject
/// (see ServerListView.swift).
private final class RoutingRuleSheetState: ObservableObject {
    @Published var type: RoutingRuleType
    @Published var value: String
    @Published var action: RoutingAction
    @Published var enabled: Bool
    let isNew: Bool
    let ruleID: UUID

    init(rule: RoutingRule?) {
        type = rule?.type ?? .domainSuffix
        value = rule?.value ?? ""
        action = rule?.action ?? .proxy
        enabled = rule?.enabled ?? true
        isNew = rule == nil
        ruleID = rule?.id ?? UUID()
    }

    var validationError: String? { RoutingRule.validationError(type: type, value: value) }
}

/// Add or edit one rule. Passing `nil` back to `onDone` means "delete this rule" (only reachable from Edit).
private struct RoutingRuleSheet: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var ui: RoutingRuleSheetState
    let onDone: (RoutingRule?) -> Void

    init(rule: RoutingRule?, onDone: @escaping (RoutingRule?) -> Void) {
        _ui = StateObject(wrappedValue: RoutingRuleSheetState(rule: rule))
        self.onDone = onDone
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Picker("Match", selection: $ui.type) {
                    ForEach(RoutingRuleType.allCases) { Text($0.label).tag($0) }
                }
                TextField(placeholder(for: ui.type), text: $ui.value)
                    .textFieldStyle(.roundedBorder)
                if let error = ui.validationError, !ui.value.isEmpty { Text(error).font(.caption).foregroundStyle(.red) }
                Picker("Action", selection: $ui.action) {
                    ForEach(RoutingAction.allCases) { Text($0.label).tag($0) }
                }
                Toggle("Enabled", isOn: $ui.enabled)
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                if !ui.isNew {
                    Button("Delete", role: .destructive) { onDone(nil); dismiss() }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button(ui.isNew ? "Add" : "Save") {
                    onDone(RoutingRule(id: ui.ruleID, type: ui.type, value: ui.value, action: ui.action, enabled: ui.enabled))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(ui.validationError != nil)
            }
            .padding(12)
        }
        .frame(width: 420, height: 260)
    }

    private func placeholder(for type: RoutingRuleType) -> String {
        switch type {
        case .domainSuffix, .domainFull: return "example.com"
        case .domainKeyword: return "ads"
        case .domainRegex: return "^(.+\\.)?example\\.com$"
        case .ip: return "203.0.113.5"
        case .cidr: return "10.0.0.0/8"
        }
    }
}
