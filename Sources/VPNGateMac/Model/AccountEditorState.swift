import Combine
import Foundation
import VPNGateCore

/// Form state of the connection-setting editor. Kept free of SwiftUI so the save logic can be tested.
final class AccountEditorState: ObservableObject {
    @Published var name: String
    @Published var host: String
    @Published var portString: String
    @Published var hub: String
    @Published var username: String
    @Published var authType: AccountAuthType
    @Published var password: String
    /// The rarely needed options are folded away until asked for.
    @Published var showAdvanced = false

    @Published var maxConnection: Int
    @Published var compression: Bool
    @Published var udpAcceleration: Bool
    @Published var useQoS: Bool
    @Published var halfConnection: Bool
    @Published var autoReconnect: Bool
    @Published var reconnectIntervalSeconds: Int
    @Published var reconnectCount: Int
    @Published var checkServerCert: Bool
    @Published var fingerprint: String
    /// "Automatic" (DHCP-provided) when empty, otherwise the "Virtual Network Adapter" MTU override.
    @Published var mtuString: String
    /// Random when empty, otherwise the "Virtual Network Adapter" MAC override.
    @Published var macString: String
    /// When on, `routing` replaces the app's global rules for this account; when off, the global rules apply.
    @Published var useCustomRouting: Bool
    @Published var routing: RoutingConfig

    /// Certificate login: freshly imported material (nil = keep what is stored) and whether something is stored already.
    @Published var certDer: Data?
    @Published var privateKeyDer: Data?
    @Published var hasStoredIdentity: Bool
    @Published var importError: String?
    @Published var p12Passphrase = ""

    init(account: ClientAccount? = nil, initialPassword: String? = nil, hasStoredIdentity: Bool = false) {
        self.name = account?.name ?? "New Connection"
        self.host = account?.host ?? ""
        self.portString = account?.portList.map(String.init).joined(separator: ", ") ?? "443, 992, 5555, 1194"
        self.hub = account?.hub ?? "DEFAULT"
        self.username = account?.username ?? ""
        self.authType = account?.authType ?? .password
        self.password = initialPassword ?? ""
        self.maxConnection = account?.maxConnection ?? 1
        self.compression = account?.compression ?? false
        self.udpAcceleration = account?.udpAcceleration ?? true
        self.useQoS = !(account?.disableQoS ?? false)
        self.halfConnection = account?.halfConnection ?? false
        self.autoReconnect = account?.autoReconnect ?? true
        self.reconnectIntervalSeconds = Int((account?.reconnectInterval ?? 3).rounded())
        self.reconnectCount = account?.reconnectCount ?? 8
        self.checkServerCert = account?.checkServerCert ?? false
        self.fingerprint = account?.serverCertFingerprint ?? ""
        self.mtuString = account?.mtu.map(String.init) ?? ""
        self.macString = account?.virtualMacAddress ?? ""
        self.useCustomRouting = account?.routing != nil
        self.routing = account?.routing ?? RoutingConfig()
        self.hasStoredIdentity = hasStoredIdentity
    }

    var parsedPorts: [UInt16] {
        portString.split(separator: ",").compactMap { UInt16($0.trimmingCharacters(in: .whitespaces)) }.filter { $0 > 0 }
    }

    var trimmedFingerprint: String { fingerprint.trimmingCharacters(in: .whitespaces) }

    /// Empty is fine (no pin); otherwise it must be a SHA-1 or SHA-256 hex fingerprint.
    var fingerprintError: String? {
        trimmedFingerprint.isEmpty || InputValidation.normalizedFingerprint(trimmedFingerprint) != nil
            ? nil : "Fingerprint must be 40 (SHA-1) or 64 (SHA-256) hex digits."
    }

    var certificateReady: Bool { authType != .certificate || certDer != nil && privateKeyDer != nil || hasStoredIdentity }

    var trimmedMtu: String { mtuString.trimmingCharacters(in: .whitespaces) }
    var mtuError: String? {
        trimmedMtu.isEmpty || (Int(trimmedMtu).map { (576...1500).contains($0) } ?? false)
            ? nil : "MTU must be 576–1500, or blank for automatic."
    }

    var trimmedMac: String { macString.trimmingCharacters(in: .whitespaces) }
    var macError: String? {
        trimmedMac.isEmpty || InputValidation.parseMacAddress(trimmedMac) != nil
            ? nil : "MAC must be 6 hex byte pairs, e.g. 00:AC:DE:12:34:56."
    }

    var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && !host.trimmingCharacters(in: .whitespaces).isEmpty
            && InputValidation.isValidHost(host.trimmingCharacters(in: .whitespaces))
            && fingerprintError == nil && certificateReady && mtuError == nil && macError == nil
            && InputValidation.isValidIdentityField(hub) && InputValidation.isValidIdentityField(username)
    }

    /// The saved account: starts from `base` (when editing) so every field the form does not show (proxy, reserved
    /// settings, creation date, ...) survives, and only the fields the form shows are replaced.
    func makeAccount(base: ClientAccount?) -> ClientAccount {
        var acc = base ?? ClientAccount(name: "", host: "")
        let ports = parsedPorts
        acc.name = name.trimmingCharacters(in: .whitespaces)
        acc.host = host.trimmingCharacters(in: .whitespaces)
        acc.portList = ports.isEmpty ? [443] : ports
        let h = hub.trimmingCharacters(in: .whitespaces)
        acc.hub = h.isEmpty ? "DEFAULT" : h
        acc.username = username.trimmingCharacters(in: .whitespaces)
        acc.authType = authType
        acc.checkServerCert = checkServerCert
        acc.serverCertFingerprint = InputValidation.normalizedFingerprint(trimmedFingerprint)
        acc.maxConnection = max(1, min(maxConnection, 32))
        acc.compression = compression
        acc.udpAcceleration = udpAcceleration
        acc.disableQoS = !useQoS
        acc.halfConnection = halfConnection
        acc.autoReconnect = autoReconnect
        acc.reconnectInterval = TimeInterval(max(1, reconnectIntervalSeconds))
        acc.reconnectCount = max(1, reconnectCount)
        acc.mtu = trimmedMtu.isEmpty ? nil : Int(trimmedMtu)
        acc.virtualMacAddress = trimmedMac.isEmpty ? nil : trimmedMac
        acc.routing = useCustomRouting ? routing : nil
        return acc
    }
}
