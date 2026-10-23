import Foundation
import ServiceManagement

enum LoginItemStatus: Equatable { case enabled, requiresApproval, notRegistered, notFound }

/// Seam over SMAppService so the launch-at-login handling can be tested.
protocol LoginItemControlling {
    var status: LoginItemStatus { get }
    func register() throws
    func unregister() throws
}

struct SMAppLoginItem: LoginItemControlling {
    var status: LoginItemStatus {
        switch SMAppService.mainApp.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        default: return .notRegistered
        }
    }
    func register() throws { try SMAppService.mainApp.register() }
    func unregister() throws { try SMAppService.mainApp.unregister() }
}
