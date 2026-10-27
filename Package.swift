// swift-tools-version:6.0
import PackageDescription

// The installed manifest API only links without the language-mode argument,
// so pin Swift 5 mode per target with a compiler flag instead.
let swift5: [SwiftSetting] = [.unsafeFlags(["-swift-version", "5"])]

let package = Package(
    name: "VPNGateMac",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "VPNGateCore", targets: ["VPNGateCore"]),
        .executable(name: "vpngate-helper", targets: ["vpngate-helper"]),
        .executable(name: "VPNGateMac", targets: ["VPNGateMac"]),
    ],
    targets: [
        .target(name: "VPNGateCore", swiftSettings: swift5),
        .executableTarget(name: "vpngate-helper", dependencies: ["VPNGateCore"], swiftSettings: swift5),
        .executableTarget(name: "VPNGateMac", swiftSettings: swift5),
    ]
)
