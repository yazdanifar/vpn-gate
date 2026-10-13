import Foundation
import Security

setvbuf(stdout, nil, _IOLBF, 0)

// Never touch the user's real app data: point file storage and the Keychain at throwaway locations.
let testSupportDir = FileManager.default.temporaryDirectory.appendingPathComponent("vpngate-appdata-\(getpid())", isDirectory: true)
let testKeychainService = "com.yazdanifar.VPNGateMac.tests"
AppPaths.supportDirectory = testSupportDir
Keychain.service = testKeychainService
func cleanUpTestData() {
    try? FileManager.default.removeItem(at: testSupportDir)
    try? FileManager.default.removeItem(atPath: NSTemporaryDirectory() + "vpngate-tests-\(getpid())")   // Fakes.swift tmp dir
    // Only items under the *test* service are removed; the real service name is never used here.
    SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: testKeychainService] as CFDictionary)
}
atexit { cleanUpTestData() }
let allRegistrars: [() -> Void] = [
    registerPackTests, registerPacketTests, registerServerListTests, registerVGDatTests, registerAccountTests, registerTelemetryTests, registerIPv6Tests, registerDataPhaseTests,
    registerValidationTests, registerBridgeTests, registerBridgeIPv6Tests, registerHandshakeTests, registerProtocolFixTests, registerSessionTests, registerSocksTests,
    registerNetConfigTests, registerIPCTests, registerDaemonTests, registerFuzzTests, registerSystemTests, registerPackagingTests, registerAppModelTests, registerAppFixTests, registerLoginParityTests, registerTLSPinTests, registerParityTests, registerProbeTests, registerLiveTests,
    registerRoutingRuleTests, registerDNSProxyTests,
]
allRegistrars.forEach { $0() }

// Hard stop so a deadlocked test cannot hang CI forever.
DispatchQueue.global().asyncAfter(deadline: .now() + 300) { print("GLOBAL WATCHDOG: test run exceeded 300s"); exit(3) }

Task {
    let code = await runAllTests(args: Array(CommandLine.arguments.dropFirst()))
    exit(code)
}
dispatchMain()
