import Foundation

setvbuf(stdout, nil, _IOLBF, 0)
let allRegistrars: [() -> Void] = [
    registerPackTests, registerPacketTests, registerServerListTests, registerVGDatTests, registerAccountTests, registerTelemetryTests, registerDataPhaseTests,
    registerValidationTests, registerBridgeTests, registerHandshakeTests, registerSessionTests,
    registerNetConfigTests, registerIPCTests, registerDaemonTests, registerFuzzTests, registerSystemTests, registerPackagingTests, registerAppModelTests, registerLiveTests,
]
allRegistrars.forEach { $0() }

// Hard stop so a deadlocked test cannot hang CI forever.
DispatchQueue.global().asyncAfter(deadline: .now() + 300) { print("GLOBAL WATCHDOG: test run exceeded 300s"); exit(3) }

Task {
    let code = await runAllTests(args: Array(CommandLine.arguments.dropFirst()))
    exit(code)
}
dispatchMain()
