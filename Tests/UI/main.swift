import AppKit
import Foundation

setvbuf(stdout, nil, _IOLBF, 0)

// Never touch the user's real app data.
let testSupportDir = FileManager.default.temporaryDirectory.appendingPathComponent("vpngate-ui-\(getpid())", isDirectory: true)
AppPaths.supportDirectory = testSupportDir
Keychain.service = "com.yazdanifar.VPNGateMac.uitests"
atexit { try? FileManager.default.removeItem(at: testSupportDir) }

_ = NSApplication.shared
NSApp.setActivationPolicy(.accessory)

registerScreenshotTests()

DispatchQueue.global().asyncAfter(deadline: .now() + 300) {
    print("GLOBAL WATCHDOG: UI test run exceeded 300s"); exit(3)
}

Task {
    let code = await runAllTests(args: Array(CommandLine.arguments.dropFirst()))
    exit(code)
}
RunLoop.main.run()  // not dispatchMain(): AppKit needs the main queue drained by the main thread
