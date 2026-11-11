import AppKit
import ApplicationServices
import Foundation

// Launch test: starts the real `VPN Gate.app` against a fake helper and drives it from outside through the macOS
// accessibility API and synthetic mouse/keyboard events, the way a user would. SwiftUI toolbar items cannot be
// reached from inside the process, so this is the only place the Filter menu is really opened and clicked.
//
// Needs Accessibility permission for the process that runs it and a logged-in GUI session, so it runs on CI only
// (scripts/test-app-launch.sh refuses to run elsewhere unless VPNGATE_LAUNCH_TEST_OK=1). It takes over the mouse.
//
// Environment: VPNGATE_APP (path of the .app), VPNGATE_SHOTS (directory for failure screenshots and AX dumps).

setvbuf(stdout, nil, _IOLBF, 0)

// MARK: accessibility helpers

struct AX {
    let el: AXUIElement

    func attr(_ name: String) -> CFTypeRef? {
        var v: CFTypeRef?
        return AXUIElementCopyAttributeValue(el, name as CFString, &v) == .success ? v : nil
    }
    func str(_ name: String) -> String? {
        if let s = attr(name) as? String, !s.isEmpty { return s }
        return nil
    }
    var role: String { str("AXRole") ?? "" }
    var title: String { str("AXTitle") ?? "" }
    var desc: String { str("AXDescription") ?? "" }
    var ident: String { str("AXIdentifier") ?? "" }
    var value: String { (attr("AXValue") as? String) ?? "" }
    var children: [AX] { ((attr("AXChildren") as? [AXUIElement]) ?? []).map(AX.init) }
    /// The labels a control may carry, SwiftUI puts a toolbar item's name in any of them.
    var names: [String] { [title, desc, ident, value].filter { !$0.isEmpty } }
    var frame: CGRect? {
        guard let p = attr("AXPosition"), let s = attr("AXSize") else { return nil }
        var pt = CGPoint.zero, sz = CGSize.zero
        guard AXValueGetValue(p as! AXValue, .cgPoint, &pt), AXValueGetValue(s as! AXValue, .cgSize, &sz) else { return nil }
        return CGRect(origin: pt, size: sz)
    }

    /// Depth-first search; stops after `limit` elements so a huge table cannot stall the test.
    func find(limit: Int = 6000, _ match: (AX) -> Bool) -> AX? {
        var seen = 0
        func walk(_ n: AX, _ depth: Int) -> AX? {
            seen += 1
            if seen > limit || depth > 40 { return nil }
            if match(n) { return n }
            for c in n.children { if let r = walk(c, depth + 1) { return r } }
            return nil
        }
        return walk(self, 0)
    }
    func findAll(limit: Int = 6000, _ match: (AX) -> Bool) -> [AX] {
        var out: [AX] = []; var seen = 0
        func walk(_ n: AX, _ depth: Int) {
            seen += 1
            if seen > limit || depth > 40 { return }
            if match(n) { out.append(n) }
            for c in n.children { walk(c, depth + 1) }
        }
        walk(self, 0)
        return out
    }
    func named(_ name: String, roles: Set<String>? = nil) -> AX? {
        find { n in n.names.contains(name) && (roles == nil || roles!.contains(n.role)) }
    }
    func press() -> Bool { AXUIElementPerformAction(el, "AXPress" as CFString) == .success }

    func dump(maxLines: Int = 160) -> String {
        var lines: [String] = []
        func walk(_ n: AX, _ depth: Int) {
            if lines.count >= maxLines { return }
            lines.append(String(repeating: "  ", count: depth) + "\(n.role) \(n.names.map { "\"\($0.prefix(40))\"" }.joined(separator: " "))")
            for c in n.children { walk(c, depth + 1) }
        }
        walk(self, 0)
        return lines.joined(separator: "\n")
    }
}

func click(_ p: CGPoint) {
    let move = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: p, mouseButton: .left)
    move?.post(tap: .cghidEventTap)
    usleep(80_000)
    CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: p, mouseButton: .left)?.post(tap: .cghidEventTap)
    usleep(60_000)
    CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: p, mouseButton: .left)?.post(tap: .cghidEventTap)
}
func clickCenter(_ e: AX) -> Bool {
    guard let f = e.frame, f.width > 0 else { return false }
    click(CGPoint(x: f.midX, y: f.midY)); return true
}
func typeText(_ s: String) {
    for ch in s.utf16 {
        var c = ch
        for down in [true, false] {
            let ev = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: down)
            ev?.keyboardSetUnicodeString(stringLength: 1, unicodeString: &c)
            ev?.post(tap: .cghidEventTap)
            usleep(20_000)
        }
    }
}
func pressEscape() {
    for down in [true, false] { CGEvent(keyboardEventSource: nil, virtualKey: 53, keyDown: down)?.post(tap: .cghidEventTap) }
}

// MARK: the app under test and the fake helper

let appPath = ProcessInfo.processInfo.environment["VPNGATE_APP"] ?? "build/VPN Gate.app"
let shotsDir = ProcessInfo.processInfo.environment["VPNGATE_SHOTS"] ?? "build/launch-test"
try? FileManager.default.createDirectory(atPath: shotsDir, withIntermediateDirectories: true)

let countries = [("Japan", "JP"), ("South Korea", "KR"), ("United States", "US")]
let fakeServers: [VPNServer] = (0..<240).map { i in
    var s = parsedServer("relay\(i)", ip: "10.1.\(i / 200).\(i % 200 + 1)")
    s.countryLong = countries[i % 3].0; s.countryShort = countries[i % 3].1
    return s
}

final class Rig: @unchecked Sendable {
    let session = FakeHelperSession()
    var server: FakeHelperServer?
    let replied = Locked(0)  // probe replies sent so far: the progress the menu must survive
    var proc: Process?
    var ax: AX!
    let socket = tempPath("launch-\(UUID().uuidString.prefix(6)).sock")
    let support = tempPath("support-\(UUID().uuidString.prefix(6))")

    func start() throws {
        var snap = HelperEvent(state: .disconnected); snap.helperVersion = helperVersion
        session.snapshot = snap
        session.listResult = ServerListResult(
            servers: fakeServers, source: .httpApi, timestampMs: UInt64(Date().timeIntervalSince1970 * 1000), isFresh: true,
            outcome: .synced, nextPollSeconds: 3600)
        session.refreshResult = session.listResult
        // Each relay answers after a pause, so a Test Connection over 240 relays streams results for about eighteen seconds.
        session.probeReply = { [replied] ts in
            Thread.sleep(forTimeInterval: 0.6)
            replied.update { $0 += ts.count }
            return ts.map { ProbeEntry(host: $0.host, ok: true, port: 443, connectMs: 20, helloMs: 40, build: nil, error: nil) }
        }
        server = FakeHelperServer(path: socket, session: session)
        try server!.start()
        try FileManager.default.createDirectory(atPath: support, withIntermediateDirectories: true)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/MacOS/VPNGateMac")
        var env = ProcessInfo.processInfo.environment
        env["VPNGATE_HELPER_SOCKET"] = socket
        env["VPNGATE_SUPPORT_DIR"] = support
        p.environment = env
        // Not the runner's pipes: a child holding them open keeps `tee` (and the CI step) waiting after the test is done.
        let log = FileHandle(forWritingAtPath: { FileManager.default.createFile(atPath: "\(shotsDir)/app.log", contents: nil); return "\(shotsDir)/app.log" }())
        p.standardOutput = log; p.standardError = log; p.standardInput = FileHandle.nullDevice
        try p.run()
        proc = p
        ax = AX(el: AXUIElementCreateApplication(p.processIdentifier))
        AXUIElementSetMessagingTimeout(ax.el, 5)
    }
    func stop() {
        if let p = proc { p.terminate(); usleep(500_000); kill(p.processIdentifier, SIGKILL) }  // a menu left open can ignore SIGTERM
        server?.stop()
    }

    func activate() { NSRunningApplication(processIdentifier: proc!.processIdentifier)?.activate(options: [.activateIgnoringOtherApps]) }

    /// On failure: the accessibility tree and a screenshot, which CI uploads.
    func evidence(_ label: String) -> String {
        let tree = ax.dump(maxLines: 300)
        try? tree.write(toFile: "\(shotsDir)/\(label).ax.txt", atomically: true, encoding: .utf8)
        let t = Process(); t.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        t.arguments = ["-x", "\(shotsDir)/\(label).png"]; try? t.run(); t.waitUntilExit()
        return "\n--- accessibility tree ---\n" + ax.dump(maxLines: 60)
    }

    // Finders. `table` is the server list.
    var table: AX? { ax.find { $0.role == "AXTable" || $0.role == "AXOutline" } }
    func shows(_ text: String) -> Bool { (table ?? ax).find { n in n.names.contains { $0 == text || $0.hasSuffix(" " + text) } } != nil }  // cells read "🇯🇵 Japan"
    var rowCount: Int { table?.findAll { $0.role == "AXRow" }.count ?? 0 }
    var filterButton: AX? { ax.named("toolbar.filter") ?? ax.named("Filter", roles: ["AXMenuButton", "AXPopUpButton", "AXButton"]) }
    var testButton: AX? { ax.named("toolbar.test") ?? ax.named("Test Connection", roles: ["AXButton"]) }
    func menuItem(_ name: String) -> AX? { ax.find { $0.role == "AXMenuItem" && $0.names.contains(name) } }
}

let rig = Rig()

/// Fails the test with the accessibility tree attached.
func need(_ cond: Bool, _ msg: String, _ label: String) {
    if !cond { fail(msg + rig.evidence(label)) }
}

func ensureRunning() async throws {
    if rig.proc != nil { return }
    try rig.start()
    // The disclaimer sheet comes first on a fresh profile.
    let agreed = await eventuallyA(30) {
        rig.activate()
        if let b = rig.ax.named("Agree and Continue", roles: ["AXButton"]) { return b.press() }
        return false
    }
    need(agreed, "the disclaimer sheet never appeared", "no-disclaimer")
    let listed = await eventuallyA(30) { rig.shows("South Korea") && rig.shows("Japan") }
    need(listed, "the server list never showed the fake relays", "no-list")
}

/// Opens the Filter menu with a real click and descends into the Country submenu.
func openCountryMenu(_ label: String) async {
    rig.activate()
    let btn = await eventuallyA(10) { rig.filterButton != nil }
    need(btn, "no Filter toolbar item", "\(label)-no-filter")
    _ = clickCenter(rig.filterButton!)
    let country = await eventuallyA(5) { rig.menuItem("Country") != nil }
    need(country, "the Filter menu did not open", "\(label)-no-menu")
    // Open the submenu (a press selects it without closing the menu).
    _ = rig.menuItem("Country")!.press()
    let items = await eventuallyA(5) { rig.menuItem("South Korea") != nil }
    need(items, "the Country submenu did not open", "\(label)-no-submenu")
}

func holdMenuOpen(seconds: Double, tickEvery: Double = 0.25, tick: () -> Void) async {
    let end = Date().addingTimeInterval(seconds)
    while Date() < end { tick(); try? await Task.sleep(nanoseconds: UInt64(tickEvery * 1e9)) }
}

// MARK: tests

test("launch/the-app-starts-and-lists-the-relays-from-the-helper", timeout: 120) {
    try await ensureRunning()
    expect(rig.rowCount > 0, "no table rows")
}

test("launch/country-menu-stays-open-while-the-helper-publishes-and-applies-a-country", timeout: 90) {
    try await ensureRunning()
    await openCountryMenu("idle")
    // Everything that used to rebuild the toolbar: status events, list refreshes, log lines.
    await holdMenuOpen(seconds: 3) {
        rig.session.emit?(HelperEvent(state: .disconnected))
    }
    need(rig.menuItem("South Korea") != nil, "the Country submenu closed by itself while events arrived", "idle-closed")
    _ = rig.menuItem("South Korea")!.press()
    let filtered = await eventuallyA(8) { !rig.shows("Japan") && rig.shows("South Korea") }
    need(filtered, "choosing South Korea did not filter the list", "idle-not-filtered")
}

test("launch/country-menu-stays-open-while-test-connection-streams-results", timeout: 120) {
    try await ensureRunning()
    // Back to all countries first (the previous test left South Korea chosen).
    rig.activate()
    if let b = rig.filterButton { _ = clickCenter(b) }
    if await eventuallyA(5, { rig.menuItem("Clear Filters") != nil }) { _ = rig.menuItem("Clear Filters")!.press() } else { pressEscape() }
    need(await eventuallyA(8) { rig.shows("Japan") }, "Clear Filters did not restore the list", "probe-clear")

    let probesBefore = rig.session.probes.count
    need(rig.testButton != nil && clickCenter(rig.testButton!), "no Test Connection button", "probe-no-test")
    need(await eventuallyA(10) { rig.session.probes.count > probesBefore }, "Test Connection sent no probes", "probe-none-sent")

    await openCountryMenu("probe")
    let sentAtOpen = rig.replied.value
    await holdMenuOpen(seconds: 3) {}
    let sentAfter = rig.replied.value
    need(sentAfter > sentAtOpen, "no probe results arrived while the menu was open, so this proves nothing (\(sentAtOpen) -> \(sentAfter))", "probe-idle")
    need(rig.menuItem("United States") != nil, "the Country submenu closed while Test Connection was running", "probe-closed")
    _ = rig.menuItem("United States")!.press()
    need(await eventuallyA(8) { !rig.shows("Japan") && rig.shows("United States") }, "choosing United States did not filter the list", "probe-not-filtered")
}

test("launch/typing-in-the-search-field-narrows-the-list", timeout: 90) {
    try await ensureRunning()
    rig.activate()
    // Start from the full list.
    if let b = rig.filterButton, rig.menuItem("Clear Filters") == nil, !rig.shows("Japan") {
        _ = clickCenter(b)
        if await eventuallyA(5, { rig.menuItem("Clear Filters") != nil }) { _ = rig.menuItem("Clear Filters")!.press() } else { pressEscape() }
    }
    need(await eventuallyA(8) { rig.shows("Japan") && rig.shows("South Korea") }, "could not get the full list back", "search-start")
    let field = rig.ax.find { $0.role == "AXTextField" && ($0.names.contains { $0.localizedCaseInsensitiveContains("search") } || $0.role == "AXSearchField") }
        ?? rig.ax.find { $0.role == "AXSearchField" || $0.role == "AXTextField" }
    need(field != nil && clickCenter(field!), "no search field", "search-no-field")
    typeText("Korea")
    need(await eventuallyA(8) { !rig.shows("Japan") && rig.shows("South Korea") }, "typing Korea did not narrow the list", "search-not-narrowed")
}

Task {
    guard AXIsProcessTrusted() else {
        print("Accessibility permission is missing for this process; see scripts/test-app-launch.sh"); exit(4)
    }
    let code = await runAllTests(args: Array(CommandLine.arguments.dropFirst()))
    rig.stop()
    exit(code)
}
// A plain thread: it must fire even when the Swift concurrency pool is stuck in a blocking accessibility call.
Thread.detachNewThread {
    Thread.sleep(forTimeInterval: 420)
    print("GLOBAL WATCHDOG: launch test exceeded 420s")
    if let p = rig.proc { kill(p.processIdentifier, SIGKILL) }
    exit(3)
}
_ = NSApplication.shared
RunLoop.main.run()
