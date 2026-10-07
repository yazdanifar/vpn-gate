import Foundation
import VPNGateCore

/// The first-run setup flow: Connect with no (or an outdated) helper asks once, opens the installer, then
/// continues by itself when the helper is up.
private func makeDefaults() -> UserDefaults {
    let name = "vpngate-tests-\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    return d
}

private func server(_ host: String = "vpn1", ip: String = "1.2.3.4", port: Int = 443) -> VPNServer {
    ServerList.parse("#h\n\(host),\(ip),1,1,1,Japan,JP,1,1,1,1,2weeks,Op,msg,\(Data("proto tcp\nremote \(ip) \(port)\n".utf8).base64EncodedString())\n")[0]
}

@MainActor private func model(_ path: String, opened: Locked<Int>, installerExists: Bool = true) -> AppModel {
    AppModel(socketPath: path, defaults: makeDefaults(), autoStart: false,
             openInstaller: { opened.update { $0 += 1 }; return installerExists })
}

private func startHelper(_ path: String, version: Int?) -> (IPCServer, FakeSession) {
    let fake = FakeSession()
    var snap = HelperEvent(state: .disconnected); snap.helperVersion = version
    fake.snapshot = snap
    let srv = IPCServer(path: path, allowedUID: getuid(), session: fake)
    try! srv.start()
    return (srv, fake)
}

private func sockPath() -> String { tempPath("app-\(UUID().uuidString.prefix(6)).sock") }

func registerAppModelTests() {
    test("setup/connect-without-a-helper-asks-once-and-does-not-connect") {
        let opened = Locked(0)
        let m = await model(sockPath(), opened: opened)
        await MainActor.run { m.connect(server()) }
        let prompt = await MainActor.run { m.setupPrompt }
        expectEqual(prompt == .install, true, "first run must show the one-time setup alert")
        expectEqual(opened.value, 0, "the installer must not open before the user confirms")
        let state = await MainActor.run { m.event.state }
        expectEqual(state, .disconnected, "no phantom 'Connecting…'")
    }
    test("setup/confirming-opens-the-standard-installer") {
        let opened = Locked(0)
        let m = await model(sockPath(), opened: opened)
        await MainActor.run { m.connect(server()); m.beginSetup() }
        expectEqual(opened.value, 1)
        let (prompt, waiting, notice) = await MainActor.run { (m.setupPrompt, m.waitingForInstaller, m.notice) }
        expect(prompt == nil); expect(waiting); expect(notice?.contains("installer") == true, "\(String(describing: notice))")
    }
    test("setup/connects-by-itself-once-the-helper-appears") {
        let path = sockPath(); let opened = Locked(0)
        let m = await model(path, opened: opened)
        let s = server("vpn9", ip: "9.9.9.9", port: 995)
        await MainActor.run { m.connect(s); m.beginSetup() }
        await MainActor.run { m.pollHelper() }                             // installer still running: nothing yet
        let (srv, fake) = startHelper(path, version: helperVersion); defer { srv.stop() }
        await expectA(await eventuallyA(3) { await MainActor.run { m.pollHelper() }; return fake.connects.count == 1 },
                      "the pending connection never resumed after the helper came up")
        expectEqual(fake.connects.first?.host, "9.9.9.9"); expectEqual(fake.connects.first?.port, 995)
        let waiting = await MainActor.run { m.waitingForInstaller }
        expect(!waiting)
    }
    test("setup/not-now-forgets-the-pending-connection") {
        let path = sockPath(); let opened = Locked(0)
        let m = await model(path, opened: opened)
        await MainActor.run { m.connect(server()); m.cancelSetup() }
        let (srv, fake) = startHelper(path, version: helperVersion); defer { srv.stop() }
        for _ in 0..<5 { await MainActor.run { m.pollHelper() }; try await Task.sleep(nanoseconds: 50_000_000) }
        expectEqual(fake.connects.count, 0, "a connection the user declined must never start on its own later")
        expectEqual(opened.value, 0)
    }
    test("setup/outdated-helper-asks-for-an-update") {
        let path = sockPath(); let opened = Locked(0)
        let (srv, fake) = startHelper(path, version: helperVersion - 1); defer { srv.stop() }
        let m = await model(path, opened: opened)
        await MainActor.run { m.pollHelper() }
        await expectA(await eventuallyA(3) { await MainActor.run { m.helperOutdated } }, "version of the old helper never noticed")
        await MainActor.run { m.connect(server()) }
        let prompt = await MainActor.run { m.setupPrompt }
        expect(prompt == .update); expectEqual(fake.connects.count, 0)
    }
    test("setup/helper-from-before-versioning-counts-as-outdated") {
        let path = sockPath(); let opened = Locked(0)
        let (srv, _) = startHelper(path, version: nil); defer { srv.stop() }      // v1–v3 idle snapshots had no version
        let m = await model(path, opened: opened)
        await MainActor.run { m.pollHelper() }
        await expectA(await eventuallyA(3) { await MainActor.run { m.helperOutdated } })
    }
    test("setup/current-helper-connects-immediately-without-prompting") {
        let path = sockPath(); let opened = Locked(0)
        let (srv, fake) = startHelper(path, version: helperVersion); defer { srv.stop() }
        let m = await model(path, opened: opened)
        await MainActor.run { m.pollHelper() }
        await expectA(await eventuallyA(3) { await MainActor.run { !m.helperOutdated && m.helperRunning } })
        await MainActor.run { m.connect(server()) }
        await expectA(await eventuallyA(3) { fake.connects.count == 1 })
        let prompt = await MainActor.run { m.setupPrompt }
        expect(prompt == nil); expectEqual(opened.value, 0)
    }
    test("setup/missing-installer-is-reported-not-silent") {
        let opened = Locked(0)
        let m = await model(sockPath(), opened: opened, installerExists: false)
        await MainActor.run { m.connect(server()); m.beginSetup() }
        let (waiting, notice) = await MainActor.run { (m.waitingForInstaller, m.notice) }
        expect(!waiting); expect(notice?.contains("Installer not found") == true, "\(String(describing: notice))")
    }
    test("setup/helper-that-never-answers-does-not-leave-the-ui-connecting", timeout: 15) {
        // accepts the socket but never replies (the daemon bug seen in the field)
        let path = sockPath()
        let listener = SilentUnixListener(path: path); defer { listener.close() }
        let m = await model(path, opened: Locked(0))
        await MainActor.run { m.pollHelper() }
        await MainActor.run { m.connect(server()) }
        let before = await MainActor.run { m.event.state }
        expectEqual(before, .connecting)
        await expectA(await eventuallyA(11) { await MainActor.run { m.event.state == .disconnected && m.notice?.contains("not responding") == true } },
                      "UI stayed on Connecting…")
    }
}
