import Foundation
import CryptoKit
import Security
import VPNGateCore

// App-side behaviour: disclaimer gate, telemetry opt-in, account editing/storage, certificate import,
// connection history, launch at login, IPC field validation. Everything is isolated: throwaway UserDefaults suites,
// temp files and the test Keychain service (see Tests/Harness/main.swift).

private func freshDefaults(agreed: Bool = true) -> UserDefaults {
    let name = "vpngate-fix-tests-\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    if agreed { d.set(true, forKey: "hasAgreedToDisclaimer") }
    return d
}

private final class FakeLoginItem: LoginItemControlling, @unchecked Sendable {
    var registerError: Error?
    var unregisterError: Error?
    var statusAfterRegister: LoginItemStatus = .enabled
    private(set) var registered = false, unregistered = 0
    var status: LoginItemStatus { registered ? statusAfterRegister : .notRegistered }
    func register() throws { if let e = registerError { throw e }; registered = true }
    func unregister() throws { unregistered += 1; if let e = unregisterError { throw e }; registered = false }
}
private struct LoginError: LocalizedError { var errorDescription: String? { "boom" } }

private func sockPath() -> String { tempPath("fix-\(UUID().uuidString.prefix(6)).sock") }

private func server(ip: String = "5.6.7.8") -> VPNServer {
    ServerList.parse("#h\nvpn1,\(ip),1,1,1,Japan,JP,1,1,1,1,2weeks,Op,msg,\(Data("proto tcp\nremote \(ip) 443\n".utf8).base64EncodedString())\n")[0]
}

@MainActor private func makeModel(_ path: String, agreed: Bool = true, login: LoginItemControlling = FakeLoginItem(),
                                  defaults: UserDefaults? = nil) -> AppModel {
    AppModel(socketPath: path, defaults: defaults ?? freshDefaults(agreed: agreed), autoStart: false, openInstaller: { true },
             loginItem: login,
             accountManager: AccountManager(fileURL: URL(fileURLWithPath: tempPath("acc-\(UUID().uuidString.prefix(6)).json"))),
             connectionLog: ConnectionLogStore(fileURL: URL(fileURLWithPath: tempPath("hist-\(UUID().uuidString.prefix(6)).json"))))
}

private func startHelper(_ path: String) -> (IPCServer, FakeSession) {
    let fake = FakeSession()
    var snap = HelperEvent(state: .disconnected); snap.helperVersion = helperVersion
    fake.snapshot = snap
    let srv = IPCServer(path: path, allowedUID: getuid(), session: fake)
    try! srv.start()
    return (srv, fake)
}

@MainActor private func waitReady(_ m: AppModel) async {
    for _ in 0..<300 {
        m.pollHelper()
        if m.helperRunning && !m.helperOutdated && m.event.helperVersion != nil { return }   // snapshot received
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    fail("helper never became ready")
}

private func readText(_ path: String) -> String { (try? String(contentsOfFile: path, encoding: .utf8)) ?? "" }

private func pemDER(_ pem: String) -> Data { CertImport.pemBlocks(Data(pem.utf8)).first!.der }

func registerAppFixTests() {
    // MARK: telemetry (opt-in)
    test("telemetry/off-by-default-and-nothing-scheduled") {
        await MainActor.run {
            let s = VGStatistics(defaults: freshDefaults())
            expect(!s.isEnabled, "telemetry must default to off")
            expect(!s.isScheduled, "no upload may be scheduled before the user opts in")
        }
    }
    test("telemetry/the-old-default-on-key-does-not-count-as-consent") {
        await MainActor.run {
            let d = freshDefaults(); d.set(true, forKey: "telemetryEnabled")       // what earlier builds wrote for everyone
            expect(!VGStatistics(defaults: d).isEnabled)
        }
    }
    test("telemetry/opt-in-schedules-and-persists-opt-out-cancels") {
        await MainActor.run {
            let d = freshDefaults()
            let s = VGStatistics(defaults: d)
            s.isEnabled = true
            expect(s.isScheduled); expect(d.bool(forKey: "telemetryOptIn"))
            expect(VGStatistics(defaults: d, startIfEnabled: false).isEnabled, "the choice must persist")
            s.isEnabled = false
            expect(!s.isScheduled); expect(!d.bool(forKey: "telemetryOptIn"))
        }
    }
    test("telemetry/app-launch-with-the-default-sends-nothing") {
        await MainActor.run {
            let m = makeModel(sockPath())
            expect(!m.statistics.isEnabled && !m.statistics.isScheduled)
        }
    }
    test("telemetry/disabled-sends-nothing-enabled-posts-to-the-endpoint") {
        let http = LocalHTTPServer(body: Data()); defer { http.stop() }
        let off = await MainActor.run { VGStatistics(defaults: freshDefaults(), startIfEnabled: false) }
        let r1 = await off.sendStatistics(overrideURL: http.url)
        expect(!r1); expectEqual(http.requests, 0, "a disabled client must not send anything")
        let on = await MainActor.run { () -> VGStatistics in
            let s = VGStatistics(defaults: freshDefaults(), startIfEnabled: false); s.isEnabled = true; s.stop(); return s
        }
        let r2 = await on.sendStatistics(overrideURL: http.url)
        expect(r2, "upload to the local endpoint failed"); expectEqual(http.requests, 1)
        await MainActor.run { on.stop() }
    }
    test("telemetry/host-key-is-random-stable-and-resettable") {
        await MainActor.run {
            let d = freshDefaults()
            let s = VGStatistics(defaults: d)
            let k = s.hostKey
            expectEqual(s.hostKey, k, "must be stable between reads")
            expectEqual(VGStatistics(defaults: d, startIfEnabled: false).hostKey, k, "must persist")
            let old = Insecure.SHA1.hash(data: Data(ProcessInfo.processInfo.hostName.utf8)).map { String(format: "%02x", $0) }.joined()
            expect(k != old, "must not be derived from the host name")
            expectEqual(k.count, 32)
            let k2 = s.resetHostKey()
            expect(k2 != k); expectEqual(s.hostKey, k2)
            expect(VGStatistics(defaults: freshDefaults(), startIfEnabled: false).hostKey != k, "another install gets another ID")
        }
    }
    test("telemetry/settings-list-matches-the-real-payload") {
        let desc = VGStatistics.payloadDescription
        let pack = VGStatistics.makeTelemetryPack(hostKey: "x")
        expectEqual(desc.count, 6)
        expect(desc.contains("ClientOsName: \(pack.str("ClientOsName") ?? "?")"))
        expect(desc.contains("IsClient: 1"))
    }

    // MARK: disclaimer gate
    test("disclaimer/connect-without-agreement-never-reaches-the-helper") {
        let path = sockPath()
        let (srv, fake) = startHelper(path); defer { srv.stop() }
        let m = await MainActor.run { makeModel(path, agreed: false) }
        await waitReady(m)
        await MainActor.run { m.connect(server()) }
        try await Task.sleep(nanoseconds: 200_000_000)
        expectEqual(fake.connects.count, 0, "connect must be blocked until the disclaimer is accepted")
        let (showing, state) = await MainActor.run { (m.showingDisclaimer, m.event.state) }
        expect(showing, "the sheet must be requested"); expectEqual(state, .disconnected)
        await MainActor.run { m.connect(account: ClientAccount(name: "a", host: "1.2.3.4")) }
        try await Task.sleep(nanoseconds: 100_000_000)
        expectEqual(fake.connects.count, 0, "Client Manager connects are gated too")
    }
    test("disclaimer/agreeing-persists-and-continues-the-parked-connect") {
        let path = sockPath(); let d = freshDefaults(agreed: false)
        let (srv, fake) = startHelper(path); defer { srv.stop() }
        let m = await MainActor.run { makeModel(path, defaults: d) }
        await waitReady(m)
        await MainActor.run { m.connect(server(ip: "9.9.9.9")) }
        expectEqual(fake.connects.count, 0)
        await MainActor.run { m.agreeToDisclaimer() }
        await expectA(await eventuallyA(3) { fake.connects.count == 1 }, "the connect the user asked for never started")
        expectEqual(fake.connects.first?.host, "9.9.9.9")
        let (showing, agreed) = await MainActor.run { (m.showingDisclaimer, m.hasAgreedToDisclaimer) }
        expect(!showing && agreed); expect(d.bool(forKey: "hasAgreedToDisclaimer"))
        await MainActor.run { m.connect(server()) }                       // no second prompt
        await expectA(await eventuallyA(3) { fake.connects.count == 2 })
    }
    test("disclaimer/declining-drops-the-parked-connect") {
        let path = sockPath()
        let (srv, fake) = startHelper(path); defer { srv.stop() }
        let m = await MainActor.run { makeModel(path, agreed: false) }
        await waitReady(m)
        await MainActor.run { m.connect(server()); m.declineDisclaimer(); m.agreeToDisclaimer() }
        try await Task.sleep(nanoseconds: 200_000_000)
        expectEqual(fake.connects.count, 0, "a declined connect must not start after a later agreement")
    }

    // MARK: account editor
    test("editor/save-keeps-every-field-the-form-does-not-show") {
        var base = ClientAccount(name: "Lab", host: "vpn.example.com", portList: [443], hub: "H", username: "u",
                                 authType: .plainPassword, checkServerCert: true,
                                 serverCertFingerprint: "1122334455667788990011223344556677889900", maxConnection: 4,
                                 halfConnection: true, reconnectInterval: 9, reconnectCount: 3,
                                 virtualMacAddress: "00:AC:00:00:00:01", mtu: 1300,
                                 createdAt: Date(timeIntervalSince1970: 1000))
        base.proxy.kind = .socks5; base.proxy.host = "10.0.0.1"; base.proxy.port = 1080
        let ui = AccountEditorState(account: base)
        ui.name = "Lab renamed"; ui.compression = true
        let out = ui.makeAccount(base: base)
        expectEqual(out.name, "Lab renamed"); expect(out.compression)
        expectEqual(out.id, base.id); expectEqual(out.createdAt, base.createdAt)
        expectEqual(out.proxy, base.proxy); expectEqual(out.serverCertFingerprint, base.serverCertFingerprint)
        expect(out.halfConnection)
        expectEqual(out.virtualMacAddress, "00:AC:00:00:00:01"); expectEqual(out.mtu, 1300)
        expectEqual(out.reconnectInterval, 9); expectEqual(out.reconnectCount, 3)
        expectEqual(out.maxConnection, 4); expectEqual(out.authType, .plainPassword)
    }
    test("editor/half-connection-toggle-is-editable") {
        let base = ClientAccount(name: "Lab", host: "vpn.example.com", halfConnection: false)
        let ui = AccountEditorState(account: base)
        expect(!ui.halfConnection)
        ui.halfConnection = true
        expect(ui.makeAccount(base: base).halfConnection)
    }
    test("editor/mtu-and-mac-override-are-editable-and-validated") {
        let base = ClientAccount(name: "Lab", host: "vpn.example.com", virtualMacAddress: nil, mtu: nil)
        let ui = AccountEditorState(account: base)
        expectEqual(ui.mtuString, ""); expectEqual(ui.macString, "")
        expect(ui.makeAccount(base: base).mtu == nil, "blank must mean automatic, not 0")
        expect(ui.makeAccount(base: base).virtualMacAddress == nil, "blank must mean random, not an empty string")

        ui.mtuString = "1300"; ui.macString = "00:AC:DE:12:34:56"
        expect(ui.mtuError == nil); expect(ui.macError == nil); expect(ui.canSave)
        let out = ui.makeAccount(base: base)
        expectEqual(out.mtu, 1300); expectEqual(out.virtualMacAddress, "00:AC:DE:12:34:56")

        ui.mtuString = "100"   // below 576
        expect(ui.mtuError != nil); expect(!ui.canSave)
        ui.mtuString = ""; ui.macString = "not-a-mac"
        expect(ui.macError != nil); expect(!ui.canSave)
    }
    test("editor/reconnect-interval-and-count-are-editable-and-clamped") {
        let base = ClientAccount(name: "Lab", host: "vpn.example.com", autoReconnect: true,
                                 reconnectInterval: 3, reconnectCount: 8)
        let ui = AccountEditorState(account: base)
        expectEqual(ui.reconnectIntervalSeconds, 3); expectEqual(ui.reconnectCount, 8)
        ui.reconnectIntervalSeconds = 20; ui.reconnectCount = 2
        let out = ui.makeAccount(base: base)
        expectEqual(out.reconnectInterval, 20); expectEqual(out.reconnectCount, 2)
        // Zero/negative must not reach the helper as an infinite-fast loop or a give-up-immediately policy.
        ui.reconnectIntervalSeconds = 0; ui.reconnectCount = 0
        let clamped = ui.makeAccount(base: base)
        expect(clamped.reconnectInterval >= 1); expect(clamped.reconnectCount >= 1)
    }
    test("editor/fingerprint-is-validated-and-normalised") {
        let ui = AccountEditorState(account: ClientAccount(name: "a", host: "1.2.3.4"))
        ui.fingerprint = "zz"
        expect(ui.fingerprintError != nil); expect(!ui.canSave)
        ui.fingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
        expect(ui.fingerprintError == nil); expect(ui.canSave)
        expectEqual(ui.makeAccount(base: nil).serverCertFingerprint, "aabbccddeeff00112233445566778899aabbccdd")
        ui.fingerprint = ""
        expect(ui.makeAccount(base: nil).serverCertFingerprint == nil)
        expectEqual(InputValidation.normalizedFingerprint(String(repeating: "ab", count: 32)), String(repeating: "ab", count: 32))
        expect(InputValidation.normalizedFingerprint(String(repeating: "ab", count: 31)) == nil)
    }
    test("editor/certificate-login-cannot-be-saved-without-an-identity") {
        let ui = AccountEditorState(account: ClientAccount(name: "a", host: "1.2.3.4"))
        ui.authType = .certificate
        expect(!ui.canSave)
        ui.certDer = Data([1]); ui.privateKeyDer = Data([2])
        expect(ui.canSave)
        let stored = AccountEditorState(account: ClientAccount(name: "a", host: "1.2.3.4", authType: .certificate), hasStoredIdentity: true)
        expect(stored.canSave, "an already stored identity is enough when editing")
    }

    // MARK: storage
    test("accounts/secrets-never-reach-accounts-json") {
        try await MainActor.run {
            let url = URL(fileURLWithPath: tempPath("secrets-\(UUID().uuidString.prefix(6)).json"))
            let mgr = AccountManager(fileURL: url)
            var acc = ClientAccount(name: "S", host: "1.2.3.4", authType: .certificate)
            acc.proxy.kind = .http; acc.proxy.host = "10.1.1.1"; acc.proxy.port = 8080
            acc.proxy.username = "pu"; acc.proxy.password = "ProxySecret-42"
            let key = Data((0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) })
            mgr.add(acc, password: "Pw-Secret-77", certDer: Data("CERT-BYTES".utf8), privateKeyDer: key)
            let text = try String(contentsOf: url, encoding: .utf8)
            for secret in ["Pw-Secret-77", "ProxySecret-42", key.base64EncodedString(), Data("CERT-BYTES".utf8).base64EncodedString()] {
                expect(!text.contains(secret), "secret found in accounts.json: \(secret.prefix(8))…")
            }
            let a = mgr.accounts[0]
            expectEqual(mgr.password(for: a), "Pw-Secret-77"); expectEqual(mgr.proxyPassword(for: a), "ProxySecret-42")
            expectEqual(mgr.privateKey(for: a), key); expect(mgr.accounts[0].proxy.password == nil)
            // a reload keeps the Keychain link
            let again = AccountManager(fileURL: url)
            expectEqual(again.proxyPassword(for: again.accounts[0]), "ProxySecret-42")
            mgr.delete(a)
            expect(mgr.privateKey(for: a) == nil && mgr.proxyPassword(for: a) == nil && mgr.password(for: a) == nil)
        }
    }
    test("accounts/an-old-file-with-a-plaintext-proxy-password-is-migrated") {
        try await MainActor.run {
            let url = URL(fileURLWithPath: tempPath("migrate-\(UUID().uuidString.prefix(6)).json"))
            let id = UUID()
            let json = #"[{"id":"\#(id.uuidString)","name":"Old","host":"2.2.2.2","proxy":{"kind":"http","host":"1.1.1.1","port":3128,"username":"u","password":"OldPlain"}}]"#
            try json.write(to: url, atomically: true, encoding: .utf8)
            let mgr = AccountManager(fileURL: url)
            expectEqual(mgr.proxyPassword(for: mgr.accounts[0]), "OldPlain")
            expect(!(readText(url.path)).contains("OldPlain"), "the clear-text password must be rewritten away")
            mgr.delete(mgr.accounts[0])
        }
    }
    test("accounts/load-is-tolerant-of-older-schemas-and-bad-records") {
        try await MainActor.run {
            let dir = tempPath("tolerant-\(UUID().uuidString.prefix(6))")
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let url = URL(fileURLWithPath: dir + "/accounts.json")
            let good = UUID(), future = UUID()
            // record 1: minimal old schema; record 2: newer file with unknown keys; record 3: unknown auth type; record 4: junk
            let json = """
            [{"id":"\(good.uuidString)","name":"Minimal","host":"1.1.1.1"},
             {"id":"\(future.uuidString)","name":"Future","host":"2.2.2.2","authType":"Plain Password","maxConnection":3,"quantumMode":true},
             {"id":"\(UUID().uuidString)","name":"Weird","host":"3.3.3.3","authType":"Retina Scan"},
             42]
            """
            try json.write(to: url, atomically: true, encoding: .utf8)
            let mgr = AccountManager(fileURL: url)
            expectEqual(mgr.accounts.map(\.name), ["Minimal", "Future"])
            expectEqual(mgr.accounts[0].hub, "DEFAULT"); expectEqual(mgr.accounts[0].maxConnection, 1)
            expectEqual(mgr.accounts[1].authType, .plainPassword); expectEqual(mgr.accounts[1].maxConnection, 3)
            expect(mgr.loadNotice != nil, "skipped records must be reported")
            let kept = try FileManager.default.contentsOfDirectory(atPath: dir).filter { $0.hasPrefix("accounts.json.corrupt-") }
            expectEqual(kept.count, 1, "the original must be kept before anything is saved over it")
            expect(readText(dir + "/" + kept[0]).contains("Retina Scan"))
            mgr.saveAccounts()
            expect(readText(dir + "/" + kept[0]).contains("Retina Scan"))
        }
    }
    test("accounts/an-unreadable-file-is-moved-aside-never-overwritten") {
        try await MainActor.run {
            let dir = tempPath("garbage-\(UUID().uuidString.prefix(6))")
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let url = URL(fileURLWithPath: dir + "/accounts.json")
            try "{ this is not json".write(to: url, atomically: true, encoding: .utf8)
            let mgr = AccountManager(fileURL: url)
            expect(mgr.accounts.isEmpty); expect(mgr.loadNotice != nil)
            let kept = try FileManager.default.contentsOfDirectory(atPath: dir).filter { $0.hasPrefix("accounts.json.corrupt-") }
            expectEqual(kept.count, 1)
            expectEqual(readText(dir + "/" + kept[0]), "{ this is not json")
            mgr.add(ClientAccount(name: "New", host: "4.4.4.4"))
            expectEqual(readText(dir + "/" + kept[0]), "{ this is not json", "saving must not touch the saved-aside copy")
            expectEqual(AccountManager(fileURL: url).accounts.map(\.name), ["New"])
            // a missing file is simply an empty list, with no scary notice
            expect(AccountManager(fileURL: URL(fileURLWithPath: dir + "/none.json")).loadNotice == nil)
        }
    }

    // MARK: certificate import
    test("cert/pem-and-der-pairs-become-pkcs1-der") {
        let id = try CertImport.identity(certificateFile: Data(CertFixtures.certPEM.utf8), keyFile: Data(CertFixtures.rsaPKCS1PEM.utf8))
        let pkcs1 = pemDER(CertFixtures.rsaPKCS1PEM)
        expectEqual(id.privateKeyDer, pkcs1); expectEqual(id.certDer, pemDER(CertFixtures.certPEM))
        let id8 = try CertImport.identity(certificateFile: Data(CertFixtures.certPEM.utf8), keyFile: Data(CertFixtures.rsaPKCS8PEM.utf8))
        expectEqual(id8.privateKeyDer, pkcs1, "PKCS#8 must be unwrapped to PKCS#1")
        let raw = try CertImport.identity(certificateFile: id.certDer, keyFile: pkcs1)          // raw DER files
        expectEqual(raw, id)
        // the helper signs with exactly this blob
        let sig = try CertAuth.sign(Data(repeating: 7, count: 20), privateKeyDer: id.privateKeyDer)
        expectEqual(sig.count, 256)
    }
    test("cert/bad-material-gives-clear-errors") {
        let cert = Data(CertFixtures.certPEM.utf8)
        func failure(_ key: String) -> CertImport.Failure? {
            do { _ = try CertImport.identity(certificateFile: cert, keyFile: Data(key.utf8)); return nil }
            catch { return error as? CertImport.Failure }
        }
        expectEqual(failure(CertFixtures.encryptedPEM), .encryptedKey)
        expectEqual(failure(CertFixtures.ecPEM), .unsupportedKeyType("EC"))
        expectEqual(failure(CertFixtures.otherRSAPEM), .keyMismatch)
        expectEqual(failure("hello"), .notPrivateKey)
        expect(CertImport.Failure.encryptedKey.errorDescription?.contains("passphrase") == true)
        expectThrows(try CertImport.parseCertificate(Data("not a cert".utf8)))
        expectThrows(try CertImport.parseCertificate(Data(CertFixtures.rsaPKCS1PEM.utf8)), "a key is not a certificate")
    }
    test("cert/pkcs12-modern-and-legacy-import-in-memory", timeout: 40) {
        let pem = try CertImport.identity(certificateFile: Data(CertFixtures.certPEM.utf8), keyFile: Data(CertFixtures.rsaPKCS1PEM.utf8))
        for (label, p12) in [("modern", CertFixtures.modernP12), ("legacy", CertFixtures.legacyP12)] {
            let id = try CertImport.importPKCS12(p12, passphrase: CertFixtures.p12Passphrase)
            expectEqual(id.certDer, pem.certDer, "\(label) .p12 certificate")
            expectEqual(id.privateKeyDer, pem.privateKeyDer, "\(label) .p12 key must come out as PKCS#1")
        }
    }
    test("cert/pkcs12-wrong-passphrase-and-ec-keys-are-reported", timeout: 40) {
        do { _ = try CertImport.importPKCS12(CertFixtures.modernP12, passphrase: "nope"); fail("wrong passphrase accepted") }
        catch { expectEqual(error as? CertImport.Failure, .wrongPassphrase) }
        do { _ = try CertImport.importPKCS12(CertFixtures.ecP12, passphrase: CertFixtures.p12Passphrase); fail("EC key accepted") }
        catch { expectEqual(error as? CertImport.Failure, .unsupportedKeyType("EC"), "\(error)") }
        expectThrows(try CertImport.importPKCS12(Data("junk".utf8), passphrase: ""))
    }
    test("cert/connect-sends-certificate-and-key-to-the-helper-and-requires-both") {
        let path = sockPath()
        let (srv, fake) = startHelper(path); defer { srv.stop() }
        let m = await MainActor.run { makeModel(path) }
        await waitReady(m)
        let id = try CertImport.identity(certificateFile: Data(CertFixtures.certPEM.utf8), keyFile: Data(CertFixtures.rsaPKCS8PEM.utf8))
        let acc = ClientAccount(name: "Cert", host: "7.7.7.7", username: "alice", authType: .certificate)
        await MainActor.run { m.accountManager.add(acc, certDer: id.certDer) }               // key missing
        await MainActor.run { m.connect(account: acc) }
        try await Task.sleep(nanoseconds: 200_000_000)
        expectEqual(fake.configs.count, 0, "certificate login without a key must not be attempted")
        let notice = await MainActor.run { m.notice }
        expect(notice?.contains("certificate") == true, "\(String(describing: notice))")
        await MainActor.run { m.accountManager.update(acc, certDer: id.certDer, privateKeyDer: id.privateKeyDer) }
        await MainActor.run { m.connect(account: acc) }
        await expectA(await eventuallyA(3) { fake.configs.count == 1 })
        expectEqual(fake.configs.first?.certDer, id.certDer); expectEqual(fake.configs.first?.privateKeyDer, id.privateKeyDer)
        expectEqual(fake.configs.first?.authType, AccountAuthType.certificate.rawValue)
        await MainActor.run { m.accountManager.delete(acc) }
    }
    test("accounts/proxy-password-reaches-the-helper-from-the-keychain") {
        let path = sockPath()
        let (srv, fake) = startHelper(path); defer { srv.stop() }
        let m = await MainActor.run { makeModel(path) }
        await waitReady(m)
        var acc = ClientAccount(name: "P", host: "8.8.8.8")
        acc.proxy.kind = .http; acc.proxy.host = "10.0.0.2"; acc.proxy.port = 3128; acc.proxy.username = "u"; acc.proxy.password = "px-secret"
        let stored = await MainActor.run { () -> ClientAccount in m.accountManager.add(acc, password: "pw"); return m.accountManager.accounts[0] }
        expect(stored.proxy.password == nil)
        await MainActor.run { m.connect(account: stored) }
        await expectA(await eventuallyA(3) { fake.configs.count == 1 })
        expectEqual(fake.configs.first?.proxy.password, "px-secret"); expectEqual(fake.configs.first?.password, "pw")
        await MainActor.run { m.accountManager.delete(stored) }
    }

    // MARK: connection history
    test("history/connected-period-is-recorded-with-bytes-and-error") {
        let path = sockPath()
        let (srv, fake) = startHelper(path); defer { srv.stop() }
        let m = await MainActor.run { makeModel(path) }
        await MainActor.run { m.servers = [server(ip: "5.6.7.8")] }
        await waitReady(m)
        var up = HelperEvent(state: .connected); up.server = "5.6.7.8"; up.bytesIn = 100; up.bytesOut = 50
        // the server registers the client slightly after connect(): repeat the (idempotent) event until it lands
        await expectA(await eventuallyA(3) { fake.emit?(up); try? await Task.sleep(nanoseconds: 30_000_000)
                                             return await MainActor.run { m.connectionLog.entries.count == 1 } }, "no entry on connect")
        up.bytesIn = 5000; up.bytesOut = 3000
        fake.emit?(up)
        try await Task.sleep(nanoseconds: 100_000_000)
        let count = await MainActor.run { m.connectionLog.entries.count }
        expectEqual(count, 1, "byte updates must not start new entries")
        var down = HelperEvent(state: .disconnected); down.error = "Link closed"
        fake.emit?(down)
        await expectA(await eventuallyA(3) { await MainActor.run { m.connectionLog.entries.first?.disconnectedAt != nil } }, "entry never ended")
        let e = await MainActor.run { m.connectionLog.entries[0] }
        expectEqual(e.serverName, "vpn1"); expectEqual(e.serverIP, "5.6.7.8")
        expectEqual(e.bytesIn, 5000); expectEqual(e.bytesOut, 3000); expectEqual(e.error, "Link closed")
        // a second session is a second entry; and it persists to disk
        fake.emit?(up)
        await expectA(await eventuallyA(3) { await MainActor.run { m.connectionLog.entries.count == 2 } })
    }
    test("history/helper-going-away-ends-the-open-entry") {
        let path = sockPath()
        let (srv, fake) = startHelper(path)
        let m = await MainActor.run { makeModel(path) }
        await waitReady(m)
        var up = HelperEvent(state: .connected); up.server = "5.6.7.8"
        await expectA(await eventuallyA(3) { fake.emit?(up); try? await Task.sleep(nanoseconds: 30_000_000)
                                             return await MainActor.run { m.connectionLog.entries.count == 1 } })
        srv.stop()
        await expectA(await eventuallyA(3) { await MainActor.run { m.connectionLog.entries.first?.disconnectedAt != nil } }, "entry left open")
    }

    // MARK: launch at login
    test("login-item/register-failure-reverts-the-toggle-and-says-why") {
        let login = FakeLoginItem(); login.registerError = LoginError()
        let d = freshDefaults()
        let m = await MainActor.run { makeModel(sockPath(), login: login, defaults: d) }
        await MainActor.run { m.launchAtLogin = true }
        let (on, notice) = await MainActor.run { (m.launchAtLogin, m.notice) }
        expect(!on, "toggle must go back to off"); expect(notice?.contains("boom") == true, "\(String(describing: notice))")
        expect(!d.bool(forKey: "launchAtLogin"))
    }
    test("login-item/needing-approval-is-not-pretended-to-be-enabled") {
        let login = FakeLoginItem(); login.statusAfterRegister = .requiresApproval
        let m = await MainActor.run { makeModel(sockPath(), login: login) }
        await MainActor.run { m.launchAtLogin = true }
        let (on, notice) = await MainActor.run { (m.launchAtLogin, m.notice) }
        expect(!on); expect(notice?.contains("Login Items") == true, "\(String(describing: notice))")
        expectEqual(login.unregistered, 1, "the half-registered item is withdrawn")
    }
    test("login-item/success-and-unregister-failure") {
        let login = FakeLoginItem()
        let m = await MainActor.run { makeModel(sockPath(), login: login) }
        await MainActor.run { m.launchAtLogin = true }
        let on = await MainActor.run { m.launchAtLogin }
        expect(on); expect(login.registered)
        login.unregisterError = LoginError()
        await MainActor.run { m.launchAtLogin = false }
        let (still, notice) = await MainActor.run { (m.launchAtLogin, m.notice) }
        expect(still, "still registered, so the toggle must stay on"); expect(notice?.contains("boom") == true)
    }

    // MARK: IPC field validation
    test("ipc/validate-caps-hub-and-user-names") {
        func req(hub: String = "HUB", user: String = "u") -> HelperRequest {
            var r = HelperRequest(cmd: "connect")
            r.config = ConnectConfig(host: "1.2.3.4", hubName: hub, userName: user)
            return r
        }
        expect(IPCServer.validate(req()) == nil)
        expect(IPCServer.validate(req(hub: String(repeating: "h", count: 255))) == nil)
        expect(IPCServer.validate(req(hub: String(repeating: "h", count: 256))) != nil, "hub over 255 bytes")
        expect(IPCServer.validate(req(user: String(repeating: "é", count: 128))) != nil, "255-byte limit counts bytes, not characters")
        expect(IPCServer.validate(req(user: "a\0b")) != nil, "NUL in the user name")
        expect(IPCServer.validate(req(hub: "a\0b")) != nil, "NUL in the hub name")
    }
}
