import Foundation

// The account editor and certificate import, plus the tolerant decoding of the app's own ConnectConfig mirror.

func registerAppLoginTests() {
    test("loginparity/connect-config-mirror-from-an-older-app-still-decodes") {
        var cfg = ConnectConfig(host: "h", maxConnection: 5)
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(cfg)) as! [String: Any]
        json.removeValue(forKey: "disableQoS")
        cfg = try JSONDecoder().decode(ConnectConfig.self, from: JSONSerialization.data(withJSONObject: json))
        expectEqual(cfg.disableQoS, false); expectEqual(cfg.maxConnection, 5)
        let min = try JSONDecoder().decode(ConnectConfig.self, from: Data(#"{"host":"x"}"#.utf8))
        expectEqual(min.maxConnection, 1); expectEqual(min.hubName, "VPNGATE")
    }
    test("loginparity/pkcs12-legacy-keychain-path-cleans-up", timeout: 60) {
        let dir = tempPath("kc-\(UUID().uuidString.prefix(6))")
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        func left() -> [String] { (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? ["<unreadable>"] }
        let pem = try CertImport.identity(certificateFile: Data(CertFixtures.certPEM.utf8), keyFile: Data(CertFixtures.rsaPKCS1PEM.utf8))
        let id = try CertImport.importPKCS12(
            CertFixtures.legacyP12, passphrase: CertFixtures.p12Passphrase,
            forceLegacyKeychain: true, keychainDirectory: dir)
        expectEqual(id.certDer, pem.certDer, "certificate via the legacy path")
        expectEqual(id.privateKeyDer, pem.privateKeyDer, "key via the legacy path (must be exportable)")
        expectEqual(left(), [], "temporary keychain left behind after a successful import")
        // The newer encoding cannot be exported from a keychain: either it works or the user gets an explanation.
        do {
            let m = try CertImport.importPKCS12(
                CertFixtures.modernP12, passphrase: CertFixtures.p12Passphrase,
                forceLegacyKeychain: true, keychainDirectory: dir)
            expectEqual(m.certDer, pem.certDer)
        } catch { expect(error is CertImport.Failure, "\(error)") }
        expectEqual(left(), [], "temporary keychain left behind after the modern file")
        do {
            _ = try CertImport.importPKCS12(CertFixtures.legacyP12, passphrase: "nope", forceLegacyKeychain: true, keychainDirectory: dir);
            fail("wrong passphrase accepted")
        } catch { expectEqual(error as? CertImport.Failure, .wrongPassphrase) }
        do {
            _ = try CertImport.importPKCS12(CertFixtures.modernP12, passphrase: "nope", forceLegacyKeychain: true, keychainDirectory: dir);
            fail("wrong passphrase accepted")
        } catch { expectEqual(error as? CertImport.Failure, .wrongPassphrase) }
        do {
            _ = try CertImport.importPKCS12(CertFixtures.ecP12, passphrase: CertFixtures.p12Passphrase, forceLegacyKeychain: true, keychainDirectory: dir);
            fail("EC accepted")
        } catch { expectEqual(error as? CertImport.Failure, .unsupportedKeyType("EC"), "\(error)") }
        expectEqual(left(), [], "failure paths clean up too")
        do {
            _ = try CertImport.importPKCS12(
                CertFixtures.modernP12, passphrase: CertFixtures.p12Passphrase, forceLegacyKeychain: true, keychainDirectory: dir + "/missing");
            fail("unusable keychain dir accepted")
        } catch { expect(error is CertImport.Failure, "\(error)") }
    }
    test("loginparity/editor-toggle-maps-to-disable-qos") {
        let fresh = AccountEditorState()
        expect(fresh.useQoS, "QoS is on for a new account"); expectEqual(fresh.maxConnection, 1)
        fresh.host = "h"; fresh.useQoS = false
        expectEqual(fresh.makeAccount(base: nil).disableQoS, true)
        let editing = AccountEditorState(account: ClientAccount(name: "a", host: "h", disableQoS: true))
        expect(!editing.useQoS)
    }
}
