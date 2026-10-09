import Foundation
import Network
import Security
import CryptoKit
import VPNGateCore

// Server certificate pinning through a real TLS handshake against a loopback (127.0.0.1) server that presents the
// throwaway certificate from CertFixtures.

private final class LoopbackTLSServer {
    let listener: NWListener
    let port: UInt16
    let leafDER: Data
    private let conns = Locked([NWConnection]())

    /// The fixture identity, imported memory-only (macOS 15+); nil where that import does not exist.
    private static func fixtureIdentity() -> (identity: sec_identity_t, leafDER: Data)? {
        guard #available(macOS 15.0, *) else { return nil }
        var items: CFArray?
        let opts: [String: Any] = [kSecImportExportPassphrase as String: CertFixtures.p12Passphrase,
                                   kSecImportToMemoryOnly as String: true]
        guard SecPKCS12Import(CertFixtures.modernP12 as CFData, opts as CFDictionary, &items) == errSecSuccess,
              let first = (items as? [[String: Any]])?.first, let idRef = first[kSecImportItemIdentity as String] else { return nil }
        let secIdentity = idRef as! SecIdentity
        var cert: SecCertificate?
        SecIdentityCopyCertificate(secIdentity, &cert)
        guard let c = cert, let identity = sec_identity_create(secIdentity) else { return nil }
        return (identity, SecCertificateCopyData(c) as Data)
    }

    init?() {
        guard let (identity, der) = Self.fixtureIdentity() else { return nil }
        leafDER = der

        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, identity)
        let params = NWParameters(tls: tls)
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)      // loopback only
        guard let l = try? NWListener(using: params) else { return nil }
        listener = l
        let ready = DispatchSemaphore(value: 0)
        l.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        let held = conns
        l.newConnectionHandler = { conn in
            held.update { $0.append(conn) }
            conn.start(queue: .global())
            conn.send(content: Data("hello".utf8), completion: .contentProcessed { _ in })
        }
        l.start(queue: .global())
        guard ready.wait(timeout: .now() + 5) == .success, let p = l.port?.rawValue else { return nil }
        port = p
    }

    func stop() { listener.cancel(); conns.value.forEach { $0.cancel() } }
}

private func attempt(_ server: LoopbackTLSServer, policy: ServerCertPolicy) async -> (ok: Bool, error: String?, stream: TLSStream) {
    let s = TLSStream(host: "127.0.0.1", port: server.port, proxy: ProxySettings(), policy: policy)
    do {
        try await s.start(timeout: 10)
        let data = try await s.recv(5)
        _ = data
        return (true, nil, s)
    } catch { s.cancel(); return (false, error.localizedDescription, s) }
}

private func hex(_ b: some Sequence<UInt8>) -> String { b.map { String(format: "%02x", $0) }.joined() }

func registerTLSPinTests() {
    test("tlspin/correct-sha1-and-sha256-fingerprints-succeed", timeout: 40) {
        guard let srv = LoopbackTLSServer() else { fail("could not start the loopback TLS server"); return }
        defer { srv.stop() }
        let sha1 = hex(Insecure.SHA1.hash(data: srv.leafDER)), sha256 = hex(SHA256.hash(data: srv.leafDER))
        for (label, fp) in [("sha1", sha1), ("SHA-1 with colons", sha1.uppercased().enumerated().map { $0.offset % 2 == 0 && $0.offset > 0 ? ":\($0.element)" : "\($0.element)" }.joined()),
                            ("sha256", sha256)] {
            let r = await attempt(srv, policy: ServerCertPolicy(checkServerCert: false, fingerprint: fp))
            expect(r.ok, "\(label): \(r.error ?? "")")
            if label == "sha1" { expectEqual(r.stream.remoteIPv4, "127.0.0.1", "the connected peer is exposed") }
            r.stream.cancel()
        }
    }
    test("tlspin/wrong-fingerprint-fails-with-the-pin-mismatch-error", timeout: 40) {
        guard let srv = LoopbackTLSServer() else { fail("could not start the loopback TLS server"); return }
        defer { srv.stop() }
        var wrong1 = hex(Insecure.SHA1.hash(data: srv.leafDER)); wrong1.removeLast(); wrong1 += "0"
        if wrong1 == hex(Insecure.SHA1.hash(data: srv.leafDER)) { wrong1.removeLast(); wrong1 += "1" }
        for fp in [wrong1, hex(SHA256.hash(data: Data("other".utf8)))] {
            let r = await attempt(srv, policy: ServerCertPolicy(checkServerCert: false, fingerprint: fp))
            expect(!r.ok, "a mismatching pin must not connect")
            expect(r.error?.contains("does not match the pinned fingerprint") == true, "error was: \(r.error ?? "nil")")
        }
        let bad = await attempt(srv, policy: ServerCertPolicy(checkServerCert: false, fingerprint: "xyz"))
        expect(!bad.ok && bad.error?.contains("not a valid") == true, "an unparseable pin fails closed: \(bad.error ?? "nil")")
    }
    test("tlspin/no-pin-accepts-any-certificate", timeout: 40) {
        guard let srv = LoopbackTLSServer() else { fail("could not start the loopback TLS server"); return }
        defer { srv.stop() }
        let r = await attempt(srv, policy: .acceptAny)
        expect(r.ok, r.error ?? ""); r.stream.cancel()
        // the throwaway certificate is self-signed: plain "verify server certificate" must refuse it
        let strict = await attempt(srv, policy: ServerCertPolicy(checkServerCert: true, fingerprint: nil))
        expect(!strict.ok, "system trust must reject a self-signed certificate")
    }
}
