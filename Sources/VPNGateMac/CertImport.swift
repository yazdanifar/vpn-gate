import Foundation
import Security

/// Turns user-supplied certificate / key files into the DER blobs the helper needs for certificate login:
/// the certificate (X.509 DER) and an RSA private key as PKCS#1 `RSAPrivateKey` DER. Only RSA is supported
/// (SoftEther signs the server challenge with RSA PKCS#1 v1.5 / SHA-1). Nothing here touches the Keychain or disk.
enum CertImport {
    struct Identity: Equatable {
        var certDer: Data
        var privateKeyDer: Data
    }

    enum Failure: LocalizedError, Equatable {
        case notCertificate
        case notPrivateKey
        case encryptedKey
        case unsupportedKeyType(String)
        case keyMismatch
        case wrongPassphrase
        case pkcs12(String)

        var errorDescription: String? {
            switch self {
            case .notCertificate: return "That file is not an X.509 certificate (PEM or DER expected)."
            case .notPrivateKey: return "That file is not an RSA private key (PEM or DER expected)."
            case .encryptedKey: return "The private key is passphrase-protected. Remove the passphrase first (openssl rsa -in key.pem -out plain.pem) or import a .p12 file instead."
            case .unsupportedKeyType(let t): return "Only RSA keys are supported for certificate login (this key is \(t))."
            case .keyMismatch: return "The private key does not belong to the certificate."
            case .wrongPassphrase: return "Wrong passphrase for the .p12 file."
            case .pkcs12(let m): return "Could not read the .p12 file: \(m)"
            }
        }
    }

    // MARK: PEM / DER files

    static func parseCertificate(_ data: Data) throws -> Data {
        let der: Data
        if let block = pemBlocks(data).first(where: { $0.label == "CERTIFICATE" || $0.label == "X509 CERTIFICATE" }) { der = block.der }
        else if data.first == 0x30 { der = data }
        else { throw Failure.notCertificate }
        guard SecCertificateCreateWithData(nil, der as CFData) != nil else { throw Failure.notCertificate }
        return der
    }

    /// Accepts PKCS#1 (`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`) or raw DER of either; always returns PKCS#1 DER.
    static func parsePrivateKey(_ data: Data) throws -> Data {
        var der: Data?
        for block in pemBlocks(data) {
            switch block.label {
            case "ENCRYPTED PRIVATE KEY": throw Failure.encryptedKey
            case "EC PRIVATE KEY": throw Failure.unsupportedKeyType("EC")
            case "DSA PRIVATE KEY": throw Failure.unsupportedKeyType("DSA")
            case "RSA PRIVATE KEY":
                if block.headers.contains(where: { $0.lowercased().contains("encrypted") }) { throw Failure.encryptedKey }
                der = block.der
            case "PRIVATE KEY": der = block.der
            default: continue
            }
            if der != nil { break }
        }
        if der == nil, pemBlocks(data).isEmpty, data.first == 0x30 { der = data }
        guard let raw = der else { throw Failure.notPrivateKey }
        let pkcs1: Data
        switch pkcs8Algorithm(raw) {
        case .rsa(let inner): pkcs1 = inner
        case .other: throw Failure.unsupportedKeyType("not RSA")
        case .notPKCS8: pkcs1 = raw
        }
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, nil) != nil else { throw Failure.notPrivateKey }
        return pkcs1
    }

    /// Certificate and key from two files; checks they belong together.
    static func identity(certificateFile: Data, keyFile: Data) throws -> Identity {
        let cert = try parseCertificate(certificateFile)
        let key = try parsePrivateKey(keyFile)
        try requireMatch(certDer: cert, keyDer: key)
        return Identity(certDer: cert, privateKeyDer: key)
    }

    static func requireMatch(certDer: Data, keyDer: Data) throws {
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard let cert = SecCertificateCreateWithData(nil, certDer as CFData),
              let certKey = SecCertificateCopyKey(cert),
              let privKey = SecKeyCreateWithData(keyDer as CFData, attrs as CFDictionary, nil),
              let pubKey = SecKeyCopyPublicKey(privKey),
              let a = SecKeyCopyExternalRepresentation(certKey, nil) as Data?,
              let b = SecKeyCopyExternalRepresentation(pubKey, nil) as Data? else { throw Failure.keyMismatch }
        if a != b { throw Failure.keyMismatch }
    }

    // MARK: PKCS#12

    /// `forceLegacyKeychain` takes the macOS 14 path (a throwaway keychain file in `keychainDirectory`, deleted again
    /// before returning) even where the memory-only import exists; the user's keychains are never opened either way.
    static func importPKCS12(_ data: Data, passphrase: String, forceLegacyKeychain: Bool = false,
                             keychainDirectory: String = NSTemporaryDirectory()) throws -> Identity {
        if #available(macOS 15.0, *), !forceLegacyKeychain {
            // Memory-only import: never lands in a keychain, and the key stays exportable.
            var items: CFArray?
            let status = SecPKCS12Import(data as CFData, [kSecImportExportPassphrase as String: passphrase,
                                                          kSecImportToMemoryOnly as String: true] as CFDictionary, &items)
            return try extract(try identity(status, items))
        }
        return try withLegacyKeychain(directory: keychainDirectory) { keychain in
            try extract(try legacyIdentity(data, passphrase: passphrase, keychain: keychain))
        }
    }

    private static func identity(_ status: OSStatus, _ items: CFArray?) throws -> SecIdentity {
        if status == errSecAuthFailed { throw Failure.wrongPassphrase }
        guard status == errSecSuccess else {
            throw Failure.pkcs12((SecCopyErrorMessageString(status, nil) as String?) ?? "error \(status)")
        }
        guard let first = (items as? [[String: Any]])?.first(where: { $0[kSecImportItemIdentity as String] != nil }),
              let identityRef = first[kSecImportItemIdentity as String] else {
            throw Failure.pkcs12("the file contains no certificate with a private key")
        }
        return identityRef as! SecIdentity            // CFTypeRef -> SecIdentity cannot fail
    }

    /// Runs `body` with a throwaway keychain file in `directory`; the file is gone again on every exit path.
    private static func withLegacyKeychain<T>(directory: String, _ body: (SecKeychain) throws -> T) throws -> T {
        let path = (directory as NSString).appendingPathComponent("vpngate-p12-\(UUID().uuidString).keychain")
        var kc: SecKeychain?
        let pw = UUID().uuidString
        guard let api = LegacyKeychainAPI.shared,
              api.create(path, UInt32(pw.utf8.count), pw, 0, nil, &kc) == errSecSuccess, let keychain = kc else {
            throw Failure.pkcs12("cannot create a temporary keychain")
        }
        defer { _ = LegacyKeychainAPI.shared?.delete(keychain); try? FileManager.default.removeItem(atPath: path) }
        return try body(keychain)
    }

    /// Keys imported into a keychain by `SecPKCS12Import` are not extractable, so first try `SecItemImport` with the
    /// extractable attribute (works for the older PKCS#12 encodings). Newer encodings make it fail with a MAC error,
    /// which is indistinguishable from a wrong passphrase; `SecPKCS12Import` then tells the two apart, and for a
    /// correct passphrase explains that such a file cannot be read here.
    private static func legacyIdentity(_ data: Data, passphrase: String, keychain: SecKeychain) throws -> SecIdentity {
        var format = SecExternalFormat.formatPKCS12
        var itemType = SecExternalItemType.itemTypeAggregate
        let extractable = [0x20 as NSNumber] as CFArray                 // CSSM_KEYATTR_EXTRACTABLE
        var params = SecItemImportExportKeyParameters()
        params.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
        params.passphrase = Unmanaged.passUnretained(passphrase as CFString)
        params.keyAttributes = Unmanaged.passUnretained(extractable)
        var items: CFArray?
        let status = SecItemImport(data as CFData, nil, &format, &itemType, [], &params, keychain, &items)
        if status == errSecSuccess,
           let id = (items as? [CFTypeRef])?.first(where: { CFGetTypeID($0) == SecIdentityGetTypeID() }) {
            return id as! SecIdentity
        }
        var viaImport: CFArray?
        let status2 = SecPKCS12Import(data as CFData, [kSecImportExportPassphrase as String: passphrase,
                                                       kSecImportExportKeychain as String: keychain] as CFDictionary, &viaImport)
        let found = try identity(status2, viaImport)
        // Readable, but the key sits non-extractable in the keychain: tell the user how to get it out.
        var key: SecKey?
        if SecIdentityCopyPrivateKey(found, &key) == errSecSuccess, let k = key, SecKeyCopyExternalRepresentation(k, nil) != nil {
            return found
        }
        if let k = key, let type = (SecKeyCopyAttributes(k) as? [String: Any])?[kSecAttrKeyType as String] as? String,
           type != (kSecAttrKeyTypeRSA as String) {
            return found                                                // let `extract` report the key type
        }
        throw Failure.pkcs12("this macOS version cannot read the private key of that .p12 (newer encoding). Import the PEM files instead: openssl pkcs12 -in file.p12 -nodes -out all.pem")
    }

    private static func extract(_ identity: SecIdentity) throws -> Identity {
        var certRef: SecCertificate?
        var keyRef: SecKey?
        guard SecIdentityCopyCertificate(identity, &certRef) == errSecSuccess, let cert = certRef,
              SecIdentityCopyPrivateKey(identity, &keyRef) == errSecSuccess, let key = keyRef else {
            throw Failure.pkcs12("cannot read the certificate or key")
        }
        let keyAttrs = SecKeyCopyAttributes(key) as? [String: Any]
        let type = keyAttrs?[kSecAttrKeyType as String] as? String
        guard type == (kSecAttrKeyTypeRSA as String) else { throw Failure.unsupportedKeyType(type == (kSecAttrKeyTypeECSECPrimeRandom as String) ? "EC" : "not RSA") }
        var err: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(key, &err) as Data? else {
            err?.release()
            throw Failure.pkcs12("the private key is not exportable")
        }
        let certDer = SecCertificateCopyData(cert) as Data
        try requireMatch(certDer: certDer, keyDer: keyData)
        return Identity(certDer: certDer, privateKeyDer: keyData)
    }

    // MARK: PEM / ASN.1 helpers

    struct PEMBlock { var label: String; var headers: [String]; var der: Data }

    static func pemBlocks(_ data: Data) -> [PEMBlock] {
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        var out = [PEMBlock]()
        var label: String?
        var headers = [String](), body = ""
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") {
                label = String(line.dropFirst(11).dropLast(5)); headers = []; body = ""
            } else if line.hasPrefix("-----END ") {
                if let l = label, let der = Data(base64Encoded: body) { out.append(PEMBlock(label: l, headers: headers, der: der)) }
                label = nil
            } else if label != nil {
                if line.contains(":") { headers.append(line) } else { body += line }
            }
        }
        return out
    }

    enum PKCS8 { case rsa(Data), other, notPKCS8 }

    /// PrivateKeyInfo { INTEGER 0, SEQUENCE { OID, ... }, OCTET STRING key }: RSA -> the inner PKCS#1 key.
    static func pkcs8Algorithm(_ der: Data) -> PKCS8 {
        let b = [UInt8](der)
        var pos = 0
        func header(_ tag: UInt8) -> (start: Int, len: Int)? {
            guard pos + 2 <= b.count, b[pos] == tag else { return nil }
            var len = Int(b[pos + 1]); pos += 2
            if len & 0x80 != 0 {
                let n = len & 0x7f
                guard n >= 1, n <= 3, pos + n <= b.count else { return nil }
                len = 0
                for _ in 0..<n { len = len << 8 | Int(b[pos]); pos += 1 }
            }
            guard pos + len <= b.count else { return nil }
            return (pos, len)
        }
        guard header(0x30) != nil, let version = header(0x02) else { return .notPKCS8 }
        pos = version.start + version.len
        // PKCS#1 RSAPrivateKey is also SEQUENCE { INTEGER 0, INTEGER n, ... }: the next element tells them apart.
        guard let alg = header(0x30) else { return .notPKCS8 }
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let isRSA = alg.len >= rsaOID.count && Array(b[alg.start..<alg.start + rsaOID.count]) == rsaOID
        pos = alg.start + alg.len
        guard let key = header(0x04) else { return .other }
        return isRSA ? .rsa(Data(b[key.start..<key.start + key.len])) : .other
    }
}

/// `SecKeychainCreate` / `SecKeychainDelete` are deprecated, but a throwaway *file* keychain is the only way to import
/// an extractable key from an older-encoding .p12 on macOS 14 (`SecPKCS12Import` makes non-extractable keys there).
/// They are looked up at run time so the build stays free of deprecation warnings; if a future macOS drops them the
/// lookup returns nil and the import fails with a clear message instead of crashing.
private struct LegacyKeychainAPI {
    typealias Create = @convention(c) (UnsafePointer<CChar>, UInt32, UnsafeRawPointer?, UInt8, SecAccess?,
                                       UnsafeMutablePointer<SecKeychain?>) -> OSStatus
    typealias Delete = @convention(c) (SecKeychain?) -> OSStatus
    let create: Create
    let delete: Delete

    static let shared: LegacyKeychainAPI? = {
        guard let handle = dlopen(nil, RTLD_NOW),
              let c = dlsym(handle, "SecKeychainCreate"), let d = dlsym(handle, "SecKeychainDelete") else { return nil }
        return LegacyKeychainAPI(create: unsafeBitCast(c, to: Create.self), delete: unsafeBitCast(d, to: Delete.self))
    }()
}
