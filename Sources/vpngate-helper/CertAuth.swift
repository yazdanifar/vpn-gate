import Foundation
import Security
import VPNGateCore

/// Certificate authentication (authtype 3): the server sends a 20-byte random challenge and expects an RSA
/// PKCS#1 v1.5 / SHA-1 signature over it (upstream HashForSign = SHA1 + DigestInfo, then RSA private encrypt).
/// The helper runs as root and cannot read the user's Keychain, so the app sends the key in `ConnectConfig.privateKeyDer`.
enum CertAuth {
    static let maxCertBytes = 16 * 1024
    static let maxKeyBytes = 16 * 1024

    /// Returns a signer for `ClientAuth.certificate`. Throws (without including key material) if the key is unusable.
    static func signer(privateKeyDer: Data?) -> (Data) throws -> Data {
        { challenge in
            guard let der = privateKeyDer, !der.isEmpty else {
                throw StreamError.protocolError("Certificate authentication needs the account's private key")
            }
            return try sign(challenge, privateKeyDer: der)
        }
    }

    static func sign(_ challenge: Data, privateKeyDer: Data) throws -> Data {
        guard privateKeyDer.count <= maxKeyBytes else { throw StreamError.protocolError("Private key too large") }
        let pkcs1 = unwrapPKCS8(privateKeyDer) ?? privateKeyDer
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, &err) else {
            err?.release()
            throw StreamError.protocolError("Private key is not a valid RSA key (PKCS#1 or PKCS#8 DER expected)")
        }
        guard let sig = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA1, challenge as CFData, &err) else {
            err?.release()
            throw StreamError.protocolError("Signing the server challenge failed")
        }
        return sig as Data
    }

    /// PKCS#8 PrivateKeyInfo { INTEGER 0, SEQUENCE alg, OCTET STRING key } -> the inner PKCS#1 key; nil if `der` is not that shape.
    static func unwrapPKCS8(_ der: Data) -> Data? {
        let b = [UInt8](der)
        var pos = 0
        func header(expect tag: UInt8) -> (start: Int, len: Int)? {
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
        guard header(expect: 0x30) != nil else { return nil }
        guard let version = header(expect: 0x02), version.len == 1, b[version.start] == 0 else { return nil }
        pos = version.start + version.len
        guard let alg = header(expect: 0x30) else { return nil }
        pos = alg.start + alg.len
        guard let key = header(expect: 0x04) else { return nil }
        return Data(b[key.start..<key.start + key.len])
    }
}
