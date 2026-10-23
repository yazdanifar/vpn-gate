import Compression
import CryptoKit
import Foundation
import Security

public enum VGDatError: Error, LocalizedError {
    case invalidHeader
    case truncated
    case signatureVerificationFailed
    case decompressionFailed
    case invalidPack

    public var errorDescription: String? {
        switch self {
        case .invalidHeader: return "Invalid VPNGate.dat header"
        case .truncated: return "Truncated VPNGate.dat file"
        case .signatureVerificationFailed: return "VPNGate.dat RSA signature verification failed"
        case .decompressionFailed: return "Failed to decompress VPNGate.dat inner payload"
        case .invalidPack: return "Invalid Pack format in VPNGate.dat"
        }
    }
}

public struct VGDatFile {
    public let headerText: String
    public let soapURL: String
    public let timestamp: Date
    public let timestampMs: UInt64
    public let servers: [VPNServer]
    public let rawInnerPack: Pack
    public let isSignatureValid: Bool
    public let isFresh: Bool
    /// Client tunables from the signed `DynList` blob (empty when the list carries none).
    public let tunables: VGTunables
}

/// The client's named tunables (client_exe.c FUN_0061b3f0 / FUN_0061b380 / FUN_0061b430, 282360-282470).
/// A verified VPNGate.dat may carry a `DynList`: an unencrypted nested Pack of name -> int64 that overrides the
/// defaults compiled into the client. A lookup returns the default when the name is absent or its value is 0,
/// otherwise the value clamped to [default / 5, default * 50]. Names compare case-insensitively.
public struct VGTunables: Equatable {
    public private(set) var values: [String: UInt64] = [:]

    public init() {}

    /// Parses the `DynList` blob (client_exe.c FUN_0061b690: every named element read as an int64). Elements that
    /// are not int64 read as 0 in the original, i.e. "use the default", so they are skipped. Unparseable = empty.
    public init(dynList: Data) {
        guard let pack = try? Pack(parsing: dynList) else { return }
        for e in pack.elements {
            if case .int64(let v)? = e.values.first { values[e.name.lowercased()] = v }
        }
    }

    /// The original keeps one process-wide table and only overwrites names a newer list mentions (FUN_0061b520).
    public mutating func merge(_ newer: VGTunables) {
        values.merge(newer.values) { _, new in new }
    }

    public func value(_ name: String, default d: UInt64) -> UInt64 {
        guard let v = values[name.lowercased()], v != 0 else { return d }
        let hi = d.multipliedReportingOverflow(by: 50)
        return min(max(v, d / 5), hi.overflow ? UInt64.max : hi.partialValue)
    }

    /// Milliseconds tunable as seconds.
    public func seconds(_ name: String, defaultMs: UInt64) -> TimeInterval { Double(value(name, default: defaultMs)) / 1000.0 }
}

public enum VGDat {
    /// 36 hours in milliseconds (VG_ALLOW_TIME_DIFF from client_exe.c / VG.c).
    public static let allowTimeDiffMs: UInt64 = 36 * 3600 * 1000

    /// RSA-1024 public certificate (CN=vpngate_api_cert, O=SoftEther Corporation) that signs VPNGate.dat.
    /// It does not appear as text in client_exe.c (the CN=Root cert at line 281993 is a different one); it was
    /// confirmed instead by verifying the shipped VPNGate.dat signature with it (see Tests/Unit/VGDatTests.swift).
    public static let apiCertificatePEM = """
        -----BEGIN CERTIFICATE-----
        MIIB/zCCAWgCAQAwDQYJKoZIhvcNAQEFBQAwSDEZMBcGA1UEAxQQdnBuZ2F0ZV9h
        cGlfY2VydDEeMBwGA1UEChMVU29mdEV0aGVyIENvcnBvcmF0aW9uMQswCQYDVQQG
        EwJKUDAeFw0xMzAxMTUwNjM4MTVaFw0zNzAxMDkwNjM4MTVaMEgxGTAXBgNVBAMU
        EHZwbmdhdGVfYXBpX2NlcnQxHjAcBgNVBAoTFVNvZnRFdGhlciBDb3Jwb3JhdGlv
        bjELMAkGA1UEBhMCSlAwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANKvJddX
        AO7XIt+ZXBvzH10R/nlFV9RRG7nW0Kge6/FVVlfgYuninG/s9RF6rloWh4v7sotp
        GUKFJ7jD76NAzkemvsNpcQfkddxZD/Nv6k3ZoWK1Z2Wm77UkhBiI34/Ez9uLPgiJ
        rc10hwkeixpO2V5ewi0RvWEayq79xGS1jLpnAgMBAAEwDQYJKoZIhvcNAQEFBQAD
        gYEAMKQNaIw5eusl1sOZ6BlcqVCXRAFG+/rF9ZFUHQzdu3hO2k1F08naMpoO9PIE
        d8yEiIuOzeylfCReS34JclCWOz/IVVgk9gYNDKeGZpM17ZuXes1EkG4SrCDqUnaN
        /gl7JR92FEfGHsyteExq/09Q7b1BfHCHSmXfKhoOBD/TlV4=
        -----END CERTIFICATE-----
        """

    private static let publicKey: SecKey? = {
        let lines = apiCertificatePEM.components(separatedBy: .newlines).filter {
            !$0.hasPrefix("-----") && !$0.isEmpty
        }
        guard let der = Data(base64Encoded: lines.joined()),
            let cert = SecCertificateCreateWithData(nil, der as CFData),
            let pubKey = SecCertificateCopyKey(cert)
        else {
            return nil
        }
        return pubKey
    }()

    // MARK: - Parse

    /// Parses and always verifies a VPNGate.dat. `now` is only injectable so tests can pin the freshness check.
    public static func parse(data: Data, now: Date = Date()) throws -> VGDatFile {
        guard data.count > 0x104 else { throw VGDatError.truncated }

        // 1. Header (240 bytes)
        let headerBytes = data.prefix(0xF0)
        let headerText = String(decoding: headerBytes, as: UTF8.self)
        guard headerText.hasPrefix("[VPNGate Data File]") else { throw VGDatError.invalidHeader }

        // 2. Seed (20 bytes)
        let seed = [UInt8](data[0xF0..<0x104])

        // 3. Body
        let body = [UInt8](data[0x104...])
        let key = Array(Insecure.SHA1.hash(data: seed))
        let decryptedBody = RC4.cipher(key: key, data: body)

        // 4. Outer Pack
        let outer: Pack
        do {
            outer = try Pack(parsing: Data(decryptedBody))
        } catch {
            throw VGDatError.invalidPack
        }

        guard let outerData = outer.data("data"),
            let dataSize = outer.int("data_size") ?? outer.int64("data_size").map(UInt32.init),
            let sign = outer.data("sign"),
            let tsData = outer.data("timestamp"), tsData.count == 8
        else {
            throw VGDatError.invalidPack
        }

        let soapURL =
            outer.str("soap_url")
            ?? outer.data("soap_url").map { String(decoding: $0, as: UTF8.self) }
            ?? ""
        let compressed = (outer.int("compressed") ?? 0) != 0

        // Parse 64-bit big-endian timestamp milliseconds. `tsData` is a slice of a larger buffer at an arbitrary
        // byte offset, so a raw `.load(as: UInt64.self)` can hit a misaligned address and trap; rd64 reads byte
        // by byte instead.
        let tsMs = rd64([UInt8](tsData), 0)
        let timestamp = Date(timeIntervalSince1970: Double(tsMs) / 1000.0)

        // 5. Signature verification (RSA PKCS#1 v1.5 SHA-1)
        var sigValid = false
        if let pubKey = publicKey {
            var signedMsg = Data()
            signedMsg.append(tsData)
            signedMsg.append(outerData)
            withUnsafeBytes(of: dataSize.bigEndian) { signedMsg.append(contentsOf: $0) }

            var error: Unmanaged<CFError>?
            sigValid = SecKeyVerifySignature(
                pubKey, .rsaSignatureMessagePKCS1v15SHA1,
                signedMsg as CFData, sign as CFData, &error)
        }

        guard sigValid else { throw VGDatError.signatureVerificationFailed }

        // 6. Decompress
        let uncompressedBytes: [UInt8]
        if compressed {
            uncompressedBytes = try decompress(data: [UInt8](outerData), expectedSize: Int(dataSize))
        } else {
            uncompressedBytes = [UInt8](outerData)
        }

        // 7. Inner Pack
        let inner: Pack
        do {
            inner = try Pack(parsing: Data(uncompressedBytes))
        } catch {
            throw VGDatError.invalidPack
        }

        let servers = parseInnerServers(innerPack: inner)
        let nowMs = UInt64(max(0, now.timeIntervalSince1970 * 1000.0))
        let diffMs = nowMs > tsMs ? (nowMs - tsMs) : (tsMs - nowMs)
        let isFresh = diffMs <= allowTimeDiffMs

        return VGDatFile(
            headerText: headerText,
            soapURL: soapURL,
            timestamp: timestamp,
            timestampMs: tsMs,
            servers: servers,
            rawInnerPack: inner,
            isSignatureValid: sigValid,
            isFresh: isFresh,
            tunables: inner.data("DynList").map { VGTunables(dynList: $0) } ?? VGTunables()
        )
    }

    // MARK: - Decompression

    /// Largest inflated `data` accepted (the real list is ~75 KB).
    public static let maxInflatedSize = 16 * 1024 * 1024

    /// Inflates a zlib stream (2-byte header, raw deflate, big-endian Adler-32) to exactly `expectedSize` bytes.
    /// COMPRESSION_ZLIB is raw deflate, so the header and trailer are handled here: a longer or shorter stream,
    /// or a bad Adler-32, is rejected.
    public static func decompress(data: [UInt8], expectedSize: Int) throws -> [UInt8] {
        guard expectedSize > 0, expectedSize <= maxInflatedSize, data.count >= 6 else {
            throw VGDatError.decompressionFailed
        }
        // CMF/FLG: deflate, 32K window, no preset dictionary, header checksum multiple of 31.
        guard data[0] & 0x0F == 8, (Int(data[0]) << 8 | Int(data[1])) % 31 == 0, data[1] & 0x20 == 0 else {
            throw VGDatError.decompressionFailed
        }
        let rawDeflate = Array(data.dropFirst(2).dropLast(4))
        let adler = data.suffix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }

        // One spare byte: an inflated stream longer than expectedSize shows up as expectedSize + 1.
        var dest = [UInt8](repeating: 0, count: expectedSize + 1)
        let decodedSize = rawDeflate.withUnsafeBytes { srcPtr in
            dest.withUnsafeMutableBytes { dstPtr in
                compression_decode_buffer(
                    dstPtr.bindMemory(to: UInt8.self).baseAddress!, dstPtr.count,
                    srcPtr.bindMemory(to: UInt8.self).baseAddress!, rawDeflate.count,
                    nil, COMPRESSION_ZLIB
                )
            }
        }
        guard decodedSize == expectedSize else { throw VGDatError.decompressionFailed }

        let out = Array(dest.prefix(expectedSize))
        guard adler32(out) == adler else { throw VGDatError.decompressionFailed }
        return out
    }

    static func adler32(_ bytes: [UInt8]) -> UInt32 {
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in bytes {
            a = (a + UInt32(byte)) % 65521
            b = (b + a) % 65521
        }
        return b << 16 | a
    }

    // MARK: - Inner Pack parsing

    public static func parseInnerServers(innerPack: Pack) -> [VPNServer] {
        guard let numHostsVal = innerPack.int("NumHosts") else { return [] }
        let ips = innerPack.strs("IP")
        // NumHosts is attacker-influenced (signed, but a malicious relay can replay): never trust it past the arrays.
        let count = min(Int(clamping: numHostsVal), ips.count)
        guard count > 0 else { return [] }

        let fqdns = innerPack.strs("Fqdn")
        let hostNames = innerPack.strs("HostName")
        let countryShorts = innerPack.strs("CountryShort")
        let countryFulls = innerPack.strs("CountryFull")
        let scores = innerPack.int64s("Score")
        let pings = innerPack.ints("PingToJapan")
        let speeds = innerPack.int64s("SpeedToJapan")
        let numClients = innerPack.ints("NumClients")
        let uptimes = innerPack.int64s("Uptime")
        let sslPortsStrs = innerPack.strs("SslPorts")
        let udpPorts = innerPack.ints("UdpPort")
        let openVpnUdpPortsStrs = innerPack.strs("OpenVpnUdpPorts")
        let l2tps = innerPack.ints("L2TP")
        let oss = innerPack.ints("Os")
        let softs = innerPack.strs("Soft")
        let builds = innerPack.ints("Build")
        let owners = innerPack.strs("Owner")
        let abuses = innerPack.strs("Abuse")
        let messages = innerPack.strs("Message")
        let numLogins = innerPack.int64s("NumLogin")
        let logs = innerPack.ints("Log")
        let logPermanents = innerPack.ints("LogPermanent")
        let names = innerPack.strs("Name")
        let pingsGoogle = innerPack.ints("PingToGoogle")
        let sendSizes = innerPack.int64s("SendSize")
        let recvSizes = innerPack.int64s("RecvSize")
        let kernelNats = innerPack.ints("IsKernelModeNAT")

        var servers = [VPNServer]()
        servers.reserveCapacity(count)

        for i in 0..<count {
            let ip = i < ips.count ? ips[i] : ""
            guard !ip.isEmpty else { continue }

            let fqdn = i < fqdns.count ? fqdns[i] : ""
            let hostName = i < hostNames.count && !hostNames[i].isEmpty ? hostNames[i] : fqdn
            let countryShort = i < countryShorts.count ? countryShorts[i] : ""
            let countryLong = i < countryFulls.count ? countryFulls[i] : ""
            let score = i < scores.count ? Int(clamping: scores[i]) : 0
            let ping = i < pings.count ? Int(clamping: pings[i]) : 0
            let speed = i < speeds.count ? Int(clamping: speeds[i]) : 0
            let sessions = i < numClients.count ? Int(clamping: numClients[i]) : 0
            let uptimeMs = i < uptimes.count ? Int(clamping: uptimes[i]) : 0

            let sslPortsStr = i < sslPortsStrs.count ? sslPortsStrs[i] : ""
            let sslPorts = sslPortsStr.split(separator: " ").compactMap { UInt16($0) }

            let udpPort: UInt16? = (i < udpPorts.count && udpPorts[i] > 0) ? UInt16(exactly: udpPorts[i]) : nil

            let openVpnStr = i < openVpnUdpPortsStrs.count ? openVpnUdpPortsStrs[i] : ""
            let openVpnUdpPorts = openVpnStr.split(separator: " ").compactMap { UInt16($0) }

            let l2tp = i < l2tps.count ? (l2tps[i] != 0) : false
            let osStr = i < oss.count ? String(oss[i]) : nil
            let soft = i < softs.count ? softs[i] : nil
            let build = i < builds.count ? Int(clamping: builds[i]) : nil
            let owner = i < owners.count ? owners[i] : nil
            let abuse = i < abuses.count ? abuses[i] : nil
            let message = i < messages.count ? messages[i] : ""
            let numLogin = i < numLogins.count ? Int64(clamping: numLogins[i]) : nil

            let pingGoogle = i < pingsGoogle.count ? Int(clamping: pingsGoogle[i]) : 0
            let sendSize = i < sendSizes.count ? sendSizes[i] : 0
            let recvSize = i < recvSizes.count ? recvSizes[i] : 0
            let traffic = Int(clamping: sendSize.addingReportingOverflow(recvSize).overflow ? UInt64.max : sendSize + recvSize)

            let isLogPermanent = i < logPermanents.count ? (logPermanents[i] != 0) : false
            let isLog2Weeks = i < logs.count ? (logs[i] != 0) : false
            let noLog = !isLogPermanent && !isLog2Weeks

            let logType = isLogPermanent ? "Permanent" : (isLog2Weeks ? "2 Weeks" : "No Log")

            let firstPort = VPNServer.portPriority(sslPorts).first.map(Int.init) ?? (udpPort.map(Int.init) ?? 443)

            let server = VPNServer(
                hostName: hostName,
                ip: ip,
                score: score,
                ping: ping,
                speed: speed,
                countryLong: countryLong,
                countryShort: countryShort,
                sessions: sessions,
                uptimeMs: uptimeMs,
                totalUsers: numLogin.map { Int(clamping: $0) } ?? 0,
                totalTraffic: traffic,
                logType: logType,
                operatorName: owner ?? "",
                message: message,
                listedPort: firstPort,
                listedProto: "tcp",
                fqdn: fqdn,
                sslPorts: sslPorts,
                udpPort: udpPort,
                openVpnUdpPorts: openVpnUdpPorts,
                l2tp: l2tp,
                os: osStr,
                soft: soft,
                build: build,
                owner: owner,
                abuse: abuse,
                numLogin: numLogin,
                noLog: noLog,
                logPermanent: isLogPermanent,
                name: i < names.count ? names[i] : nil,
                pingToGoogle: pingGoogle,
                sendSize: sendSize,
                recvSize: recvSize,
                isKernelModeNAT: i < kernelNats.count ? kernelNats[i] != 0 : false
            )
            servers.append(server)
        }

        return servers
    }

    // MARK: - 16-byte Probe Generator & Validator

    /// Generates the 16-byte probe sent with HTTP GET /vgc_download_dat/
    /// Format: 8 bytes big-endian timestamp + 8 bytes of SHA0(SHA0(SHA0(SHA1(ts))))[0..<8]
    public static func generateProbe(timestampMs: UInt64 = UInt64(Date().timeIntervalSince1970 * 1000.0)) -> [UInt8] {
        var tsBe = timestampMs.bigEndian
        let tsBytes = withUnsafeBytes(of: &tsBe) { Array($0) }

        let h1 = Array(Insecure.SHA1.hash(data: tsBytes))
        let s1 = SHA0.hash(h1)
        let s2 = SHA0.hash(s1)
        let s3 = SHA0.hash(s2)

        return tsBytes + Array(s3.prefix(8))
    }

    /// Verifies a 16-byte probe
    public static func verifyProbe(_ probe: [UInt8], allowedDiffMs: UInt64 = allowTimeDiffMs, now: Date = Date()) -> Bool {
        guard probe.count == 16 else { return false }
        let tsBytes = Array(probe[0..<8])
        let hashBytes = Array(probe[8..<16])

        let tsMs = rd64(tsBytes, 0)
        let nowMs = UInt64(max(0, now.timeIntervalSince1970 * 1000.0))
        let diffMs = nowMs > tsMs ? (nowMs - tsMs) : (tsMs - nowMs)
        guard diffMs <= allowedDiffMs else { return false }

        let h1 = Array(Insecure.SHA1.hash(data: tsBytes))
        let s1 = SHA0.hash(h1)
        let s2 = SHA0.hash(s1)
        let s3 = SHA0.hash(s2)

        return Array(s3.prefix(8)) == hashBytes
    }
}
