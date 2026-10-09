import Foundation
import CryptoKit
import VPNGateCore

/// zlib.compress(b"hello vpngate " * 20) from Python: an independent vector for the inflate path.
private let zlibPlain = [UInt8](Array(repeating: Array("hello vpngate ".utf8), count: 20).joined())
private let zlibFixture: [UInt8] = [0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0x2b, 0xc8, 0x4b, 0x4f, 0x2c, 0x49,
                                    0x55, 0xc8, 0x18, 0xe5, 0x41, 0x79, 0x00, 0x25, 0x32, 0x69, 0xb5]

private func fixtureURL(_ name: String, file: String = #filePath) -> URL {
    URL(fileURLWithPath: file).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures/" + name)
}

private func tempDir() -> URL {
    let d = FileManager.default.temporaryDirectory.appendingPathComponent("vpngate-test-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
    return d
}

func registerVGDatTests() {
    test("crypto/rc4-roundtrip-and-vector") {
        // Key "Key", plaintext "Plaintext"
        let key = Array("Key".utf8)
        let plaintext = Array("Plaintext".utf8)
        let encrypted = RC4.cipher(key: key, data: plaintext)
        let decrypted = RC4.cipher(key: key, data: encrypted)
        expectEqual(decrypted, plaintext)
        // Standard RC4 test vector: Key="Key", PT="Plaintext" -> BB F3 16 E8 D9 40 AF 0A D3
        let expectedHex = "bbf316e8d940af0ad3"
        let hex = encrypted.map { String(format: "%02x", $0) }.joined()
        expectEqual(hex, expectedHex)
    }

    test("crypto/sha0-standard-vector") {
        // FIPS PUB 180 SHA-0 vector: "abc" -> 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
        let digest = SHA0.hash(Array("abc".utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        expectEqual(hex, "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880")
    }

    test("vgdat/probe-generate-and-verify") {
        let probe = VGDat.generateProbe()
        expectEqual(probe.count, 16)
        expect(VGDat.verifyProbe(probe), "fresh probe must verify")

        // Corrupted probe fails
        var badProbe = probe
        badProbe[15] ^= 0x01
        expect(!VGDat.verifyProbe(badProbe), "corrupted probe must fail")

        // Old probe outside allowed time diff fails
        let oldProbe = VGDat.generateProbe(timestampMs: 1000)
        expect(!VGDat.verifyProbe(oldProbe), "expired probe must fail")
    }

    test("vgdat/shipped-file-decodes-and-verifies-rsa-signature") {
        let data = fixtureData("VPNGate.dat")
        expect(data.count > 0, "fixture VPNGate.dat must be present")
        let file = try VGDat.parse(data: data)
        expect(file.isSignatureValid, "RSA signature must be valid")
        expectEqual(file.servers.count, 200, "must parse exactly 200 servers")
        expect(file.soapURL.contains("vpngate.net"), "SOAP URL present")

        // Compare first server with known values from decompiled CSV
        let s0 = file.servers[0]
        expectEqual(s0.ip, "67.5.100.174")
        expectEqual(s0.fqdn, "vpn118756292.opengw.net")
        expectEqual(s0.countryShort, "US")
        expectEqual(s0.score, 4137650)
        expectEqual(s0.ping, 8)
        expectEqual(s0.speed, 393236421)
        expectEqual(s0.sessions, 137)
        expectEqual(s0.uptimeMs, 542874958)
        expectEqual(s0.sslPorts, [465, 995, 1195, 1897, 9008])
        expectEqual(s0.udpPort, 50226)
        expectEqual(s0.build, 9807)
        expectEqual(s0.connectPort, 995, "connectPort follows the Windows priority 443, 992, 995, 465, ... (995 beats 465)")

        // Compare all servers against decompiled/VPNGate_dat_hosts.csv if present
        let csvPath = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("decompiled/VPNGate_dat_hosts.csv").path
        if let csvString = try? String(contentsOfFile: csvPath, encoding: .utf8) {
            let lines = csvString.components(separatedBy: .newlines).filter { !$0.isEmpty }
            expectEqual(lines.count, 201, "CSV header + 200 rows")
            for i in 0..<min(file.servers.count, lines.count - 1) {
                let s = file.servers[i]
                let parts = lines[i + 1].components(separatedBy: ",")
                expectEqual(s.ip, parts[0], "row \(i) IP")
                expectEqual(s.fqdn, parts[1], "row \(i) Fqdn")
                expectEqual(s.countryShort, parts[3], "row \(i) CountryShort")
                expectEqual(s.score, Int(parts[4]) ?? 0, "row \(i) Score")
            }
        }
    }

    /// Re-encrypts the fixture after `mutate` edits the decrypted outer Pack, so the Pack stays parseable and only
    /// the signed content (or the signature) changes.
    func tamperedDat(_ mutate: (inout [UInt8], _ pack: Pack) -> Void) throws -> Data {
        var data = fixtureData("VPNGate.dat")
        let key = Array(Insecure.SHA1.hash(data: [UInt8](data[0xF0..<0x104])))
        var plain = RC4.cipher(key: key, data: [UInt8](data[0x104...]))
        let pack = try Pack(parsing: Data(plain))
        mutate(&plain, pack)
        data.replaceSubrange(0x104..., with: RC4.cipher(key: key, data: plain))
        return data
    }

    func flipFirstByte(of field: String, in plain: inout [UInt8], pack: Pack) {
        let needle = [UInt8](pack.data(field) ?? Data())
        guard !needle.isEmpty, let at = Data(plain).range(of: Data(needle))?.lowerBound else {
            expect(false, "field \(field) not found in outer pack"); return
        }
        plain[at] ^= 0x01
    }

    test("vgdat/tampering-with-signed-content-fails-the-signature-check") {
        for field in ["timestamp", "sign", "data"] {
            let data = try tamperedDat { plain, pack in flipFirstByte(of: field, in: &plain, pack: pack) }
            do {
                _ = try VGDat.parse(data: data)
                expect(false, "tampered \(field) must not verify")
            } catch let e as VGDatError {
                // Signed content must fail at the signature stage, not later in the inflate/Pack parse.
                expect(e == .signatureVerificationFailed, "tampered \(field): expected signatureVerificationFailed, got \(e)")
            }
        }
    }

    test("vgdat/corrupted-ciphertext-is-rejected") {
        var data = fixtureData("VPNGate.dat")
        data[0x200] ^= 0x55
        do { _ = try VGDat.parse(data: data); expect(false, "corrupted file must not parse") } catch {}
    }

    test("vgdat/decompress-is-strict") {
        let good = try VGDat.decompress(data: zlibFixture, expectedSize: zlibPlain.count)
        expectEqual(good, zlibPlain)
        // too large an expected size, too small, bad Adler-32, bad header, absurd size
        for (bytes, size) in [(zlibFixture, zlibPlain.count + 1), (zlibFixture, zlibPlain.count - 1),
                              (zlibFixture.dropLast() + [zlibFixture.last! ^ 1], zlibPlain.count),
                              ([0x00] + zlibFixture.dropFirst(), zlibPlain.count),
                              (zlibFixture, VGDat.maxInflatedSize + 1)] as [([UInt8], Int)] {
            do { _ = try VGDat.decompress(data: bytes, expectedSize: size); expect(false, "must reject") } catch {}
        }
    }

    test("vgdat/invalid-header-is-rejected") {
        var data = fixtureData("VPNGate.dat")
        data[0] = 0x58 // replace '[' with 'X'
        var failed = false
        do {
            _ = try VGDat.parse(data: data)
        } catch {
            failed = true
        }
        expect(failed, "invalid header must fail")
    }

    test("vgdat/fetcher-bootstrap-picks-the-newest-stored-list") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let fileTime = try VGDat.parse(data: fixtureData("VPNGate.dat")).timestamp
        let fetcher = VGDatFetcher(httpGet: { _, _, _, _ in throw StreamError.closed }, cacheURL: dir.appendingPathComponent("VPNGate.dat"),
                                   bundleURLs: [fixtureURL("VPNGate.dat")], now: { fileTime.addingTimeInterval(3600) })
        expect(fetcher.loadCached() == nil, "empty temp cache")
        let bundled = fetcher.loadBundleDat()
        expectEqual(bundled?.servers.count, 200)

        let result = await fetcher.sync(currentServers: [], proxy: ProxySettings())
        expectEqual(result.servers.count, 200)
        expect(result.source == .bundle)
        expect(result.isFresh, "an hour old is fresh")

        // Past 36 h the list is still used (it is signed) but is flagged stale.
        let stale = VGDatFetcher(httpGet: { _, _, _, _ in throw StreamError.closed }, cacheURL: dir.appendingPathComponent("VPNGate.dat"),
                                 bundleURLs: [fixtureURL("VPNGate.dat")], now: { fileTime.addingTimeInterval(40 * 3600) })
        let staleResult = await stale.sync(currentServers: [], proxy: ProxySettings())
        expectEqual(staleResult.servers.count, 200)
        expect(!staleResult.isFresh, "40 h old must be flagged stale")
    }

    /// A relay that serves `payload` after the 4-byte length, then the 1-byte reply.
    final class RelayStream: ByteStream {
        var buffer = ByteBuffer()
        var sentData = [Data]()
        var isCancelled = false
        private var served = false
        let payload: Data
        let hangAfterStart: Bool
        init(payload: Data, hangAfterStart: Bool = false) { self.payload = payload; self.hangAfterStart = hangAfterStart }

        func start() async throws {}
        func send(_ data: Data) async throws { sentData.append(data) }
        func readChunk() async throws -> Data {
            if hangAfterStart {
                while !isCancelled { try await Task.sleep(nanoseconds: 5_000_000) }
                throw StreamError.closed
            }
            guard !served else { return Data([1]) }
            served = true
            var resp = Data()
            var lenBe = UInt32(payload.count).bigEndian
            withUnsafeBytes(of: &lenBe) { resp.append(contentsOf: $0) }
            resp.append(payload)
            return resp
        }
        func cancel() { isCancelled = true }
    }

    test("vgdat/fetcher-relay-download-with-ack-handshake") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let cache = dir.appendingPathComponent("VPNGate.dat")
        let rawPayload = fixtureData("VPNGate.dat")
        let fileTime = try VGDat.parse(data: rawPayload).timestamp
        let stream = RelayStream(payload: rawPayload)
        let fetcher = VGDatFetcher(makeStream: { _, _, _ in stream }, cacheURL: cache,
                                   bundleURLs: [], now: { fileTime.addingTimeInterval(60) })

        let dat = try await fetcher.downloadFromHost(host: "1.2.3.4", port: 443, proxy: ProxySettings())
        expectEqual(dat.servers.count, 200)
        expect(dat.isSignatureValid)
        expect(stream.isCancelled, "socket must be closed afterwards")
        expectEqual((try? Data(contentsOf: cache)) ?? Data(), rawPayload, "verified list is cached (in the temp dir)")

        // Verify client sent: 1) GET request + 16-byte probe, 2) 17-byte ack, 3) 512-byte junk
        expectEqual(stream.sentData.count, 3)
        let req = stream.sentData[0]
        let reqHead = "GET /vgc_download_dat/ HTTP/1.1\r\nHOST: vpngate\r\n\r\n"
        expectEqual(String(decoding: req.prefix(reqHead.utf8.count), as: UTF8.self), reqHead)
        expectEqual(req.count, reqHead.utf8.count + 16, "request header + 16 bytes probe")
        expect(VGDat.verifyProbe([UInt8](req.suffix(16)), now: fileTime.addingTimeInterval(60)), "probe must be a valid timestamp+hash")
        expectEqual(stream.sentData[1].count, 17, "ack size must be 17")
        expectEqual(stream.sentData[1][0], 1, "ack byte 0 must be 1")
        expectEqual(stream.sentData[2].count, 512, "junk size must be 512")
    }

    test("vgdat/fetcher-rejects-a-stale-list-from-a-relay") {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let cache = dir.appendingPathComponent("VPNGate.dat")
        let rawPayload = fixtureData("VPNGate.dat")
        let fileTime = try VGDat.parse(data: rawPayload).timestamp
        let stream = RelayStream(payload: rawPayload)
        let fetcher = VGDatFetcher(makeStream: { _, _, _ in stream }, cacheURL: cache,
                                   bundleURLs: [], now: { fileTime.addingTimeInterval(40 * 3600) })
        do { _ = try await fetcher.downloadFromHost(host: "1.2.3.4", port: 443, proxy: ProxySettings()); expect(false, "stale must throw") } catch {}
        expect(!FileManager.default.fileExists(atPath: cache.path), "a stale list must not be cached")
        expect(stream.isCancelled)
    }

    test("vgdat/fetcher-gives-up-on-a-relay-that-stops-answering") {
        let stream = RelayStream(payload: Data(), hangAfterStart: true)
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let fetcher = VGDatFetcher(makeStream: { _, _, _ in stream }, cacheURL: dir.appendingPathComponent("x.dat"),
                                   bundleURLs: [], timeoutScale: 0.005)   // 60 s -> 0.3 s
        let started = Date()
        do { _ = try await fetcher.downloadFromHost(host: "1.2.3.4", port: 443, proxy: ProxySettings()); expect(false, "must time out") }
        catch let e as StreamError { expect(String(describing: e).contains("timeout"), "expected timeout, got \(e)") }
        expect(Date().timeIntervalSince(started) < 5, "must not hang")
        expect(stream.isCancelled, "socket released after timeout")
    }
}
