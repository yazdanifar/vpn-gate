import Foundation
import VPNGateCore

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
        let file = try VGDat.parse(data: data, verifySignature: true)
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
        expectEqual(s0.connectPort, 465, "connectPort must pick first sslPort")

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

    test("vgdat/corrupted-signature-is-rejected") {
        var data = fixtureData("VPNGate.dat")
        // Tamper with a byte in the encrypted body
        data[0x200] ^= 0x55
        var failed = false
        do {
            _ = try VGDat.parse(data: data, verifySignature: true)
        } catch {
            failed = true
        }
        expect(failed, "tampered VPNGate.dat must fail parsing or signature check")
    }

    test("vgdat/invalid-header-is-rejected") {
        var data = fixtureData("VPNGate.dat")
        data[0] = 0x58 // replace '[' with 'X'
        var failed = false
        do {
            _ = try VGDat.parse(data: data, verifySignature: true)
        } catch {
            failed = true
        }
        expect(failed, "invalid header must fail")
    }

    test("vgdat/fetcher-bootstrap-and-fallback") {
        let fetcher = VGDatFetcher()
        let bundled = VGDatFetcher.loadBundleDat()
        expect(bundled != nil, "bundled VPNGate.dat should be found")
        expectEqual(bundled?.servers.count, 200)

        // Sync with no live candidate servers falls back to bundle or cache
        let result = await fetcher.sync(currentServers: [], proxy: ProxySettings())
        expect(result.servers.count >= 200, "fallback must yield servers")
        expect(result.source == .bundle || result.source == .cache)
    }

    test("vgdat/fetcher-relay-download-with-ack-handshake") {
        // Scripted stream delivering real VPNGate.dat payload
        final class RelayStream: ByteStream {
            var buffer = ByteBuffer()
            var sentData = [Data]()
            var isCancelled = false
            let payload: Data

            init(payload: Data) { self.payload = payload }

            func start() async throws {}
            func send(_ data: Data) async throws { sentData.append(data) }
            func readChunk() async throws -> Data {
                if buffer.count == 0 {
                    // Send 4-byte BE length followed by payload
                    var resp = Data()
                    var lenBe = UInt32(payload.count).bigEndian
                    withUnsafeBytes(of: &lenBe) { resp.append(contentsOf: $0) }
                    resp.append(payload)
                    // Plus 1-byte ack reply
                    resp.append(1)
                    return resp
                }
                return Data()
            }
            func cancel() { isCancelled = true }
        }

        let rawPayload = fixtureData("VPNGate.dat")
        let stream = RelayStream(payload: rawPayload)
        let fetcher = VGDatFetcher(makeStream: { _, _, _ in stream })

        let dat = try await fetcher.downloadFromHost(host: "1.2.3.4", port: 443, proxy: ProxySettings())
        expectEqual(dat.servers.count, 200)
        expect(dat.isSignatureValid)

        // Verify client sent: 1) GET request + 16-byte probe, 2) 17-byte ack, 3) 512-byte junk
        expect(stream.sentData.count >= 3, "expected at least 3 send calls, got \(stream.sentData.count)")
        let req = stream.sentData[0]
        let reqStr = String(decoding: req, as: UTF8.self)
        expect(reqStr.contains("GET /vgc_download_dat/"), "request path")
        expect(req.count >= 40 + 16, "request header + 16 bytes probe")

        let ack = stream.sentData[1]
        expectEqual(ack.count, 17, "ack size must be 17")
        expectEqual(ack[0], 1, "ack byte 0 must be 1")

        let junk = stream.sentData[2]
        expectEqual(junk.count, 512, "junk size must be 512")
    }
}
