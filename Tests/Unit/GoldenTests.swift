import Foundation
import VPNGateCore

private let fixturesDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("Fixtures", isDirectory: true)

func registerGoldenTests() {
    // The committed vectors are what the other languages are tested against: they must match the Swift code.
    test("golden/committed-vectors-are-current") {
        let files = try goldenFiles(fixturesDir: fixturesDir)
        expect(files.count >= 14, "exporter produced \(files.count) files")
        for f in files {
            let url = fixturesDir.appendingPathComponent("golden/" + f.name)
            guard let committed = try? Data(contentsOf: url) else { fail("\(f.name) is missing: run scripts/gen-golden.sh"); continue }
            expect(committed == f.data, "\(f.name) is stale: run scripts/gen-golden.sh and commit the result")
        }
    }
    test("golden/no-stray-files") {
        let expected = Set(try goldenFiles(fixturesDir: fixturesDir).map(\.name))
        let onDisk = (try? FileManager.default.contentsOfDirectory(atPath: fixturesDir.appendingPathComponent("golden").path)) ?? []
        for n in onDisk where n.hasSuffix(".json") && !expected.contains(n) { fail("\(n) is not produced by the exporter any more") }
    }
}
