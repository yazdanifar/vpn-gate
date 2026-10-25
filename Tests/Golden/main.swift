import Foundation

// Usage: gen-golden <fixtures-dir> <output-dir>
let args = CommandLine.arguments
guard args.count == 3 else { FileHandle.standardError.write(Data("usage: gen-golden <fixtures-dir> <output-dir>\n".utf8)); exit(2) }
do {
    let out = URL(fileURLWithPath: args[2], isDirectory: true)
    try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
    for f in try goldenFiles(fixturesDir: URL(fileURLWithPath: args[1], isDirectory: true)) {
        try f.data.write(to: out.appendingPathComponent(f.name))
        print("wrote \(f.name) (\(f.data.count) bytes)")
    }
    for f in try await transcriptFiles() {
        let url = out.appendingPathComponent(f.name)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try f.data.write(to: url)
        print("wrote \(f.name) (\(f.data.count) bytes)")
    }
} catch {
    FileHandle.standardError.write(Data("gen-golden failed: \(error)\n".utf8)); exit(1)
}
