import Darwin
import Foundation

private let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

/// Runs a package script with stub launchctl/chown/chmod/sleep on PATH; returns the exit status and the calls made.
private func runPackageScript(
    _ name: String, failBootstrapTimes: Int = 0, alwaysFailBootstrap: Bool = false,
    jobAlreadyLoaded: Bool = false
) throws -> (status: Int32, log: [String]) {
    let dir = tempPath("pkgstubs-\(UUID().uuidString.prefix(6))")
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let log = dir + "/log", counter = dir + "/count", loaded = dir + "/loaded"
    if jobAlreadyLoaded { FileManager.default.createFile(atPath: loaded, contents: Data()) }
    for tool in ["launchctl", "chown", "chmod", "sleep"] {
        var body = "#!/bin/sh\necho \"\(tool) $*\" >> '\(log)'\n"
        if tool == "launchctl" {
            body += "if [ \"$1\" = bootout ]; then [ -e '\(loaded)' ] && { rm '\(loaded)'; exit 0; }; exit 3; fi\n"
            body += "if [ \"$1\" = bootstrap ]; then\n"
            body += "  [ -e '\(loaded)' ] && exit 5\n"  // a job that is still loaded cannot be bootstrapped again
            body += "  n=$(cat '\(counter)' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '\(counter)'\n"
            if alwaysFailBootstrap { body += "  exit 5\n" } else { body += "  [ $n -le \(failBootstrapTimes) ] && exit 5\n" }
            body += "fi\nexit 0\n"
        }
        let p = dir + "/" + tool
        try body.write(toFile: p, atomically: true, encoding: .utf8); chmod(p, 0o755)
    }
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh")
    p.arguments = [repoRoot.appendingPathComponent("packaging/scripts/\(name)").path]
    p.environment = ["PATH": dir + ":/usr/bin:/bin"]
    p.standardOutput = Pipe(); p.standardError = Pipe()
    try p.run(); p.waitUntilExit()
    let lines = ((try? String(contentsOfFile: log, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
    return (p.terminationStatus, lines)
}

func registerPackagingTests() {
    test("pkg/preinstall-stops-the-old-helper-and-never-fails") {
        let r = try runPackageScript("preinstall")
        expectEqual(r.status, 0, "an old helper that is not loaded (bootout fails) must not abort the installation")
        expect(r.log.contains("launchctl bootout system/com.yazdanifar.vpngate.helper"), "\(r.log)")
    }
    test("pkg/postinstall-starts-the-daemon") {
        let r = try runPackageScript("postinstall")
        expectEqual(r.status, 0, "\(r.log)")
        expect(r.log.contains("launchctl bootstrap system /Library/LaunchDaemons/com.yazdanifar.vpngate.helper.plist"), "\(r.log)")
        expect(
            r.log.contains("chown root:wheel /Library/PrivilegedHelperTools/vpngate-helper /Library/LaunchDaemons/com.yazdanifar.vpngate.helper.plist"),
            "\(r.log)")
        expect(r.log.contains("chmod 755 /Library/PrivilegedHelperTools/vpngate-helper"), "\(r.log)")
    }
    test("pkg/postinstall-retries-bootstrap-after-the-bootout-race") {
        let r = try runPackageScript("postinstall", failBootstrapTimes: 2)
        expectEqual(r.status, 0, "\(r.log)")
        expectEqual(r.log.filter { $0.hasPrefix("launchctl bootstrap") }.count, 3)
    }
    test("pkg/postinstall-fails-the-install-when-the-daemon-cannot-start") {
        let r = try runPackageScript("postinstall", alwaysFailBootstrap: true)
        expect(r.status != 0, "the installer must report failure instead of leaving a dead helper")
        expectEqual(r.log.filter { $0.hasPrefix("launchctl bootstrap") }.count, 5)
    }
    test("pkg/postinstall-replaces-a-job-that-is-already-loaded") {
        let r = try runPackageScript("postinstall", jobAlreadyLoaded: true)
        expectEqual(r.status, 0, "reinstalling over a running helper must not fail the whole install: \(r.log)")
        expect(r.log.contains("launchctl bootout system/com.yazdanifar.vpngate.helper"), "\(r.log)")
    }
    test("pkg/version-comes-from-the-VERSION-file-not-the-ipc-version") {
        let script = try String(contentsOf: repoRoot.appendingPathComponent("scripts/build-pkg.sh"), encoding: .utf8)
        let line = script.split(separator: "\n").first { $0.hasPrefix("VERSION=") }.map(String.init) ?? ""
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", line + "; printf %s \"$VERSION\""]
        p.currentDirectoryURL = repoRoot
        let out = Pipe(); p.standardOutput = out
        try p.run(); p.waitUntilExit()
        let version = try String(contentsOf: repoRoot.appendingPathComponent("VERSION"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        expectEqual(String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self), version)
        expect(!script.contains("--version \"$HELPER"), "package versions must not be the helper IPC version")
    }
    test("pkg/daemon-plist-matches-what-the-app-expects") {
        let d = try Data(contentsOf: repoRoot.appendingPathComponent("packaging/com.yazdanifar.vpngate.helper.plist"))
        let plist = try PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any]
        expectEqual(plist?["Label"] as? String, HelperInstaller.label)
        expectEqual(plist?["ProgramArguments"] as? [String], [HelperInstaller.installedPath, "--daemon", "--bundle", HelperInstaller.bundledDatPath])
        expectEqual(plist?["KeepAlive"] as? Bool, true)
        expectEqual(HelperInstaller.plistPath, "/Library/LaunchDaemons/com.yazdanifar.vpngate.helper.plist")
    }
    test("installer/shell-quoting-for-uninstall") {
        expectEqual(HelperInstaller.shellQuote("a b"), "'a b'")
        let hostile = HelperInstaller.shellQuote("x'; touch /tmp/pwned; echo '")
        // run it through sh: the whole thing must come back as one literal argument
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", "printf %s " + hostile]
        let out = Pipe(); p.standardOutput = out
        try p.run(); p.waitUntilExit()
        expectEqual(String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self), "x'; touch /tmp/pwned; echo '")
    }
}
