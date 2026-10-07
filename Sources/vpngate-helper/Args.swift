import Foundation
import VPNGateCore

/// `--probe <host> [--port N]` → (host, port), nil when --probe is absent.
func parseProbeArgs(_ args: [String]) -> (String, Int)? {
    guard let i = args.firstIndex(of: "--probe"), i + 1 < args.count else { return nil }
    var port = 443
    if let pi = args.firstIndex(of: "--port"), pi + 1 < args.count, let p = Int(args[pi + 1]) {
        guard InputValidation.isValidPort(p) else { return nil }
        port = p
    }
    return (args[i + 1], port)
}

/// uid of the user logged in at the Mac's console (owner of /dev/console), nil when nobody is.
func currentConsoleUID() -> uid_t? {
    var st = stat()
    guard stat("/dev/console", &st) == 0, st.st_uid != 0 else { return nil }
    return st.st_uid
}
