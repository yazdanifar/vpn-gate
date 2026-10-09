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

/// `--watch-udp [N]` → how many seconds `--probe` should keep the session open afterwards, polling whether UDP
/// acceleration became usable (it needs ~10 s of stable receive before data may use it). Absent → nil (no watch,
/// today's behaviour). Present with no number, or a non-numeric one → the default, 20 s.
func parseWatchUdpSeconds(_ args: [String]) -> Int? {
    guard let i = args.firstIndex(of: "--watch-udp") else { return nil }
    guard i + 1 < args.count, let n = Int(args[i + 1]), n > 0 else { return 20 }
    return min(n, 300)
}

/// uid of the user logged in at the Mac's console (owner of /dev/console), nil when nobody is.
func currentConsoleUID() -> uid_t? {
    var st = stat()
    guard stat("/dev/console", &st) == 0, st.st_uid != 0 else { return nil }
    return st.st_uid
}
