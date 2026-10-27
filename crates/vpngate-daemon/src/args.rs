//! Command line (`Args.swift` + the option parsing in `main.swift`).

use vpngate_core::validation;

pub const DEFAULT_PROBE_PORT: i64 = 443;
pub const DEFAULT_WATCH_UDP_SECONDS: u64 = 20;
const MAX_WATCH_UDP_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Version,
    /// Handshake and DHCP only: no tun, no routes, no root.
    Probe {
        host: String,
        port: i64,
        watch_udp: Option<u64>,
    },
    /// Connect once in the foreground (debugging; needs root).
    Connect {
        host: String,
        port: Option<i64>,
        allow_ipv6: bool,
    },
    Daemon {
        uid: Option<u32>,
    },
    Usage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    /// `--socket`; the platform default when absent.
    pub socket: Option<String>,
}

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).map(String::as_str)
}

/// `--watch-udp [N]`: how long `--probe` keeps the session open afterwards. Absent: no watch. Present without a usable
/// number: the default.
pub fn parse_watch_udp_seconds(args: &[String]) -> Option<u64> {
    let i = args.iter().position(|a| a == "--watch-udp")?;
    match args.get(i + 1).and_then(|n| n.parse::<u64>().ok()) {
        Some(n) if n > 0 => Some(n.min(MAX_WATCH_UDP_SECONDS)),
        _ => Some(DEFAULT_WATCH_UDP_SECONDS),
    }
}

/// `--probe <host> [--port N]`; `None` when `--probe` is absent or the port is out of range.
pub fn parse_probe_args(args: &[String]) -> Option<(String, i64)> {
    let host = opt(args, "--probe")?.to_string();
    let mut port = DEFAULT_PROBE_PORT;
    if let Some(p) = opt(args, "--port").and_then(|p| p.parse::<i64>().ok()) {
        if !validation::is_valid_port(Some(p)) {
            return None;
        }
        port = p;
    }
    Some((host, port))
}

/// `args` excludes the program name.
pub fn parse(args: &[String]) -> Args {
    let socket = opt(args, "--socket").map(str::to_string);
    let has = |f: &str| args.iter().any(|a| a == f);
    let mode = if has("--version") {
        Mode::Version
    } else if has("--probe") {
        match parse_probe_args(args) {
            Some((host, port)) => Mode::Probe { host, port, watch_udp: parse_watch_udp_seconds(args) },
            None => Mode::Usage,
        }
    } else if let Some(host) = opt(args, "--connect") {
        Mode::Connect {
            host: host.to_string(),
            port: opt(args, "--port").and_then(|p| p.parse().ok()),
            allow_ipv6: has("--allow-ipv6"),
        }
    } else if has("--daemon") {
        Mode::Daemon { uid: opt(args, "--uid").and_then(|u| u.parse().ok()) }
    } else {
        Mode::Usage
    };
    Args { mode, socket }
}

pub const USAGE: &str = "usage: vpngate-daemon --daemon [--uid <uid>] [--socket <path>] | --connect <host> [--port N] \
[--allow-ipv6] | --probe <host> [--port N] [--watch-udp [N]] | --version";

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn probe_args() {
        assert_eq!(parse_probe_args(&v(&["--probe", "h"])), Some(("h".into(), 443)));
        assert_eq!(parse_probe_args(&v(&["--probe", "h", "--port", "992"])), Some(("h".into(), 992)));
        assert_eq!(parse_probe_args(&v(&["--probe", "h", "--port", "0"])), None);
        assert_eq!(parse_probe_args(&v(&["--probe", "h", "--port", "70000"])), None);
        assert_eq!(parse_probe_args(&v(&["--probe"])), None);
        assert_eq!(parse_probe_args(&v(&["--port", "1"])), None);
    }

    #[test]
    fn watch_udp_seconds() {
        assert_eq!(parse_watch_udp_seconds(&v(&["--probe", "h"])), None);
        assert_eq!(parse_watch_udp_seconds(&v(&["--watch-udp"])), Some(20));
        assert_eq!(parse_watch_udp_seconds(&v(&["--watch-udp", "abc"])), Some(20));
        assert_eq!(parse_watch_udp_seconds(&v(&["--watch-udp", "0"])), Some(20));
        assert_eq!(parse_watch_udp_seconds(&v(&["--watch-udp", "45"])), Some(45));
        assert_eq!(parse_watch_udp_seconds(&v(&["--watch-udp", "9999"])), Some(300));
    }

    #[test]
    fn modes() {
        assert_eq!(parse(&v(&["--version"])).mode, Mode::Version);
        assert_eq!(parse(&v(&[])).mode, Mode::Usage);
        assert_eq!(parse(&v(&["--daemon"])).mode, Mode::Daemon { uid: None });
        let a = parse(&v(&["--daemon", "--uid", "501", "--socket", "/tmp/s"]));
        assert_eq!(a.mode, Mode::Daemon { uid: Some(501) });
        assert_eq!(a.socket.as_deref(), Some("/tmp/s"));
        assert_eq!(
            parse(&v(&["--connect", "h", "--port", "992", "--allow-ipv6"])).mode,
            Mode::Connect { host: "h".into(), port: Some(992), allow_ipv6: true }
        );
        assert_eq!(
            parse(&v(&["--probe", "h", "--watch-udp", "5"])).mode,
            Mode::Probe { host: "h".into(), port: 443, watch_udp: Some(5) }
        );
        assert_eq!(parse(&v(&["--probe", "h", "--port", "0"])).mode, Mode::Usage);
    }
}
