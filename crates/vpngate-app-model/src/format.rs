//! Text of the UI, following UI-SPEC.md section 0 (`Formatting.cs` on Windows).

use vpngate_core::ipc::ConnectionState;

pub fn title(s: ConnectionState) -> &'static str {
    match s {
        ConnectionState::Disconnected => "Disconnected",
        ConnectionState::Connecting => "Connecting…",
        ConnectionState::Authenticating => "Authenticating…",
        ConnectionState::Dhcp => "Getting address…",
        ConnectionState::Connected => "Connected",
        ConnectionState::Reconnecting => "Reconnecting…",
    }
}

/// Freedesktop icon names: locked shield, open lock, or spinning arrows.
pub fn icon_name(s: ConnectionState) -> &'static str {
    match s {
        ConnectionState::Connected => "channel-secure-symbolic",
        ConnectionState::Disconnected => "channel-insecure-symbolic",
        _ => "emblem-synchronizing-symbolic",
    }
}

pub fn speed(bits_per_second: i64) -> String {
    format!("{:.1} Mbps", bits_per_second as f64 / 1_000_000.0)
}

/// Binary units like ByteCountFormatter: "0 bytes", "12 bytes", "1.5 KB", "3.2 MB".
pub fn bytes(n: u64) -> String {
    if n < 1024 {
        return if n == 1 { "1 byte".into() } else { format!("{n} bytes") };
    }
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut i = 0;
    loop {
        v /= 1024.0;
        if v < 1024.0 || i == UNITS.len() - 1 {
            break;
        }
        i += 1;
    }
    if v < 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.0} {}", UNITS[i])
    }
}

pub fn rate(bytes_per_second: f64) -> String {
    format!("{}/s", bytes(bytes_per_second.max(0.0) as u64))
}

/// "H:MM:SS".
pub fn duration(seconds: u64) -> String {
    format!("{}:{:02}:{:02}", seconds / 3600, seconds % 3600 / 60, seconds % 60)
}

/// "↓ in  ↑ out"; with the seconds since connecting it is prefixed by the duration.
pub fn traffic(bytes_in: u64, bytes_out: u64, since_seconds: Option<u64>) -> String {
    let t = format!("↓ {}  ↑ {}", bytes(bytes_in), bytes(bytes_out));
    match since_seconds {
        Some(s) => format!("{}  {t}", duration(s)),
        None => t,
    }
}

fn unit(n: i64, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

pub fn uptime(ms: i64) -> String {
    let ms = ms.max(0);
    if ms < 3_600_001 {
        unit(ms / 60_000, "min")
    } else if ms < 86_400_001 {
        unit(ms / 3_600_000, "hour")
    } else {
        unit(ms / 86_400_000, "day")
    }
}

pub fn sessions(n: i64) -> String {
    unit(n, "session")
}

pub fn logging(log_type: &str) -> String {
    let t = log_type.to_lowercase();
    if t.starts_with("no") {
        "No Logs".into()
    } else if t.contains('2') && t.contains("week") {
        "2 Weeks".into()
    } else if t.starts_with("perm") {
        "Permanent".into()
    } else if log_type.is_empty() {
        "-".into()
    } else {
        log_type.into()
    }
}

pub fn pings(google: i64, japan: i64) -> String {
    let one = |v: i64| if v == 0 { "-".to_string() } else { format!("{v} ms") };
    format!("{}, {}", one(google), one(japan))
}

/// The list is OK within 24 h of its timestamp, older it is "stale".
pub fn list_is_ok(timestamp_ms: u64, now_ms: u64) -> bool {
    timestamp_ms.abs_diff(now_ms) < 86_400_001
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_use_binary_units() {
        assert_eq!(bytes(0), "0 bytes");
        assert_eq!(bytes(1), "1 byte");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(3 * 1024 * 1024 + 200_000), "3.2 MB");
        assert_eq!(bytes(20 * 1024 * 1024), "20 MB");
        assert_eq!(rate(-5.0), "0 bytes/s");
    }

    #[test]
    fn durations_and_traffic() {
        assert_eq!(duration(3725), "1:02:05");
        assert_eq!(traffic(1024, 0, None), "↓ 1.0 KB  ↑ 0 bytes");
        assert_eq!(traffic(0, 0, Some(61)), "0:01:01  ↓ 0 bytes  ↑ 0 bytes");
    }

    #[test]
    fn list_cells() {
        assert_eq!(speed(94_500_000), "94.5 Mbps");
        assert_eq!(uptime(60_000), "1 min");
        assert_eq!(uptime(7_200_000), "2 hours");
        assert_eq!(uptime(86_400_001 * 3), "3 days");
        assert_eq!(sessions(1), "1 session");
        assert_eq!(logging("No logs"), "No Logs");
        assert_eq!(logging("2weeks"), "2 Weeks");
        assert_eq!(logging(""), "-");
        assert_eq!(pings(0, 12), "-, 12 ms");
        assert!(list_is_ok(1_000, 1_000 + 86_400_000));
        assert!(!list_is_ok(1_000, 1_000 + 86_400_001));
    }

    #[test]
    fn titles_and_icons() {
        assert_eq!(title(ConnectionState::Dhcp), "Getting address…");
        assert_eq!(icon_name(ConnectionState::Connected), "channel-secure-symbolic");
        assert_eq!(icon_name(ConnectionState::Reconnecting), "emblem-synchronizing-symbolic");
    }
}
