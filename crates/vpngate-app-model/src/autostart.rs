//! "Launch at login" on Linux: an XDG autostart entry, `$XDG_CONFIG_HOME/autostart/vpngate.desktop`.

use std::io;
use std::path::{Path, PathBuf};

pub fn entry_path() -> PathBuf {
    crate::settings::config_home().join("autostart").join("vpngate.desktop")
}

pub fn is_enabled(path: &Path) -> bool {
    path.exists()
}

/// `exec` is the command line the desktop runs at login.
pub fn set_enabled(path: &Path, enabled: bool, exec: &str) -> io::Result<()> {
    if !enabled {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(
        path,
        format!(
            "[Desktop Entry]\nType=Application\nName=VPN Gate\nComment=VPN Gate Public VPN Relay Servers\nExec={exec}\nIcon=net.vpngate.App\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_and_disable() {
        let p = std::env::temp_dir().join(format!("vg-auto-{}/autostart/vpngate.desktop", std::process::id()));
        assert!(!is_enabled(&p));
        set_enabled(&p, true, "/usr/bin/vpngate-gtk").unwrap();
        assert!(is_enabled(&p));
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("Exec=/usr/bin/vpngate-gtk") && text.starts_with("[Desktop Entry]"));
        set_enabled(&p, false, "").unwrap();
        assert!(!is_enabled(&p));
        set_enabled(&p, false, "").unwrap();
        let _ = std::fs::remove_dir_all(p.parent().unwrap().parent().unwrap());
    }
}
