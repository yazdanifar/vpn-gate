//! The app's preferences: a JSON file under the XDG config directory. The proxy password does not belong here: it lives in the
//! secret service (`PROXY_PASSWORD_KEY`).

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vpngate_core::ipc::{ProxyKind, TunnelMode, DEFAULT_SOCKS_PORT};
use vpngate_core::routing_rule::RoutingConfig;

pub const PROXY_PASSWORD_KEY: &str = "proxy-password";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub has_agreed_to_disclaimer: bool,
    pub auto_reconnect: bool,
    #[serde(rename = "blockIPv6")]
    pub block_ipv6: bool,
    /// Alternative CSV list URL for the daemon's sync.
    pub mirror_url: String,
    pub favorites: BTreeSet<String>,
    pub proxy_kind: ProxyKind,
    pub proxy_host: String,
    pub proxy_port: i64,
    pub proxy_username: String,
    pub tunnel_mode: TunnelMode,
    pub socks_port: i64,
    /// The global routing rules; accounts with their own rules ignore them.
    pub routing: RoutingConfig,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            has_agreed_to_disclaimer: false,
            auto_reconnect: true,
            block_ipv6: false,
            mirror_url: String::new(),
            favorites: BTreeSet::new(),
            proxy_kind: ProxyKind::None,
            proxy_host: String::new(),
            proxy_port: 0,
            proxy_username: String::new(),
            tunnel_mode: TunnelMode::FullTunnel,
            socks_port: DEFAULT_SOCKS_PORT,
            routing: RoutingConfig::default(),
        }
    }
}

/// `$XDG_CONFIG_HOME`, else `~/.config`.
pub fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Where the app keeps settings, accounts and the history.
pub fn config_dir() -> PathBuf {
    config_home().join("vpngate")
}

pub trait SettingsStore: Send + Sync {
    fn load(&self) -> Settings;
    fn save(&self, settings: &Settings) -> io::Result<()>;
}

/// `settings.json` in [`config_dir`].
pub struct FileSettings {
    path: PathBuf,
}

impl FileSettings {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileSettings { path: path.into() }
    }

    pub fn default_path() -> PathBuf {
        config_dir().join("settings.json")
    }
}

impl SettingsStore for FileSettings {
    /// A missing or unreadable file gives the defaults.
    fn load(&self) -> Settings {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, settings: &Settings) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(settings).map_err(io::Error::other)?)?;
        std::fs::rename(tmp, &self.path)
    }
}

/// For tests: keeps the last saved value.
#[derive(Default)]
pub struct MemorySettings {
    value: std::sync::Mutex<Settings>,
}

impl MemorySettings {
    pub fn with(settings: Settings) -> Self {
        MemorySettings { value: std::sync::Mutex::new(settings) }
    }
}

impl SettingsStore for MemorySettings {
    fn load(&self) -> Settings {
        self.value.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn save(&self, settings: &Settings) -> io::Result<()> {
        *self.value.lock().unwrap_or_else(|e| e.into_inner()) = settings.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_round_trip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("vg-settings-{}", std::process::id()));
        let store = FileSettings::new(dir.join("a/settings.json"));
        assert_eq!(store.load(), Settings::default(), "missing file");
        let s = Settings {
            has_agreed_to_disclaimer: true,
            favorites: ["1.2.3.4".to_string()].into(),
            ..Settings::default()
        };
        store.save(&s).unwrap();
        assert_eq!(store.load(), s);
        std::fs::write(dir.join("a/settings.json"), b"{\"autoReconnect\":false}").unwrap();
        let partial = store.load();
        assert!(!partial.auto_reconnect && !partial.has_agreed_to_disclaimer, "missing keys take their defaults");
        std::fs::write(dir.join("a/settings.json"), b"not json").unwrap();
        assert_eq!(store.load(), Settings::default());
        let mut s =
            Settings { proxy_kind: ProxyKind::Socks5, tunnel_mode: TunnelMode::SocksProxy, ..Settings::default() };
        s.routing.bypass_private_networks = true;
        store.save(&s).unwrap();
        assert_eq!(store.load(), s);
        let _ = std::fs::remove_dir_all(dir);
    }
}
