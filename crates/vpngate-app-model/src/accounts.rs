//! `accounts.json` plus the secrets in a [`SecretStore`] (mirrors `AccountManager.swift` / `Accounts.cs`), and the form
//! state of the account editor (UI-SPEC 6), which has no toolkit types so it can be tested.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;
use vpngate_core::client_account::{now_reference_seconds, AccountAuthType, ClientAccount};
use vpngate_core::routing_rule::RoutingConfig;
use vpngate_core::validation;

use crate::secrets::SecretStore;

pub struct AccountStore {
    path: PathBuf,
    secrets: Arc<dyn SecretStore>,
    pub accounts: Vec<ClientAccount>,
    /// Set when the file could not be read completely (the original is kept next to it).
    pub load_notice: Option<String>,
}

fn key(a: &ClientAccount, suffix: &str) -> String {
    format!("account-{}-{suffix}", a.id)
}

impl AccountStore {
    pub fn new(path: impl Into<PathBuf>, secrets: Arc<dyn SecretStore>) -> Self {
        let mut s = AccountStore { path: path.into(), secrets, accounts: Vec::new(), load_notice: None };
        s.load();
        s
    }

    pub fn default_path() -> PathBuf {
        crate::settings::config_dir().join("accounts.json")
    }

    pub fn load(&mut self) {
        self.load_notice = None;
        self.accounts.clear();
        let Ok(bytes) = std::fs::read(&self.path) else { return };
        let Ok(records) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) else {
            let kept = self.set_aside(true);
            self.load_notice = Some(format!(
                "The saved connection settings could not be read{}",
                kept.map_or(".".into(), |k| format!(" (kept as {k})."))
            ));
            return;
        };
        let total = records.len();
        self.accounts = records.into_iter().filter_map(|r| serde_json::from_value(r).ok()).collect();
        if self.accounts.len() < total {
            let kept = self.set_aside(false);
            self.load_notice = Some(format!(
                "{} saved connection setting(s) could not be read and were skipped{}",
                total - self.accounts.len(),
                kept.map_or(".".into(), |k| format!(" (original kept as {k})."))
            ));
        }
    }

    fn set_aside(&self, rename: bool) -> Option<String> {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let name = format!("{}.corrupt-{secs}", self.path.file_name()?.to_string_lossy());
        let dest = self.path.with_file_name(&name);
        let _ = std::fs::remove_file(&dest);
        let ok =
            if rename { std::fs::rename(&self.path, &dest).is_ok() } else { std::fs::copy(&self.path, &dest).is_ok() };
        ok.then_some(name)
    }

    /// `false` when the file could not be written.
    pub fn save(&self) -> bool {
        let write = || -> std::io::Result<()> {
            if let Some(dir) = self.path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let tmp = self.path.with_extension("json.tmp");
            // `ClientAccount` never serializes the proxy password.
            std::fs::write(&tmp, serde_json::to_vec_pretty(&self.accounts).map_err(std::io::Error::other)?)?;
            std::fs::rename(tmp, &self.path)
        };
        write().is_ok()
    }

    pub fn password(&self, a: &ClientAccount) -> Option<String> {
        self.secrets.get(&key(a, "pw"))
    }

    pub fn certificate(&self, a: &ClientAccount) -> Option<Vec<u8>> {
        self.secrets.get_bytes(&key(a, "cert"))
    }

    /// PKCS#1 RSA private key (DER).
    pub fn private_key(&self, a: &ClientAccount) -> Option<Vec<u8>> {
        self.secrets.get_bytes(&key(a, "key"))
    }

    pub fn proxy_password(&self, a: &ClientAccount) -> Option<String> {
        self.secrets.get(&key(a, "proxypw"))
    }

    pub fn has_identity(&self, a: &ClientAccount) -> bool {
        self.certificate(a).is_some() && self.private_key(a).is_some()
    }

    /// Stores what was given (`None` keeps the stored value) and removes secrets that no longer apply. `false` when the
    /// secret service refused a value.
    fn save_secrets(&self, a: &mut ClientAccount, secrets: &Secrets) -> bool {
        let mut ok = true;
        let mut put = |k: String, v: &str| ok &= self.secrets.set(&k, v);
        if let Some(p) = secrets.password.as_deref().filter(|p| !p.is_empty()) {
            put(key(a, "pw"), p);
        }
        if let Some(c) = secrets.cert_der.as_deref().filter(|c| !c.is_empty()) {
            put(key(a, "cert"), &base64_of(c));
        }
        if let Some(k) = secrets.key_der.as_deref().filter(|c| !c.is_empty()) {
            put(key(a, "key"), &base64_of(k));
        }
        if let Some(p) = a.proxy.password.take().filter(|p| !p.is_empty()) {
            put(key(a, "proxypw"), &p);
        }
        if a.auth_type != AccountAuthType::Certificate {
            self.secrets.delete(&key(a, "cert"));
            self.secrets.delete(&key(a, "key"));
        }
        if !matches!(a.auth_type, AccountAuthType::Password | AccountAuthType::PlainPassword) {
            self.secrets.delete(&key(a, "pw"));
        }
        ok
    }

    pub fn add(&mut self, mut account: ClientAccount, secrets: Secrets) -> bool {
        let ok = self.save_secrets(&mut account, &secrets);
        self.accounts.push(account);
        self.save() && ok
    }

    pub fn update(&mut self, mut account: ClientAccount, secrets: Secrets) -> bool {
        let Some(i) = self.accounts.iter().position(|a| a.id == account.id) else { return false };
        account.updated_at = now_reference_seconds();
        let ok = self.save_secrets(&mut account, &secrets);
        self.accounts[i] = account;
        self.save() && ok
    }

    pub fn duplicate(&mut self, id: Uuid) -> bool {
        let Some(src) = self.accounts.iter().find(|a| a.id == id).cloned() else { return false };
        let mut copy = src.clone();
        copy.id = Uuid::new_v4();
        copy.name = format!("{} (Copy)", src.name);
        copy.created_at = now_reference_seconds();
        copy.updated_at = copy.created_at;
        copy.proxy.password = self.proxy_password(&src);
        let secrets = Secrets {
            password: self.password(&src),
            cert_der: self.certificate(&src),
            key_der: self.private_key(&src),
        };
        self.add(copy, secrets)
    }

    pub fn delete(&mut self, id: Uuid) {
        if let Some(a) = self.accounts.iter().find(|a| a.id == id).cloned() {
            for s in ["pw", "cert", "key", "proxypw"] {
                self.secrets.delete(&key(&a, s));
            }
        }
        self.accounts.retain(|a| a.id != id);
        self.save();
    }

    pub fn find(&self, id: Uuid) -> Option<&ClientAccount> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn base64_of(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// What the editor hands to the store besides the account itself.
#[derive(Debug, Default, Clone)]
pub struct Secrets {
    pub password: Option<String>,
    pub cert_der: Option<Vec<u8>>,
    pub key_der: Option<Vec<u8>>,
}

pub const AUTH_TYPES: [AccountAuthType; 4] = [
    AccountAuthType::Anonymous,
    AccountAuthType::Password,
    AccountAuthType::PlainPassword,
    AccountAuthType::Certificate,
];

pub fn uses_password(t: AccountAuthType) -> bool {
    matches!(t, AccountAuthType::Password | AccountAuthType::PlainPassword)
}

/// Form state of the account editor (UI-SPEC 6).
#[derive(Debug, Clone)]
pub struct AccountEditor {
    pub name: String,
    pub host: String,
    pub ports: String,
    pub hub: String,
    pub username: String,
    pub auth_type: AccountAuthType,
    pub password: String,
    pub max_connection: i64,
    pub compression: bool,
    pub udp_acceleration: bool,
    pub use_qos: bool,
    pub half_connection: bool,
    pub auto_reconnect: bool,
    pub reconnect_interval: i64,
    pub reconnect_count: i64,
    pub check_server_cert: bool,
    pub fingerprint: String,
    pub mtu: String,
    pub mac: String,
    pub use_custom_routing: bool,
    pub routing: RoutingConfig,
    /// Freshly imported material; `None` keeps what is stored.
    pub cert_der: Option<Vec<u8>>,
    pub key_der: Option<Vec<u8>>,
    pub has_stored_identity: bool,
    pub import_error: Option<String>,
}

impl Default for AccountEditor {
    fn default() -> Self {
        AccountEditor::from_account(&ClientAccount::new("New Connection", ""), None, false)
    }
}

impl AccountEditor {
    pub fn from_account(a: &ClientAccount, password: Option<String>, has_stored_identity: bool) -> Self {
        AccountEditor {
            name: a.name.clone(),
            host: a.host.clone(),
            ports: a.port_list.iter().map(u16::to_string).collect::<Vec<_>>().join(", "),
            hub: a.hub.clone(),
            username: a.username.clone(),
            auth_type: a.auth_type,
            password: password.unwrap_or_default(),
            max_connection: a.max_connection,
            compression: a.compression,
            udp_acceleration: a.udp_acceleration,
            use_qos: !a.disable_qos,
            half_connection: a.half_connection,
            auto_reconnect: a.auto_reconnect,
            reconnect_interval: a.reconnect_interval.round() as i64,
            reconnect_count: a.reconnect_count,
            check_server_cert: a.check_server_cert,
            fingerprint: a.server_cert_fingerprint.clone().unwrap_or_default(),
            mtu: a.mtu.map(|m| m.to_string()).unwrap_or_default(),
            mac: a.virtual_mac_address.clone().unwrap_or_default(),
            use_custom_routing: a.routing.is_some(),
            routing: a.routing.clone().unwrap_or_default(),
            cert_der: None,
            key_der: None,
            has_stored_identity,
            import_error: None,
        }
    }

    /// Ports are parsed as 1...65535; anything else is dropped.
    pub fn parsed_ports(&self) -> Vec<u16> {
        self.ports.split(',').filter_map(|p| p.trim().parse::<u16>().ok()).filter(|&p| p > 0).collect()
    }

    pub fn host_error(&self) -> Option<&'static str> {
        let h = self.host.trim();
        (!h.is_empty() && !validation::is_valid_host(h)).then_some("Not a valid host name or IPv4 address.")
    }

    pub fn fingerprint_error(&self) -> Option<&'static str> {
        let f = self.fingerprint.trim();
        (!f.is_empty() && validation::normalized_fingerprint(f).is_none())
            .then_some("Fingerprint must be 40 (SHA-1) or 64 (SHA-256) hex digits.")
    }

    pub fn mtu_error(&self) -> Option<&'static str> {
        let m = self.mtu.trim();
        (!m.is_empty() && !m.parse::<i64>().is_ok_and(|v| (576..=1500).contains(&v)))
            .then_some("MTU must be 576–1500, or blank for automatic.")
    }

    pub fn mac_error(&self) -> Option<&'static str> {
        let m = self.mac.trim();
        (!m.is_empty() && validation::parse_mac_address(m).is_none())
            .then_some("MAC must be 6 hex byte pairs, e.g. 00:AC:DE:12:34:56.")
    }

    pub fn advanced_invalid(&self) -> bool {
        self.fingerprint_error().is_some() || self.mtu_error().is_some() || self.mac_error().is_some()
    }

    pub fn certificate_ready(&self) -> bool {
        self.auth_type != AccountAuthType::Certificate
            || (self.cert_der.is_some() && self.key_der.is_some())
            || self.has_stored_identity
    }

    pub fn can_save(&self) -> bool {
        let (name, host) = (self.name.trim(), self.host.trim());
        !name.is_empty()
            && !host.is_empty()
            && validation::is_valid_host(host)
            && !self.advanced_invalid()
            && self.certificate_ready()
            && validation::is_valid_identity_field(&self.hub)
            && validation::is_valid_identity_field(&self.username)
            && !self.routing_invalid()
    }

    /// A custom rule set with an invalid rule cannot be sent to the daemon.
    pub fn routing_invalid(&self) -> bool {
        self.use_custom_routing && self.routing.rules.iter().any(|r| !r.is_valid())
    }

    /// Starts from `base` when editing, so fields the form does not show (proxy, creation date) survive.
    pub fn make_account(&self, base: Option<&ClientAccount>) -> ClientAccount {
        let mut a = base.cloned().unwrap_or_else(|| ClientAccount::new("", ""));
        let ports = self.parsed_ports();
        a.name = self.name.trim().into();
        a.host = self.host.trim().into();
        a.port_list = if ports.is_empty() { vec![443] } else { ports };
        let hub = self.hub.trim();
        a.hub = if hub.is_empty() { "DEFAULT".into() } else { hub.into() };
        a.username = self.username.trim().into();
        a.auth_type = self.auth_type;
        a.check_server_cert = self.check_server_cert;
        a.server_cert_fingerprint = validation::normalized_fingerprint(self.fingerprint.trim());
        a.max_connection = self.max_connection.clamp(1, 32);
        a.compression = self.compression;
        a.udp_acceleration = self.udp_acceleration;
        a.disable_qos = !self.use_qos;
        a.half_connection = self.half_connection;
        a.auto_reconnect = self.auto_reconnect;
        a.reconnect_interval = self.reconnect_interval.clamp(1, 300) as f64;
        a.reconnect_count = self.reconnect_count.clamp(1, 1000);
        a.mtu = self.mtu.trim().parse().ok();
        a.virtual_mac_address = Some(self.mac.trim().to_string()).filter(|m| !m.is_empty());
        a.routing = self.use_custom_routing.then(|| self.routing.clone());
        a.normalize();
        a
    }

    pub fn secrets(&self) -> Secrets {
        Secrets {
            password: uses_password(self.auth_type).then(|| self.password.clone()).filter(|p| !p.is_empty()),
            cert_der: if self.auth_type == AccountAuthType::Certificate { self.cert_der.clone() } else { None },
            key_der: if self.auth_type == AccountAuthType::Certificate { self.key_der.clone() } else { None },
        }
    }

    /// Reads the two files of a PEM/DER import; the error is shown under the buttons.
    pub fn import_identity(&mut self, cert_file: &[u8], key_file: &[u8]) {
        let result = crate::cert_import::parse_certificate(cert_file)
            .and_then(|c| crate::cert_import::parse_private_key(key_file).map(|k| (c, k)));
        match result {
            Ok((c, k)) => {
                self.cert_der = Some(c);
                self.key_der = Some(k);
                self.import_error = None;
            }
            Err(e) => self.import_error = Some(e),
        }
    }

    pub fn certificate_status(&self) -> &'static str {
        if self.cert_der.is_some() && self.key_der.is_some() {
            "Certificate and RSA key ready to save."
        } else if self.has_stored_identity {
            "A certificate and key are stored in the keyring. Import again to replace them."
        } else {
            "No certificate yet. Import a PEM or DER certificate with its RSA key."
        }
    }
}

#[cfg(test)]
mod tests;
