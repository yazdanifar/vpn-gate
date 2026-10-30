//! Where passwords, certificates and keys live: the Secret Service (GNOME Keyring, KWallet) through `secret-tool`
//! from libsecret-tools, never a file. Same trait as the Windows `ISecretStore`; the command is behind [`Run`] so the
//! command lines are tested on every OS.

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
    /// `false` when the store refused (no secret service running, locked keyring dismissed).
    fn set(&self, key: &str, value: &str) -> bool;
    fn delete(&self, key: &str);
}

impl dyn SecretStore + '_ {
    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        STANDARD.decode(self.get(key)?).ok()
    }

    pub fn set_bytes(&self, key: &str, value: &[u8]) -> bool {
        self.set(key, &STANDARD.encode(value))
    }
}

/// Runs `secret-tool` with `args`, feeding `stdin`; returns stdout when it exited 0.
pub trait Run: Send + Sync {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Option<String>;
}

pub struct Process;

impl Run for Process {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Option<String> {
        let mut child = Command::new("secret-tool")
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(text.as_bytes()).ok()?;
        }
        let out = child.wait_with_output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Items carry the attributes `service=vpngate key=<key>`; the value goes in on stdin so it never shows in `ps`.
pub struct SecretTool<R: Run = Process>(R);

impl SecretTool {
    pub fn new() -> Self {
        SecretTool(Process)
    }
}

impl Default for SecretTool {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Run> SecretTool<R> {
    pub fn with_runner(r: R) -> Self {
        SecretTool(r)
    }
}

impl<R: Run> SecretStore for SecretTool<R> {
    fn get(&self, key: &str) -> Option<String> {
        self.0.run(&["lookup", "service", "vpngate", "key", key], None).filter(|v| !v.is_empty())
    }

    fn set(&self, key: &str, value: &str) -> bool {
        let label = format!("VPN Gate {key}");
        self.0.run(&["store", "--label", &label, "service", "vpngate", "key", key], Some(value)).is_some()
    }

    fn delete(&self, key: &str) {
        let _ = self.0.run(&["clear", "service", "vpngate", "key", key], None);
    }
}

#[derive(Default)]
pub struct MemorySecrets(Mutex<HashMap<String, String>>);

impl SecretStore for MemorySecrets {
    fn get(&self, key: &str) -> Option<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(key).cloned()
    }

    fn set(&self, key: &str, value: &str) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(key.into(), value.into());
        true
    }

    fn delete(&self, key: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(Vec<String>, Option<String>)>>);

    impl Run for std::sync::Arc<Recorder> {
        fn run(&self, args: &[&str], stdin: Option<&str>) -> Option<String> {
            self.0.lock().unwrap().push((args.iter().map(|s| s.to_string()).collect(), stdin.map(Into::into)));
            Some("value".into())
        }
    }

    #[test]
    fn command_lines() {
        let rec = std::sync::Arc::new(Recorder::default());
        let s = SecretTool::with_runner(rec.clone());
        assert_eq!(s.get("account-1-pw").as_deref(), Some("value"));
        assert!(s.set("account-1-pw", "hunter2"));
        s.delete("account-1-pw");
        let calls = rec.0.lock().unwrap();
        assert_eq!(calls[0].0, ["lookup", "service", "vpngate", "key", "account-1-pw"]);
        assert_eq!(
            calls[1].0,
            ["store", "--label", "VPN Gate account-1-pw", "service", "vpngate", "key", "account-1-pw"]
        );
        assert_eq!(calls[1].1.as_deref(), Some("hunter2"), "the secret travels on stdin, not argv");
        assert_eq!(calls[2].0, ["clear", "service", "vpngate", "key", "account-1-pw"]);
    }

    #[test]
    fn bytes_round_trip_and_missing_tool() {
        let m = MemorySecrets::default();
        let dynm: &dyn SecretStore = &m;
        assert!(dynm.set_bytes("k", &[1, 2, 255]));
        assert_eq!(dynm.get_bytes("k"), Some(vec![1, 2, 255]));
        dynm.delete("k");
        assert_eq!(dynm.get("k"), None);

        struct Gone;
        impl Run for Gone {
            fn run(&self, _: &[&str], _: Option<&str>) -> Option<String> {
                None
            }
        }
        let s = SecretTool::with_runner(Gone);
        assert!(!s.set("k", "v") && s.get("k").is_none());
    }

    /// Against a real Secret Service. The `deb` CI job runs it inside `dbus-run-session` with an unlocked
    /// gnome-keyring-daemon:  cargo test -p vpngate-app-model real_secret_service -- --ignored
    #[test]
    #[ignore = "needs secret-tool and an unlocked Secret Service on the session bus"]
    fn real_secret_service_round_trip() {
        let s = SecretTool::new();
        let key = format!("ci-roundtrip-{}", std::process::id());
        assert_eq!(s.get(&key), None, "starts empty");
        assert!(s.set(&key, "p@ss w0rd with spaces\nand a newline"), "the keyring accepted the secret");
        assert_eq!(s.get(&key).as_deref(), Some("p@ss w0rd with spaces\nand a newline"));
        let dynm: &dyn SecretStore = &s;
        assert!(dynm.set_bytes(&format!("{key}-bin"), &[0, 1, 2, 254, 255]));
        assert_eq!(dynm.get_bytes(&format!("{key}-bin")), Some(vec![0, 1, 2, 254, 255]));
        s.delete(&key);
        s.delete(&format!("{key}-bin"));
        assert_eq!(s.get(&key), None, "deleted");
    }
}
