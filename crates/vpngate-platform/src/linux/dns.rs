//! DNS for the tunnel. With systemd-resolved the tunnel link gets the servers, the catch-all routing domain `~.` and
//! the default-route flag, which makes it the resolver for every name; the other links keep their own settings, so
//! nothing needs restoring but the link, and the link disappears with the tun device. Without resolved,
//! `/etc/resolv.conf` is backed up and replaced, and [`DnsConfigurator::remove`] puts it back. `remove` keeps no
//! state in memory, so the next daemon start can run it for a run that died.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{CommandRunner, DnsConfigurator};

const RESOLVECTL: &str = "/usr/bin/resolvectl";
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// resolved's own copy of the upstream servers, without its 127.0.0.53 stub.
pub const RESOLVED_UPSTREAM: &str = "/run/systemd/resolve/resolv.conf";
pub const DEFAULT_BACKUP: &str = "/var/lib/vpngate/resolv.conf.backup";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct LinuxDns {
    runner: Arc<dyn CommandRunner>,
    resolv_conf: PathBuf,
    upstream: PathBuf,
    backup: PathBuf,
    /// The link handed to resolved, for `resolvectl revert` on `remove`.
    link: Mutex<Option<String>>,
}

/// What the backup file holds: a symlink target or the file's text, so a stub-resolver symlink survives the round trip.
#[derive(Debug, PartialEq, Eq)]
enum Saved {
    Link(String),
    Text(String),
}

impl Saved {
    fn encode(&self) -> String {
        match self {
            Saved::Link(t) => format!("link\n{t}"),
            Saved::Text(t) => format!("text\n{t}"),
        }
    }

    fn decode(s: &str) -> Option<Saved> {
        let (kind, rest) = s.split_once('\n')?;
        match kind {
            "link" => Some(Saved::Link(rest.to_string())),
            "text" => Some(Saved::Text(rest.to_string())),
            _ => None,
        }
    }
}

impl LinuxDns {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self::with_paths(runner, RESOLV_CONF.into(), RESOLVED_UPSTREAM.into(), DEFAULT_BACKUP.into())
    }

    pub fn with_paths(
        runner: Arc<dyn CommandRunner>,
        resolv_conf: PathBuf,
        upstream: PathBuf,
        backup: PathBuf,
    ) -> Self {
        LinuxDns { runner, resolv_conf, upstream, backup, link: Mutex::new(None) }
    }

    fn resolvectl(&self, args: &[&str]) -> bool {
        let r = self.runner.run(RESOLVECTL, args);
        if r.status != 0 {
            println!("[dns] resolvectl {} failed ({}): {}", args.join(" "), r.status, r.output.trim());
        }
        r.status == 0
    }

    fn set_with_resolved(&self, servers: &[String], iface: &str) -> bool {
        let mut dns = vec!["dns", iface];
        dns.extend(servers.iter().map(String::as_str));
        if !self.resolvectl(&dns) {
            return false;
        }
        *lock(&self.link) = Some(iface.to_string());
        // `~.` routes every name to this link; the flag keeps it the default route for names with no domain match.
        let routed = self.resolvectl(&["domain", iface, "~."]) & self.resolvectl(&["default-route", iface, "yes"]);
        if !routed {
            println!("[dns] resolved did not accept the routing domain; names may still go to the LAN resolver");
        }
        true
    }

    fn set_in_resolv_conf(&self, servers: &[String]) -> bool {
        if !self.backup.exists() {
            let saved = match fs::read_link(&self.resolv_conf) {
                Ok(target) => Saved::Link(target.to_string_lossy().into_owned()),
                Err(_) => Saved::Text(fs::read_to_string(&self.resolv_conf).unwrap_or_default()),
            };
            if let Some(dir) = self.backup.parent() {
                let _ = fs::create_dir_all(dir);
            }
            if let Err(e) = fs::write(&self.backup, saved.encode()) {
                println!("[dns] cannot back up {}: {e}", self.resolv_conf.display());
                return false;
            }
        }
        let mut text = String::from("# Written by vpngate while connected; restored on disconnect.\n");
        for s in servers {
            text.push_str(&format!("nameserver {s}\n"));
        }
        // A symlink (the stub resolver's) must be replaced, not written through.
        let _ = fs::remove_file(&self.resolv_conf);
        match fs::write(&self.resolv_conf, text) {
            Ok(()) => true,
            Err(e) => {
                println!("[dns] cannot write {}: {e}", self.resolv_conf.display());
                self.restore_backup();
                false
            }
        }
    }

    fn restore_backup(&self) {
        let Some(saved) = fs::read_to_string(&self.backup).ok().and_then(|s| Saved::decode(&s)) else { return };
        let _ = fs::remove_file(&self.resolv_conf);
        let restored = match &saved {
            Saved::Link(target) => std::os::unix::fs::symlink(target, &self.resolv_conf),
            Saved::Text(text) => fs::write(&self.resolv_conf, text),
        };
        match restored {
            Ok(()) => {
                let _ = fs::remove_file(&self.backup);
            }
            Err(e) => println!("[dns] cannot restore {}: {e}", self.resolv_conf.display()),
        }
    }
}

/// `nameserver` lines of a resolv.conf, IPv4 literals only.
pub fn parse_nameservers(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|s| s.trim().to_string())
        .filter(|s| vpngate_core::validation::is_ipv4_literal(s))
        .collect()
}

impl DnsConfigurator for LinuxDns {
    fn set(&self, servers: &[String], iface: &str, _address: &str, _router: &str) -> bool {
        // resolved is tried first; if it is not running (or `resolvectl` is missing) the file is rewritten instead.
        self.set_with_resolved(servers, iface) || self.set_in_resolv_conf(servers)
    }

    fn remove(&self) {
        if let Some(link) = lock(&self.link).take() {
            self.resolvectl(&["revert", &link]);
        }
        self.restore_backup();
    }

    fn current_servers(&self) -> Vec<String> {
        // Before `set`: resolved's own list when it runs (the stub in /etc/resolv.conf would answer 127.0.0.53), else
        // the plain file.
        let read = |p: &Path| fs::read_to_string(p).ok().map(|t| parse_nameservers(&t));
        read(&self.upstream).filter(|s| !s.is_empty()).or_else(|| read(&self.resolv_conf)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
