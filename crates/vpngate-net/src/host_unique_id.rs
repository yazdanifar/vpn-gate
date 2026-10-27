//! A random value generated once per install and kept in a file, so the `unique_id` the login pack carries stays the
//! same across sessions. Deliberately not derived from the hostname or any hardware identifier.

use std::path::Path;

use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUniqueId {
    pub key: [u8; 32],
}

impl HostUniqueId {
    pub fn new(key: [u8; 32]) -> Self {
        HostUniqueId { key }
    }

    /// Reads `path`; creates it with 32 random bytes (mode 0600 on Unix) when missing or malformed. Never fails: when the
    /// file cannot be written the value only lives for this process.
    pub fn load(path: &Path, random: impl FnOnce(usize) -> Vec<u8>) -> Self {
        if let Ok(d) = std::fs::read(path) {
            if let Ok(key) = <[u8; 32]>::try_from(d.as_slice()) {
                return HostUniqueId { key };
            }
        }
        let fresh: [u8; 32] = random(32).try_into().expect("random(32) returns 32 bytes");
        if std::fs::write(path, fresh).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        HostUniqueId { key: fresh }
    }

    /// 20-byte login `unique_id` (SHA-1 of "login" + key).
    pub fn login_id(&self) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(b"login");
        h.update(self.key);
        h.finalize().into()
    }

    /// 16-byte NodeInfo `UniqueId` (first 16 bytes of SHA-256 of "node" + key).
    pub fn node_id(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(b"node");
        h.update(self.key);
        let d = h.finalize();
        d[..16].try_into().expect("16 bytes")
    }
}
