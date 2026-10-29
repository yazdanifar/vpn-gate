//! Connection history (UI-SPEC 9): newest first, at most 100 entries, one per connected period. A JSON file next to the
//! settings.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_ENTRIES: usize = 100;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HistoryEntry {
    pub id: Uuid,
    pub server_name: String,
    pub server_ip: String,
    pub connected_at_ms: u64,
    pub disconnected_at_ms: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub error: Option<String>,
}

impl Default for HistoryEntry {
    fn default() -> Self {
        HistoryEntry {
            id: Uuid::new_v4(),
            server_name: String::new(),
            server_ip: String::new(),
            connected_at_ms: 0,
            disconnected_at_ms: None,
            bytes_in: 0,
            bytes_out: 0,
            error: None,
        }
    }
}

impl HistoryEntry {
    pub fn duration_seconds(&self) -> Option<u64> {
        self.disconnected_at_ms.map(|d| d.saturating_sub(self.connected_at_ms) / 1000)
    }
}

pub struct History {
    path: Option<PathBuf>,
    pub entries: Vec<HistoryEntry>,
}

impl History {
    pub fn default_path() -> PathBuf {
        crate::settings::config_dir().join("connection_history.json")
    }

    /// `None` keeps the history in memory only (tests).
    pub fn new(path: Option<PathBuf>) -> Self {
        let entries = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        History { path, entries }
    }

    pub fn record_start(&mut self, server_name: &str, server_ip: &str, now_ms: u64) -> Uuid {
        let e = HistoryEntry {
            server_name: server_name.into(),
            server_ip: server_ip.into(),
            connected_at_ms: now_ms,
            ..HistoryEntry::default()
        };
        let id = e.id;
        self.entries.insert(0, e);
        self.entries.truncate(MAX_ENTRIES);
        self.save();
        id
    }

    pub fn record_end(&mut self, id: Uuid, bytes_in: u64, bytes_out: u64, error: Option<String>, now_ms: u64) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
            e.disconnected_at_ms = Some(now_ms);
            e.bytes_in = bytes_in;
            e.bytes_out = bytes_out;
            e.error = error;
            self.save();
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.save();
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.entries) {
            let _ = std::fs::write(path, bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_newest_first_and_caps() {
        let mut h = History::new(None);
        let first = h.record_start("a", "1.1.1.1", 1_000);
        for i in 0..MAX_ENTRIES {
            h.record_start("b", "2.2.2.2", 2_000 + i as u64);
        }
        assert_eq!(h.entries.len(), MAX_ENTRIES);
        assert!(h.entries.iter().all(|e| e.id != first), "the oldest fell off");
        let id = h.entries[0].id;
        h.record_end(id, 10, 20, Some("boom".into()), 5_000_000);
        let e = &h.entries[0];
        assert_eq!((e.bytes_in, e.bytes_out, e.error.as_deref()), (10, 20, Some("boom")));
        assert_eq!(e.duration_seconds(), Some((5_000_000 - e.connected_at_ms) / 1000));
        h.clear();
        assert!(h.entries.is_empty());
    }

    #[test]
    fn persists() {
        let path = std::env::temp_dir().join(format!("vg-hist-{}.json", std::process::id()));
        let mut h = History::new(Some(path.clone()));
        h.record_start("a", "1.1.1.1", 7);
        let again = History::new(Some(path.clone()));
        assert_eq!(again.entries, h.entries);
        std::fs::write(&path, b"junk").unwrap();
        assert!(History::new(Some(path.clone())).entries.is_empty());
        let _ = std::fs::remove_file(path);
    }
}
