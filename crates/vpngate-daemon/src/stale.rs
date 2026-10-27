//! The stale-state undo list: what a platform backend changed on the machine, persisted as it goes so a daemon that
//! died without tearing down can undo it at the next start (`NetConfig.cleanupStale`).
//!
//! The list is opaque to the daemon: an op is a backend-defined `kind` plus arguments (a route to delete, "restore the
//! system DNS", ...). The backend records ops while applying and hands an [`Undoer`] to [`cleanup_stale`].

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use vpngate_platform::UndoOp;

#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    undo: Vec<UndoOp>,
}

pub use vpngate_platform::Undoer;

pub struct StaleState {
    path: PathBuf,
}

impl vpngate_platform::UndoLog for StaleState {
    fn record(&self, op: UndoOp) {
        if let Err(e) = StaleState::record(self, op) {
            println!("[state] cannot persist the undo list: {e}");
        }
    }

    fn clear(&self) {
        StaleState::clear(self);
    }
}

impl StaleState {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        StaleState { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The recorded ops, oldest first. A missing or unreadable file is an empty list.
    pub fn load(&self) -> Vec<UndoOp> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|d| serde_json::from_slice::<StateFile>(&d).ok())
            .map(|s| s.undo)
            .unwrap_or_default()
    }

    /// Appends `op` and rewrites the file (via a temporary file, so a crash never leaves half of one).
    pub fn record(&self, op: UndoOp) -> io::Result<()> {
        let mut undo = self.load();
        undo.push(op);
        let data = serde_json::to_vec(&StateFile { undo }).map_err(io::Error::other)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)
    }

    /// The tunnel was torn down normally: nothing left to undo.
    pub fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    /// Undoes leftovers of a run that did not shut down cleanly, newest change first, then forgets them.
    /// Returns how many ops were undone. A file that does not parse is left alone, like Swift.
    pub fn cleanup_stale(&self, undoer: &dyn Undoer) -> usize {
        let Ok(d) = std::fs::read(&self.path) else { return 0 };
        let Ok(state) = serde_json::from_slice::<StateFile>(&d) else { return 0 };
        for op in state.undo.iter().rev() {
            undoer.undo(op);
        }
        self.clear();
        state.undo.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Rec(Mutex<Vec<UndoOp>>);
    impl Undoer for Rec {
        fn undo(&self, op: &UndoOp) {
            self.0.lock().unwrap().push(op.clone());
        }
    }

    fn state(name: &str) -> StaleState {
        let dir = std::env::temp_dir().join(format!("vg-stale-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = StaleState::new(dir.join("state.json"));
        s.clear();
        s
    }

    #[test]
    fn undoes_newest_first_then_forgets() {
        let s = state("order");
        s.record(UndoOp::new("route", &["-net", "0.0.0.0/1", "10.0.0.1"])).unwrap();
        s.record(UndoOp::new("route", &["-host", "1.2.3.4"])).unwrap();
        s.record(UndoOp::new("dns", &[])).unwrap();
        assert_eq!(s.load().len(), 3);
        let r = Rec::default();
        assert_eq!(s.cleanup_stale(&r), 3);
        let kinds: Vec<_> = r.0.lock().unwrap().iter().map(|o| o.kind.clone()).collect();
        assert_eq!(kinds, ["dns", "route", "route"]);
        assert_eq!(r.0.lock().unwrap()[2].args, ["-net", "0.0.0.0/1", "10.0.0.1"]);
        assert!(!s.path().exists(), "state file removed");
        assert_eq!(s.cleanup_stale(&r), 0, "second run finds nothing");
    }

    #[test]
    fn missing_or_corrupt_file_does_nothing() {
        let s = state("corrupt");
        let r = Rec::default();
        assert_eq!(s.cleanup_stale(&r), 0);
        std::fs::write(s.path(), b"{not json").unwrap();
        assert_eq!(s.cleanup_stale(&r), 0);
        assert!(r.0.lock().unwrap().is_empty());
        assert!(s.path().exists(), "unparsable state is left in place");
        s.clear();
    }

    #[test]
    fn clear_forgets_a_clean_shutdown() {
        let s = state("clear");
        s.record(UndoOp::new("dns", &[])).unwrap();
        s.clear();
        assert_eq!(s.cleanup_stale(&Rec::default()), 0);
        assert!(s.load().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let s = state("mode");
        s.record(UndoOp::new("dns", &[])).unwrap();
        assert_eq!(std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777, 0o600);
        s.clear();
    }
}
