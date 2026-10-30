//! Linux peer authorisation: `SO_PEERCRED` (what tokio's `peer_cred` reports) against the `vpngate` group. root and
//! members of the group may talk to the daemon; the package's postinst adds the installing user to it. Membership is
//! looked up per connection, so `usermod -aG` takes effect without a restart.

use std::sync::Arc;

use crate::ipc_server::{Peer, PeerAuth};

pub const GROUP_NAME: &str = "vpngate";

/// A group as the account database lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub gid: u32,
    /// Login names of the supplementary members (the primary-group members are matched by gid).
    pub members: Vec<String>,
}

/// The account database, injected so the policy is tested without one.
pub trait Directory: Send + Sync {
    fn group(&self, name: &str) -> Option<Group>;
    fn user_name(&self, uid: u32) -> Option<String>;
}

pub struct GroupPeerAuth {
    group: String,
    directory: Arc<dyn Directory>,
}

impl GroupPeerAuth {
    pub fn new(group: impl Into<String>, directory: Arc<dyn Directory>) -> Self {
        GroupPeerAuth { group: group.into(), directory }
    }
}

impl PeerAuth for GroupPeerAuth {
    fn is_allowed(&self, peer: &Peer) -> bool {
        if peer.uid == 0 {
            return true;
        }
        let Some(group) = self.directory.group(&self.group) else { return false };
        peer.gid == group.gid || self.directory.user_name(peer.uid).is_some_and(|n| group.members.contains(&n))
    }
}

/// The real account database through `getgrnam_r` / `getpwuid_r`.
#[cfg(unix)]
pub struct SystemDirectory;

#[cfg(unix)]
impl Directory for SystemDirectory {
    fn group(&self, name: &str) -> Option<Group> {
        use std::ffi::{CStr, CString};

        let name = CString::new(name).ok()?;
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        // SAFETY: `group` is plain old data; zeroed is a valid value.
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live local, and `buf` is as long as stated.
        let rc = unsafe { libc::getgrnam_r(name.as_ptr(), &mut group, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc != 0 || result.is_null() {
            return None;
        }
        let mut members = Vec::new();
        let mut next = group.gr_mem;
        // SAFETY: `gr_mem` is a NULL-terminated array of C strings inside `buf`, which outlives this loop.
        unsafe {
            while !next.is_null() && !(*next).is_null() {
                members.push(CStr::from_ptr(*next).to_string_lossy().into_owned());
                next = next.add(1);
            }
        }
        Some(Group { gid: group.gr_gid, members })
    }

    fn user_name(&self, uid: u32) -> Option<String> {
        use std::ffi::CStr;

        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        // SAFETY: `passwd` is plain old data; zeroed is a valid value.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live local, and `buf` is as long as stated.
        let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut result) };
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: `pw_name` points at a NUL-terminated string inside `buf`.
        Some(unsafe { CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(Option<Group>);

    impl Directory for Fake {
        fn group(&self, _name: &str) -> Option<Group> {
            self.0.clone()
        }
        fn user_name(&self, uid: u32) -> Option<String> {
            match uid {
                1000 => Some("alice".into()),
                1001 => Some("bob".into()),
                _ => None,
            }
        }
    }

    fn auth(group: Option<Group>) -> GroupPeerAuth {
        GroupPeerAuth::new(GROUP_NAME, Arc::new(Fake(group)))
    }

    fn group() -> Option<Group> {
        Some(Group { gid: 990, members: vec!["alice".into()] })
    }

    #[test]
    fn root_is_always_allowed_even_without_the_group() {
        assert!(auth(None).is_allowed(&Peer { uid: 0, gid: 0 }));
    }

    #[test]
    fn supplementary_members_and_primary_group_are_allowed() {
        let a = auth(group());
        assert!(a.is_allowed(&Peer { uid: 1000, gid: 1000 }), "listed member");
        assert!(a.is_allowed(&Peer { uid: 1002, gid: 990 }), "primary group");
    }

    #[test]
    fn everyone_else_is_refused() {
        let a = auth(group());
        assert!(!a.is_allowed(&Peer { uid: 1001, gid: 1001 }));
        assert!(!a.is_allowed(&Peer { uid: 4242, gid: 4242 }), "unknown uid");
    }

    #[test]
    fn a_missing_group_refuses_non_root() {
        assert!(!auth(None).is_allowed(&Peer { uid: 1000, gid: 1000 }));
    }

    #[cfg(unix)]
    #[test]
    fn system_directory_finds_root_and_not_nonsense() {
        assert_eq!(SystemDirectory.user_name(0).as_deref(), Some("root"));
        assert!(SystemDirectory.group("no-such-group-vpngate-test").is_none());
    }
}
