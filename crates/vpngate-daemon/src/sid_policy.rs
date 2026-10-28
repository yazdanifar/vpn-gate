//! Who may talk to the Windows service: decided from the client process's token, as SID strings, so the rule is
//! testable on every OS. The pipe's own ACL (SYSTEM, Administrators, Interactive) is the first gate; this is the check
//! of the client's SID that backs it up.

pub const SYSTEM: &str = "S-1-5-18";
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// Everyone logged on at the machine's console or over RDP; remote network logons do not carry it.
pub const INTERACTIVE: &str = "S-1-5-4";
/// Network logons, which must never reach the service even if the ACL were loosened.
pub const NETWORK: &str = "S-1-5-2";

/// The ACL on the pipe: full access for SYSTEM and Administrators, read/write for Interactive users. Interactive users
/// get no `FILE_CREATE_PIPE_INSTANCE`, so nobody else can create a further instance of the pipe.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// `user` is the token's user SID, `groups` its group SIDs.
pub fn is_allowed(user: &str, groups: &[String]) -> bool {
    let has = |sid: &str| groups.iter().any(|g| g == sid);
    if has(NETWORK) {
        return false;
    }
    user == SYSTEM || has(ADMINISTRATORS) || has(INTERACTIVE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups(g: &[&str]) -> Vec<String> {
        g.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn system_administrators_and_interactive_users_are_allowed() {
        assert!(is_allowed(SYSTEM, &[]));
        assert!(is_allowed("S-1-5-21-1-2-3-1001", &groups(&[INTERACTIVE, "S-1-1-0"])));
        assert!(is_allowed("S-1-5-21-1-2-3-500", &groups(&[ADMINISTRATORS])));
    }

    #[test]
    fn network_logons_and_strangers_are_not() {
        assert!(!is_allowed("S-1-5-21-1-2-3-1001", &groups(&["S-1-1-0"])));
        assert!(!is_allowed("S-1-5-21-1-2-3-1001", &groups(&[INTERACTIVE, NETWORK])));
        assert!(!is_allowed(SYSTEM, &groups(&[NETWORK])));
        assert!(!is_allowed("S-1-5-19", &[]));
    }
}
