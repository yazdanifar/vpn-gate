//! The server table's columns (UI-SPEC 4): which exist, which show by default, and how a saved layout is read back.

use crate::model::SortKey;

pub struct Column {
    pub key: &'static str,
    pub title: &'static str,
    pub default_visible: bool,
    /// Clicking the header sorts by this; `None` for columns the list cannot sort on.
    pub sort: Option<SortKey>,
}

const fn col(key: &'static str, title: &'static str, default_visible: bool, sort: Option<SortKey>) -> Column {
    Column { key, title, default_visible, sort }
}

/// In the default order.
pub const ALL: [Column; 15] = [
    col("host", "IP Address (Hostname)", true, Some(SortKey::Host)),
    col("region", "Region", true, Some(SortKey::Country)),
    col("uptime", "Uptime", true, Some(SortKey::Uptime)),
    col("sessions", "VPN Sessions", true, Some(SortKey::Sessions)),
    col("speed", "Line Speed", true, Some(SortKey::Speed)),
    col("ping", "Ping (Google, SE)", true, Some(SortKey::Ping)),
    col("test", "Test from this computer", true, Some(SortKey::Test)),
    col("logging", "Logging Policy", true, Some(SortKey::Logging)),
    col("score", "Total Score", true, Some(SortKey::Score)),
    col("ddns", "DDNS Hostname", false, None),
    col("ssl", "SSL-VPN (TCP)", false, None),
    col("udp", "UDP Support", false, None),
    col("transfers", "Cumulative Transfers", false, None),
    col("users", "Cumulative Users", false, None),
    col("operator", "Operator's Name", false, None),
];

pub const MESSAGE: Column = col("message", "Operator's Message", false, None);

pub fn all() -> impl Iterator<Item = &'static Column> {
    ALL.iter().chain(std::iter::once(&MESSAGE))
}

pub fn find(key: &str) -> Option<&'static Column> {
    all().find(|c| c.key == key)
}

/// The columns in display order, each with whether it shows. `saved` is the visible keys in order (what the settings
/// hold); unknown keys are ignored, and an empty list means the default layout. Hidden columns follow the visible ones.
pub fn layout(saved: &[String]) -> Vec<(&'static Column, bool)> {
    let mut visible: Vec<&'static Column> = Vec::new();
    for k in saved {
        if let Some(c) = find(k).filter(|c| !visible.iter().any(|v| v.key == c.key)) {
            visible.push(c);
        }
    }
    if visible.is_empty() {
        visible = all().filter(|c| c.default_visible).collect();
    }
    let hidden = all().filter(|c| !visible.iter().any(|v| v.key == c.key));
    visible.iter().map(|c| (*c, true)).chain(hidden.map(|c| (c, false))).collect()
}

/// What to store for a layout: the visible keys in order. A layout with nothing visible keeps the first column, so the
/// table never ends up empty.
pub fn to_saved(layout: &[(&'static str, bool)]) -> Vec<String> {
    let mut keys: Vec<String> = layout.iter().filter(|(_, v)| *v).map(|(k, _)| k.to_string()).collect();
    if keys.is_empty() {
        keys.push(ALL[0].key.into());
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(l: &[(&Column, bool)]) -> Vec<(&'static str, bool)> {
        l.iter().map(|(c, v)| (c.key, *v)).collect()
    }

    #[test]
    fn default_layout_shows_the_documented_nine() {
        let l = keys(&layout(&[]));
        assert_eq!(l.iter().filter(|c| c.1).count(), 9);
        assert_eq!(l[0], ("host", true));
        assert_eq!(l[9], ("ddns", false));
        assert_eq!(l.len(), 16);
    }

    #[test]
    fn saved_order_wins_and_junk_is_ignored() {
        let saved: Vec<String> = ["score", "bogus", "host", "score", "message"].map(String::from).to_vec();
        let l = keys(&layout(&saved));
        assert_eq!(&l[..3], [("score", true), ("host", true), ("message", true)]);
        assert!(l[3..].iter().all(|c| !c.1), "everything else is hidden");
        assert_eq!(l.len(), 16);
    }

    #[test]
    fn saving_never_leaves_the_table_empty() {
        assert_eq!(to_saved(&[("ping", false)]), ["host"]);
        assert_eq!(to_saved(&[("ping", true), ("host", false), ("test", true)]), ["ping", "test"]);
    }
}
