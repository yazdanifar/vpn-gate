//! Minimal HTTP response head parser (status line plus lowercased header names).

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHead {
    pub status: String,
    /// Names lowercased; a repeated name keeps the last value.
    pub headers: BTreeMap<String, String>,
}

pub const TERMINATOR: [u8; 4] = *b"\r\n\r\n";
pub const MAX_SIZE: usize = 16384;

/// Swift `CharacterSet.whitespaces`: blanks and tabs, not line breaks.
fn is_blank(c: char) -> bool {
    c.is_whitespace() && !matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

impl HttpHead {
    /// The numeric code from the second space-separated field of the status line.
    pub fn status_code(&self) -> Option<i64> {
        self.status.split(' ').filter(|p| !p.is_empty()).nth(1)?.parse().ok()
    }

    /// Parses the header block (without the blank-line terminator). Invalid UTF-8 is replaced, lines without a colon ignored.
    pub fn parse(head: &[u8]) -> HttpHead {
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split("\r\n");
        let status = lines.next().unwrap_or_default().to_string();
        let mut headers = BTreeMap::new();
        for l in lines {
            if let Some((name, value)) = l.split_once(':') {
                headers.insert(name.to_lowercase(), value.trim_matches(is_blank).to_string());
            }
        }
        HttpHead { status, headers }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::{load, unhex};

    #[test]
    fn golden() {
        let v = load("httphead");
        for c in v["cases"].as_array().unwrap() {
            let h = HttpHead::parse(&unhex(c["hex"].as_str().unwrap()));
            assert_eq!(h.status, c["status"].as_str().unwrap());
            let want: BTreeMap<String, String> = c["headers"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
                .collect();
            assert_eq!(h.headers, want, "{}", c["status"]);
            assert_eq!(h.status_code(), c["statusCode"].as_i64(), "{}", c["status"]);
        }
    }

    #[test]
    fn later_header_wins_and_value_is_trimmed() {
        let h = HttpHead::parse(b"HTTP/1.1 200 OK\r\nX: 1\r\nx:\t two \t");
        assert_eq!(h.headers["x"], "two");
    }
}
