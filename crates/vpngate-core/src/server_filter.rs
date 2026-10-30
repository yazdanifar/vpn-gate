//! Search / country / favourites / log-retention filter for the server list. Mirrors `ServerFilter.swift`.

use std::collections::HashSet;

use crate::routing_rule::trim_blank;
use crate::server_list::VpnServer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFilter {
    pub search: String,
    pub country: String,
    pub favorites_only: bool,
    pub favorites: HashSet<String>,
    /// Hide servers that keep logs longer than this many weeks (`None` = show all).
    pub max_log_weeks: Option<i64>,
}

impl Default for ServerFilter {
    fn default() -> Self {
        ServerFilter {
            search: String::new(),
            country: "All".into(),
            favorites_only: false,
            favorites: HashSet::new(),
            max_log_weeks: None,
        }
    }
}

impl ServerFilter {
    pub fn apply<'a>(&self, servers: &'a [VpnServer]) -> Vec<&'a VpnServer> {
        // Unicode lower-casing on both sides: `MÜLLER` finds `Müller`, but `elodie` does not find `ÉLODIE`
        // (no diacritic folding), like `localizedCaseInsensitiveContains`.
        let needle = self.search.to_lowercase();
        servers
            .iter()
            .filter(|s| {
                if self.country != "All" && s.country_long != self.country {
                    return false;
                }
                if self.favorites_only && !self.favorites.contains(s.id()) {
                    return false;
                }
                if let Some(max) = self.max_log_weeks {
                    // unknown retention is treated as "too long"
                    if !Self::log_weeks(&s.log_type).is_some_and(|w| w <= max) {
                        return false;
                    }
                }
                if !needle.is_empty() {
                    let hit = [&s.host_name, &s.ip, &s.country_long, &s.operator_name]
                        .iter()
                        .any(|f| f.to_lowercase().contains(&needle));
                    if !hit {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// "2weeks" → 2, "3months" → 13, "1year" → 52, "no" / "none" / "0" → 0, unparseable → `None`.
    pub fn log_weeks(s: &str) -> Option<i64> {
        let lower = s.to_lowercase();
        let t = trim_blank(&lower);
        if ["no", "none", "nolog", "0"].contains(&t) {
            return Some(0);
        }
        let digits_len = t.find(|c: char| !c.is_numeric()).unwrap_or(t.len());
        let (digits, rest) = t.split_at(digits_len);
        let n: i64 = digits.parse().ok()?;
        match trim_blank(rest) {
            "day" | "days" => n.checked_add(6).map(|v| v / 7),
            "week" | "weeks" => Some(n),
            "month" | "months" => {
                let w = n.checked_mul(52)?;
                Some(w / 12 + i64::from(w % 12 != 0))
            }
            "year" | "years" => n.checked_mul(52),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::load;

    #[test]
    fn log_weeks_vectors() {
        let v = load("serverlist");
        let c = v["cases"].as_array().unwrap().iter().find(|c| c["name"] == "log-weeks").unwrap();
        for c in c["cases"].as_array().unwrap() {
            assert_eq!(ServerFilter::log_weeks(c["input"].as_str().unwrap()), c["weeks"].as_i64(), "{c}");
        }
    }

    #[test]
    fn filter_vectors() {
        let v = load("serverlist");
        let cases = v["cases"].as_array().unwrap();
        let pool: Vec<VpnServer> =
            serde_json::from_value(cases.iter().find(|c| c["name"] == "filter-pool").unwrap()["servers"].clone())
                .unwrap();
        let mut seen = 0;
        for c in cases.iter().filter(|c| c["name"].as_str().unwrap().starts_with("filter-") && c["params"].is_object())
        {
            let p = &c["params"];
            let mut f = ServerFilter::default();
            if let Some(s) = p["search"].as_str() {
                f.search = s.into();
            }
            if let Some(s) = p["country"].as_str() {
                f.country = s.into();
            }
            f.favorites_only = p["favoritesOnly"].as_bool().unwrap_or(false);
            if let Some(a) = p["favorites"].as_array() {
                f.favorites = a.iter().map(|x| x.as_str().unwrap().to_string()).collect();
            }
            f.max_log_weeks = p["maxLogWeeks"].as_i64();
            let got: Vec<&str> = f.apply(&pool).iter().map(|s| s.id()).collect();
            let want: Vec<&str> = c["result"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
            assert_eq!(got, want, "{}", c["name"]);
            seen += 1;
        }
        assert_eq!(seen, 16);
    }
}
