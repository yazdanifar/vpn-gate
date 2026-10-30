//! Loader for the JSON vectors exported from the Swift code (`Tests/Fixtures/golden`).

use serde_json::Value;
use std::path::{Path, PathBuf};

/// Directory holding the committed vectors, relative to the workspace root.
pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Tests/Fixtures/golden")
}

/// Loads `<name>.json` (e.g. `"pack"` or `"transcripts/bridge"`). Panics with the path on failure: this is test support.
pub fn load(name: &str) -> Value {
    let path = dir().join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Decodes a lowercase/uppercase hex string as used throughout the vectors.
pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| panic!("bad hex: {s}")))
        .collect()
}

/// JSON equality that treats `3` and `3.0` as equal (Swift writes whole-number Doubles without a fraction).
pub fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            if let (Some(x), Some(y)) = (x.as_u64(), y.as_u64()) {
                x == y
            } else if let (Some(x), Some(y)) = (x.as_i64(), y.as_i64()) {
                x == y
            } else {
                x.as_f64() == y.as_f64()
            }
        }
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(x, y)| json_eq(x, y)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| json_eq(v, w)))
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILES: &[&str] = &[
        "account",
        "certpin",
        "crypto",
        "dataphase",
        "httphead",
        "ipc",
        "pack",
        "packets",
        "routing",
        "serverlist",
        "softether_error",
        "udpaccel",
        "validation",
        "vgdat",
        "transcripts/bridge",
        "transcripts/dnsproxy",
        "transcripts/host_unique_id",
        "transcripts/softether_login",
    ];

    #[test]
    fn every_golden_file_parses() {
        for f in FILES {
            assert!(load(f).is_object(), "{f} is not a JSON object");
        }
    }

    #[test]
    fn every_golden_file_is_listed() {
        let count = |d: &Path| {
            std::fs::read_dir(d)
                .unwrap()
                .filter(|e| e.as_ref().unwrap().path().extension().is_some_and(|x| x == "json"))
                .count()
        };
        assert_eq!(count(&dir()) + count(&dir().join("transcripts")), FILES.len());
    }

    #[test]
    fn unhex_decodes() {
        assert_eq!(unhex("00ff10"), vec![0, 255, 16]);
    }
}
