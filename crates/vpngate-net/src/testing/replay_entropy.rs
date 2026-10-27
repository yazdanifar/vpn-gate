use serde_json::Value;

use crate::entropy::Entropy;

/// Replays the `entropy` log of a golden transcript: each call must be the same operation with the same size as the
/// recorded one, and gets the recorded value.
pub struct ReplayEntropy {
    log: Vec<Value>,
    next: usize,
}

impl ReplayEntropy {
    pub fn new(log: &Value) -> Self {
        ReplayEntropy { log: log.as_array().expect("entropy log is an array").clone(), next: 0 }
    }

    /// True once every recorded draw was consumed.
    pub fn exhausted(&self) -> bool {
        self.next == self.log.len()
    }

    fn take(&mut self, op: &str, n: usize) -> &Value {
        let e = self.log.get(self.next).unwrap_or_else(|| panic!("unexpected extra draw {op} {n}"));
        assert_eq!(e["op"], op, "draw #{} is {} in the transcript", self.next, e["op"]);
        assert_eq!(e["n"].as_u64(), Some(n as u64), "size of draw #{}", self.next);
        self.next += 1;
        e
    }
}

impl Entropy for ReplayEntropy {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let hex = self.take("bytes", n)["hex"].as_str().expect("hex").to_string();
        let mut out = Vec::with_capacity(n);
        for i in (0..hex.len()).step_by(2) {
            out.push(u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"));
        }
        out
    }

    fn below(&mut self, n: usize) -> usize {
        self.take("below", n)["value"].as_u64().expect("value") as usize
    }
}
