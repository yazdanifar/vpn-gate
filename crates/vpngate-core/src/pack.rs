//! SoftEther PACK: an ordered list of named elements, each holding one or more values. Big-endian on the wire.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackValue {
    Int(u32),
    Data(Vec<u8>),
    Str(String),
    Unistr(String),
    Int64(u64),
}

impl PackValue {
    fn type_code(&self) -> u32 {
        match self {
            PackValue::Int(_) => 0,
            PackValue::Data(_) => 1,
            PackValue::Str(_) => 2,
            PackValue::Unistr(_) => 3,
            PackValue::Int64(_) => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    Truncated,
    BadType(u32),
    BadName,
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::Truncated => write!(f, "truncated pack"),
            PackError::BadType(t) => write!(f, "bad pack value type {t}"),
            PackError::BadName => write!(f, "bad pack element name"),
        }
    }
}

impl std::error::Error for PackError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub values: Vec<PackValue>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pack {
    elements: Vec<Element>,
}

/// SoftEther compares element names case-insensitively.
fn same_name(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

impl Pack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn elements(&self) -> &[Element] {
        &self.elements
    }

    /// Adds a single-valued element, replacing any element of the same (case-insensitive) name:
    /// SoftEther rejects packs with duplicates.
    pub fn add(&mut self, name: &str, value: PackValue) {
        self.add_values(name, vec![value]);
    }

    fn add_values(&mut self, name: &str, values: Vec<PackValue>) {
        self.elements.retain(|e| !same_name(&e.name, name));
        self.elements.push(Element { name: name.to_string(), values });
    }

    pub fn add_int(&mut self, name: &str, v: u32) {
        self.add(name, PackValue::Int(v));
    }
    pub fn add_bool(&mut self, name: &str, v: bool) {
        self.add_int(name, v as u32);
    }
    pub fn add_str(&mut self, name: &str, v: &str) {
        self.add(name, PackValue::Str(v.to_string()));
    }
    pub fn add_uni(&mut self, name: &str, v: &str) {
        self.add(name, PackValue::Unistr(v.to_string()));
    }
    pub fn add_data(&mut self, name: &str, v: &[u8]) {
        self.add(name, PackValue::Data(v.to_vec()));
    }
    pub fn add_int64(&mut self, name: &str, v: u64) {
        self.add(name, PackValue::Int64(v));
    }
    /// A multi-valued integer element (SoftEther `PackAddIntEx` array), e.g. the redirect "Port" list.
    pub fn add_ints(&mut self, name: &str, v: &[u32]) {
        self.add_values(name, v.iter().map(|&n| PackValue::Int(n)).collect());
    }

    /// IPv4 address stored the way SoftEther's `PackAddIp` does it.
    pub fn add_ipv4(&mut self, name: &str, ip: u32) {
        self.add_bool(&format!("{name}@ipv6_bool"), false);
        self.add_data(&format!("{name}@ipv6_array"), &[0u8; 16]);
        self.add_int(&format!("{name}@ipv6_scope_id"), 0);
        self.add_int(name, ip);
    }

    pub fn element(&self, name: &str) -> Option<&Element> {
        self.elements.iter().find(|e| same_name(&e.name, name))
    }

    pub fn value(&self, name: &str) -> Option<&PackValue> {
        self.element(name)?.values.first()
    }

    /// The first value as `u32`; a 64-bit value is truncated to its low 32 bits.
    pub fn int(&self, name: &str) -> Option<u32> {
        match self.value(name)? {
            PackValue::Int(v) => Some(*v),
            PackValue::Int64(v) => Some(*v as u32),
            _ => None,
        }
    }

    pub fn int64(&self, name: &str) -> Option<u64> {
        match self.value(name)? {
            PackValue::Int64(v) => Some(*v),
            PackValue::Int(v) => Some(u64::from(*v)),
            _ => None,
        }
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        match self.value(name)? {
            PackValue::Str(s) | PackValue::Unistr(s) => Some(s),
            _ => None,
        }
    }

    pub fn data(&self, name: &str) -> Option<&[u8]> {
        match self.value(name)? {
            PackValue::Data(d) => Some(d),
            _ => None,
        }
    }

    fn values(&self, name: &str) -> &[PackValue] {
        self.element(name).map_or(&[], |e| &e.values)
    }

    pub fn ints(&self, name: &str) -> Vec<u32> {
        self.values(name)
            .iter()
            .filter_map(|v| match v {
                PackValue::Int(n) => Some(*n),
                PackValue::Int64(n) => Some(*n as u32),
                _ => None,
            })
            .collect()
    }

    pub fn int64s(&self, name: &str) -> Vec<u64> {
        self.values(name)
            .iter()
            .filter_map(|v| match v {
                PackValue::Int64(n) => Some(*n),
                PackValue::Int(n) => Some(u64::from(*n)),
                _ => None,
            })
            .collect()
    }

    pub fn strs(&self, name: &str) -> Vec<&str> {
        self.values(name)
            .iter()
            .filter_map(|v| match v {
                PackValue::Str(s) | PackValue::Unistr(s) => Some(s.as_str()),
                _ => None,
            })
            .collect()
    }

    pub fn datas(&self, name: &str) -> Vec<&[u8]> {
        self.values(name)
            .iter()
            .filter_map(|v| match v {
                PackValue::Data(d) => Some(d.as_slice()),
                _ => None,
            })
            .collect()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let u32be = |out: &mut Vec<u8>, v: u32| out.extend_from_slice(&v.to_be_bytes());
        u32be(&mut out, self.elements.len() as u32);
        for e in &self.elements {
            u32be(&mut out, e.name.len() as u32 + 1);
            out.extend_from_slice(e.name.as_bytes());
            u32be(&mut out, e.values.first().map_or(0, PackValue::type_code));
            u32be(&mut out, e.values.len() as u32);
            for v in &e.values {
                match v {
                    PackValue::Int(n) => u32be(&mut out, *n),
                    PackValue::Data(d) => {
                        u32be(&mut out, d.len() as u32);
                        out.extend_from_slice(d);
                    }
                    PackValue::Str(s) => {
                        u32be(&mut out, s.len() as u32);
                        out.extend_from_slice(s.as_bytes());
                    }
                    PackValue::Unistr(s) => {
                        u32be(&mut out, s.len() as u32 + 1);
                        out.extend_from_slice(s.as_bytes());
                        out.push(0);
                    }
                    PackValue::Int64(n) => out.extend_from_slice(&n.to_be_bytes()),
                }
            }
        }
        out
    }

    /// Parses a serialized pack. Values of an element all take the element's type. Duplicate names are kept as read.
    pub fn parse(bytes: &[u8]) -> Result<Pack, PackError> {
        let mut r = Reader { bytes, pos: 0 };
        let count = r.u32()?;
        if count >= 4096 {
            return Err(PackError::Truncated);
        }
        let mut elements = Vec::new();
        for _ in 0..count {
            let name_len = i64::from(r.u32()?) - 1;
            if !(0..64).contains(&name_len) {
                return Err(PackError::BadName);
            }
            let name = String::from_utf8_lossy(r.take(name_len as usize)?).into_owned();
            let ty = r.u32()?;
            let n = r.u32()?;
            if n >= 65536 {
                return Err(PackError::Truncated);
            }
            let mut values = Vec::new();
            for _ in 0..n {
                values.push(match ty {
                    0 => PackValue::Int(r.u32()?),
                    1 => {
                        let len = r.u32()? as usize;
                        PackValue::Data(r.take(len)?.to_vec())
                    }
                    2 => {
                        let len = r.u32()? as usize;
                        PackValue::Str(String::from_utf8_lossy(r.take(len)?).into_owned())
                    }
                    3 => {
                        let len = r.u32()? as usize;
                        let b = r.take(len)?;
                        let b = b.strip_suffix(&[0]).unwrap_or(b);
                        PackValue::Unistr(String::from_utf8_lossy(b).into_owned())
                    }
                    4 => {
                        let hi = u64::from(r.u32()?);
                        let lo = u64::from(r.u32()?);
                        PackValue::Int64(hi << 32 | lo)
                    }
                    _ => return Err(PackError::BadType(ty)),
                });
            }
            elements.push(Element { name, values });
        }
        Ok(Pack { elements })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PackError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.bytes.len()).ok_or(PackError::Truncated)?;
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, PackError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use vpngate_testkit::golden::{load, unhex};

    fn value_from_json(v: &Value) -> PackValue {
        let (k, x) = v.as_object().unwrap().iter().next().unwrap();
        match k.as_str() {
            "int" => PackValue::Int(x.as_u64().unwrap() as u32),
            "int64" => PackValue::Int64(x.as_u64().unwrap()),
            "str" => PackValue::Str(x.as_str().unwrap().into()),
            "unistr" => PackValue::Unistr(x.as_str().unwrap().into()),
            "data" => PackValue::Data(unhex(x.as_str().unwrap())),
            other => panic!("unknown value kind {other}"),
        }
    }

    fn error_name(e: &PackError) -> String {
        match e {
            PackError::Truncated => "truncated".into(),
            PackError::BadName => "badName".into(),
            PackError::BadType(t) => format!("badType({t})"),
        }
    }

    #[test]
    fn golden() {
        let v = load("pack");
        let cases = v["cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let hex = unhex(c["hex"].as_str().unwrap());
            match c["op"].as_str().unwrap() {
                "serialize" => {
                    let mut p = Pack::new();
                    for e in c["elements"].as_array().unwrap() {
                        let vals: Vec<PackValue> =
                            e["values"].as_array().unwrap().iter().map(value_from_json).collect();
                        p.add_values(e["name"].as_str().unwrap(), vals);
                    }
                    assert_eq!(p.serialize(), hex, "{name}");
                }
                "parse" => match Pack::parse(&hex) {
                    Ok(p) => {
                        let elements = c["elements"].as_array().expect(name);
                        assert_eq!(p.elements().len(), elements.len(), "{name}");
                        for (got, want) in p.elements().iter().zip(elements) {
                            assert_eq!(got.name, want["name"].as_str().unwrap(), "{name}");
                            let vals: Vec<PackValue> =
                                want["values"].as_array().unwrap().iter().map(value_from_json).collect();
                            assert_eq!(got.values, vals, "{name}");
                        }
                        assert_eq!(p.serialize(), unhex(c["reserialized"].as_str().unwrap()), "{name}");
                    }
                    Err(e) => assert_eq!(error_name(&e), c["error"].as_str().expect(name), "{name}"),
                },
                op => panic!("unknown op {op}"),
            }
        }
    }

    #[test]
    fn duplicate_names_are_replaced_case_insensitively() {
        let mut p = Pack::new();
        p.add_int("HubName", 1);
        p.add_int("hubname", 2);
        assert_eq!(p.elements().len(), 1);
        assert_eq!(p.int("HUBNAME"), Some(2));
    }

    #[test]
    fn accessors() {
        let mut p = Pack::new();
        p.add_int64("big", 0x1_0000_0005);
        p.add_int("small", 7);
        p.add_ints("Port", &[443, 992]);
        p.add_uni("u", "x");
        p.add_data("d", &[1, 2]);
        p.add_ipv4("ip", 0x01020304);
        assert_eq!(p.int("big"), Some(5));
        assert_eq!(p.int64("small"), Some(7));
        assert_eq!(p.ints("port"), vec![443, 992]);
        assert_eq!(p.str("u"), Some("x"));
        assert_eq!(p.str("d"), None);
        assert_eq!(p.data("d"), Some(&[1u8, 2][..]));
        assert_eq!(p.int("ip"), Some(0x01020304));
        assert_eq!(p.data("ip@ipv6_array").map(<[u8]>::len), Some(16));
        assert!(p.ints("missing").is_empty());
    }

    #[test]
    fn every_prefix_of_a_pack_is_truncated() {
        let mut p = Pack::new();
        p.add_str("s", "hello");
        p.add_int64("n", 1);
        let full = p.serialize();
        for n in 0..full.len() {
            assert!(Pack::parse(&full[..n]).is_err(), "prefix {n}");
        }
        assert_eq!(Pack::parse(&full).unwrap(), p);
    }
}
