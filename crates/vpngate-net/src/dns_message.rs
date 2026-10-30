//! A tiny, read-mostly DNS message parser/writer: just enough to read a query's question name, pull A-record answers
//! out of a response (for dynamic routing) and build NXDOMAIN/SERVFAIL replies. Not a general DNS library.

struct Header {
    ancount: usize,
    qdcount: usize,
}

fn header(p: &[u8]) -> Option<Header> {
    if p.len() < 12 {
        return None;
    }
    Some(Header {
        ancount: usize::from(p[6]) << 8 | usize::from(p[7]),
        qdcount: usize::from(p[4]) << 8 | usize::from(p[5]),
    })
}

/// The first question's name, lowercased and dot-joined with no trailing dot; `None` if malformed or absent.
pub fn query_name(p: &[u8]) -> Option<String> {
    let h = header(p)?;
    if h.qdcount < 1 {
        return None;
    }
    read_name(p, 12).map(|(name, _)| name.to_lowercase())
}

/// A recursive type-A query for `name` (a plain dotted DNS name).
pub fn a_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = vec![(id >> 8) as u8, (id & 0xff) as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        q.push(bytes.len() as u8);
        q.extend_from_slice(bytes);
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
    q
}

/// Resolved IPv4 addresses (type-A records) in the answer section of a response.
pub fn resolved_ipv4_addresses(p: &[u8]) -> Vec<String> {
    let Some(h) = header(p) else { return Vec::new() };
    let mut offset = 12;
    for _ in 0..h.qdcount {
        let Some(after_name) = skip_name(p, offset) else { return Vec::new() };
        offset = after_name + 4; // QTYPE + QCLASS
    }
    let mut out = Vec::new();
    for _ in 0..h.ancount {
        let Some(after_name) = skip_name(p, offset) else { break };
        if after_name + 10 > p.len() {
            break;
        }
        offset = after_name;
        let kind = usize::from(p[offset]) << 8 | usize::from(p[offset + 1]);
        let rdlength = usize::from(p[offset + 8]) << 8 | usize::from(p[offset + 9]);
        offset += 10;
        if offset + rdlength > p.len() {
            break;
        }
        if kind == 1 && rdlength == 4 {
            out.push(format!("{}.{}.{}.{}", p[offset], p[offset + 1], p[offset + 2], p[offset + 3]));
        }
        offset += rdlength;
    }
    out
}

/// NXDOMAIN (RCODE 3): what a `block` domain gets back.
pub fn blocked_response(query: &[u8]) -> Vec<u8> {
    fixed_rcode_response(query, 3)
}

/// SERVFAIL (RCODE 2): whenever a query cannot be answered safely (no usable upstream, it failed, the query itself did
/// not parse). Never falls back to answering some other way, which would risk a leak or a lie.
pub fn servfail_response(query: &[u8]) -> Vec<u8> {
    fixed_rcode_response(query, 2)
}

fn fixed_rcode_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }
    let mut out = query.to_vec();
    out[2] |= 0x80; // QR = 1 (this is a response)
    out[3] = (out[3] & 0xf0) | (rcode & 0x0f);
    out[6..12].fill(0); // ANCOUNT, NSCOUNT, ARCOUNT = 0
                        // Drop anything past the question section (there should be none in a query, but be safe).
    if let Some(after_question) = skip_name(&out, 12).map(|o| o + 4) {
        if after_question <= out.len() {
            out.truncate(after_question);
        }
    }
    out
}

/// Advances past one (possibly pointer-compressed) name; returns the offset right after it.
fn skip_name(p: &[u8], offset: usize) -> Option<usize> {
    let (mut o, mut steps) = (offset, 0);
    loop {
        if o >= p.len() || steps >= 128 {
            return None;
        }
        steps += 1;
        let len = usize::from(p[o]);
        if len == 0 {
            return Some(o + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(o + 2); // pointer: 2 bytes, terminal
        }
        o += 1 + len;
    }
}

/// Like `skip_name`, but also decodes the labels (pointers are not followed: a question name is never compressed in a
/// message a resolver sends us).
fn read_name(p: &[u8], offset: usize) -> Option<(String, usize)> {
    let (mut o, mut steps) = (offset, 0);
    let mut labels: Vec<String> = Vec::new();
    loop {
        if o >= p.len() || steps >= 128 {
            return None;
        }
        steps += 1;
        let len = usize::from(p[o]);
        if len == 0 {
            return Some((labels.join("."), o + 1));
        }
        if len & 0xc0 == 0xc0 || o + 1 + len > p.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&p[o + 1..o + 1 + len]).into_owned());
        o += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    pub(crate) fn build_query(name: &str) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        p.extend(encode_name(name));
        p.extend_from_slice(&[0, 1, 0, 1]);
        p
    }

    pub(crate) fn build_response(query: &[u8], answers: &[&str]) -> Vec<u8> {
        let mut p = query.to_vec();
        p[2] |= 0x80;
        p[6] = (answers.len() >> 8) as u8;
        p[7] = (answers.len() & 0xff) as u8;
        for ip in answers {
            p.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0x3c, 0, 4]);
            p.extend(ip.split('.').map(|o| o.parse::<u8>().unwrap()));
        }
        p
    }

    #[test]
    fn query_name_round_trips() {
        assert_eq!(query_name(&build_query("www.example.com")).as_deref(), Some("www.example.com"));
        assert_eq!(query_name(&build_query("WWW.Example.COM")).as_deref(), Some("www.example.com"));
        assert_eq!(query_name(&a_query("a.b.test", 7)).as_deref(), Some("a.b.test"));
    }

    #[test]
    fn resolved_ipv4_addresses_reads_a_records() {
        let r = build_response(&build_query("example.com"), &["93.184.216.34", "1.2.3.4"]);
        assert_eq!(resolved_ipv4_addresses(&r), ["93.184.216.34", "1.2.3.4"]);
        assert!(resolved_ipv4_addresses(&build_query("example.com")).is_empty());
    }

    #[test]
    fn truncated_answers_stop_cleanly() {
        let mut r = build_response(&build_query("example.com"), &["93.184.216.34", "1.2.3.4"]);
        r.truncate(r.len() - 3);
        assert_eq!(resolved_ipv4_addresses(&r), ["93.184.216.34"]);
        assert!(resolved_ipv4_addresses(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn blocked_response_is_nxdomain_with_no_answers() {
        let q = build_query("example.com");
        let r = blocked_response(&q);
        assert_ne!(r[2] & 0x80, 0, "QR bit");
        assert_eq!(r[3] & 0x0f, 3);
        assert_eq!(usize::from(r[6]) << 8 | usize::from(r[7]), 0);
        assert_eq!(query_name(&r).as_deref(), Some("example.com"), "question survives");
    }

    #[test]
    fn servfail_response_sets_rcode_2_and_drops_trailing_sections() {
        let q = build_query("example.com");
        assert_eq!(servfail_response(&q)[3] & 0x0f, 2);
        let with_answers = build_response(&q, &["1.2.3.4"]);
        assert_eq!(servfail_response(&with_answers).len(), q.len());
        assert_eq!(servfail_response(&[0x12, 0x34]), [0x12, 0x34], "too short to answer: echoed back");
    }

    #[test]
    fn compressed_or_looping_question_names_are_rejected() {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0, 1, 0, 1];
        assert_eq!(query_name(&q), None);
        q.truncate(14);
        assert_eq!(query_name(&q), None);
    }

    #[test]
    fn a_query_caps_labels_at_63_bytes() {
        let q = a_query(&format!("{}.test", "a".repeat(80)), 1);
        assert_eq!(q[12], 63);
    }
}
