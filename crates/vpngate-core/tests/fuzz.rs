//! Property tests: the port of `Tests/Fuzz/FuzzTests.swift`. Parsers must never panic on arbitrary input and
//! the codecs must round trip. `PROPTEST_CASES` raises or lowers the case count (default 2000).

use proptest::prelude::*;
use vpngate_core::data_phase::{self, DataPhaseDecoder, DataPhaseItem};
use vpngate_core::http_head::HttpHead;
use vpngate_core::pack::{Pack, PackValue};
use vpngate_core::{packets, server_list, validation};

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    ProptestConfig { cases, ..ProptestConfig::default() }
}

fn pack_value() -> impl Strategy<Value = PackValue> {
    prop_oneof![
        any::<u32>().prop_map(PackValue::Int),
        proptest::collection::vec(any::<u8>(), 0..300).prop_map(PackValue::Data),
        "[ -~]{0,30}".prop_map(PackValue::Str),
        prop_oneof![
            Just("".to_string()),
            Just("é".to_string()),
            Just("日本語".to_string()),
            Just("😀 emoji".to_string())
        ]
        .prop_map(PackValue::Unistr),
        any::<u64>().prop_map(PackValue::Int64),
    ]
}

fn random_pack() -> impl Strategy<Value = Pack> {
    proptest::collection::vec(pack_value(), 0..12).prop_map(|values| {
        let mut p = Pack::new();
        for (i, v) in values.into_iter().enumerate() {
            p.add(&format!("e{i}_name"), v);
        }
        p
    })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn pack_parse_random_bytes_never_panics(b in proptest::collection::vec(any::<u8>(), 0..200)) {
        let _ = Pack::parse(&b);
    }

    #[test]
    fn pack_parse_mutated_valid_packs_never_panics(
        p in random_pack(),
        edits in proptest::collection::vec((0u8..3, any::<usize>(), any::<u8>()), 1..5),
    ) {
        let mut b = p.serialize();
        for (kind, at, byte) in edits {
            match kind {
                0 if !b.is_empty() => { let i = at % b.len(); b[i] = byte; }
                1 => { let n = (at % 9).min(b.len()); b.truncate(b.len() - n); }
                _ => { let i = at % (b.len() + 1); b.insert(i, byte); }
            }
        }
        let _ = Pack::parse(&b);
    }

    #[test]
    fn pack_roundtrip_holds_for_random_packs(p in random_pack()) {
        prop_assert_eq!(Pack::parse(&p.serialize()).unwrap(), p);
    }

    #[test]
    fn data_phase_decoder_never_panics(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 1..7)) {
        let mut d = DataPhaseDecoder::new(false);
        for c in chunks {
            if d.feed(&c).is_err() {
                break;
            }
        }
    }

    #[test]
    fn data_phase_valid_streams_survive_random_chunking(
        frames in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..400), 1..7),
        junk in proptest::collection::vec(any::<u8>(), 0..100),
        sizes in proptest::collection::vec(1usize..20, 1..64),
    ) {
        let mut stream = data_phase::encode(&frames);
        stream.extend(data_phase::encode_keep_alive(&junk));
        let mut d = DataPhaseDecoder::new(false);
        let (mut got, mut i, mut s) = (Vec::new(), 0, sizes.iter().cycle());
        while i < stream.len() {
            let n = *s.next().unwrap();
            for item in d.feed(&stream[i..(i + n).min(stream.len())]).unwrap() {
                if let DataPhaseItem::Frame(f) = item {
                    got.push(f);
                }
            }
            i += n;
        }
        prop_assert_eq!(got, frames);
    }

    #[test]
    fn packet_parsers_never_panic(b in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = packets::ipv4_parse(&b);
        let _ = packets::udp_parse(&b);
        let _ = packets::ArpPacket::parse(&b);
        let _ = packets::DhcpMessage::parse(&b);
        let _ = packets::ipv6_parse(&b);
        let _ = HttpHead::parse(&b);
        // structurally plausible DHCP with random options
        let mut d = packets::DhcpMessage::new(packets::DhcpType::Offer, 1, [1, 2, 3, 4, 5, 6]).encode();
        d[0] = 2;
        d.truncate(240);
        d.extend_from_slice(&b);
        let _ = packets::DhcpMessage::parse(&d);
    }

    #[test]
    fn server_list_parser_never_panics(
        edits in proptest::collection::vec((any::<usize>(), 0usize..7), 0..30),
        noise in proptest::collection::vec(any::<u8>(), 0..500),
    ) {
        let base = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/Fixtures/vpngate-snapshot.csv"))
            .unwrap();
        let mut chars: Vec<char> = base.chars().take(3000).collect();
        for (at, c) in edits {
            if !chars.is_empty() {
                let i = at % chars.len();
                chars[i] = [',', '\n', '\r', 'a', '=', 'é', ' '][c];
            }
        }
        let _ = server_list::parse(&chars.into_iter().collect::<String>());
        let _ = server_list::parse(&String::from_utf8_lossy(&noise));
    }

    #[test]
    fn input_validation_never_panics(b in proptest::collection::vec(any::<u8>(), 0..40)) {
        let s = String::from_utf8_lossy(&b);
        let _ = validation::is_local_address(&s);
        let _ = validation::is_non_public_ipv4(&s);
        let _ = validation::normalized_fingerprint(&s);
        let _ = validation::parse_mac_address(&s);
        let _ = vpngate_core::server_filter::ServerFilter::log_weeks(&s);
        if validation::is_valid_host(&s) {
            prop_assert!(!s.starts_with('-'), "valid host starting with '-': {s}");
        }
    }
}
