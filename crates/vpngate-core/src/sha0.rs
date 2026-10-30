//! SHA-0 (FIPS 180, 1993): SHA-1 without the 1-bit rotate in the message schedule. SoftEther uses it for
//! secure-password authentication and the VPN Gate probe.

pub const DIGEST_LENGTH: usize = 20;

pub fn hash(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&(data.len() as u64).wrapping_mul(8).to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in padded.chunks_exact(64) {
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (hv, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *hv = hv.wrapping_add(v);
        }
    }

    let mut out = [0u8; DIGEST_LENGTH];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::{load, unhex};

    #[test]
    fn golden() {
        let v = load("crypto");
        let group = v["cases"].as_array().unwrap().iter().find(|g| g["name"] == "sha0").unwrap();
        for c in group["cases"].as_array().unwrap() {
            let input = unhex(c["input"].as_str().unwrap());
            assert_eq!(hash(&input).to_vec(), unhex(c["digest"].as_str().unwrap()), "{} bytes", input.len());
        }
    }

    #[test]
    fn fips_180_abc() {
        // The original FIPS 180 test vector for "abc".
        assert_eq!(hash(b"abc").to_vec(), unhex("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"));
    }
}
