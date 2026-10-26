//! ChaCha20-Poly1305 AEAD (RFC 8439) with an empty AAD, as SoftEther's UDP acceleration v2 uses it.
//!
//! Written by hand because the sandbox that builds this crate cannot reach crates.io; the RFC vectors and the Swift
//! golden vectors pin the behaviour. Not constant-time hardened beyond the tag comparison.

const MASK26: u32 = 0x03ff_ffff;

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn chacha_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for (i, w) in key.chunks_exact(4).enumerate() {
        init[4 + i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    }
    init[12] = counter;
    for (i, w) in nonce.chunks_exact(4).enumerate() {
        init[13 + i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

fn chacha_xor(key: &[u8; 32], nonce: &[u8; 12], first_counter: u32, data: &mut [u8]) {
    for (n, chunk) in data.chunks_mut(64).enumerate() {
        let block = chacha_block(key, first_counter.wrapping_add(n as u32), nonce);
        for (b, k) in chunk.iter_mut().zip(block) {
            *b ^= k;
        }
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// One-time authenticator (26-bit limbs).
struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let r = [
            le32(&key[0..]) & 0x03ff_ffff,
            (le32(&key[3..]) >> 2) & 0x03ff_ff03,
            (le32(&key[6..]) >> 4) & 0x03ff_c0ff,
            (le32(&key[9..]) >> 6) & 0x03f0_3fff,
            (le32(&key[12..]) >> 8) & 0x000f_ffff,
        ];
        Poly1305 { r, h: [0; 5], pad: [le32(&key[16..]), le32(&key[20..]), le32(&key[24..]), le32(&key[28..])] }
    }

    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let h = &mut self.h;
        h[0] += le32(&m[0..]) & MASK26;
        h[1] += (le32(&m[3..]) >> 2) & MASK26;
        h[2] += (le32(&m[6..]) >> 4) & MASK26;
        h[3] += (le32(&m[9..]) >> 6) & MASK26;
        h[4] += (le32(&m[12..]) >> 8) | hibit;
        let [h0, h1, h2, h3, h4] = h.map(u64::from);
        let mut d = [
            h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1,
            h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2,
            h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3,
            h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4,
            h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0,
        ];
        let mut c = 0u64;
        for (i, di) in d.iter_mut().enumerate() {
            *di += c;
            c = *di >> 26;
            h[i] = (*di as u32) & MASK26;
        }
        h[0] += (c as u32) * 5;
        let c = h[0] >> 26;
        h[0] &= MASK26;
        h[1] += c;
    }

    fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for c in &mut chunks {
            self.block(c.try_into().expect("16 bytes"), 1 << 24);
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut last = [0u8; 16];
            last[..rest.len()].copy_from_slice(rest);
            last[rest.len()] = 1;
            self.block(&last, 0);
        }
    }

    fn finish(mut self) -> [u8; 16] {
        let h = &mut self.h;
        let mut c = h[1] >> 26;
        h[1] &= MASK26;
        for limb in &mut h[2..] {
            *limb += c;
            c = *limb >> 26;
            *limb &= MASK26;
        }
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= MASK26;
        h[1] += c;

        // h - p, selected when h >= p.
        let mut g = [0u32; 5];
        let mut c = 5u32;
        for i in 0..5 {
            g[i] = h[i] + c;
            c = g[i] >> 26;
            g[i] &= MASK26;
        }
        let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);
        let keep_g = (g4 >> 31).wrapping_sub(1);
        g[4] = g4 & MASK26;
        for i in 0..5 {
            h[i] = (h[i] & !keep_g) | (g[i] & keep_g);
        }

        let w = [h[0] | h[1] << 26, h[1] >> 6 | h[2] << 20, h[2] >> 12 | h[3] << 14, h[3] >> 18 | h[4] << 8];
        let mut out = [0u8; 16];
        let mut carry = 0u64;
        for i in 0..4 {
            carry += u64::from(w[i]) + u64::from(self.pad[i]);
            out[4 * i..4 * i + 4].copy_from_slice(&(carry as u32).to_le_bytes());
            carry >>= 32;
        }
        out
    }
}

fn tag(poly_key: &[u8; 32], ciphertext: &[u8]) -> [u8; 16] {
    // Empty AAD, so the MAC input is the zero-padded ciphertext then both lengths; every block is a full block.
    let mut data = ciphertext.to_vec();
    data.resize(ciphertext.len().div_ceil(16) * 16, 0);
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    let mut p = Poly1305::new(poly_key);
    p.update(&data);
    p.finish()
}

fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    chacha_block(key, 0, nonce)[..32].try_into().expect("32 bytes")
}

/// Returns the ciphertext and the 16-byte tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut ct = plaintext.to_vec();
    chacha_xor(key, nonce, 1, &mut ct);
    let t = tag(&poly_key(key, nonce), &ct);
    (ct, t)
}

/// Verifies the tag, then returns the plaintext; `None` if authentication fails.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], expected: &[u8; 16]) -> Option<Vec<u8>> {
    let t = tag(&poly_key(key, nonce), ciphertext);
    if t.iter().zip(expected).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return None;
    }
    let mut pt = ciphertext.to_vec();
    chacha_xor(key, nonce, 1, &mut pt);
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        vpngate_testkit::golden::unhex(&s.split_whitespace().collect::<String>())
    }

    #[test]
    fn poly1305_rfc8439_2_5_2() {
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap();
        let mut p = Poly1305::new(&key);
        p.update(b"Cryptographic Forum Research Group");
        assert_eq!(p.finish().to_vec(), hex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    #[test]
    fn chacha20_block_rfc8439_2_3_2() {
        let key: [u8; 32] = (0..32u8).collect::<Vec<_>>().try_into().unwrap();
        let nonce: [u8; 12] = hex("000000090000004a00000000").try_into().unwrap();
        let block = chacha_block(&key, 1, &nonce);
        assert_eq!(block[..16].to_vec(), hex("10f1e7e4d13b5915500fdd1fa32071c4"));
        assert_eq!(block[48..].to_vec(), hex("b5129cd1de164eb9cbd083e8a2503c4e"));
    }

    #[test]
    fn aead_rfc8439_2_8_2_without_aad() {
        // Same key and nonce as the RFC; the RFC example uses a 12-byte AAD, so only the round trip is checked here.
        let key: [u8; 32] = (0x80..=0x9f).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let msg = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let (ct, t) = seal(&key, &nonce, msg);
        assert_eq!(open(&key, &nonce, &ct, &t).as_deref(), Some(&msg[..]));
        let mut bad = t;
        bad[0] ^= 1;
        assert_eq!(open(&key, &nonce, &ct, &bad), None);
    }
}
