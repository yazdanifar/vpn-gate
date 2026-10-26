//! RC4 (ARC4) stream cipher: VPNGate.dat body decryption (key = SHA-1 of the seed).

pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// An empty key leaves the state at the identity permutation, as the Swift version does.
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (n, b) in s.iter_mut().enumerate() {
            *b = n as u8;
        }
        if !key.is_empty() {
            let mut j = 0u8;
            for i in 0..256 {
                j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
                s.swap(i, usize::from(j));
            }
        }
        Rc4 { s, i: 0, j: 0 }
    }

    pub fn process(&mut self, bytes: &mut [u8]) {
        for b in bytes {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let t = self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]);
            *b ^= self.s[usize::from(t)];
        }
    }

    pub fn cipher(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        Rc4::new(key).process(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::{load, unhex};

    #[test]
    fn golden() {
        let v = load("crypto");
        let group = v["cases"].as_array().unwrap().iter().find(|g| g["name"] == "rc4").unwrap();
        for c in group["cases"].as_array().unwrap() {
            let out = Rc4::cipher(&unhex(c["key"].as_str().unwrap()), &unhex(c["input"].as_str().unwrap()));
            assert_eq!(out, unhex(c["output"].as_str().unwrap()));
        }
    }

    #[test]
    fn streaming_matches_one_shot_and_is_symmetric() {
        let data: Vec<u8> = (0..=255).collect();
        let mut r = Rc4::new(b"key");
        let (a, b) = data.split_at(100);
        let mut out = a.to_vec();
        r.process(&mut out);
        let mut rest = b.to_vec();
        r.process(&mut rest);
        out.extend(rest);
        assert_eq!(out, Rc4::cipher(b"key", &data));
        assert_eq!(Rc4::cipher(b"key", &out), data);
    }

    #[test]
    fn empty_key_is_identity_permutation_keystream() {
        // Matches Swift: no key schedule is run, so the output is still deterministic and reversible.
        let enc = Rc4::cipher(&[], b"abc");
        assert_eq!(Rc4::cipher(&[], &enc), b"abc");
    }
}
