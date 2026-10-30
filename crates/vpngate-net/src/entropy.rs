//! Every random value the protocol layer draws, plus what the login pack says about the host.
//! Production uses the system generator; the golden transcripts inject a replaying one.

pub trait Entropy: Send {
    fn bytes(&mut self, n: usize) -> Vec<u8>;
    /// Uniform in `0..n` (n > 0).
    fn below(&mut self, n: usize) -> usize;
}

pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        getrandom::getrandom(&mut v).expect("system random generator");
        v
    }

    fn below(&mut self, n: usize) -> usize {
        // Rejection sampling keeps the draw uniform.
        let n = n as u64;
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).expect("system random generator");
            let v = u64::from_le_bytes(b);
            if v < zone {
                return (v % n) as usize;
            }
        }
    }
}

/// What the login pack says about the machine it runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEnvironment {
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
}
