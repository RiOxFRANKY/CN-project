use std::io;

use crate::hash::{colon_hex, digest};
use crate::math::{gcd, inv_mod, pow_mod};
use crate::prime::random_prime;
use crate::random::Rng;

const EXPONENT: u64 = 65537;
const PLAIN_BLOCK: usize = 7;
const CIPHER_BLOCK: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub n: u64,
    pub e: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct PrivateKey {
    pub n: u64,
    pub e: u64,
    pub d: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct KeyPair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl KeyPair {
    pub fn generate(rng: &mut Rng) -> Self {
        loop {
            let p = random_prime(rng, 32);
            let q = random_prime(rng, 32);
            if p == q {
                continue;
            }
            let phi = (p - 1) * (q - 1);
            if gcd(EXPONENT, phi) != 1 {
                continue;
            }
            let Some(d) = inv_mod(EXPONENT, phi) else {
                continue;
            };
            let n = p * q;
            return KeyPair {
                public: PublicKey { n, e: EXPONENT },
                private: PrivateKey { n, e: EXPONENT, d },
            };
        }
    }
}

impl PublicKey {
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
        for chunk in data.chunks(PLAIN_BLOCK) {
            let mut block = [0u8; 8];
            block[1..1 + chunk.len()].copy_from_slice(chunk);
            let m = u64::from_be_bytes(block);
            out.extend_from_slice(&pow_mod(m, self.e, self.n).to_be_bytes());
        }
        out
    }

    pub fn verify(&self, data: &[u8], signature: u64) -> bool {
        pow_mod(signature, self.e, self.n) == digest(data) % self.n
    }

    pub fn fingerprint(&self) -> String {
        let mut bytes = self.n.to_be_bytes().to_vec();
        bytes.extend_from_slice(&self.e.to_be_bytes());
        colon_hex(digest(&bytes))
    }
}

impl PrivateKey {
    pub fn public(&self) -> PublicKey {
        PublicKey {
            n: self.n,
            e: self.e,
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "bad ciphertext");
        if data.len() < 4 {
            return Err(bad());
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let body = &data[4..];
        if body.len() != len.div_ceil(PLAIN_BLOCK) * CIPHER_BLOCK {
            return Err(bad());
        }
        let mut out = Vec::with_capacity(len);
        for chunk in body.chunks(CIPHER_BLOCK) {
            let c = u64::from_be_bytes(chunk.try_into().map_err(|_| bad())?);
            let m = pow_mod(c, self.d, self.n).to_be_bytes();
            let take = (len - out.len()).min(PLAIN_BLOCK);
            out.extend_from_slice(&m[1..1 + take]);
        }
        Ok(out)
    }

    pub fn sign(&self, data: &[u8]) -> u64 {
        pow_mod(digest(data) % self.n, self.d, self.n)
    }
}
