use crate::math::{mul_mod, pow_mod};
use crate::random::Rng;

const BASES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for &p in &BASES {
        if n.is_multiple_of(p) {
            return n == p;
        }
    }
    let mut d = n - 1;
    let mut s = 0;
    while d.is_multiple_of(2) {
        d /= 2;
        s += 1;
    }
    'witness: for &a in &BASES {
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..s {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

pub fn random_prime(rng: &mut Rng, bits: u32) -> u64 {
    let top = 1u64 << (bits - 1);
    let mask = (top << 1).wrapping_sub(1);
    loop {
        let candidate = (rng.next_u64() & mask) | top | 1;
        if is_prime(candidate) {
            return candidate;
        }
    }
}
