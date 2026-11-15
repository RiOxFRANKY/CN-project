//! Factoring the toy RSA modulus. Run with
//! `cargo test --release --test attack -- --nocapture` to see the table.

use std::time::Instant;

use rsh_crypto::math::{gcd, inv_mod, mul_mod};
use rsh_crypto::prime::{is_prime, random_prime};
use rsh_crypto::{KeyPair, PrivateKey, Rng};

fn trial_division(n: u64) -> u64 {
    if n.is_multiple_of(2) {
        return 2;
    }
    let mut d = 3;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return d;
        }
        d += 2;
    }
    n
}

/// Pollard's rho with Brent's cycle detection.
fn pollard_rho(n: u64, rng: &mut Rng) -> u64 {
    if n.is_multiple_of(2) {
        return 2;
    }
    loop {
        let c = rng.next_u64() % (n - 1) + 1;
        let f = |x: u64| ((mul_mod(x, x, n) as u128 + c as u128) % n as u128) as u64;
        let mut y = rng.next_u64() % n;
        let (mut x, mut ys) = (y, y);
        let (mut g, mut r, mut q) = (1, 1u64, 1);
        while g == 1 {
            x = y;
            for _ in 0..r {
                y = f(y);
            }
            let mut k = 0;
            while k < r && g == 1 {
                ys = y;
                for _ in 0..128.min(r - k) {
                    y = f(y);
                    q = mul_mod(q, x.abs_diff(y), n);
                }
                g = gcd(q, n);
                k += 128;
            }
            r *= 2;
        }
        if g == n {
            // The batch overshot: redo it one step at a time.
            loop {
                ys = f(ys);
                g = gcd(x.abs_diff(ys), n);
                if g > 1 {
                    break;
                }
            }
        }
        if g != n {
            return g;
        }
    }
}

fn break_key(n: u64, e: u64, rng: &mut Rng) -> PrivateKey {
    let p = pollard_rho(n, rng);
    let q = n / p;
    let d = inv_mod(e, (p - 1) * (q - 1)).unwrap();
    PrivateKey { n, e, d }
}

#[test]
fn pollard_rho_finds_factors() {
    let mut rng = Rng::new();
    for bits in [8, 12, 16, 20, 24, 28, 32] {
        for _ in 0..20 {
            let p = random_prime(&mut rng, bits);
            let q = random_prime(&mut rng, bits);
            let n = p * q;
            let f = pollard_rho(n, &mut rng);
            assert!(f == p || f == q, "n={n} f={f}");
            assert!(is_prime(f));
        }
    }
}

#[test]
fn public_key_alone_recovers_session_key() {
    let mut rng = Rng::new();
    for _ in 0..10 {
        let host = KeyPair::generate(&mut rng);
        let session_key = rng.bytes(32);
        let wire = host.public.encrypt(&session_key);

        let start = Instant::now();
        let cracked = break_key(host.public.n, host.public.e, &mut rng);
        let elapsed = start.elapsed();

        assert_eq!(cracked.d, host.private.d);
        assert_eq!(cracked.decrypt(&wire).unwrap(), session_key);
        let data = b"rsh-auth forged";
        assert!(host.public.verify(data, cracked.sign(data)));
        println!("broke {:016x} in {:.2} ms", host.public.n, elapsed.as_secs_f64() * 1e3);
    }
}

#[test]
fn factoring_time_by_modulus_size() {
    let mut rng = Rng::new();
    let trials = 20;
    println!("modulus_bits trial_ms rho_ms");
    for prime_bits in [12u32, 16, 20, 24, 28, 32] {
        let moduli: Vec<u64> = (0..trials)
            .map(|_| random_prime(&mut rng, prime_bits) * random_prime(&mut rng, prime_bits))
            .collect();

        // Trial division gets slow fast; stop it at 48-bit moduli.
        let trial_ms = if prime_bits <= 24 {
            let start = Instant::now();
            for &n in &moduli {
                assert!(n % trial_division(n) == 0);
            }
            format!("{:.3}", start.elapsed().as_secs_f64() * 1e3 / trials as f64)
        } else {
            "-".to_string()
        };

        let start = Instant::now();
        for &n in &moduli {
            let f = pollard_rho(n, &mut rng);
            assert!(f > 1 && f < n && n.is_multiple_of(f));
        }
        let rho_ms = start.elapsed().as_secs_f64() * 1e3 / trials as f64;
        println!("{:>12} {:>8} {:>6.3}", prime_bits * 2, trial_ms, rho_ms);
    }
}
