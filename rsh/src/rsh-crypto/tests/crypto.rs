use rsh_crypto::hash::{colon_hex, digest};
use rsh_crypto::keyfile::{parse_private, parse_public, private_text, public_line};
use rsh_crypto::math::{gcd, inv_mod, mul_mod, pow_mod};
use rsh_crypto::prime::is_prime;
use rsh_crypto::{KeyPair, Rng, StreamCipher};

fn sieve(limit: usize) -> Vec<bool> {
    let mut prime = vec![true; limit + 1];
    prime[0] = false;
    prime[1] = false;
    let mut i = 2;
    while i * i <= limit {
        if prime[i] {
            let mut j = i * i;
            while j <= limit {
                prime[j] = false;
                j += i;
            }
        }
        i += 1;
    }
    prime
}

#[test]
fn modular_arithmetic_is_correct() {
    let mut rng = Rng::new();
    for _ in 0..1000 {
        let m = rng.next_u64() | 1;
        let a = rng.next_u64() % m;
        let b = rng.next_u64() % m;
        assert_eq!(mul_mod(a, b, m) as u128, (a as u128 * b as u128) % m as u128);
        if gcd(a, m) == 1 {
            let inv = inv_mod(a, m).expect("inverse exists");
            assert_eq!(mul_mod(a, inv, m), 1 % m);
        } else {
            assert!(inv_mod(a, m).is_none());
        }
    }
    for base in 0..20u64 {
        for exp in 0..20u64 {
            let naive = (0..exp).fold(1u128, |acc, _| acc * base as u128 % 1_000_003) as u64;
            assert_eq!(pow_mod(base, exp, 1_000_003), naive);
        }
    }
}

#[test]
fn miller_rabin_agrees_with_sieve() {
    let limit = 200_000;
    let table = sieve(limit);
    for (n, &prime) in table.iter().enumerate() {
        assert_eq!(is_prime(n as u64), prime, "n = {n}");
    }
    for carmichael in [561u64, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265] {
        assert!(!is_prime(carmichael), "{carmichael} is a Carmichael number");
    }
    assert!(is_prime((1u64 << 61) - 1));
    assert!(is_prime(18_446_744_073_709_551_557)); // largest 64-bit prime
    assert!(!is_prime(u64::MAX));
}

#[test]
fn keys_have_64_bit_modulus() {
    let mut rng = Rng::new();
    for _ in 0..50 {
        let pair = KeyPair::generate(&mut rng);
        let n = pair.public.n;
        assert!(n >= 1 << 62, "modulus too small: {n:x}");
        assert_eq!(pair.public.e, 65537);
        assert_eq!(pair.private.n, n);
        let m = rng.next_u64() % n;
        assert_eq!(pow_mod(pow_mod(m, pair.public.e, n), pair.private.d, n), m);
    }
}

#[test]
fn rsa_encrypt_decrypt_round_trip() {
    let mut rng = Rng::new();
    let pair = KeyPair::generate(&mut rng);
    for len in 0..100 {
        let plain = rng.bytes(len);
        let cipher = pair.public.encrypt(&plain);
        assert_eq!(cipher.len(), 4 + len.div_ceil(7) * 8);
        assert_eq!(pair.private.decrypt(&cipher).unwrap(), plain);
    }
}

#[test]
fn wrong_private_key_cannot_decrypt() {
    let mut rng = Rng::new();
    let alice = KeyPair::generate(&mut rng);
    let eve = KeyPair::generate(&mut rng);
    let session_key = rng.bytes(32);
    let cipher = alice.public.encrypt(&session_key);
    let guess = eve.private.decrypt(&cipher).unwrap();
    assert_ne!(guess, session_key);
    assert!(alice.private.decrypt(&cipher[..cipher.len() - 1]).is_err());
}

#[test]
fn signatures_verify_and_detect_changes() {
    let mut rng = Rng::new();
    let pair = KeyPair::generate(&mut rng);
    let other = KeyPair::generate(&mut rng);
    let data = b"rsh-auth session key and user".to_vec();
    let sig = pair.private.sign(&data);
    assert!(pair.public.verify(&data, sig));
    assert!(!other.public.verify(&data, sig));
    let mut changed = data.clone();
    changed[0] ^= 1;
    assert!(!pair.public.verify(&changed, sig));
    assert!(!pair.public.verify(&data, sig ^ 1));
}

#[test]
fn stream_cipher_round_trip_and_directions() {
    let mut rng = Rng::new();
    let key = rng.bytes(32);
    let plain = b"echo secret-command\n".to_vec();

    let mut data = plain.clone();
    StreamCipher::new(&key, b"rsh client to server").apply(&mut data);
    assert_ne!(data, plain);
    let mut back = data.clone();
    StreamCipher::new(&key, b"rsh client to server").apply(&mut back);
    assert_eq!(back, plain);

    let mut other_dir = plain.clone();
    StreamCipher::new(&key, b"rsh server to client").apply(&mut other_dir);
    assert_ne!(other_dir, data, "each direction needs its own keystream");

    let mut other_key = plain.clone();
    StreamCipher::new(&rng.bytes(32), b"rsh client to server").apply(&mut other_key);
    assert_ne!(other_key, data);

    // Splitting the data into pieces gives the same keystream.
    let mut pieces = plain.clone();
    let mut c = StreamCipher::new(&key, b"rsh client to server");
    let (a, b) = pieces.split_at_mut(5);
    c.apply(a);
    c.apply(b);
    assert_eq!(pieces, data);
}

#[test]
fn flipped_ciphertext_bit_flips_plaintext_bit() {
    let key = Rng::new().bytes(32);
    let plain = b"rm -i notes.txt\n".to_vec();
    let mut wire = plain.clone();
    StreamCipher::new(&key, b"c2s").apply(&mut wire);
    wire[4] ^= b'i' ^ b'f'; // attacker never sees the key
    StreamCipher::new(&key, b"c2s").apply(&mut wire);
    assert_eq!(wire, b"rm -f notes.txt\n");
}

#[test]
fn key_files_round_trip() {
    let pair = KeyPair::generate(&mut Rng::new());
    let line = public_line(&pair.public, "user@lab pc");
    let (public, comment) = parse_public(&line).unwrap();
    assert_eq!(public, pair.public);
    assert_eq!(comment, "user@lab pc");

    let private = parse_private(&private_text(&pair.private)).unwrap();
    assert_eq!((private.n, private.e, private.d), (pair.private.n, pair.private.e, pair.private.d));

    assert!(parse_public("ssh-rsa AAAA").is_err());
    assert!(parse_public("rsh-rsa zz 10001").is_err());
    assert!(parse_private("rsh-rsa-private 1 2").is_err());
}

#[test]
fn fingerprint_format() {
    let fp = KeyPair::generate(&mut Rng::new()).public.fingerprint();
    assert_eq!(fp.len(), 23);
    assert_eq!(fp.matches(':').count(), 7);
    assert_eq!(colon_hex(0x0123_4567_89ab_cdef), "01:23:45:67:89:ab:cd:ef");
    assert_ne!(digest(b"a"), digest(b"b"));
}
