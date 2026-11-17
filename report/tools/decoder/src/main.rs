//! keygen <dir>  : make a host key the way KeyPair::generate does, keeping p and q
//! decode <dir>  : decode a recorded rsh session (cap.log) with the host private key
use std::env;
use std::fs;
use std::path::Path;

use rsh_crypto::hash::{digest, fnv1a};
use rsh_crypto::keyfile;
use rsh_crypto::math::{gcd, inv_mod, mul_mod, pow_mod};
use rsh_crypto::prime::is_prime;
use rsh_crypto::random::splitmix64;
use rsh_crypto::{KeyPair, PrivateKey, PublicKey, Rng, StreamCipher};
use rsh_main::auth::auth_data;
use rsh_main::message::Message;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ") }
fn js(s: &str) -> String { format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r")) }

fn prime_with_trace(rng: &mut Rng, bits: u32) -> (u64, u32) {
    let top = 1u64 << (bits - 1);
    let mask = (top << 1).wrapping_sub(1);
    let mut tries = 0;
    loop {
        tries += 1;
        let c = (rng.next_u64() & mask) | top | 1;
        if is_prime(c) { return (c, tries); }
    }
}

fn mr_trace(n: u64) -> String {
    let mut d = n - 1; let mut s = 0;
    while d % 2 == 0 { d /= 2; s += 1; }
    let mut parts = Vec::new();
    for a in [2u64, 3, 5] {
        let mut x = pow_mod(a, d, n);
        let mut seq = vec![x];
        let mut i = 1;
        while x != 1 && x != n - 1 && i < s { x = mul_mod(x, x, n); seq.push(x); i += 1; }
        parts.push(format!("{{\"a\":{a},\"seq\":[{}]}}", seq.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",")));
    }
    format!("{{\"n\":{n},\"s\":{s},\"d\":{d},\"witnesses\":[{}]}}", parts.join(","))
}

fn keygen(dir: &Path) {
    let mut rng = Rng::new();
    loop {
        let (p, tp) = prime_with_trace(&mut rng, 32);
        let (q, tq) = prime_with_trace(&mut rng, 32);
        if p == q { continue; }
        let phi = (p - 1) * (q - 1);
        if gcd(65537, phi) != 1 { continue; }
        let d = inv_mod(65537, phi).unwrap();
        let n = p * q;
        let pair = KeyPair { public: PublicKey { n, e: 65537 }, private: PrivateKey { n, e: 65537, d } };
        keyfile::save_pair(&dir.join("host_key"), &pair, "host").unwrap();
        fs::write(dir.join("hostkey.json"), format!(
            "{{\"p\":{p},\"q\":{q},\"tries_p\":{tp},\"tries_q\":{tq},\"n\":{n},\"phi\":{phi},\"d\":{d},\"ed_mod_phi\":{},\"mr_p\":{}}}\n",
            mul_mod(65537, d, phi), mr_trace(p))).unwrap();
        return;
    }
}

fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

/// The cipher written out step by step, checked against StreamCipher.
struct Trace { s: [u64; 4] }
impl Trace {
    fn next(&mut self) -> u64 {
        let s = &mut self.s;
        let r = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = s[3].rotate_left(45);
        r
    }
}

fn cipher_setup(key: &[u8], label: &[u8]) -> String {
    let seed0 = fnv1a(label);
    let mut seed = seed0;
    let mut state = [0u64; 4];
    for s in state.iter_mut() { *s = splitmix64(&mut seed); }
    let init = state;
    let words: Vec<u64> = key.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    for (i, w) in words.iter().enumerate() { state[i % 4] ^= w; }
    let mixed = state;
    let mut t = Trace { s: state };
    for _ in 0..16 { t.next(); }
    let warmed = t.s;
    let first: Vec<u64> = (0..4).map(|_| t.next()).collect();
    // check against the library
    let mut ks = vec![0u8; 32];
    StreamCipher::new(key, label).apply(&mut ks);
    let mine: Vec<u8> = first.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert_eq!(ks, mine, "trace must match StreamCipher");
    let arr = |a: &[u64]| a.iter().map(|v| format!("\"{v:016x}\"")).collect::<Vec<_>>().join(",");
    format!("{{\"label\":{},\"fnv\":\"{seed0:016x}\",\"init\":[{}],\"words\":[{}],\"mixed\":[{}],\"warmed\":[{}],\"out\":[{}],\"stream32\":{}}}",
        js(&String::from_utf8_lossy(label)), arr(&init), arr(&words), arr(&mixed), arr(&warmed), arr(&first), js(&hex(&ks)))
}

fn decode(dir: &Path) {
    let host = keyfile::load_private(&dir.join("home/host_key")).unwrap();
    let (client_pub, _) = keyfile::load_public(&dir.join("home/id_rsh.pub")).unwrap();
    // Rebuild frames in the order they completed on the wire.
    let mut buf = [Vec::new(), Vec::new()];
    let mut frames: Vec<(usize, Vec<u8>)> = Vec::new();
    for line in fs::read_to_string(dir.join("cap.log")).unwrap().lines() {
        let (tag, h) = line.split_once(' ').unwrap();
        let k = if tag == "c2s" { 0 } else { 1 };
        buf[k].extend(unhex(h));
        while buf[k].len() >= 4 {
            let len = u32::from_be_bytes(buf[k][..4].try_into().unwrap()) as usize;
            if buf[k].len() < 4 + len { break; }
            let f: Vec<u8> = buf[k].drain(..4 + len).collect();
            frames.push((k, f));
        }
    }
    let mut out = Vec::new();
    let mut ciphers: [Option<StreamCipher>; 2] = [None, None];
    let mut offset = [0usize; 2];
    let mut session_key = Vec::new();
    for (k, frame) in &frames {
        let body = &frame[4..];
        let dir_s = if *k == 0 { "c2s" } else { "s2c" };
        let (plain, ks) = match &mut ciphers[*k] {
            None => (body.to_vec(), Vec::new()),
            Some(c) => {
                let mut z = vec![0u8; body.len()];
                c.apply(&mut z);
                let p: Vec<u8> = body.iter().zip(&z).map(|(a, b)| a ^ b).collect();
                (p, z)
            }
        };
        let off = offset[*k];
        if ciphers[*k].is_some() { offset[*k] += body.len(); }
        let msg = Message::decode(&plain).unwrap();
        let mut extra = String::new();
        match &msg {
            Message::SessionKey(enc) => {
                let len = u32::from_be_bytes(enc[..4].try_into().unwrap());
                let mut blocks = Vec::new();
                for c in enc[4..].chunks(8) {
                    let cv = u64::from_be_bytes(c.try_into().unwrap());
                    let mv = pow_mod(cv, host.d, host.n);
                    blocks.push(format!("{{\"c\":\"{cv:016x}\",\"m\":\"{mv:016x}\",\"m_dec\":{mv},\"c_dec\":{cv},\"check\":{}}}",
                        pow_mod(mv, host.e, host.n) == cv));
                }
                session_key = host.decrypt(enc).unwrap();
                extra = format!(",\"rsa_len\":{len},\"blocks\":[{}],\"K\":{},\"setup\":[{},{}]",
                    blocks.join(","), js(&hex(&session_key)),
                    cipher_setup(&session_key, b"rsh client to server"), cipher_setup(&session_key, b"rsh server to client"));
            }
            Message::Auth { user, key, signature } => {
                let data = auth_data(&session_key, user);
                let h = digest(&data);
                extra = format!(",\"auth_data\":{},\"fnv1\":\"{:016x}\",\"H\":\"{h:016x}\",\"H_dec\":{h},\"Hmodn\":{},\"sig\":{signature},\"sig_e\":{},\"key_matches\":{},\"verify\":{}",
                    js(&hex(&data)), fnv1a(&data), h % key.n, pow_mod(*signature, key.e, key.n), *key == client_pub, key.verify(&data, *signature));
            }
            _ => {}
        }
        out.push(format!("{{\"dir\":\"{dir_s}\",\"frame_len\":{},\"offset\":{off},\"wire\":{},\"keystream\":{},\"plain\":{},\"msg\":{}{extra}}}",
            frame.len(), js(&hex(frame)), js(&hex(&ks)), js(&hex(&plain)), js(&format!("{msg:?}"))));
        if let Message::SessionKey(_) = msg {
            // both sides switch on after this frame
            ciphers = [Some(StreamCipher::new(&session_key, b"rsh client to server")), Some(StreamCipher::new(&session_key, b"rsh server to client"))];
        }
    }
    println!("{{\"host_n\":{},\"host_d\":{},\"client_n\":{},\"frames\":[\n{}\n]}}", host.n, host.d, client_pub.n, out.join(",\n"));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let dir = Path::new(&args[2]);
    match args[1].as_str() { "keygen" => keygen(dir), "decode" => decode(dir), _ => panic!() }
}
