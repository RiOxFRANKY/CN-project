const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;

pub fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = OFFSET;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

pub fn digest(data: &[u8]) -> u64 {
    let first = fnv1a(data);
    let mut tail = data.to_vec();
    tail.extend_from_slice(&first.to_be_bytes());
    fnv1a(&tail).rotate_left(17) ^ first
}

pub fn colon_hex(value: u64) -> String {
    value
        .to_be_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
