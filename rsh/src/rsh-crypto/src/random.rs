use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new() -> Self {
        let mut hasher = RandomState::new().build_hasher();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        hasher.write_u128(nanos);
        hasher.write_u32(std::process::id());
        Rng {
            state: hasher.finish(),
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        splitmix64(&mut self.state)
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        self.fill(&mut buf);
        buf
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}
