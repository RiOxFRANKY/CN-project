use crate::hash::fnv1a;
use crate::random::splitmix64;

pub struct StreamCipher {
    state: [u64; 4],
    block: [u8; 8],
    used: usize,
}

impl StreamCipher {
    pub fn new(key: &[u8], label: &[u8]) -> Self {
        let mut seed = fnv1a(label);
        let mut state = [0u64; 4];
        for s in state.iter_mut() {
            *s = splitmix64(&mut seed);
        }
        for (i, chunk) in key.chunks(8).enumerate() {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            state[i % 4] ^= u64::from_le_bytes(bytes);
        }
        let mut cipher = StreamCipher {
            state,
            block: [0; 8],
            used: 8,
        };
        for _ in 0..16 {
            cipher.next();
        }
        cipher
    }

    fn next(&mut self) -> u64 {
        let s = &mut self.state;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.used == 8 {
                self.block = self.next().to_le_bytes();
                self.used = 0;
            }
            *byte ^= self.block[self.used];
            self.used += 1;
        }
    }
}
