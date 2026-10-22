//! SHA-256 of FIPS 180-4 in plain Rust, absorbing its message in parts, for
//! CPUs without the SHA extensions.

use super::{BLOCK, INITIAL_STATE, K};

pub struct Sha256 {
    state: [u32; 8],
    pending: [u8; BLOCK],
    pending_len: usize,
    /// Modulo 2^64, as the padding encodes the bit length modulo 2^64.
    length: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self { state: INITIAL_STATE, pending: [0; BLOCK], pending_len: 0, length: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let room = BLOCK - self.pending_len;
        if data.len() < room {
            self.pending[self.pending_len..self.pending_len + data.len()].copy_from_slice(data);
            self.pending_len += data.len();
        } else {
            let mut start = 0;
            if self.pending_len > 0 {
                self.pending[self.pending_len..].copy_from_slice(&data[..room]);
                self.state = compress_blocks(&self.state, &self.pending, 0, 1);
                start = room;
            }
            let blocks = (data.len() - start) / BLOCK;
            self.state = compress_blocks(&self.state, data, start, blocks);
            start += BLOCK * blocks;
            self.pending_len = data.len() - start;
            self.pending[..self.pending_len].copy_from_slice(&data[start..]);
        }
    }

    pub fn finish(self) -> [u8; 32] {
        let mut tail = [0u8; 2 * BLOCK];
        tail[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
        tail[self.pending_len] = 0x80;
        let blocks = if self.pending_len < BLOCK - 8 { 1 } else { 2 };
        tail[BLOCK * blocks - 8..BLOCK * blocks].copy_from_slice(&(self.length << 3).to_be_bytes());
        let state = compress_blocks(&self.state, &tail, 0, blocks);
        let mut digest = [0u8; 32];
        let mut i = 0;
        while i < 8 {
            digest[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
            i += 1;
        }
        digest
    }
}

/// The state after the `blocks` blocks of `data` from `offset`.
fn compress_blocks(state: &[u32; 8], data: &[u8], offset: usize, blocks: usize) -> [u32; 8] {
    let mut state = *state;
    let mut block = 0;
    while block < blocks {
        state = compress(&state, data, offset + BLOCK * block);
        block += 1;
    }
    state
}

/// FIPS 180-4 §6.2.2, steps 2 to 4, on the block of `data` at `offset`.
fn compress(state: &[u32; 8], data: &[u8], offset: usize) -> [u32; 8] {
    let w = schedule(data, offset);
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    let mut t = 0;
    while t < 64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        t += 1;
    }
    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
        state[5].wrapping_add(f),
        state[6].wrapping_add(g),
        state[7].wrapping_add(h),
    ]
}

/// FIPS 180-4 §6.2.2, step 1.
fn schedule(data: &[u8], offset: usize) -> [u32; 64] {
    let mut w = [0u32; 64];
    let mut t = 0;
    while t < 16 {
        let mut word = [0u8; 4];
        word.copy_from_slice(&data[offset + 4 * t..offset + 4 * t + 4]);
        w[t] = u32::from_be_bytes(word);
        t += 1;
    }
    while t < 64 {
        w[t] = w[t - 16]
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma1(w[t - 2]));
        t += 1;
    }
    w
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[cfg(test)]
mod tests;
