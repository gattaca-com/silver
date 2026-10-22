//! SHA-256 of FIPS 180-4, absorbing its message in parts.

const BLOCK: usize = 64;

/// FIPS 180-4 §4.2.2.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// FIPS 180-4 §5.3.3.
const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

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
