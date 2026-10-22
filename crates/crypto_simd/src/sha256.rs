//! SHA-256 of FIPS 180-4 on the SHA extensions, absorbing its message in
//! parts. Vectors are named by their lanes from the top one down, as Intel's
//! documentation names them: `_mm_sha256rnds2_epu32` keeps the state as ABEF
//! and CDGH.

use std::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
    _mm_shuffle_epi32, _mm_storeu_si128,
};

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

    #[target_feature(enable = "sha,sse4.1")]
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

    #[target_feature(enable = "sha,sse4.1")]
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
#[target_feature(enable = "sha,sse4.1")]
fn compress_blocks(state: &[u32; 8], data: &[u8], offset: usize, blocks: usize) -> [u32; 8] {
    let data = &data[offset..offset + BLOCK * blocks];
    let byte_swap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
    // SAFETY: `state` holds eight words, so both loads stay inside it.
    let (dcba, hgfe) = unsafe {
        (_mm_loadu_si128(state.as_ptr().cast()), _mm_loadu_si128(state.as_ptr().add(4).cast()))
    };
    let cdab = _mm_shuffle_epi32(dcba, 0xb1);
    let efgh = _mm_shuffle_epi32(hgfe, 0x1b);
    let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);
    let mut block = 0;
    while block < blocks {
        let (abef_before, cdgh_before) = (abef, cdgh);
        let mut w = [abef; 4];
        let mut i = 0;
        while i < 4 {
            // SAFETY: block < blocks and i < 4 keep the 16 bytes inside `data`.
            let bytes =
                unsafe { _mm_loadu_si128(data.as_ptr().add(BLOCK * block + 16 * i).cast()) };
            w[i] = _mm_shuffle_epi8(bytes, byte_swap);
            i += 1;
        }
        let mut quad = 0;
        while quad < 16 {
            // SAFETY: quad < 16 keeps the four words inside `K`.
            let k = unsafe { _mm_loadu_si128(K.as_ptr().add(4 * quad).cast()) };
            let wk = _mm_add_epi32(w[0], k);
            cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
            abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0e));
            if quad < 12 {
                let partial = _mm_sha256msg1_epu32(w[0], w[1]);
                let next = _mm_sha256msg2_epu32(
                    _mm_add_epi32(partial, _mm_alignr_epi8(w[3], w[2], 4)),
                    w[3],
                );
                w = [w[1], w[2], w[3], next];
            } else {
                w = [w[1], w[2], w[3], w[3]];
            }
            quad += 1;
        }
        abef = _mm_add_epi32(abef, abef_before);
        cdgh = _mm_add_epi32(cdgh, cdgh_before);
        block += 1;
    }
    let feba = _mm_shuffle_epi32(abef, 0x1b);
    let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
    let mut out = [0u32; 8];
    // SAFETY: `out` holds eight words, so both stores stay inside it.
    unsafe {
        _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), _mm_blend_epi16(feba, dchg, 0xf0));
        _mm_storeu_si128(out.as_mut_ptr().add(4).cast::<__m128i>(), _mm_alignr_epi8(dchg, feba, 8));
    }
    out
}

#[cfg(test)]
mod tests;
