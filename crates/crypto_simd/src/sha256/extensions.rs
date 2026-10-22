//! SHA-256 on the SHA extensions. Vectors are named by their lanes from the
//! top one down, as Intel's documentation names them:
//! `_mm_sha256rnds2_epu32` keeps the state as ABEF and CDGH.

use std::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
    _mm_shuffle_epi32, _mm_storeu_si128,
};

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
    let dcba = load_words(&[state[0], state[1], state[2], state[3]]);
    let hgfe = load_words(&[state[4], state[5], state[6], state[7]]);
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
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[BLOCK * block + 16 * i..BLOCK * block + 16 * i + 16]);
            w[i] = _mm_shuffle_epi8(load_bytes(&bytes), byte_swap);
            i += 1;
        }
        let mut quad = 0;
        while quad < 16 {
            let k = load_words(&[K[4 * quad], K[4 * quad + 1], K[4 * quad + 2], K[4 * quad + 3]]);
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
    let low = store_words(_mm_blend_epi16(feba, dchg, 0xf0));
    let high = store_words(_mm_alignr_epi8(dchg, feba, 8));
    [low[0], low[1], low[2], low[3], high[0], high[1], high[2], high[3]]
}

// Aeneas cannot model raw pointers, so they stay inside these three opaque
// functions.
fn load_bytes(bytes: &[u8; 16]) -> __m128i {
    // SAFETY: the load reads the array's 16 bytes.
    unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
}

fn load_words(words: &[u32; 4]) -> __m128i {
    // SAFETY: the load reads the array's 16 bytes.
    unsafe { _mm_loadu_si128(words.as_ptr().cast()) }
}

fn store_words(v: __m128i) -> [u32; 4] {
    let mut words = [0u32; 4];
    // SAFETY: the store writes the array's 16 bytes.
    unsafe { _mm_storeu_si128(words.as_mut_ptr().cast(), v) };
    words
}

#[cfg(test)]
mod tests;
