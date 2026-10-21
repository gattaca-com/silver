use std::arch::x86_64::{
    __m512i, _mm512_add_epi64, _mm512_and_si512, _mm512_permutex2var_epi64, _mm512_set_epi64,
    _mm512_slli_epi64, _mm512_srli_epi64,
};

use super::{LANES, LIMBS, MASK52, splat, zero};
use crate::bls::fp8::{index_vector, lanes};

const WORDS: usize = 4;

/// Eight integers below 2^256, one per lane, as four 64-bit words from the
/// least significant. The pieces that make up a limb or a word occupy
/// disjoint bits, so `add` joins them as `or` would.
pub(super) struct U256x8([__m512i; WORDS]);

impl U256x8 {
    /// Lane l takes the 32 big-endian bytes at `at + 32·l`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub(super) fn from_bytes(bytes: &[u8], at: usize) -> Self {
        let elements = &bytes[at..at + 32 * LANES];
        let mut blocks = [zero(); WORDS];
        for b in 0..WORDS {
            blocks[b] = swap_bytes(load_block(elements, 64 * b));
        }
        Self::from_blocks(&blocks)
    }

    /// The inverse of `from_bytes`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub(super) fn to_bytes(&self, bytes: &mut [u8], at: usize) {
        let blocks = self.blocks();
        let elements = &mut bytes[at..at + 32 * LANES];
        for b in 0..WORDS {
            store_block(swap_bytes(blocks[b]), elements, 64 * b);
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub(super) fn limbs(&self) -> [__m512i; LIMBS] {
        let w = &self.0;
        let mask = splat(MASK52);
        [
            _mm512_and_si512(w[0], mask),
            _mm512_and_si512(
                _mm512_add_epi64(_mm512_srli_epi64::<52>(w[0]), _mm512_slli_epi64::<12>(w[1])),
                mask,
            ),
            _mm512_and_si512(
                _mm512_add_epi64(_mm512_srli_epi64::<40>(w[1]), _mm512_slli_epi64::<24>(w[2])),
                mask,
            ),
            _mm512_and_si512(
                _mm512_add_epi64(_mm512_srli_epi64::<28>(w[2]), _mm512_slli_epi64::<36>(w[3])),
                mask,
            ),
            _mm512_srli_epi64::<16>(w[3]),
        ]
    }

    /// The inverse of `limbs`, for normalised limbs of values below 2^256.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub(super) fn from_limbs(l: &[__m512i; LIMBS]) -> Self {
        Self([
            _mm512_add_epi64(l[0], _mm512_slli_epi64::<52>(l[1])),
            _mm512_add_epi64(_mm512_srli_epi64::<12>(l[1]), _mm512_slli_epi64::<40>(l[2])),
            _mm512_add_epi64(_mm512_srli_epi64::<24>(l[2]), _mm512_slli_epi64::<28>(l[3])),
            _mm512_add_epi64(_mm512_srli_epi64::<36>(l[3]), _mm512_slli_epi64::<16>(l[4])),
        ])
    }

    /// The first `count` lanes onto `words`, as four words each.
    pub(super) fn push_words(&self, words: &mut Vec<[u64; 4]>, count: usize) {
        let w = [lanes(self.0[0]), lanes(self.0[1]), lanes(self.0[2]), lanes(self.0[3])];
        let mut lane = 0;
        while lane < count {
            words.push([w[0][lane], w[1][lane], w[2][lane], w[3][lane]]);
            lane += 1;
        }
    }

    /// From blocks in the elements' byte order: lane i of block b holds word
    /// 3 − i % 4 of element 2b + i / 4. The first round gathers words 0 and 1,
    /// then 2 and 3, of the four elements in two blocks; the second joins
    /// elements 0 to 3 with elements 4 to 7.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn from_blocks(blocks: &[__m512i; WORDS]) -> Self {
        let low_words = index_vector(&[3, 7, 11, 15, 2, 6, 10, 14]);
        let high_words = index_vector(&[1, 5, 9, 13, 0, 4, 8, 12]);
        let quarters = [
            _mm512_permutex2var_epi64(blocks[0], low_words, blocks[1]),
            _mm512_permutex2var_epi64(blocks[0], high_words, blocks[1]),
            _mm512_permutex2var_epi64(blocks[2], low_words, blocks[3]),
            _mm512_permutex2var_epi64(blocks[2], high_words, blocks[3]),
        ];
        let (first_halves, second_halves) = half_selectors();
        Self([
            _mm512_permutex2var_epi64(quarters[0], first_halves, quarters[2]),
            _mm512_permutex2var_epi64(quarters[0], second_halves, quarters[2]),
            _mm512_permutex2var_epi64(quarters[1], first_halves, quarters[3]),
            _mm512_permutex2var_epi64(quarters[1], second_halves, quarters[3]),
        ])
    }

    /// The inverse of `from_blocks`, by the inverse rounds in reverse order.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn blocks(&self) -> [__m512i; WORDS] {
        let w = &self.0;
        let (first_halves, second_halves) = half_selectors();
        let quarters = [
            _mm512_permutex2var_epi64(w[0], first_halves, w[1]),
            _mm512_permutex2var_epi64(w[2], first_halves, w[3]),
            _mm512_permutex2var_epi64(w[0], second_halves, w[1]),
            _mm512_permutex2var_epi64(w[2], second_halves, w[3]),
        ];
        let even_block = index_vector(&[12, 8, 4, 0, 13, 9, 5, 1]);
        let odd_block = index_vector(&[14, 10, 6, 2, 15, 11, 7, 3]);
        [
            _mm512_permutex2var_epi64(quarters[0], even_block, quarters[1]),
            _mm512_permutex2var_epi64(quarters[0], odd_block, quarters[1]),
            _mm512_permutex2var_epi64(quarters[2], even_block, quarters[3]),
            _mm512_permutex2var_epi64(quarters[2], odd_block, quarters[3]),
        ]
    }
}

/// `_mm512_permutex2var_epi64` selectors joining the first halves, and the
/// second halves, of two vectors.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn half_selectors() -> (__m512i, __m512i) {
    (index_vector(&[0, 1, 2, 3, 8, 9, 10, 11]), index_vector(&[4, 5, 6, 7, 12, 13, 14, 15]))
}

fn le_word(bytes: &[u8], at: usize) -> i64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word) as i64
}

/// The 64 bytes at `at` as eight little-endian words.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn load_block(bytes: &[u8], at: usize) -> __m512i {
    _mm512_set_epi64(
        le_word(bytes, at + 56),
        le_word(bytes, at + 48),
        le_word(bytes, at + 40),
        le_word(bytes, at + 32),
        le_word(bytes, at + 24),
        le_word(bytes, at + 16),
        le_word(bytes, at + 8),
        le_word(bytes, at),
    )
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn store_block(block: __m512i, bytes: &mut [u8], at: usize) {
    let words = lanes(block);
    for i in 0..LANES {
        bytes[at + 8 * i..at + 8 * i + 8].copy_from_slice(&words[i].to_le_bytes());
    }
}

/// `u64::swap_bytes` in every lane.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn swap_bytes(x: __m512i) -> __m512i {
    let x = _mm512_add_epi64(_mm512_slli_epi64::<32>(x), _mm512_srli_epi64::<32>(x));
    let low_16 = splat(0x0000_ffff_0000_ffff);
    let x = _mm512_add_epi64(
        _mm512_slli_epi64::<16>(_mm512_and_si512(x, low_16)),
        _mm512_and_si512(_mm512_srli_epi64::<16>(x), low_16),
    );
    let low_8 = splat(0x00ff_00ff_00ff_00ff);
    _mm512_add_epi64(
        _mm512_slli_epi64::<8>(_mm512_and_si512(x, low_8)),
        _mm512_and_si512(_mm512_srli_epi64::<8>(x), low_8),
    )
}
