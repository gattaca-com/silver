//! Eight big-endian 32-byte field elements, as the limbs of one `Fr8Soa`.

use std::arch::x86_64::{
    __m512i, _mm512_and_si512, _mm512_cmpeq_epi64_mask, _mm512_cmplt_epu64_mask, _mm512_load_si512,
    _mm512_loadu_si512, _mm512_or_si512, _mm512_permutex2var_epi64, _mm512_set_epi64,
    _mm512_shuffle_epi8, _mm512_slli_epi64, _mm512_srli_epi64, _mm512_store_si512,
    _mm512_storeu_si512, _mm512_unpackhi_epi64, _mm512_unpacklo_epi64,
};

use crate::kzg::{
    BYTES_PER_FIELD_ELEMENT,
    fr8::{Fr8Soa, LANES, LIMBS, MASK52, R_U64, splat},
};

pub const BYTES_PER_VECTOR: usize = LANES * BYTES_PER_FIELD_ELEMENT;

impl Fr8Soa {
    /// Reads eight big-endian 32-byte elements as plain-value limbs, one per
    /// lane. False when some lane is not below r, which leaves `self`
    /// unspecified.
    #[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
    #[inline]
    pub fn set_from_be_bytes(&mut self, bytes: &[u8; BYTES_PER_VECTOR]) -> bool {
        let reverse = reverse_bytes_of_words();
        let quarters = bytes.as_chunks::<64>().0;
        // SAFETY: each chunk is 64 readable bytes, and the load is unaligned.
        let z = std::array::from_fn(|k| unsafe {
            _mm512_shuffle_epi8(_mm512_loadu_si512(quarters[k].as_ptr().cast()), reverse)
        });
        let w = words_of_elements(&z);

        let below_r = (0..4).fold(0, |below, k| {
            let r = splat(R_U64[k]);
            _mm512_cmplt_epu64_mask(w[k], r) | (_mm512_cmpeq_epi64_mask(w[k], r) & below)
        });

        let mask = splat(MASK52);
        let limbs = [
            _mm512_and_si512(w[0], mask),
            _mm512_and_si512(
                _mm512_or_si512(_mm512_srli_epi64::<52>(w[0]), _mm512_slli_epi64::<12>(w[1])),
                mask,
            ),
            _mm512_and_si512(
                _mm512_or_si512(_mm512_srli_epi64::<40>(w[1]), _mm512_slli_epi64::<24>(w[2])),
                mask,
            ),
            _mm512_and_si512(
                _mm512_or_si512(_mm512_srli_epi64::<28>(w[2]), _mm512_slli_epi64::<36>(w[3])),
                mask,
            ),
            _mm512_srli_epi64::<16>(w[3]),
        ];
        for j in 0..LIMBS {
            // SAFETY: each limb row is 64 bytes and `Fr8Soa` is 64-aligned.
            unsafe { _mm512_store_si512(self.0[j].as_mut_ptr().cast(), limbs[j]) };
        }
        below_r == !0
    }

    /// Writes the eight lanes, normalised below 2^256, as big-endian 32-byte
    /// elements.
    #[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
    #[inline]
    pub fn write_be_bytes(&self, bytes: &mut [u8; BYTES_PER_VECTOR]) {
        // SAFETY: each limb row is 64 bytes and `Fr8Soa` is 64-aligned.
        let l: [_; LIMBS] =
            std::array::from_fn(|j| unsafe { _mm512_load_si512(self.0[j].as_ptr().cast()) });
        let w = [
            _mm512_or_si512(l[0], _mm512_slli_epi64::<52>(l[1])),
            _mm512_or_si512(_mm512_srli_epi64::<12>(l[1]), _mm512_slli_epi64::<40>(l[2])),
            _mm512_or_si512(_mm512_srli_epi64::<24>(l[2]), _mm512_slli_epi64::<28>(l[3])),
            _mm512_or_si512(_mm512_srli_epi64::<36>(l[3]), _mm512_slli_epi64::<16>(l[4])),
        ];
        let reverse = reverse_bytes_of_words();
        let z = elements_of_words(&w);
        for (quarter, z) in bytes.as_chunks_mut::<64>().0.iter_mut().zip(z) {
            // SAFETY: the chunk is 64 writable bytes, and the store is unaligned.
            unsafe {
                _mm512_storeu_si512(quarter.as_mut_ptr().cast(), _mm512_shuffle_epi8(z, reverse))
            };
        }
    }
}

/// `vpshufb` control that reverses the bytes of every u64.
#[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
#[inline]
fn reverse_bytes_of_words() -> __m512i {
    _mm512_set_epi64(
        0x0809_0a0b_0c0d_0e0f,
        0x0001_0203_0405_0607,
        0x0809_0a0b_0c0d_0e0f,
        0x0001_0203_0405_0607,
        0x0809_0a0b_0c0d_0e0f,
        0x0001_0203_0405_0607,
        0x0809_0a0b_0c0d_0e0f,
        0x0001_0203_0405_0607,
    )
}

/// From four vectors of two elements each, as u64 words most significant
/// first, to word `k` (least significant first) of all eight elements.
#[target_feature(enable = "avx512f")]
#[inline]
fn words_of_elements(z: &[__m512i; 4]) -> [__m512i; 4] {
    let first = _mm512_set_epi64(13, 9, 12, 8, 5, 1, 4, 0);
    let second = _mm512_set_epi64(15, 11, 14, 10, 7, 3, 6, 2);
    let (low_01, high_01) = (_mm512_unpacklo_epi64(z[0], z[1]), _mm512_unpackhi_epi64(z[0], z[1]));
    let (low_23, high_23) = (_mm512_unpacklo_epi64(z[2], z[3]), _mm512_unpackhi_epi64(z[2], z[3]));
    [
        _mm512_permutex2var_epi64(high_01, second, high_23),
        _mm512_permutex2var_epi64(low_01, second, low_23),
        _mm512_permutex2var_epi64(high_01, first, high_23),
        _mm512_permutex2var_epi64(low_01, first, low_23),
    ]
}

/// Inverse of `words_of_elements`.
#[target_feature(enable = "avx512f")]
#[inline]
fn elements_of_words(w: &[__m512i; 4]) -> [__m512i; 4] {
    let first = _mm512_set_epi64(11, 9, 3, 1, 10, 8, 2, 0);
    let second = _mm512_set_epi64(15, 13, 7, 5, 14, 12, 6, 4);
    let low_01 = _mm512_permutex2var_epi64(w[3], first, w[1]);
    let low_23 = _mm512_permutex2var_epi64(w[3], second, w[1]);
    let high_01 = _mm512_permutex2var_epi64(w[2], first, w[0]);
    let high_23 = _mm512_permutex2var_epi64(w[2], second, w[0]);
    [
        _mm512_unpacklo_epi64(low_01, high_01),
        _mm512_unpackhi_epi64(low_01, high_01),
        _mm512_unpacklo_epi64(low_23, high_23),
        _mm512_unpackhi_epi64(low_23, high_23),
    ]
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::kzg::{
        fr8::{R_U64, unpack52},
        fr8_test_util::{available, lanes},
    };

    #[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
    fn decode(bytes: &[u8; BYTES_PER_VECTOR]) -> (Fr8Soa, bool) {
        let mut out = Fr8Soa::ZERO;
        let below_r = out.set_from_be_bytes(bytes);
        (out, below_r)
    }

    #[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
    fn encode(x: &Fr8Soa) -> [u8; BYTES_PER_VECTOR] {
        let mut bytes = [0; BYTES_PER_VECTOR];
        x.write_be_bytes(&mut bytes);
        bytes
    }

    fn bytes_available() -> bool {
        available() && is_x86_feature_detected!("avx512bw")
    }

    fn be_bytes(value: &[u64; 4]) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (chunk, word) in bytes.chunks_exact_mut(8).zip(value.iter().rev()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn be_bytes_decode_to_limbs_and_encode_back() {
        if !bytes_available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(6);
        for _ in 0..200 {
            let values: [[u64; 4]; LANES] = std::array::from_fn(|_| {
                let mut value: [u64; 4] = std::array::from_fn(|_| rng.r#gen());
                value[3] &= R_U64[3] - 1;
                value
            });
            let mut bytes = [0; BYTES_PER_VECTOR];
            for (chunk, value) in bytes.chunks_exact_mut(32).zip(&values) {
                chunk.copy_from_slice(&be_bytes(value));
            }
            // SAFETY: `bytes_available` checked avx512f, avx512ifma and avx512bw.
            let (decoded, below_r) = unsafe { decode(&bytes) };
            assert!(below_r);
            for l in 0..LANES {
                assert_eq!(lanes(&decoded)[l], unpack52(&values[l]));
            }
            // SAFETY: as above.
            assert_eq!(unsafe { encode(&decoded) }, bytes);
        }
    }

    #[test]
    fn decode_flags_any_lane_not_below_r() {
        if !bytes_available() {
            return;
        }
        let mut r_minus_one = R_U64;
        r_minus_one[0] -= 1;
        let mut r_plus_one = R_U64;
        r_plus_one[0] += 1;
        let mut one_above_below = R_U64;
        one_above_below[1] += 1;
        one_above_below[0] = 0;
        let candidates = [
            (r_minus_one, true),
            (R_U64, false),
            (r_plus_one, false),
            (one_above_below, false),
            ([u64::MAX; 4], false),
        ];
        for (value, expected) in candidates {
            for bad_lane in 0..LANES {
                let mut bytes = [0; BYTES_PER_VECTOR];
                for chunk in bytes.chunks_exact_mut(32) {
                    chunk.copy_from_slice(&be_bytes(&r_minus_one));
                }
                bytes[32 * bad_lane..32 * (bad_lane + 1)].copy_from_slice(&be_bytes(&value));
                // SAFETY: `bytes_available` checked avx512f, avx512ifma and avx512bw.
                assert_eq!(unsafe { decode(&bytes) }.1, expected, "{value:x?} in lane {bad_lane}");
            }
        }
    }
}
