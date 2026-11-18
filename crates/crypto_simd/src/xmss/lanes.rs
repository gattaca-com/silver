//! Keccak-f[1600] over `LANES` independent states at once, lane `l` of every
//! word in `[[u64; LANES]; 25]` being one state. AVX-512F when the `simd`
//! feature is on and the CPU has it, else the scalar permutation per lane.

use crate::xmss::keccak::permutation;

pub(crate) const LANES: usize = 8;

pub(crate) type Lanes = [[u64; LANES]; 25];

pub(crate) const RATE_WORDS: usize = 136 / 8;

/// XORs `bytes`, a multiple of 8 long, into lane `l` from word `at`.
pub(crate) fn absorb(lanes: &mut Lanes, l: usize, at: usize, bytes: &[u8]) {
    debug_assert!(bytes.len().is_multiple_of(8) && at + bytes.len() / 8 <= RATE_WORDS);
    for (word, chunk) in lanes[at..].iter_mut().zip(bytes.chunks_exact(8)) {
        word[l] ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

/// Keccak padding on every lane after `len` bytes of the block, `len` a
/// multiple of 8.
pub(crate) fn pad(lanes: &mut Lanes, len: usize) {
    debug_assert!(len.is_multiple_of(8) && len < 136);
    for word in &mut lanes[len / 8] {
        *word ^= 0x01;
    }
    for word in &mut lanes[RATE_WORDS - 1] {
        *word ^= 0x80 << 56;
    }
}

/// Output words `word` and `word + 1` of lane `l`.
pub(crate) fn digest(lanes: &Lanes, l: usize, word: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&lanes[word][l].to_le_bytes());
    out[8..].copy_from_slice(&lanes[word + 1][l].to_le_bytes());
    out
}

pub(crate) fn permutation_lanes(a: &mut Lanes) {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    if is_x86_feature_detected!("avx512f") {
        // SAFETY: AVX-512F detected.
        unsafe { avx512::permutation_lanes(a) };
        return;
    }
    for l in 0..LANES {
        let mut state = [0u64; 25];
        for (word, row) in state.iter_mut().zip(a.iter()) {
            *word = row[l];
        }
        permutation(&mut state);
        for (word, row) in state.iter().zip(a.iter_mut()) {
            row[l] = *word;
        }
    }
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
mod avx512 {
    use core::arch::x86_64::{
        __m512i, _mm512_loadu_epi64, _mm512_rol_epi64, _mm512_rolv_epi64, _mm512_set1_epi64,
        _mm512_storeu_epi64, _mm512_ternarylogic_epi64, _mm512_xor_si512,
    };

    use super::Lanes;
    use crate::xmss::keccak::{PI, RC, RHO};

    /// `_mm512_ternarylogic_epi64` truth tables, bit `(a << 2) | (b << 1) | c`.
    const XOR3: i32 = 0x96;
    const CHI: i32 = 0xD2; // a ^ (!b & c)

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn permutation_lanes(lanes: &mut Lanes) {
        let mut a: [__m512i; 25] =
            std::array::from_fn(|i| unsafe { _mm512_loadu_epi64(lanes[i].as_ptr().cast()) });
        let rho: [__m512i; 24] = std::array::from_fn(|t| _mm512_set1_epi64(RHO[t] as i64));

        for rc in RC {
            let c: [__m512i; 5] = std::array::from_fn(|x| {
                let c3 = _mm512_ternarylogic_epi64::<XOR3>(a[x], a[x + 5], a[x + 10]);
                _mm512_ternarylogic_epi64::<XOR3>(c3, a[x + 15], a[x + 20])
            });
            for x in 0..5 {
                let d = _mm512_xor_si512(c[(x + 4) % 5], _mm512_rol_epi64::<1>(c[(x + 1) % 5]));
                for y in 0..5 {
                    a[x + 5 * y] = _mm512_xor_si512(a[x + 5 * y], d);
                }
            }

            let mut last = a[1];
            for t in 0..24 {
                let next = a[PI[t]];
                a[PI[t]] = _mm512_rolv_epi64(last, rho[t]);
                last = next;
            }

            for y in 0..5 {
                let row: [__m512i; 5] = std::array::from_fn(|x| a[x + 5 * y]);
                for x in 0..5 {
                    a[x + 5 * y] = _mm512_ternarylogic_epi64::<CHI>(
                        row[x],
                        row[(x + 1) % 5],
                        row[(x + 2) % 5],
                    );
                }
            }

            a[0] = _mm512_xor_si512(a[0], _mm512_set1_epi64(rc as i64));
        }

        for (row, v) in lanes.iter_mut().zip(a) {
            unsafe { _mm512_storeu_epi64(row.as_mut_ptr().cast(), v) };
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::{LANES, Lanes, permutation_lanes};
    use crate::xmss::keccak::permutation;

    #[test]
    fn matches_scalar_per_lane() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        for _ in 0..16 {
            let mut lanes: Lanes = std::array::from_fn(|_| std::array::from_fn(|_| rng.next_u64()));
            let expected: Vec<[u64; 25]> = (0..LANES)
                .map(|l| {
                    let mut state: [u64; 25] = std::array::from_fn(|i| lanes[i][l]);
                    permutation(&mut state);
                    state
                })
                .collect();
            permutation_lanes(&mut lanes);
            for (l, state) in expected.iter().enumerate() {
                for i in 0..25 {
                    assert_eq!(lanes[i][l], state[i], "lane {l} word {i}");
                }
            }
        }
    }
}
