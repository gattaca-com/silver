//! Eight Fr elements per `__m512i` limb, as five 52-bit limbs in Montgomery
//! form with R' = 2^260: the shape `vpmadd52` multiplies natively.
//!
//! Values are not kept canonical. Each operation documents the range it takes
//! and returns, and `SimdCellExtender` composes them so that no range is
//! exceeded.

use std::arch::x86_64::{
    __m512i, __mmask8, _mm512_add_epi64, _mm512_and_si512, _mm512_cmpeq_epi64_mask,
    _mm512_load_si512, _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_mask_blend_epi64,
    _mm512_set1_epi64, _mm512_setzero_si512, _mm512_shuffle_i64x2, _mm512_srai_epi64,
    _mm512_srli_epi64, _mm512_store_si512, _mm512_sub_epi64, _mm512_unpackhi_epi64,
    _mm512_unpacklo_epi64,
};

use blst::blst_fr;

use crate::kzg::blst_ops::{fr_from_u64, fr_mul};

pub const LANES: usize = 8;
pub const LIMBS: usize = 5;
const LIMB_BITS: u32 = 52;
pub const MASK52: u64 = (1 << LIMB_BITS) - 1;

pub const R_U64: [u64; 4] =
    [0xffff_ffff_0000_0001, 0x53bd_a402_fffe_5bfe, 0x3339_d808_09a1_d805, 0x73ed_a753_299d_7d48];
pub const R52: [u64; LIMBS] = unpack52(&R_U64);
pub const TWO_R52: [u64; LIMBS] = unpack52(&double(&R_U64));
/// −r⁻¹ mod 2^52.
pub const R_INV52: u64 = negated_inverse_mod_2_52(R_U64[0]);

const fn double(x: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0;
    let mut i = 0;
    while i < 4 {
        out[i] = (x[i] << 1) | carry;
        carry = x[i] >> 63;
        i += 1;
    }
    out
}

/// Newton iteration: each step doubles the number of correct low bits, from 3
/// for any odd `x`.
const fn negated_inverse_mod_2_52(x: u64) -> u64 {
    let mut inverse = x;
    let mut step = 0;
    while step < 5 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(inverse)));
        step += 1;
    }
    inverse.wrapping_neg() & MASK52
}

/// Limb-major: `limbs[j][lane]`.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct Fr8Soa(pub [[u64; LANES]; LIMBS]);

#[derive(Clone, Copy)]
pub struct Fr8([__m512i; LIMBS]);

pub const fn unpack52(x: &[u64; 4]) -> [u64; LIMBS] {
    [
        x[0] & MASK52,
        ((x[0] >> 52) | (x[1] << 12)) & MASK52,
        ((x[1] >> 40) | (x[2] << 24)) & MASK52,
        ((x[2] >> 28) | (x[3] << 36)) & MASK52,
        x[3] >> 16,
    ]
}

pub const fn pack64(x: &[u64; LIMBS]) -> [u64; 4] {
    [
        x[0] | (x[1] << 52),
        (x[1] >> 12) | (x[2] << 40),
        (x[2] >> 24) | (x[3] << 28),
        (x[3] >> 36) | (x[4] << 16),
    ]
}

/// The R' = 2^260 Montgomery form of a blst (R = 2^256) element. Multiplying
/// by 16 in blst's form multiplies the value by 2^4 relative to its own R.
pub fn to_r260(a: &blst_fr) -> [u64; LIMBS] {
    unpack52(&fr_mul(a, &fr_from_u64(16)).l)
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub(crate) fn splat(x: u64) -> __m512i {
    _mm512_set1_epi64(x as i64)
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn zero() -> __m512i {
    _mm512_setzero_si512()
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn muladd_row(t: &mut [__m512i; 2 * LIMBS + 1], a: &[__m512i; LIMBS], b_i: __m512i, i: usize) {
    for j in 0..LIMBS {
        t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[j], b_i);
        t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[j], b_i);
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn reduce_row(t: &mut [__m512i; 2 * LIMBS + 1], r: &[__m512i; LIMBS], rinv: __m512i, i: usize) {
    let q = _mm512_madd52lo_epu64(zero(), t[i], rinv);
    muladd_row(t, r, q, i);
    t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64::<52>(t[i]));
}

impl Fr8Soa {
    pub const ZERO: Self = Self([[0; LANES]; LIMBS]);

    /// The value in `lane`, normalised below 2^256, as the little-endian bytes
    /// of a `blst_scalar`.
    pub fn lane_le_bytes(&self, lane: usize) -> [u8; 32] {
        let words = pack64(&std::array::from_fn(|j| self.0[j][lane]));
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

impl Fr8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn load(src: &Fr8Soa) -> Self {
        let mut v = [zero(); LIMBS];
        for j in 0..LIMBS {
            // SAFETY: each limb row is 64 bytes and `Fr8Soa` is 64-aligned.
            v[j] = unsafe { _mm512_load_si512(src.0[j].as_ptr().cast()) };
        }
        Self(v)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn store(&self, dst: &mut Fr8Soa) {
        for j in 0..LIMBS {
            // SAFETY: as in `load`.
            unsafe { _mm512_store_si512(dst.0[j].as_mut_ptr().cast(), self.0[j]) };
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn splat(limbs: &[u64; LIMBS]) -> Self {
        let mut v = [zero(); LIMBS];
        for j in 0..LIMBS {
            v[j] = splat(limbs[j]);
        }
        Self(v)
    }

    /// Montgomery product. Both inputs are normalised. When one of them is
    /// below r the other may be any 260-bit value, and the output is
    /// normalised and below 2r: (a·b + q·r) / 2^260 < (a/2^260 + 1)·r, as
    /// b < r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let r = Self::splat(&R52).0;
        let rinv = splat(R_INV52);
        let mut t = [zero(); 2 * LIMBS + 1];
        muladd_row(&mut t, &self.0, rhs.0[0], 0);
        muladd_row(&mut t, &self.0, rhs.0[1], 1);
        muladd_row(&mut t, &self.0, rhs.0[2], 2);
        muladd_row(&mut t, &self.0, rhs.0[3], 3);
        muladd_row(&mut t, &self.0, rhs.0[4], 4);
        reduce_row(&mut t, &r, rinv, 0);
        reduce_row(&mut t, &r, rinv, 1);
        reduce_row(&mut t, &r, rinv, 2);
        reduce_row(&mut t, &r, rinv, 3);
        reduce_row(&mut t, &r, rinv, 4);

        let mask = splat(MASK52);
        let mut out = [zero(); LIMBS];
        out[0] = t[LIMBS];
        for j in 0..LIMBS - 1 {
            out[j + 1] = _mm512_add_epi64(t[LIMBS + j + 1], _mm512_srli_epi64::<52>(out[j]));
            out[j] = _mm512_and_si512(out[j], mask);
        }
        Self(out)
    }

    /// Lane u of vector l becomes lane l of vector u, for the eight vectors
    /// of `block`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn transpose_block(block: &mut [Fr8Soa]) {
        assert_eq!(block.len(), LANES);
        for j in 0..LIMBS {
            let mut rows = [zero(); LANES];
            for k in 0..LANES {
                // SAFETY: each limb row is 64 bytes and `Fr8Soa` is 64-aligned.
                rows[k] = unsafe { _mm512_load_si512(block[k].0[j].as_ptr().cast()) };
            }
            transpose8(&mut rows);
            for k in 0..LANES {
                // SAFETY: as above.
                unsafe { _mm512_store_si512(block[k].0[j].as_mut_ptr().cast(), rows[k]) };
            }
        }
    }

    /// Limb-wise sum, no carries.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn add_raw(&self, rhs: &Self) -> Self {
        let mut s = [zero(); LIMBS];
        for j in 0..LIMBS {
            s[j] = _mm512_add_epi64(self.0[j], rhs.0[j]);
        }
        Self(s)
    }

    /// Limb-wise `self + c − rhs`, no carries; limbs may go negative.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sub_raw(&self, rhs: &Self, c: &Self) -> Self {
        let mut s = [zero(); LIMBS];
        for j in 0..LIMBS {
            s[j] = _mm512_sub_epi64(_mm512_add_epi64(self.0[j], c.0[j]), rhs.0[j]);
        }
        Self(s)
    }

    /// Signed carry propagation into 52-bit limbs, for a value in [0, 2^260).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn normalise(&self) -> Self {
        let mask = splat(MASK52);
        let mut s = self.0;
        for j in 0..LIMBS - 1 {
            let carry = _mm512_srai_epi64::<52>(s[j]);
            s[j] = _mm512_and_si512(s[j], mask);
            s[j + 1] = _mm512_add_epi64(s[j + 1], carry);
        }
        Self(s)
    }

    /// `self − c` normalised, and the lanes where it borrowed.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn sub_borrow(&self, c: &Self) -> (Self, __mmask8) {
        let mask = splat(MASK52);
        let mut d = [zero(); LIMBS];
        let mut borrow = zero();
        for j in 0..LIMBS {
            let s = _mm512_add_epi64(_mm512_sub_epi64(self.0[j], c.0[j]), borrow);
            borrow = _mm512_srai_epi64::<63>(s);
            d[j] = _mm512_and_si512(s, mask);
        }
        (Self(d), _mm512_cmpeq_epi64_mask(borrow, splat(u64::MAX)))
    }

    /// The lanes where normalised `self` is below `c`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn below(&self, c: &Self) -> __mmask8 {
        self.sub_borrow(c).1
    }

    /// For normalised `self` below 2c: `self − c` where `self ≥ c`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn cond_sub(&self, c: &Self) -> Self {
        let (d, borrowed) = self.sub_borrow(c);
        let mut out = [zero(); LIMBS];
        for j in 0..LIMBS {
            out[j] = _mm512_mask_blend_epi64(borrowed, d.0[j], self.0[j]);
        }
        Self(out)
    }
}

/// Transposes the 8×8 matrix of u64 held in eight vectors.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub(crate) fn transpose8(r: &mut [__m512i; 8]) {
    let t0 = _mm512_unpacklo_epi64(r[0], r[1]);
    let t1 = _mm512_unpackhi_epi64(r[0], r[1]);
    let t2 = _mm512_unpacklo_epi64(r[2], r[3]);
    let t3 = _mm512_unpackhi_epi64(r[2], r[3]);
    let t4 = _mm512_unpacklo_epi64(r[4], r[5]);
    let t5 = _mm512_unpackhi_epi64(r[4], r[5]);
    let t6 = _mm512_unpacklo_epi64(r[6], r[7]);
    let t7 = _mm512_unpackhi_epi64(r[6], r[7]);
    let u0 = _mm512_shuffle_i64x2::<0x88>(t0, t2);
    let u1 = _mm512_shuffle_i64x2::<0xDD>(t0, t2);
    let u2 = _mm512_shuffle_i64x2::<0x88>(t1, t3);
    let u3 = _mm512_shuffle_i64x2::<0xDD>(t1, t3);
    let u4 = _mm512_shuffle_i64x2::<0x88>(t4, t6);
    let u5 = _mm512_shuffle_i64x2::<0xDD>(t4, t6);
    let u6 = _mm512_shuffle_i64x2::<0x88>(t5, t7);
    let u7 = _mm512_shuffle_i64x2::<0xDD>(t5, t7);
    r[0] = _mm512_shuffle_i64x2::<0x88>(u0, u4);
    r[4] = _mm512_shuffle_i64x2::<0xDD>(u0, u4);
    r[1] = _mm512_shuffle_i64x2::<0x88>(u2, u6);
    r[5] = _mm512_shuffle_i64x2::<0xDD>(u2, u6);
    r[2] = _mm512_shuffle_i64x2::<0x88>(u1, u5);
    r[6] = _mm512_shuffle_i64x2::<0xDD>(u1, u5);
    r[3] = _mm512_shuffle_i64x2::<0x88>(u3, u7);
    r[7] = _mm512_shuffle_i64x2::<0xDD>(u3, u7);
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::{bls::simd_available, kzg::blst_ops::fr_from_bytes};

    fn available() -> bool {
        let ok = simd_available();
        assert!(
            ok || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
            "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
        );
        ok
    }

    fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes[1..]);
        fr_from_bytes(&bytes).expect("top byte zero is below r")
    }

    /// `x + k·r` as normalised limbs.
    fn plus_multiple_of_r(x: &[u64; LIMBS], k: u64) -> [u64; LIMBS] {
        let mut out = [0u64; LIMBS];
        let mut carry = 0;
        for j in 0..LIMBS {
            let sum = x[j] + k * R52[j] + carry;
            out[j] = sum & MASK52;
            carry = sum >> 52;
        }
        assert_eq!(carry, 0, "fits in 260 bits");
        out
    }

    fn soa(lanes: &[[u64; LIMBS]; LANES]) -> Fr8Soa {
        let mut out = Fr8Soa([[0; LANES]; LIMBS]);
        for lane in 0..LANES {
            for j in 0..LIMBS {
                out.0[j][lane] = lanes[lane][j];
            }
        }
        out
    }

    fn lanes(soa: &Fr8Soa) -> [[u64; LIMBS]; LANES] {
        let mut out = [[0; LIMBS]; LANES];
        for lane in 0..LANES {
            for j in 0..LIMBS {
                out[lane][j] = soa.0[j][lane];
            }
        }
        out
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn mul_canonical(x: &Fr8Soa, y: &Fr8Soa) -> Fr8Soa {
        let mut out = Fr8Soa([[0; LANES]; LIMBS]);
        Fr8::load(x).mul(&Fr8::load(y)).cond_sub(&Fr8::splat(&R52)).store(&mut out);
        out
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn normalise_all(x: &Fr8Soa) -> Fr8Soa {
        let mut out = Fr8Soa([[0; LANES]; LIMBS]);
        Fr8::load(x).normalise().store(&mut out);
        out
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn cond_sub_r(x: &Fr8Soa) -> Fr8Soa {
        let mut out = Fr8Soa([[0; LANES]; LIMBS]);
        Fr8::load(x).cond_sub(&Fr8::splat(&R52)).store(&mut out);
        out
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn transposed(x: &[Fr8Soa; 8]) -> [Fr8Soa; 8] {
        let mut out = *x;
        for j in 0..LIMBS {
            let mut limb = [zero(); 8];
            for k in 0..8 {
                limb[k] = Fr8::load(&x[k]).0[j];
            }
            transpose8(&mut limb);
            for k in 0..8 {
                let mut v = Fr8::load(&out[k]);
                v.0[j] = limb[k];
                v.store(&mut out[k]);
            }
        }
        out
    }

    #[test]
    fn mul_matches_blst() {
        if !available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        for _ in 0..200 {
            let xs: [blst_fr; LANES] = std::array::from_fn(|_| random_fr(&mut rng));
            let ys: [blst_fr; LANES] = std::array::from_fn(|_| random_fr(&mut rng));
            let x = soa(&std::array::from_fn(|l| to_r260(&xs[l])));
            let y = soa(&std::array::from_fn(|l| to_r260(&ys[l])));
            // SAFETY: `available` checked avx512f and avx512ifma.
            let product = lanes(&unsafe { mul_canonical(&x, &y) });
            for l in 0..LANES {
                assert_eq!(product[l], to_r260(&fr_mul(&xs[l], &ys[l])));
            }
        }
    }

    #[test]
    fn mul_accepts_data_operand_up_to_32r() {
        if !available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        for k in 0..32 {
            let xs: [blst_fr; LANES] = std::array::from_fn(|_| random_fr(&mut rng));
            let ys: [blst_fr; LANES] = std::array::from_fn(|_| random_fr(&mut rng));
            let data = soa(&std::array::from_fn(|l| plus_multiple_of_r(&to_r260(&xs[l]), k)));
            let canonical = soa(&std::array::from_fn(|l| to_r260(&ys[l])));
            // SAFETY: `available` checked avx512f and avx512ifma.
            let (data_first, data_second) =
                unsafe { (mul_canonical(&data, &canonical), mul_canonical(&canonical, &data)) };
            for l in 0..LANES {
                let expected = to_r260(&fr_mul(&xs[l], &ys[l]));
                assert_eq!(lanes(&data_first)[l], expected, "k {k}");
                assert_eq!(lanes(&data_second)[l], expected, "k {k}");
            }
        }
    }

    #[test]
    fn mul_output_is_below_2r_before_reduction() {
        if !available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let xs: [blst_fr; LANES] = std::array::from_fn(|_| random_fr(&mut rng));
        let data = soa(&std::array::from_fn(|l| plus_multiple_of_r(&to_r260(&xs[l]), 31)));
        let mut below_r = R52;
        below_r[0] -= 1;
        let canonical = soa(&[below_r; LANES]);
        let mut out = Fr8Soa([[0; LANES]; LIMBS]);
        #[target_feature(enable = "avx512f,avx512ifma")]
        fn raw(x: &Fr8Soa, y: &Fr8Soa, out: &mut Fr8Soa) {
            Fr8::load(x).mul(&Fr8::load(y)).store(out);
        }
        // SAFETY: `available` checked avx512f and avx512ifma.
        unsafe { raw(&data, &canonical, &mut out) };
        for lane in lanes(&out) {
            assert!(lane.iter().all(|&limb| limb <= MASK52), "normalised");
            let below_2r = lane.iter().rev().zip(TWO_R52.iter().rev()).find(|(a, b)| a != b);
            assert!(below_2r.is_none_or(|(a, b)| a < b), "below 2r");
        }
    }

    #[test]
    fn normalise_propagates_negative_limbs() {
        if !available() {
            return;
        }
        let mut input = Fr8Soa([[0; LANES]; LIMBS]);
        for lane in 0..LANES {
            let l = lane as u64;
            input.0[0][lane] = l.wrapping_sub(10);
            input.0[1][lane] = 3;
            input.0[2][lane] = 1u64.wrapping_sub(l * 2);
            input.0[3][lane] = 2 * l + 7;
            input.0[4][lane] = 9;
        }
        // SAFETY: `available` checked avx512f and avx512ifma.
        let out = lanes(&unsafe { normalise_all(&input) });
        let value = |limbs: &[u64; LIMBS]| -> i128 {
            limbs.iter().rev().fold(0i128, |acc, &l| (acc << 52) + l as i64 as i128)
        };
        for lane in 0..LANES {
            let before: [u64; LIMBS] = std::array::from_fn(|j| input.0[j][lane]);
            assert_eq!(value(&before), value(&out[lane]), "lane {lane}");
            assert!(out[lane].iter().all(|&limb| limb <= MASK52), "lane {lane}");
        }
    }

    #[test]
    fn cond_sub_splits_at_c() {
        if !available() {
            return;
        }
        let one = |x: u64| {
            let mut limbs = [0; LIMBS];
            limbs[0] = x;
            limbs
        };
        let mut below = R52;
        below[0] -= 1;
        let mut above = R52;
        above[0] += 1;
        let mut twice_below = TWO_R52;
        twice_below[0] -= 1;
        let cases = [
            (below, below),
            (R52, one(0)),
            (above, one(1)),
            (twice_below, below),
            (one(0), one(0)),
            (one(1), one(1)),
            (TWO_R52, R52),
            (below, below),
        ];
        let input = soa(&std::array::from_fn(|l| cases[l].0));
        // SAFETY: `available` checked avx512f and avx512ifma.
        let out = lanes(&unsafe { cond_sub_r(&input) });
        for l in 0..LANES {
            assert_eq!(out[l], cases[l].1, "case {l}");
        }
    }

    #[test]
    fn r_inv52_is_negated_inverse() {
        assert_eq!(R_INV52, 0xf_fffe_ffff_ffff);
        assert_eq!(R52[0].wrapping_mul(R_INV52).wrapping_add(1) & MASK52, 0);
    }

    #[test]
    fn pack_inverts_unpack() {
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        for _ in 0..1000 {
            let x: [u64; 4] = std::array::from_fn(|_| rng.r#gen());
            assert_eq!(pack64(&unpack52(&x)), x);
        }
        assert_eq!(pack64(&R52), R_U64);
    }

    #[test]
    fn transpose8_is_an_involutive_transpose() {
        if !available() {
            return;
        }
        let mut input = [Fr8Soa([[0; LANES]; LIMBS]); 8];
        for k in 0..8 {
            for j in 0..LIMBS {
                for lane in 0..LANES {
                    input[k].0[j][lane] = (j * 64 + k * 8 + lane) as u64;
                }
            }
        }
        // SAFETY: `available` checked avx512f and avx512ifma.
        let once = unsafe { transposed(&input) };
        for k in 0..8 {
            for j in 0..LIMBS {
                for lane in 0..LANES {
                    assert_eq!(once[k].0[j][lane], input[lane].0[j][k]);
                }
            }
        }
        // SAFETY: as above.
        let twice = unsafe { transposed(&once) };
        for k in 0..8 {
            assert_eq!(twice[k].0, input[k].0);
        }
    }
}
