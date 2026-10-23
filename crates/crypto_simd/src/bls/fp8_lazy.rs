//! Lazy-reduction kernels of `Fp8`: raw (uncarried) limbs, early-carry
//! Montgomery reduction, and squaring. `Fp8::mul` and `Fp8::square` are these
//! kernels.
//!
//! Ranges. A normalised operand has limbs below 2^52, so its value is below
//! 2^416 = R. The Montgomery product (a·b + m·p)/R is below 2p whenever
//! a·b < R·p: one operand below 2p and the other below 2^34·p, or both below
//! 2^17·p. Raw limbs are sums of at most 16 IFMA halves plus a carry, below
//! 2^57; raw sums and differences stay far below 2^63, where the signed carry
//! propagation of `normalise` is exact.

use std::arch::x86_64::{
    __m512i, __mmask8, _mm512_add_epi64, _mm512_and_si512, _mm512_cmpeq_epi64_mask,
    _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_mask_blend_epi64, _mm512_srai_epi64,
    _mm512_srli_epi64, _mm512_sub_epi64,
};

use crate::bls::{
    constants::{LIMBS, MASK52, P, P_INV52},
    fp8::{Fp8, Limbs, muladd_row, splat, splat_limbs, zero},
};

pub type Accumulator = [__m512i; 2 * LIMBS + 1];

pub const TWO_P: Limbs = [
    0xdffffffff5556,
    0xfd62a7ffff73f,
    0xd61ec483d57ff,
    0x257ece61a541e,
    0xec8ee9709e70a,
    0x374f6c869759a,
    0x3d472ffcd3496,
    0x0000000034022,
];
pub const FOUR_P: Limbs = [
    0xbfffffffeaaac,
    0xfac54ffffee7f,
    0xac3d8907aafff,
    0x4afd9cc34a83d,
    0xd91dd2e13ce14,
    0x6e9ed90d2eb35,
    0x7a8e5ff9a692c,
    0x0000000068044,
];
pub const EIGHT_P: Limbs = [
    0x7fffffffd5558,
    0xf58a9ffffdcff,
    0x587b120f55fff,
    0x95fb39869507b,
    0xb23ba5c279c28,
    0xdd3db21a5d66b,
    0xf51cbff34d258,
    0x00000000d0088,
];

/// `(t + lo(q·p₀)) >> 52` without the product: the low limb clears to zero,
/// so the sum carries exactly when `t`'s low limb is nonzero.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn carry_of_cleared(t: __m512i) -> __m512i {
    _mm512_srli_epi64::<52>(_mm512_add_epi64(t, splat(MASK52)))
}

impl Fp8 {
    /// The 16-limb product, unreduced.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn product(&self, rhs: &Self) -> Accumulator {
        let mut t = [zero(); 2 * LIMBS + 1];
        for i in 0..LIMBS {
            muladd_row(&mut t, &self.0, rhs.0[i], i);
        }
        t
    }

    /// The 16-limb square: the off-diagonal products once, doubled, then the
    /// diagonal. 72 IFMA instead of 128.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn square_product(&self) -> Accumulator {
        let a = &self.0;
        let mut t = [zero(); 2 * LIMBS + 1];
        for i in 0..LIMBS {
            for j in i + 1..LIMBS {
                t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[i], a[j]);
                t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[i], a[j]);
            }
        }
        for k in 1..2 * LIMBS {
            t[k] = _mm512_add_epi64(t[k], t[k]);
        }
        for i in 0..LIMBS {
            t[2 * i] = _mm512_madd52lo_epu64(t[2 * i], a[i], a[i]);
            t[2 * i + 1] = _mm512_madd52hi_epu64(t[2 * i + 1], a[i], a[i]);
        }
        t
    }

    /// Montgomery-reduces `t` to raw limbs.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn reduce(mut t: Accumulator) -> Self {
        let p = splat_limbs(&P);
        let pinv = splat(P_INV52);
        for i in 0..LIMBS {
            let carry = carry_of_cleared(t[i]);
            let q = _mm512_madd52lo_epu64(zero(), t[i], pinv);
            t[i + 1] = _mm512_add_epi64(t[i + 1], carry);
            for j in 1..LIMBS {
                t[i + j] = _mm512_madd52lo_epu64(t[i + j], p[j], q);
            }
            for j in 0..LIMBS {
                t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], p[j], q);
            }
        }
        Self(std::array::from_fn(|j| t[LIMBS + j]))
    }

    /// Limb-wise sum, no carries.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn add_raw(&self, rhs: &Self) -> Self {
        Self(std::array::from_fn(|j| _mm512_add_epi64(self.0[j], rhs.0[j])))
    }

    /// Limb-wise `self + c − rhs`, no carries; limbs may go negative. `c` is
    /// a multiple of p at or above `rhs`'s bound.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sub_raw(&self, rhs: &Self, c: &Self) -> Self {
        Self(std::array::from_fn(|j| {
            _mm512_sub_epi64(_mm512_add_epi64(self.0[j], c.0[j]), rhs.0[j])
        }))
    }

    /// Signed carry propagation into 52-bit limbs, for a value in [0, 2^416).
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

    /// For normalised `self` below 2c: `self − c` where `self ≥ c`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn cond_sub(&self, c: &Self) -> Self {
        let (d, borrowed) = self.sub_borrow(c);
        Self(std::array::from_fn(|j| _mm512_mask_blend_epi64(borrowed, d.0[j], self.0[j])))
    }
}

#[cfg(test)]
mod tests {
    use std::arch::x86_64::_mm512_storeu_si512;

    use blst::{blst_fp, blst_fp_from_uint64, blst_fp_mul, blst_uint64_from_fp};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::bls::{
        constants::P_U64,
        fp8::{LANES, pack64, unpack52},
        simd_available,
    };

    fn random_below(rng: &mut ChaCha8Rng, bound: &[u64; 6]) -> Limbs {
        loop {
            let mut words: [u64; 6] = rng.r#gen();
            words[5] &= (1 << 61) - 1;
            if words.iter().rev().lt(bound.iter().rev()) {
                return unpack52(&words);
            }
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn plain(v: &Fp8) -> [[u64; 6]; LANES] {
        v.to_plain().map(|limbs| pack64(&limbs))
    }

    #[test]
    fn lazy_kernels_match_mul() {
        if !simd_available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(0x1a27);
        let mut two_p = [0u64; 6];
        let mut carry = 0u64;
        for j in 0..6 {
            let (d, c1) = P_U64[j].overflowing_add(P_U64[j]);
            let (s, c2) = d.overflowing_add(carry);
            two_p[j] = s;
            carry = u64::from(c1) + u64::from(c2);
        }
        for _ in 0..16 {
            let a: [Limbs; LANES] = std::array::from_fn(|_| random_below(&mut rng, &two_p));
            let b: [Limbs; LANES] = std::array::from_fn(|_| random_below(&mut rng, &two_p));
            // SAFETY: checked above.
            unsafe {
                let (a, b) = (Fp8::load(&a), Fp8::load(&b));
                let sum = a.add_raw(&b).normalise();
                assert!(plain(&sum.cond_sub(&Fp8::splat_limbs(&TWO_P))) == plain(&a.add(&b)));
                let diff = a.sub_raw(&b, &Fp8::splat_limbs(&TWO_P)).normalise();
                assert!(plain(&diff.cond_sub(&Fp8::splat_limbs(&TWO_P))) == plain(&a.sub(&b)));
                let zero_mod_p = a.sub_raw(&a, &Fp8::splat_limbs(&TWO_P)).normalise();
                assert_eq!(zero_mod_p.cond_sub(&Fp8::splat_limbs(&TWO_P)).is_zero_mask(), 0xff);
                assert_eq!(diff.cond_sub(&Fp8::splat_limbs(&TWO_P)).is_zero_mask(), 0);
            }
        }
    }

    const fn times_p(k: u64) -> Limbs {
        let mut out = [0u64; LIMBS];
        let mut carry = 0u64;
        let mut j = 0;
        while j < LIMBS {
            let limb = P[j] * k + carry;
            out[j] = limb & MASK52;
            carry = limb >> 52;
            j += 1;
        }
        assert!(carry == 0);
        out
    }

    #[test]
    fn times_p_matches_the_literals() {
        assert_eq!(TWO_P, times_p(2));
        assert_eq!(FOUR_P, times_p(4));
        assert_eq!(EIGHT_P, times_p(8));
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn limbs_of(v: &Fp8) -> [Limbs; LANES] {
        let mut out = [[0u64; LIMBS]; LANES];
        for j in 0..LIMBS {
            let mut lanes = [0u64; LANES];
            // SAFETY: `lanes` is 64 bytes, and `_mm512_storeu_si512` has no alignment
            // requirement.
            unsafe { _mm512_storeu_si512(lanes.as_mut_ptr().cast(), v.0[j]) };
            for lane in 0..LANES {
                out[lane][j] = lanes[lane];
            }
        }
        out
    }

    fn below_two_p(limbs: &Limbs) -> bool {
        limbs.iter().rev().lt(TWO_P.iter().rev())
    }

    #[test]
    fn square_equals_mul_limb_for_limb() {
        if !simd_available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(0x5a);
        let all_ones = [[MASK52; LIMBS]; LANES];
        let mut operands = vec![all_ones];
        for _ in 0..16 {
            operands.push(std::array::from_fn(|_| random_below(&mut rng, &two_p_words())));
        }
        for operand in operands {
            // SAFETY: checked above.
            unsafe {
                let a = Fp8::load(&operand);
                assert!(limbs_of(&a.square()) == limbs_of(&a.mul(&a)));
            }
        }
    }

    #[test]
    fn mul_equals_the_reference_limb_for_limb() {
        if !simd_available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(0x3c);
        for round in 0..17 {
            let (a, b): ([Limbs; LANES], [Limbs; LANES]) = if round == 0 {
                ([[MASK52; LIMBS]; LANES], [[MASK52; LIMBS]; LANES])
            } else {
                (
                    std::array::from_fn(|_| random_below(&mut rng, &two_p_words())),
                    std::array::from_fn(|_| random_below(&mut rng, &two_p_words())),
                )
            };
            // SAFETY: checked above.
            unsafe {
                let (a, b) = (Fp8::load(&a), Fp8::load(&b));
                assert!(limbs_of(&a.mul(&b)) == limbs_of(&a.mul_reference(&b)));
            }
        }
    }

    fn two_p_words() -> [u64; 6] {
        let mut two_p = [0u64; 6];
        let mut carry = 0u64;
        for j in 0..6 {
            let (d, c1) = P_U64[j].overflowing_add(P_U64[j]);
            let (s, c2) = d.overflowing_add(carry);
            two_p[j] = s;
            carry = u64::from(c1) + u64::from(c2);
        }
        two_p
    }

    /// `2^shift · p − 1`, which is −1 modulo p.
    fn multiple_of_p_minus_one(shift: u32) -> Limbs {
        let mut out = [0u64; LIMBS];
        let mut carry = 0u128;
        for j in 0..LIMBS {
            let limb = (u128::from(P[j]) << shift) + carry;
            out[j] = limb as u64 & MASK52;
            carry = limb >> 52;
        }
        assert_eq!(carry, 0);
        out[0] -= 1;
        out
    }

    fn blst_product(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
        let (mut x, mut y, mut product) =
            (blst_fp::default(), blst_fp::default(), blst_fp::default());
        let mut out = [0u64; 6];
        // SAFETY: the pointers are to live, correctly sized values.
        unsafe {
            blst_fp_from_uint64(&mut x, a.as_ptr());
            blst_fp_from_uint64(&mut y, b.as_ptr());
            blst_fp_mul(&mut product, &x, &y);
            blst_uint64_from_fp(out.as_mut_ptr(), &product);
        }
        out
    }

    #[test]
    fn mul_accepts_operands_up_to_the_bound() {
        if !simd_available() {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(0x17);
        let below_2_17_p = multiple_of_p_minus_one(17);
        let below_2_34_p = multiple_of_p_minus_one(34);
        let mut partner: [Limbs; LANES] =
            std::array::from_fn(|_| random_below(&mut rng, &two_p_words()));
        partner[0] = multiple_of_p_minus_one(1);
        let minus_one = multiple_of_p_minus_one(0);
        let cases = [
            ([below_2_17_p; LANES], [minus_one; LANES], [below_2_17_p; LANES], [minus_one; LANES]),
            ([below_2_34_p; LANES], [minus_one; LANES], partner, partner),
            (partner, partner, [below_2_34_p; LANES], [minus_one; LANES]),
        ];
        for (a, a_below_2p, b, b_below_2p) in cases {
            // SAFETY: checked above.
            unsafe {
                let product = Fp8::load(&a).mul(&Fp8::load(&b));
                for lane_limbs in limbs_of(&product) {
                    assert!(below_two_p(&lane_limbs));
                }
                let got = plain(&product);
                let a_plain = plain(&Fp8::load(&a_below_2p));
                let b_plain = plain(&Fp8::load(&b_below_2p));
                for lane in 0..LANES {
                    let want = blst_product(&a_plain[lane], &b_plain[lane]);
                    assert_eq!(got[lane], want, "lane {lane}");
                }
            }
        }
    }
}
