//! Eight independent Fr elements, one per 64-bit lane, as five 52-bit limbs.
//!
//! Lanes hold plain integers modulo r. `mul` is the Montgomery product
//! a·b/2^260, so it multiplies a lane by w where the other operand is
//! `multiplier(w)`, w's Montgomery form for R = 2^260. Every constant is
//! loaded that way, and blst's form (R = 2^256) of 16·w spells it out.
//!
//! A lane's value is Σ_j limb_j·2^(52j), each limb a signed 64-bit integer.
//! Operations state their ranges in three classes:
//! - normalised: every limb in [0, 2^52), as IFMA operands must be;
//! - reduced: normalised and below 2r;
//! - lazy(k, m): in [0, k·r), every limb below m·2^52 in magnitude.
//!
//! A reduced value is lazy(2, 1). Montgomery products land below 2r without a
//! conditional subtraction, as in `bls::fp8`, and `normalise` brings a lazy
//! value below 2^260 back to normalised limbs. Values are canonicalised only
//! when stored.

use std::arch::x86_64::{
    __m512i, __mmask8, _mm512_add_epi64, _mm512_and_si512, _mm512_cmpeq_epi64_mask,
    _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_mask_blend_epi64, _mm512_set_epi64,
    _mm512_set1_epi64, _mm512_setzero_si512, _mm512_srai_epi64, _mm512_sub_epi64,
};

use blst::blst_fr;

use self::u256x8::U256x8;
#[cfg(test)]
use crate::bls::fp8::lanes;
use crate::{
    bls::fp8::{carry_of_cleared, transpose8},
    kzg::blst_ops::{fr_from_u64, fr_mul},
};

mod u256x8;

pub const LANES: usize = 8;
const LIMBS: usize = 5;
const LIMB_BITS: u32 = 52;
const MASK52: u64 = (1 << LIMB_BITS) - 1;
/// r, little-endian.
const R: [u64; LIMBS] =
    [0xfffff00000001, 0x2fffe5bfefff, 0x9a1d80553bda4, 0x7d483339d8080, 0x73eda753299d];
/// `-r^-1 mod 2^52`.
const R_INV52: u64 = 0xffffeffffffff;
const SCALE: u64 = 1 << (LIMBS as u32 * LIMB_BITS - 256);

/// The blst element whose limbs, loaded by `Fr8::load`, make `Fr8::mul`
/// multiply by w.
pub fn multiplier(w: &blst_fr) -> blst_fr {
    fr_mul(w, &fr_from_u64(SCALE))
}

#[derive(Clone, Copy)]
pub struct Fr8([__m512i; LIMBS]);

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn splat(x: u64) -> __m512i {
    _mm512_set1_epi64(x as i64)
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn zero() -> __m512i {
    _mm512_setzero_si512()
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn splat_limbs(limbs: &[u64; LIMBS]) -> [__m512i; LIMBS] {
    let mut v = [zero(); LIMBS];
    for j in 0..LIMBS {
        v[j] = splat(limbs[j]);
    }
    v
}

/// `a - b` limb-wise with a borrow chain; the borrow is 0 or -1 per lane.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn sub_limbs(a: &[__m512i; LIMBS], b: &[__m512i; LIMBS]) -> ([__m512i; LIMBS], __m512i) {
    let mask = splat(MASK52);
    let mut d = [zero(); LIMBS];
    let mut borrow = zero();
    for j in 0..LIMBS {
        let s = _mm512_add_epi64(_mm512_sub_epi64(a[j], b[j]), borrow);
        borrow = _mm512_srai_epi64::<63>(s);
        d[j] = _mm512_and_si512(s, mask);
    }
    (d, borrow)
}

/// Where `borrow` is set (all ones), `a` was below `b` in `sub_limbs`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn borrowed(borrow: __m512i) -> __mmask8 {
    _mm512_cmpeq_epi64_mask(borrow, splat(u64::MAX))
}

/// Lanes where `borrow` is set take `a`, the others `b`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn select_borrowed(
    borrow: __m512i,
    a: &[__m512i; LIMBS],
    b: &[__m512i; LIMBS],
) -> [__m512i; LIMBS] {
    let k = borrowed(borrow);
    let mut r = [zero(); LIMBS];
    for j in 0..LIMBS {
        r[j] = _mm512_mask_blend_epi64(k, b[j], a[j]);
    }
    r
}

/// `t[i..] += a * b_i` over the 2·LIMBS-wide accumulator.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn muladd_row(t: &mut [__m512i; 2 * LIMBS + 1], a: &[__m512i; LIMBS], b_i: __m512i, i: usize) {
    for j in 0..LIMBS {
        t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[j], b_i);
        t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[j], b_i);
    }
}

/// Clears limb `i` of the accumulator with a multiple of r and carries it up,
/// leaving limb `i` itself stale. The next row's q waits on limb `i + 1`
/// alone. Its carry needs no product, so it enters first, and its two products
/// of q accumulate apart, so they run in parallel.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn reduce_row(t: &mut [__m512i; 2 * LIMBS + 1], r: &[__m512i; LIMBS], rinv: __m512i, i: usize) {
    let q = _mm512_madd52lo_epu64(zero(), t[i], rinv);
    t[i + 1] = _mm512_add_epi64(t[i + 1], carry_of_cleared(t[i]));
    let high = _mm512_madd52hi_epu64(zero(), r[0], q);
    for j in 1..LIMBS {
        t[i + j] = _mm512_madd52lo_epu64(t[i + j], r[j], q);
    }
    t[i + 1] = _mm512_add_epi64(t[i + 1], high);
    for j in 1..LIMBS {
        t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], r[j], q);
    }
}

/// Four little-endian 64-bit words as five 52-bit limbs.
fn unpack52(x: &[u64; 4]) -> [u64; LIMBS] {
    [
        x[0] & MASK52,
        (x[0] >> 52 | x[1] << 12) & MASK52,
        (x[1] >> 40 | x[2] << 24) & MASK52,
        (x[2] >> 28 | x[3] << 36) & MASK52,
        x[3] >> 16,
    ]
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn transpose_in(limbs: &[[u64; LIMBS]; LANES]) -> [__m512i; LIMBS] {
    let mut v = [zero(); LIMBS];
    for j in 0..LIMBS {
        v[j] = _mm512_set_epi64(
            limbs[7][j] as i64,
            limbs[6][j] as i64,
            limbs[5][j] as i64,
            limbs[4][j] as i64,
            limbs[3][j] as i64,
            limbs[2][j] as i64,
            limbs[1][j] as i64,
            limbs[0][j] as i64,
        );
    }
    v
}

impl Fr8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn zero() -> Self {
        Self([zero(); LIMBS])
    }

    /// Lane `l` takes the limbs of `values[at + l]` as they are.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn load(values: &[blst_fr], at: usize) -> Self {
        let mut limbs = [[0u64; LIMBS]; LANES];
        for lane in 0..LANES {
            limbs[lane] = unpack52(&values[at + lane].l);
        }
        Self(transpose_in(&limbs))
    }

    /// Lane `l` takes the 32 big-endian bytes at `at + 32·l`; the mask holds
    /// the lanes whose value is below r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn from_bytes(bytes: &[u8], at: usize) -> (Self, __mmask8) {
        let v = U256x8::from_bytes(bytes, at).limbs();
        let (_, borrow) = sub_limbs(&v, &splat_limbs(&R));
        (Self(v), borrowed(borrow))
    }

    /// The inverse of `from_bytes`, with each value reduced below r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn to_bytes(self, bytes: &mut [u8], at: usize) {
        U256x8::from_limbs(&self.canonical().0).to_bytes(bytes, at);
    }

    /// Montgomery product with R = 2^260: the full ten-limb product first, then
    /// five reduction rows, every index a constant so the accumulator stays in
    /// registers. For normalised operands with a·b < r·2^260, such as both
    /// below 2r or either below r, the result is lazy(2, 32), its limbs left
    /// uncarried in [0, 2^57).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let r = splat_limbs(&R);
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
        Self([t[LIMBS], t[LIMBS + 1], t[LIMBS + 2], t[LIMBS + 3], t[LIMBS + 4]])
    }

    /// The same value with limbs 0 to 3 in [0, 2^52), each limb's signed excess
    /// carried into the next. A value in [0, 2^260) comes out normalised.
    /// Limbs below 2^62 in magnitude do not overflow.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn normalise(&self) -> Self {
        let mask = splat(MASK52);
        let mut s = self.0;
        for j in 0..LIMBS - 1 {
            s[j + 1] = _mm512_add_epi64(s[j + 1], _mm512_srai_epi64::<52>(s[j]));
            s[j] = _mm512_and_si512(s[j], mask);
        }
        Self(s)
    }

    /// Limb-wise, without carries: lazy(k, m) and lazy(k', m') give
    /// lazy(k + k', m + m').
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn add_raw(&self, rhs: &Self) -> Self {
        let mut s = [zero(); LIMBS];
        for j in 0..LIMBS {
            s[j] = _mm512_add_epi64(self.0[j], rhs.0[j]);
        }
        Self(s)
    }

    /// `self + offset − rhs` limb-wise, without carries; limbs may go
    /// negative. With `offset` the normalised c·r: lazy(k, m) and lazy(k', m')
    /// for k' ≤ c give lazy(k + c, m + m' + 1).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sub_raw(&self, rhs: &Self, offset: &Self) -> Self {
        let mut s = [zero(); LIMBS];
        for j in 0..LIMBS {
            s[j] = _mm512_sub_epi64(_mm512_add_epi64(self.0[j], offset.0[j]), rhs.0[j]);
        }
        Self(s)
    }

    /// c·r in every lane, normalised.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn multiple_of_r(c: u64) -> Self {
        assert!(c <= 35, "c·r below 2^260");
        let mut v = [zero(); LIMBS];
        let mut carry = 0;
        for j in 0..LIMBS {
            let limb = R[j] * c + carry;
            v[j] = splat(limb & MASK52);
            carry = limb >> LIMB_BITS;
        }
        Self(v)
    }

    /// Lane l's limbs at l, as they are.
    #[cfg(test)]
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(super) fn lane_limbs(&self) -> [[u64; LIMBS]; LANES] {
        let mut out = [[0u64; LIMBS]; LANES];
        for j in 0..LIMBS {
            let l = lanes(self.0[j]);
            for lane in 0..LANES {
                out[lane][j] = l[lane];
            }
        }
        out
    }

    /// Down from [0, 2r) to [0, r).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn canonical(self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &splat_limbs(&R));
        Self(select_borrowed(borrow, &self.0, &d))
    }

    /// Down from [0, 4r) to [0, 2r), for normalised limbs.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn reduced(self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &Self::multiple_of_r(2).0);
        Self(select_borrowed(borrow, &self.0, &d))
    }

    /// lazy(2, m) operands, m ≤ 2^8, such as products, give a reduced sum.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        self.add_raw(rhs).normalise().reduced()
    }

    /// lazy(2, m) operands, m ≤ 2^8, such as products, give a reduced
    /// difference.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        self.sub_raw(rhs, &Self::multiple_of_r(2)).normalise().reduced()
    }

    /// The eight vectors at `at`, lane l of vector k becoming lane k of
    /// vector l.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn transpose(vectors: &[Self], at: usize) -> [Self; LANES] {
        let mut out = [[zero(); LIMBS]; LANES];
        for j in 0..LIMBS {
            let rows = transpose8(&[
                vectors[at].0[j],
                vectors[at + 1].0[j],
                vectors[at + 2].0[j],
                vectors[at + 3].0[j],
                vectors[at + 4].0[j],
                vectors[at + 5].0[j],
                vectors[at + 6].0[j],
                vectors[at + 7].0[j],
            ]);
            for k in 0..LANES {
                out[k][j] = rows[k];
            }
        }
        [
            Self(out[0]),
            Self(out[1]),
            Self(out[2]),
            Self(out[3]),
            Self(out[4]),
            Self(out[5]),
            Self(out[6]),
            Self(out[7]),
        ]
    }
}

#[cfg(test)]
mod tests;
