//! Eight independent Fp elements, one per 64-bit lane, as eight 52-bit limbs in
//! Montgomery form with R = 2^416: the shape `vpmadd52` multiplies natively.
//!
//! Values are kept in [0, 2p) with normalised limbs — Montgomery products of
//! such inputs land there without a conditional subtraction, since 4p < R —
//! and are canonicalised only where bits are compared or exported.

use std::arch::x86_64::{
    __m512i, __mmask8, _mm512_add_epi64, _mm512_and_si512, _mm512_cmpeq_epi64_mask,
    _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_mask_blend_epi64, _mm512_set_epi64,
    _mm512_set1_epi64, _mm512_setzero_si512, _mm512_srai_epi64, _mm512_srli_epi64,
    _mm512_sub_epi64,
};

use crate::constants::{
    LIMB_BITS, LIMBS, MASK52, ONE_PLAIN, P, P_INV52, R_MOD_P, R2_MOD_P, TWO_POW_384_MOD_P,
};

pub const LANES: usize = 8;

pub type Limbs = [u64; LIMBS];

#[derive(Clone, Copy)]
pub struct Fp8(pub [__m512i; LIMBS]);

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
fn splat_limbs(limbs: &Limbs) -> [__m512i; LIMBS] {
    let mut v = [zero(); LIMBS];
    for j in 0..LIMBS {
        v[j] = splat(limbs[j]);
    }
    v
}

#[inline]
fn lanes(v: __m512i) -> [u64; LANES] {
    // SAFETY: __m512i is 64 bytes of plain integer data with no invalid bit
    // patterns.
    unsafe { std::mem::transmute(v) }
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

/// `a + b` limb-wise with carries normalised into the next limb.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn add_limbs(a: &[__m512i; LIMBS], b: &[__m512i; LIMBS]) -> [__m512i; LIMBS] {
    let mask = splat(MASK52);
    let mut s = [zero(); LIMBS];
    let mut carry = zero();
    for j in 0..LIMBS {
        let t = _mm512_add_epi64(_mm512_add_epi64(a[j], b[j]), carry);
        carry = _mm512_srli_epi64::<52>(t);
        s[j] = _mm512_and_si512(t, mask);
    }
    s
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn blend(k: __mmask8, a: &[__m512i; LIMBS], b: &[__m512i; LIMBS]) -> [__m512i; LIMBS] {
    let mut r = [zero(); LIMBS];
    for j in 0..LIMBS {
        r[j] = _mm512_mask_blend_epi64(k, a[j], b[j]);
    }
    r
}

/// Where `borrow` is set (all ones), `a` was below `b` in `sub_limbs`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn borrowed(borrow: __m512i) -> __mmask8 {
    _mm512_cmpeq_epi64_mask(borrow, splat(u64::MAX))
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

/// Clears limb `i` of the accumulator with a multiple of p and carries it up.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn reduce_row(t: &mut [__m512i; 2 * LIMBS + 1], p: &[__m512i; LIMBS], pinv: __m512i, i: usize) {
    let q = _mm512_madd52lo_epu64(zero(), t[i], pinv);
    for j in 0..LIMBS {
        t[i + j] = _mm512_madd52lo_epu64(t[i + j], q, p[j]);
        t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], q, p[j]);
    }
    t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64::<52>(t[i]));
}

/// Little-endian 64-bit limbs of a 381-bit value to 52-bit limbs.
pub fn unpack52(x: &[u64; 6]) -> Limbs {
    let mut out = [0u64; LIMBS];
    for (j, limb) in out.iter_mut().enumerate() {
        let bit = j as u32 * LIMB_BITS;
        let (word, shift) = ((bit / 64) as usize, bit % 64);
        let mut v = x[word] >> shift;
        if shift > 12 && word + 1 < 6 {
            v |= x[word + 1] << (64 - shift);
        }
        *limb = v & MASK52;
    }
    out
}

/// Inverse of `unpack52`.
pub fn pack64(x: &Limbs) -> [u64; 6] {
    let mut out = [0u64; 6];
    let mut acc: u128 = 0;
    let mut acc_bits = 0u32;
    let mut word = 0;
    for &limb in x {
        acc |= (limb as u128) << acc_bits;
        acc_bits += LIMB_BITS;
        if acc_bits >= 64 {
            out[word] = acc as u64;
            word += 1;
            acc >>= 64;
            acc_bits -= 64;
        }
    }
    if word < 6 {
        out[word] = acc as u64;
    }
    out
}

impl Fp8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn splat_limbs(limbs: &Limbs) -> Self {
        Self(splat_limbs(limbs))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn zero() -> Self {
        Self([zero(); LIMBS])
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn one() -> Self {
        Self::splat_limbs(&R_MOD_P)
    }

    /// Lane `l` takes `values[l]` as raw limbs, no conversion.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn load(values: &[Limbs; LANES]) -> Self {
        let mut v = [zero(); LIMBS];
        for j in 0..LIMBS {
            v[j] = _mm512_set_epi64(
                values[7][j] as i64,
                values[6][j] as i64,
                values[5][j] as i64,
                values[4][j] as i64,
                values[3][j] as i64,
                values[2][j] as i64,
                values[1][j] as i64,
                values[0][j] as i64,
            );
        }
        Self(v)
    }

    fn store(&self) -> [Limbs; LANES] {
        let mut out = [[0u64; LIMBS]; LANES];
        for (j, limb) in self.0.iter().enumerate() {
            let l = lanes(*limb);
            for lane in 0..LANES {
                out[lane][j] = l[lane];
            }
        }
        out
    }

    /// Plain integers (< p) per lane into Montgomery form.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn from_plain(values: &[Limbs; LANES]) -> Self {
        Self::load(values).mul(&Self::splat_limbs(&R2_MOD_P))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn to_plain(self) -> [Limbs; LANES] {
        self.mul(&Self::splat_limbs(&ONE_PLAIN)).canonical().store()
    }

    /// Same values in blst's Montgomery form (R = 2^384), as its six 64-bit
    /// limbs.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn to_blst_limbs(self) -> [[u64; 6]; LANES] {
        let t = self.mul(&Self::splat_limbs(&TWO_POW_384_MOD_P)).canonical().store();
        let mut out = [[0u64; 6]; LANES];
        for lane in 0..LANES {
            out[lane] = pack64(&t[lane]);
        }
        out
    }

    /// Montgomery product: the full 16-limb product first, then eight
    /// reduction rows, every index a constant so the accumulator stays in
    /// registers.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn mul(&self, rhs: &Self) -> Self {
        let p = splat_limbs(&P);
        let pinv = splat(P_INV52);
        let mut t = [zero(); 2 * LIMBS + 1];
        muladd_row(&mut t, &self.0, rhs.0[0], 0);
        muladd_row(&mut t, &self.0, rhs.0[1], 1);
        muladd_row(&mut t, &self.0, rhs.0[2], 2);
        muladd_row(&mut t, &self.0, rhs.0[3], 3);
        muladd_row(&mut t, &self.0, rhs.0[4], 4);
        muladd_row(&mut t, &self.0, rhs.0[5], 5);
        muladd_row(&mut t, &self.0, rhs.0[6], 6);
        muladd_row(&mut t, &self.0, rhs.0[7], 7);
        reduce_row(&mut t, &p, pinv, 0);
        reduce_row(&mut t, &p, pinv, 1);
        reduce_row(&mut t, &p, pinv, 2);
        reduce_row(&mut t, &p, pinv, 3);
        reduce_row(&mut t, &p, pinv, 4);
        reduce_row(&mut t, &p, pinv, 5);
        reduce_row(&mut t, &p, pinv, 6);
        reduce_row(&mut t, &p, pinv, 7);

        let mask = splat(MASK52);
        let mut r = [zero(); LIMBS];
        r[0] = t[LIMBS];
        for j in 0..LIMBS - 1 {
            r[j + 1] = _mm512_add_epi64(t[LIMBS + j + 1], _mm512_srli_epi64::<52>(r[j]));
            r[j] = _mm512_and_si512(r[j], mask);
        }
        Self(r)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Down from [0, 2p) to [0, p).
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn canonical(self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &splat_limbs(&P));
        Self(blend(borrowed(borrow), &d, &self.0))
    }

    /// Sum below 4p, brought back under 2p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add(&self, rhs: &Self) -> Self {
        let s = add_limbs(&self.0, &rhs.0);
        let (d, borrow) = sub_limbs(&s, &two_p());
        Self(blend(borrowed(borrow), &d, &s))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn sub(&self, rhs: &Self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &rhs.0);
        let wrapped = add_limbs(&d, &two_p());
        Self(blend(borrowed(borrow), &d, &wrapped))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn eq_mask(&self, rhs: &Self) -> __mmask8 {
        let (a, b) = (self.canonical(), rhs.canonical());
        let mut k: __mmask8 = 0xff;
        for j in 0..LIMBS {
            k &= _mm512_cmpeq_epi64_mask(a.0[j], b.0[j]);
        }
        k
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn is_zero_mask(&self) -> __mmask8 {
        let a = self.canonical();
        let mut k: __mmask8 = 0xff;
        for j in 0..LIMBS {
            k &= _mm512_cmpeq_epi64_mask(a.0[j], zero());
        }
        k
    }

    /// Lanes of `k` take `b`, the rest `a`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn select(k: __mmask8, a: &Self, b: &Self) -> Self {
        Self(blend(k, &a.0, &b.0))
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn two_p() -> [__m512i; LIMBS] {
    add_limbs(&splat_limbs(&P), &splat_limbs(&P))
}
