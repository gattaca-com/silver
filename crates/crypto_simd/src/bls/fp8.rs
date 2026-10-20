//! Eight independent Fp elements, one per 64-bit lane, as eight 52-bit limbs in
//! Montgomery form with R = 2^416: the shape `vpmadd52` multiplies natively.
//!
//! Values are kept in [0, 2p) with normalised limbs — Montgomery products of
//! such inputs land there without a conditional subtraction, since 4p < R —
//! and are canonicalised only where bits are compared or exported.

use std::arch::x86_64::{
    __m512i, __mmask8, _mm512_add_epi64, _mm512_and_si512, _mm512_cmpeq_epi64_mask,
    _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_mask_blend_epi64,
    _mm512_permutex2var_epi64, _mm512_set_epi64, _mm512_set1_epi64, _mm512_setzero_si512,
    _mm512_srai_epi64, _mm512_srli_epi64, _mm512_sub_epi64,
};

use crate::bls::constants::{
    HALF_MONT, HALF_P_MINUS_1, LIMB_BITS, LIMBS, MASK52, ONE_PLAIN, P, P_INV52,
    P_MINUS_3_OVER_4_WINDOWS, R_MOD_P, R2_MOD_P, TWO_POW_384_MOD_P,
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
pub(crate) fn lanes(v: __m512i) -> [u64; LANES] {
    // SAFETY: __m512i is 64 bytes of plain integer data with no invalid bit
    // patterns.
    unsafe { std::mem::transmute(v) }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub(crate) fn index_vector(index: &[i64; LANES]) -> __m512i {
    _mm512_set_epi64(index[7], index[6], index[5], index[4], index[3], index[2], index[1], index[0])
}

/// Lane l of row k becomes lane k of row l. Round d, for d = 1, 2 and 4,
/// swaps the d bit of the row index with the d bit of the lane index: rows
/// k and k + d, for k without the d bit, trade the lanes whose d bit
/// differs from their row's.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub(crate) fn transpose8(r: &[__m512i; LANES]) -> [__m512i; LANES] {
    let low = index_vector(&[0, 8, 2, 10, 4, 12, 6, 14]);
    let high = index_vector(&[1, 9, 3, 11, 5, 13, 7, 15]);
    let a = [
        _mm512_permutex2var_epi64(r[0], low, r[1]),
        _mm512_permutex2var_epi64(r[0], high, r[1]),
        _mm512_permutex2var_epi64(r[2], low, r[3]),
        _mm512_permutex2var_epi64(r[2], high, r[3]),
        _mm512_permutex2var_epi64(r[4], low, r[5]),
        _mm512_permutex2var_epi64(r[4], high, r[5]),
        _mm512_permutex2var_epi64(r[6], low, r[7]),
        _mm512_permutex2var_epi64(r[6], high, r[7]),
    ];
    let low = index_vector(&[0, 1, 8, 9, 4, 5, 12, 13]);
    let high = index_vector(&[2, 3, 10, 11, 6, 7, 14, 15]);
    let b = [
        _mm512_permutex2var_epi64(a[0], low, a[2]),
        _mm512_permutex2var_epi64(a[1], low, a[3]),
        _mm512_permutex2var_epi64(a[0], high, a[2]),
        _mm512_permutex2var_epi64(a[1], high, a[3]),
        _mm512_permutex2var_epi64(a[4], low, a[6]),
        _mm512_permutex2var_epi64(a[5], low, a[7]),
        _mm512_permutex2var_epi64(a[4], high, a[6]),
        _mm512_permutex2var_epi64(a[5], high, a[7]),
    ];
    let low = index_vector(&[0, 1, 2, 3, 8, 9, 10, 11]);
    let high = index_vector(&[4, 5, 6, 7, 12, 13, 14, 15]);
    [
        _mm512_permutex2var_epi64(b[0], low, b[4]),
        _mm512_permutex2var_epi64(b[1], low, b[5]),
        _mm512_permutex2var_epi64(b[2], low, b[6]),
        _mm512_permutex2var_epi64(b[3], low, b[7]),
        _mm512_permutex2var_epi64(b[0], high, b[4]),
        _mm512_permutex2var_epi64(b[1], high, b[5]),
        _mm512_permutex2var_epi64(b[2], high, b[6]),
        _mm512_permutex2var_epi64(b[3], high, b[7]),
    ]
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

/// `t[2i + 1..] += a_i · a[i + 1..]`: the products of row `i` above the
/// diagonal.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn square_row(t: &mut [__m512i; 2 * LIMBS + 1], a: &[__m512i; LIMBS], i: usize) {
    for j in i + 1..LIMBS {
        t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[i], a[j]);
        t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[i], a[j]);
    }
}

/// `(t + lo(q·m₀)) >> 52` for any q with q·m₀ ≡ −t (mod 2^52), without the
/// product. Both are `t >> 52` plus one if the low 52 bits of `t` are
/// nonzero, and both wrap alike, so they agree on every `t`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
pub(crate) fn carry_of_cleared(t: __m512i) -> __m512i {
    _mm512_srli_epi64::<52>(_mm512_add_epi64(t, splat(MASK52)))
}

/// Clears limb `i` of the accumulator with a multiple of p and carries it up,
/// leaving limb `i` itself stale. The next row's q waits on limb `i + 1`
/// alone. Its carry needs no product, so it enters first, and its two products
/// of q accumulate apart, so they run in parallel.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn reduce_row(t: &mut [__m512i; 2 * LIMBS + 1], p: &[__m512i; LIMBS], pinv: __m512i, i: usize) {
    let q = _mm512_madd52lo_epu64(zero(), t[i], pinv);
    t[i + 1] = _mm512_add_epi64(t[i + 1], carry_of_cleared(t[i]));
    let high = _mm512_madd52hi_epu64(zero(), p[0], q);
    for j in 1..LIMBS {
        t[i + j] = _mm512_madd52lo_epu64(t[i + j], p[j], q);
    }
    t[i + 1] = _mm512_add_epi64(t[i + 1], high);
    for j in 1..LIMBS {
        t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], p[j], q);
    }
}

/// Little-endian 64-bit limbs of a 381-bit value to 52-bit limbs.
#[inline]
pub fn unpack52(x: &[u64; 6]) -> Limbs {
    let mut out = [0u64; LIMBS];
    for j in 0..LIMBS {
        let bit = j as u32 * LIMB_BITS;
        let (word, shift) = ((bit / 64) as usize, bit % 64);
        let mut v = x[word] >> shift;
        if shift > 12 && word + 1 < 6 {
            v |= x[word + 1] << (64 - shift);
        }
        out[j] = v & MASK52;
    }
    out
}

/// Inverse of `unpack52`.
#[inline]
pub fn pack64(x: &Limbs) -> [u64; 6] {
    let mut out = [0u64; 6];
    let mut acc: u128 = 0;
    let mut acc_bits = 0u32;
    let mut word = 0;
    for j in 0..LIMBS {
        let limb = x[j];
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
    #[inline]
    pub fn splat_limbs(limbs: &Limbs) -> Self {
        Self(splat_limbs(limbs))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn zero() -> Self {
        Self([zero(); LIMBS])
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn one() -> Self {
        Self::splat_limbs(&R_MOD_P)
    }

    /// Lane `l` takes `values[l]` as raw limbs, no conversion.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
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

    #[inline]
    fn store(&self) -> [Limbs; LANES] {
        let mut out = [[0u64; LIMBS]; LANES];
        for j in 0..LIMBS {
            let l = lanes(self.0[j]);
            for lane in 0..LANES {
                out[lane][j] = l[lane];
            }
        }
        out
    }

    /// Plain integers (< p) per lane into Montgomery form.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn from_plain(values: &[Limbs; LANES]) -> Self {
        Self::load(values).mul(&Self::splat_limbs(&R2_MOD_P))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
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

    /// Montgomery product: the full 16-limb product, then `reduce`. Every row
    /// takes a constant index, so neither phase indexes the accumulator at run
    /// time.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut t = [zero(); 2 * LIMBS + 1];
        muladd_row(&mut t, &self.0, rhs.0[0], 0);
        muladd_row(&mut t, &self.0, rhs.0[1], 1);
        muladd_row(&mut t, &self.0, rhs.0[2], 2);
        muladd_row(&mut t, &self.0, rhs.0[3], 3);
        muladd_row(&mut t, &self.0, rhs.0[4], 4);
        muladd_row(&mut t, &self.0, rhs.0[5], 5);
        muladd_row(&mut t, &self.0, rhs.0[6], 6);
        muladd_row(&mut t, &self.0, rhs.0[7], 7);
        Self::reduce(t)
    }

    /// The limbs of `self.mul(self)` from 72 products instead of 128: those
    /// above the diagonal once, doubled, then the diagonal.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn square(&self) -> Self {
        let a = &self.0;
        let mut t = [zero(); 2 * LIMBS + 1];
        square_row(&mut t, a, 0);
        square_row(&mut t, a, 1);
        square_row(&mut t, a, 2);
        square_row(&mut t, a, 3);
        square_row(&mut t, a, 4);
        square_row(&mut t, a, 5);
        square_row(&mut t, a, 6);
        for k in 0..2 * LIMBS + 1 {
            t[k] = _mm512_add_epi64(t[k], t[k]);
        }
        for i in 0..LIMBS {
            t[2 * i] = _mm512_madd52lo_epu64(t[2 * i], a[i], a[i]);
            t[2 * i + 1] = _mm512_madd52hi_epu64(t[2 * i + 1], a[i], a[i]);
        }
        Self::reduce(t)
    }

    /// Montgomery-reduces a full product: `t · 2^-416` modulo p, with
    /// normalised limbs.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn reduce(mut t: [__m512i; 2 * LIMBS + 1]) -> Self {
        let p = splat_limbs(&P);
        let pinv = splat(P_INV52);
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

    /// Down from [0, 2p) to [0, p).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn canonical(self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &splat_limbs(&P));
        Self(blend(borrowed(borrow), &d, &self.0))
    }

    /// Sum below 4p, brought back under 2p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        let s = add_limbs(&self.0, &rhs.0);
        let (d, borrow) = sub_limbs(&s, &two_p());
        Self(blend(borrowed(borrow), &d, &s))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &rhs.0);
        let wrapped = add_limbs(&d, &two_p());
        Self(blend(borrowed(borrow), &d, &wrapped))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn half(&self) -> Self {
        self.mul(&Self::splat_limbs(&HALF_MONT))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn eq_mask(&self, rhs: &Self) -> __mmask8 {
        let (a, b) = (self.canonical(), rhs.canonical());
        let mut k: __mmask8 = 0xff;
        for j in 0..LIMBS {
            k &= _mm512_cmpeq_epi64_mask(a.0[j], b.0[j]);
        }
        k
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
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
    #[inline]
    pub fn select(k: __mmask8, a: &Self, b: &Self) -> Self {
        Self(blend(k, &a.0, &b.0))
    }

    /// `self^((p-3)/4)`: the reciprocal square root when `self` is a
    /// quadratic residue (p = 3 mod 4). The exponent is shared by every lane,
    /// so a fixed 4-bit window needs no per-lane table lookups.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn pow_p_minus_3_over_4(&self) -> Self {
        let mut table = [Self::one(); 16];
        table[1] = *self;
        for k in 2..16 {
            table[k] = table[k - 1].mul(self);
        }
        let mut r = table[P_MINUS_3_OVER_4_WINDOWS[94] as usize];
        let mut w = 94;
        while w > 0 {
            w -= 1;
            r = r.square().square().square().square();
            let digit = P_MINUS_3_OVER_4_WINDOWS[w] as usize;
            if digit != 0 {
                r = r.mul(&table[digit]);
            }
        }
        r
    }

    /// `self^((p+1)/4)`: the square root when `self` is a quadratic residue.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sqrt_candidate(&self) -> Self {
        self.pow_p_minus_3_over_4().mul(self)
    }

    /// Lanes whose plain value exceeds (p - 1) / 2: the lexicographically
    /// larger of the two square roots.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn is_larger_root_mask(&self) -> __mmask8 {
        let plain = Self::load(&self.to_plain());
        let (_, borrow) = sub_limbs(&splat_limbs(&HALF_P_MINUS_1), &plain.0);
        borrowed(borrow)
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn two_p() -> [__m512i; LIMBS] {
    add_limbs(&splat_limbs(&P), &splat_limbs(&P))
}

#[cfg(test)]
mod tests;
