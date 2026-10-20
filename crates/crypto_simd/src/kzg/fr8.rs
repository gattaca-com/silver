//! Eight independent Fr elements, one per 64-bit lane, as five 52-bit limbs.
//!
//! Lanes hold plain integers modulo r. `mul` is the Montgomery product
//! a·b/2^260, so it multiplies a lane by w where the other operand is
//! `multiplier(w)`, w's Montgomery form for R = 2^260. Every constant is
//! loaded that way, and blst's form (R = 2^256) of 16·w spells it out.
//!
//! Values are kept in [0, 2r) with normalised limbs, as in `bls::fp8`:
//! Montgomery products of such inputs land there without a conditional
//! subtraction, since 4r < 2^260. They are canonicalised only when stored.

use std::arch::x86_64::{
    __m512i, __mmask8, _mm512_add_epi64, _mm512_and_si512, _mm512_cmpeq_epi64_mask,
    _mm512_madd52hi_epu64, _mm512_madd52lo_epu64, _mm512_mask_blend_epi64,
    _mm512_permutex2var_epi64, _mm512_set_epi64, _mm512_set1_epi64, _mm512_setzero_si512,
    _mm512_srai_epi64, _mm512_srli_epi64, _mm512_sub_epi64,
};

use blst::blst_fr;

use crate::{
    bls::fp8::{carry_of_cleared, lanes},
    kzg::blst_ops::{fr_from_u64, fr_mul},
};

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

/// The inverse of `unpack52` on values below 2^256.
fn pack64(x: &[u64; LIMBS]) -> [u64; 4] {
    [x[0] | x[1] << 52, x[1] >> 12 | x[2] << 40, x[2] >> 24 | x[3] << 28, x[3] >> 36 | x[4] << 16]
}

/// The 32 big-endian bytes at `at` as little-endian 64-bit words.
fn words_from_bytes(bytes: &[u8], at: usize) -> [u64; 4] {
    let mut words = [0u64; 4];
    let mut word = [0u8; 8];
    for k in 0..4 {
        word.copy_from_slice(&bytes[at + 8 * k..at + 8 * k + 8]);
        words[3 - k] = u64::from_be_bytes(word);
    }
    words
}

fn words_to_bytes(words: &[u64; 4], bytes: &mut [u8], at: usize) {
    for k in 0..4 {
        bytes[at + 8 * k..at + 8 * k + 8].copy_from_slice(&words[3 - k].to_be_bytes());
    }
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
        let mut limbs = [[0u64; LIMBS]; LANES];
        for lane in 0..LANES {
            limbs[lane] = unpack52(&words_from_bytes(bytes, at + 32 * lane));
        }
        let v = transpose_in(&limbs);
        let (_, borrow) = sub_limbs(&v, &splat_limbs(&R));
        (Self(v), borrowed(borrow))
    }

    /// The inverse of `from_bytes`, with each value reduced below r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn to_bytes(self, bytes: &mut [u8], at: usize) {
        let canonical = self.canonical();
        let mut limbs = [[0u64; LIMBS]; LANES];
        for j in 0..LIMBS {
            let l = lanes(canonical.0[j]);
            for lane in 0..LANES {
                limbs[lane][j] = l[lane];
            }
        }
        for lane in 0..LANES {
            words_to_bytes(&pack64(&limbs[lane]), bytes, at + 32 * lane);
        }
    }

    /// Montgomery product with R = 2^260: the full ten-limb product first, then
    /// five reduction rows, every index a constant so the accumulator stays in
    /// registers.
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

        let mask = splat(MASK52);
        let mut out = [zero(); LIMBS];
        out[0] = t[LIMBS];
        for j in 0..LIMBS - 1 {
            out[j + 1] = _mm512_add_epi64(t[LIMBS + j + 1], _mm512_srli_epi64::<52>(out[j]));
            out[j] = _mm512_and_si512(out[j], mask);
        }
        Self(out)
    }

    /// Down from [0, 2r) to [0, r).
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn canonical(self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &splat_limbs(&R));
        Self(select_borrowed(borrow, &self.0, &d))
    }

    /// Sum below 4r, brought back under 2r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        let s = add_limbs(&self.0, &rhs.0);
        let (d, borrow) = sub_limbs(&s, &two_r());
        Self(select_borrowed(borrow, &s, &d))
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        let (d, borrow) = sub_limbs(&self.0, &rhs.0);
        let wrapped = add_limbs(&d, &two_r());
        Self(select_borrowed(borrow, &wrapped, &d))
    }

    /// Lane `l` takes lane `index[l] & 7` of `self` if bit 3 of `index[l]` is
    /// clear, of `other` otherwise; higher bits are ignored.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn permute(&self, index: __m512i, other: &Self) -> Self {
        let mut v = [zero(); LIMBS];
        for j in 0..LIMBS {
            v[j] = _mm512_permutex2var_epi64(self.0[j], index, other.0[j]);
        }
        Self(v)
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn two_r() -> [__m512i; LIMBS] {
    add_limbs(&splat_limbs(&R), &splat_limbs(&R))
}

#[cfg(test)]
mod tests;
