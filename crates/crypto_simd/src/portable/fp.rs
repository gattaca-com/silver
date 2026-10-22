//! One Fp in blst's layout: six little-endian words holding a·2^384 mod p,
//! below p, so values pass to and from blst unchanged.
//!
//! The product is CIOS in six explicit rows with the no-carry schedule: p's top
//! word is below 2^62, so a row's running sum fits six words and a top word.
//! Under BMI2, LLVM compiles the `u128` products to `mulx`. By default, carries
//! are `overflowing_add` pairs and borrows `u128` differences. The
//! `portable_addcarry` feature takes both from `_addcarry_u64`, which LLVM
//! chains more tightly; `portable_mulx` also takes the products from
//! `_mulx_u64`.

#[cfg(any(feature = "portable_addcarry", feature = "portable_mulx"))]
use std::arch::x86_64::_addcarry_u64;
#[cfg(feature = "portable_mulx")]
use std::arch::x86_64::_mulx_u64;

use crate::{
    bls::constants::{P_MINUS_3_OVER_4_WINDOWS, P_U64},
    portable::constants::{ONE, P_INV, R2, R3},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp(pub [u64; 6]);

/// a·b as its low and high words.
#[cfg(not(feature = "portable_mulx"))]
#[inline(always)]
fn wide_mul(a: u64, b: u64) -> (u64, u64) {
    let product = a as u128 * b as u128;
    (product as u64, (product >> 64) as u64)
}

#[cfg(feature = "portable_mulx")]
#[inline(always)]
fn wide_mul(a: u64, b: u64) -> (u64, u64) {
    let mut hi = 0;
    // SAFETY: `portable_available` checked BMI2, and every caller runs under it.
    let lo = unsafe { _mulx_u64(a, b, &mut hi) };
    (lo, hi)
}

/// a + b + carry and the carry out, for a carry of 0 or 1. The carries are
/// words, not bools, so that LLVM chains them into `adc`.
#[cfg(not(any(feature = "portable_addcarry", feature = "portable_mulx")))]
#[inline(always)]
fn add_carry(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let (s, c1) = a.overflowing_add(b);
    let (s, c2) = s.overflowing_add(carry);
    (s, c1 as u64 | c2 as u64)
}

#[cfg(any(feature = "portable_addcarry", feature = "portable_mulx"))]
#[inline(always)]
fn add_carry(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let mut s = 0;
    // SAFETY: `_addcarry_u64` is plain x86-64 `adc`.
    let c = unsafe { _addcarry_u64(carry as u8, a, b, &mut s) };
    (s, c as u64)
}

/// a − b − borrow and the borrow out, for a borrow of 0 or 1, from the
/// difference lifted by 2^64. On `overflowing_add` carries, LLVM compiles the
/// complement form below to comparisons and `setb`s, and this one tighter.
#[cfg(not(any(feature = "portable_addcarry", feature = "portable_mulx")))]
#[inline(always)]
fn sub_borrow(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let d = (1u128 << 64) + a as u128 - b as u128 - borrow as u128;
    (d as u64, 1 - (d >> 64) as u64)
}

/// a − b − borrow and the borrow out, for a borrow of 0 or 1: a + !b + 1 −
/// borrow carries out exactly when nothing is borrowed.
#[cfg(any(feature = "portable_addcarry", feature = "portable_mulx"))]
#[inline(always)]
fn sub_borrow(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let (d, carry) = add_carry(a, !b, 1 - borrow);
    (d, 1 - carry)
}

/// acc + a·b in seven words, for sums below 2^448.
#[inline(always)]
fn mul_add(acc: &[u64; 7], a: &[u64; 6], b: u64) -> [u64; 7] {
    let mut lo = [0u64; 6];
    let mut hi = [0u64; 6];
    let mut j = 0;
    while j < 6 {
        let (l, h) = wide_mul(a[j], b);
        lo[j] = l;
        hi[j] = h;
        j += 1;
    }
    let mut out = [0u64; 7];
    let mut carry = 0;
    j = 0;
    while j < 6 {
        let (s, c) = add_carry(acc[j], lo[j], carry);
        out[j] = s;
        carry = c;
        j += 1;
    }
    out[6] = acc[6].wrapping_add(carry);
    carry = 0;
    j = 0;
    while j < 6 {
        let (s, c) = add_carry(out[j + 1], hi[j], carry);
        out[j + 1] = s;
        carry = c;
        j += 1;
    }
    out
}

/// (t + a·bi + m·p)/2^64 for the m that makes it exact, a Montgomery row:
/// t stays below 2p, and both sums below 2^447.
#[inline(always)]
fn row(t: &[u64; 6], a: &[u64; 6], bi: u64) -> [u64; 6] {
    let sum = mul_add(&[t[0], t[1], t[2], t[3], t[4], t[5], 0], a, bi);
    let reduced = mul_add(&sum, &P_U64, sum[0].wrapping_mul(P_INV));
    [reduced[1], reduced[2], reduced[3], reduced[4], reduced[5], reduced[6]]
}

/// a − b and whether it borrowed.
#[inline(always)]
fn sub_words(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], bool) {
    let mut d = [0u64; 6];
    let mut borrow = 0;
    let mut j = 0;
    while j < 6 {
        let (x, out) = sub_borrow(a[j], b[j], borrow);
        d[j] = x;
        borrow = out;
        j += 1;
    }
    (d, borrow == 1)
}

/// a + b and its carry.
#[inline(always)]
fn add_words(a: &[u64; 6], b: &[u64; 6]) -> ([u64; 6], bool) {
    let mut s = [0u64; 6];
    let mut carry = 0;
    let mut j = 0;
    while j < 6 {
        let (x, out) = add_carry(a[j], b[j], carry);
        s[j] = x;
        carry = out;
        j += 1;
    }
    (s, carry == 1)
}

/// All ones when d, as a signed 384-bit value, is negative; else zero. For
/// |d| below 2^383 that is the borrow of the subtraction that made d. LLVM
/// turns a select on the borrow itself into branches, as it splits a borrow
/// made of two overflow flags, and it branches on a select between constants
/// too; a select between computed values on this mask stays a `cmov`.
#[inline(always)]
fn negative_mask(d: &[u64; 6]) -> u64 {
    0u64.wrapping_sub(d[5] >> 63)
}

/// a where mask is all ones, b where it is zero.
#[inline(always)]
fn select(mask: u64, a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    let mut out = [0u64; 6];
    let mut j = 0;
    while j < 6 {
        out[j] = (a[j] & mask) | (b[j] & !mask);
        j += 1;
    }
    out
}

/// From below 2p to below p.
#[inline(always)]
fn below_p(t: &[u64; 6]) -> [u64; 6] {
    let (d, _) = sub_words(t, &P_U64);
    select(negative_mask(&d), t, &d)
}

/// p when `borrowed`, else 0: masked words, which LLVM keeps free of branches.
#[inline(always)]
fn p_if(borrowed: bool) -> [u64; 6] {
    let mask = 0u64.wrapping_sub(borrowed as u64);
    let mut out = [0u64; 6];
    let mut j = 0;
    while j < 6 {
        out[j] = P_U64[j] & mask;
        j += 1;
    }
    out
}

impl Fp {
    pub const ZERO: Fp = Fp([0; 6]);

    #[target_feature(enable = "bmi2,adx")]
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut t = row(&[0; 6], &self.0, rhs.0[0]);
        t = row(&t, &self.0, rhs.0[1]);
        t = row(&t, &self.0, rhs.0[2]);
        t = row(&t, &self.0, rhs.0[3]);
        t = row(&t, &self.0, rhs.0[4]);
        t = row(&t, &self.0, rhs.0[5]);
        Self(below_p(&t))
    }

    #[target_feature(enable = "bmi2,adx")]
    #[inline]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Two independent products, one after the other, which the core
    /// overlaps. Interleaving their rows is slower: the two need more
    /// registers than x86-64 has.
    #[target_feature(enable = "bmi2,adx")]
    #[inline]
    pub fn mul_pair(a: &[Fp; 2], b: &[Fp; 2]) -> [Fp; 2] {
        [a[0].mul(&b[0]), a[1].mul(&b[1])]
    }

    // The sums need no BMI2, and inlined they keep their selects on registers:
    // LLVM turns a `cmov` that reads memory into a branch.
    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        let (s, _) = add_words(&self.0, &rhs.0);
        Self(below_p(&s))
    }

    #[inline(always)]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        let (d, borrowed) = sub_words(&self.0, &rhs.0);
        Self(add_words(&d, &p_if(borrowed)).0)
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4] | self.0[5]) == 0
    }

    /// The form of a plain value below p.
    #[target_feature(enable = "bmi2,adx")]
    pub fn from_plain(words: &[u64; 6]) -> Self {
        Self(*words).mul(&Self(R2))
    }

    /// The plain value, below p.
    #[target_feature(enable = "bmi2,adx")]
    pub fn to_plain(&self) -> [u64; 6] {
        self.mul(&Self([1, 0, 0, 0, 0, 0])).0
    }

    /// The inverse by binary extended Euclid on the stored aR, then R³ takes
    /// (aR)⁻¹ to a⁻¹R; 0 for 0. Variable time.
    #[target_feature(enable = "bmi2,adx")]
    pub fn inverse(&self) -> Self {
        if self.is_zero() {
            return Self::ZERO;
        }
        Self(inverse_words(&self.0)).mul(&Self(R3))
    }

    /// Each value's inverse, 0 for 0, from one `inverse` by Montgomery's
    /// trick: prefix products, then back down with 2 products per value.
    #[target_feature(enable = "bmi2,adx")]
    pub fn inverse_each(values: &[Fp; 8]) -> [Fp; 8] {
        let mut prefix = [ONE; 8];
        let mut running = ONE;
        let mut k = 0;
        while k < 8 {
            if !values[k].is_zero() {
                running = running.mul(&values[k]);
            }
            prefix[k] = running;
            k += 1;
        }
        let mut inverse = running.inverse();
        let mut out = [Self::ZERO; 8];
        while k > 0 {
            k -= 1;
            if !values[k].is_zero() {
                out[k] = if k > 0 { inverse.mul(&prefix[k - 1]) } else { inverse };
                inverse = inverse.mul(&values[k]);
            }
        }
        out
    }

    /// self^((p − 3)/4), from 4-bit windows of the fixed exponent.
    #[target_feature(enable = "bmi2,adx")]
    pub fn pow_p_minus_3_over_4(&self) -> Self {
        let mut table = [ONE; 16];
        let mut k = 1;
        while k < 16 {
            table[k] = table[k - 1].mul(self);
            k += 1;
        }
        let windows = P_MINUS_3_OVER_4_WINDOWS.len();
        let mut result = table[P_MINUS_3_OVER_4_WINDOWS[windows - 1] as usize];
        let mut w = windows - 1;
        while w > 0 {
            w -= 1;
            result = result.square().square().square().square();
            result = result.mul(&table[P_MINUS_3_OVER_4_WINDOWS[w] as usize]);
        }
        result
    }

    /// `pow_p_minus_3_over_4` of two values in lockstep.
    #[target_feature(enable = "bmi2,adx")]
    pub fn pow_p_minus_3_over_4_pair(values: &[Fp; 2]) -> [Fp; 2] {
        let mut table = [[ONE; 2]; 16];
        let mut k = 1;
        while k < 16 {
            table[k] = Self::mul_pair(&table[k - 1], values);
            k += 1;
        }
        let windows = P_MINUS_3_OVER_4_WINDOWS.len();
        let mut result = table[P_MINUS_3_OVER_4_WINDOWS[windows - 1] as usize];
        let mut w = windows - 1;
        while w > 0 {
            w -= 1;
            let mut s = 0;
            while s < 4 {
                result = Self::mul_pair(&result, &result);
                s += 1;
            }
            result = Self::mul_pair(&result, &table[P_MINUS_3_OVER_4_WINDOWS[w] as usize]);
        }
        result
    }

    /// A square root when self is a square: self^((p + 1)/4), since p ≡ 3 mod
    /// 4.
    #[target_feature(enable = "bmi2,adx")]
    pub fn sqrt(&self) -> Option<Self> {
        let root = self.pow_p_minus_3_over_4().mul(self);
        if root.square() == *self { Some(root) } else { None }
    }

    /// `sqrt` of two values in lockstep: the candidate roots, and whether each
    /// squares back to its value.
    #[target_feature(enable = "bmi2,adx")]
    pub fn sqrt_pair(values: &[Fp; 2]) -> ([Fp; 2], [bool; 2]) {
        let roots = Self::mul_pair(&Self::pow_p_minus_3_over_4_pair(values), values);
        let squares = Self::mul_pair(&roots, &roots);
        (roots, [squares[0] == values[0], squares[1] == values[1]])
    }

    /// Whether the plain value exceeds (p − 1)/2: the larger of ±y.
    #[target_feature(enable = "bmi2,adx")]
    pub fn is_larger_root(&self) -> bool {
        let plain = self.to_plain();
        let (doubled, carry) = add_words(&plain, &plain);
        // 2y > p − 1 iff 2y ≥ p; 2y < 2^384 since y < p.
        let (_, borrow) = sub_words(&doubled, &P_U64);
        carry || !borrow
    }
}

fn is_even(a: &[u64; 6]) -> bool {
    a[0] & 1 == 0
}

fn is_one(a: &[u64; 6]) -> bool {
    a[0] == 1 && (a[1] | a[2] | a[3] | a[4] | a[5]) == 0
}

fn halve(a: &mut [u64; 6], top: u64) {
    let mut j = 0;
    while j < 5 {
        a[j] = (a[j] >> 1) | (a[j + 1] << 63);
        j += 1;
    }
    a[5] = (a[5] >> 1) | (top << 63);
}

/// x/2 mod p for x below p: x + p when odd, then a shift.
fn halve_mod_p(x: &mut [u64; 6]) {
    if is_even(x) {
        halve(x, 0);
    } else {
        let (sum, carry) = add_words(x, &P_U64);
        *x = sum;
        halve(x, carry as u64);
    }
}

fn geq(a: &[u64; 6], b: &[u64; 6]) -> bool {
    let (_, borrow) = sub_words(a, b);
    !borrow
}

/// a⁻¹ mod p for 0 < a < p, as plain integers: u·x1 ≡ a and v·x2 ≡ a stay
/// invariant modulo p, up to the common factor a⁻¹ the loop removes.
fn inverse_words(a: &[u64; 6]) -> [u64; 6] {
    let mut u = *a;
    let mut v = P_U64;
    let mut x1 = [1u64, 0, 0, 0, 0, 0];
    let mut x2 = [0u64; 6];
    while !is_one(&u) && !is_one(&v) {
        while is_even(&u) {
            halve(&mut u, 0);
            halve_mod_p(&mut x1);
        }
        while is_even(&v) {
            halve(&mut v, 0);
            halve_mod_p(&mut x2);
        }
        if geq(&u, &v) {
            u = sub_words(&u, &v).0;
            let (d, borrow) = sub_words(&x1, &x2);
            x1 = if borrow { add_words(&d, &P_U64).0 } else { d };
        } else {
            v = sub_words(&v, &u).0;
            let (d, borrow) = sub_words(&x2, &x1);
            x2 = if borrow { add_words(&d, &P_U64).0 } else { d };
        }
    }
    if is_one(&u) { x1 } else { x2 }
}

#[cfg(test)]
mod tests;
