//! Scalar Fr arithmetic in blst's layout: four little-endian words holding
//! a·2^256 mod r. Every function takes and returns values below r, so its
//! results equal blst's limb for limb.
//!
//! Products are Montgomery products, row by row with u128 words. Since
//! r < 2^255, a row's sum stays below 2^320, and the value between rows below
//! 2r, so four words and a carry hold every intermediate.

use blst::blst_fr;

/// r, little-endian words.
const R: [u64; 4] =
    [0xffff_ffff_0000_0001, 0x53bd_a402_fffe_5bfe, 0x3339_d808_09a1_d805, 0x73ed_a753_299d_7d48];
/// −r⁻¹ mod 2^64.
const R_INV64: u64 = 0xffff_fffe_ffff_ffff;

pub fn fr_add(a: &blst_fr, b: &blst_fr) -> blst_fr {
    blst_fr { l: below_r(&add_words(&a.l, &b.l)) }
}

pub fn fr_sub(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let (difference, borrowed) = sub_words(&a.l, &b.l);
    blst_fr { l: if borrowed { add_words(&difference, &R) } else { difference } }
}

pub fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
    blst_fr { l: montgomery_product(&a.l, &b.l) }
}

/// a·b/2^256 mod r, below r, for a below r.
fn montgomery_product(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let (sum, top) = multiply_add(&t, a, b[i]);
        t = divide_out_word(&sum, top);
        i += 1;
    }
    below_r(&t)
}

/// t + a·w, as four words and a carry word.
fn multiply_add(t: &[u64; 4], a: &[u64; 4], w: u64) -> ([u64; 4], u64) {
    let mut sum = [0u64; 4];
    let mut carry = 0u128;
    let mut j = 0;
    while j < 4 {
        let s = t[j] as u128 + a[j] as u128 * w as u128 + carry;
        sum[j] = s as u64;
        carry = s >> 64;
        j += 1;
    }
    (sum, carry as u64)
}

/// (s + m·r)/2^64 for s = low + top·2^256, with m the multiple that clears
/// s's low word.
fn divide_out_word(low: &[u64; 4], top: u64) -> [u64; 4] {
    let m = (low[0] as u128 * R_INV64 as u128) as u64;
    let mut quotient = [0u64; 4];
    let mut carry = (low[0] as u128 + m as u128 * R[0] as u128) >> 64;
    let mut j = 1;
    while j < 4 {
        let s = low[j] as u128 + m as u128 * R[j] as u128 + carry;
        quotient[j - 1] = s as u64;
        carry = s >> 64;
        j += 1;
    }
    quotient[3] = (top as u128 + carry) as u64;
    quotient
}

/// t − r if t ≥ r, else t; for t below 2r.
fn below_r(t: &[u64; 4]) -> [u64; 4] {
    let (difference, borrowed) = sub_words(t, &R);
    if borrowed { *t } else { difference }
}

/// a + b mod 2^256.
fn add_words(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut sum = [0u64; 4];
    let mut carry = 0u128;
    let mut j = 0;
    while j < 4 {
        let s = a[j] as u128 + b[j] as u128 + carry;
        sum[j] = s as u64;
        carry = s >> 64;
        j += 1;
    }
    sum
}

/// a − b mod 2^256, and whether a < b.
fn sub_words(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut difference = [0u64; 4];
    // Offset by 2^64, no step goes below 0, and bit 64 is set exactly when
    // the step does not borrow.
    let mut borrow = 0u64;
    let mut j = 0;
    while j < 4 {
        let s = (1u128 << 64) + a[j] as u128 - b[j] as u128 - borrow as u128;
        difference[j] = s as u64;
        borrow = 1 - (s >> 64) as u64;
        j += 1;
    }
    (difference, borrow == 1)
}

#[cfg(test)]
mod tests;
