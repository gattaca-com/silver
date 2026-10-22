//! The radix-2^52 layout as plain integers: a value's `Limbs`, and `LANES`
//! values to a vector.

use crate::bls::constants::{LIMB_BITS, LIMBS, MASK52};

pub const LANES: usize = 8;

pub type Limbs = [u64; LIMBS];

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
