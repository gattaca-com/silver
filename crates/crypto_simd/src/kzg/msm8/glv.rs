//! GLV decomposition for the multi-scalar multiplication: k = k₁ + k₂·λ with
//! |k₁|, |k₂| < 2^127, where [λ]P = σ(P) = (β·x, y) is free. Halving the
//! scalar length halves the windows, and with them the bucket sums and the
//! final doublings.
//!
//! λ = z² − 1 is a cube root of unity mod r, r = λ² + λ + 1. The lattice of
//! (a, b) with a + bλ ≡ 0 has the short basis (λ, −1), (1, z²). Rounding
//! (k, 0) to it gives c₁ = round(k·z²/r), c₂ = round(k/r) = [k ≥ r/2], and
//! k₁ = k − c₁·λ − c₂, k₂ = c₁ − c₂·z², both below 2^127 in magnitude.

/// λ = z² − 1, little-endian words.
const LAMBDA: [u64; 2] = [0xffff_ffff, 0xac45_a401_0001_a402];
/// z², little-endian words.
const Z2: [u64; 2] = [0x1_0000_0000, 0xac45_a401_0001_a402];
/// round(z² · 2^256 / r).
const Z2_OVER_R: [u64; 3] = [0x63f6_e522_f6cf_ee30, 0x7c6b_ecf1_e01f_aadd, 0x1];
/// ceil(r / 2), little-endian words.
const HALF_R_UP: [u64; 4] =
    [0x7fff_ffff_8000_0001, 0xa9de_d201_7fff_2dff, 0x199c_ec04_04d0_ec02, 0x39f6_d3a9_94ce_bea4];

pub const HALF_SCALAR_BITS: usize = 127;

/// A half scalar as the magnitude the buckets take, and its sign.
#[derive(Clone, Copy, Default)]
pub struct Half {
    pub magnitude: [u8; 32],
    pub negative: bool,
}

/// (k₁, k₂) of a little-endian scalar below 2^255.
pub fn decompose(scalar: &[u8; 32]) -> (Half, Half) {
    let k: [u64; 4] =
        std::array::from_fn(|i| u64::from_le_bytes(scalar[8 * i..8 * i + 8].try_into().unwrap()));
    // k₂ = (k·Z2_OVER_R + 2^255) >> 256, in 64-bit limbs.
    let mut product = [0u64; 7];
    for (i, &a) in k.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &b) in Z2_OVER_R.iter().enumerate() {
            let t = u128::from(a) * u128::from(b) + u128::from(product[i + j]) + carry;
            product[i + j] = t as u64;
            carry = t >> 64;
        }
        product[i + 3] = carry as u64;
    }
    // k < 2^255 and Z2_OVER_R < 1.5·2^128, so k·Z2_OVER_R < 1.5·2^383: limb 6 is
    // zero and the rounded quotient is below 2^128.
    debug_assert!(product[6] == 0);
    let rounding = (u128::from(product[3]) + (1u128 << 63)) >> 64;
    let c1 = ((u128::from(product[5]) << 64) | u128::from(product[4]))
        .checked_add(rounding)
        .expect("k·Z2_OVER_R is below 2^384 − 2^256");
    let c1 = [c1 as u64, (c1 >> 64) as u64];
    let c2 = u64::from(k.iter().rev().ge(HALF_R_UP.iter().rev()));

    // k₁ = k − c₁·λ − c₂ and k₂ = c₁ − c₂·z², as signed 256-bit values.
    let k1 = signed_difference(&k, &[c2, 0, 0, 0], &c1, &LAMBDA);
    let k2 = signed_difference(&[c1[0], c1[1], 0, 0], &[0; 4], &[c2, 0], &Z2);
    (k1, k2)
}

/// `a − b − c·d` as a magnitude and sign.
fn signed_difference(a: &[u64; 4], b: &[u64; 4], c: &[u64; 2], d: &[u64; 2]) -> Half {
    let mut product = [0u64; 4];
    for (i, &x) in c.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &y) in d.iter().enumerate() {
            let t = u128::from(x) * u128::from(y) + u128::from(product[i + j]) + carry;
            product[i + j] = t as u64;
            carry = t >> 64;
        }
        product[i + 2] = carry as u64;
    }
    let mut out = [0u64; 4];
    let mut borrow = 0u128;
    for i in 0..4 {
        let t =
            (2u128 << 64) + u128::from(a[i]) - u128::from(b[i]) - u128::from(product[i]) - borrow;
        out[i] = t as u64;
        borrow = 2 - (t >> 64);
    }
    let negative = borrow != 0;
    if negative {
        debug_assert!(borrow == 1);
        let mut carry = 1u128;
        for limb in &mut out {
            let t = u128::from(!*limb) + carry;
            *limb = t as u64;
            carry = t >> 64;
        }
    }
    debug_assert!(out[2] == 0 && out[3] == 0 && out[1] >> 63 == 0, "a half scalar is below 2^127");
    let mut bytes = [0u8; 32];
    for (i, limb) in out.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    Half { magnitude: bytes, negative }
}

#[cfg(test)]
mod tests {
    use blst::blst_fr;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::kzg::{
        blst_msm::scalar_bytes,
        blst_ops::{fr_add, fr_from_bytes, fr_from_u64, fr_mul, fr_sub},
    };

    /// Little-endian bytes below r to a field element.
    fn fr_of(bytes: &[u8; 32]) -> blst_fr {
        let scalar = blst::blst_scalar { b: *bytes };
        let mut fr = blst_fr::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst::blst_fr_from_scalar(&mut fr, &scalar) };
        fr
    }

    #[test]
    fn halves_recombine_to_the_scalar() {
        let mut lambda = [0u8; 32];
        lambda[..8].copy_from_slice(&LAMBDA[0].to_le_bytes());
        lambda[8..16].copy_from_slice(&LAMBDA[1].to_le_bytes());
        let lambda = fr_of(&lambda);
        let mut rng = ChaCha8Rng::seed_from_u64(0x61);
        let le = |words: [u64; 4]| {
            let mut bytes = [0u8; 32];
            for (i, word) in words.iter().enumerate() {
                bytes[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
            }
            bytes
        };
        // 0, 1, r − 1, λ, z² = λ + 1, r, and the API's largest scalar 2^255 − 1.
        let mut scalars = vec![
            [0u8; 32],
            le([1, 0, 0, 0]),
            scalar_bytes(&fr_sub(&fr_from_u64(0), &fr_from_u64(1))),
            le([LAMBDA[0], LAMBDA[1], 0, 0]),
            le([Z2[0], Z2[1], 0, 0]),
            le([
                0xffff_ffff_0000_0001,
                0x53bd_a402_fffe_5bfe,
                0x3339_d808_09a1_d805,
                0x73ed_a753_299d_7d48,
            ]),
            le([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1]),
        ];
        for _ in 0..1000 {
            let mut bytes: [u8; 32] = rng.r#gen();
            bytes[31] &= 0x7f;
            if fr_from_bytes(&bytes).is_some() {
                scalars.push(bytes);
            }
        }
        for scalar in &scalars {
            let (k1, k2) = decompose(scalar);
            assert!(k1.magnitude[16..].iter().all(|&b| b == 0) && k1.magnitude[15] < 0x80);
            assert!(k2.magnitude[16..].iter().all(|&b| b == 0) && k2.magnitude[15] < 0x80);
            let signed = |h: &Half| {
                let m = fr_of(&h.magnitude);
                if h.negative { fr_sub(&fr_from_u64(0), &m) } else { m }
            };
            let got = fr_add(&signed(&k1), &fr_mul(&signed(&k2), &lambda));
            assert!(scalar_bytes(&got) == scalar_bytes(&fr_of(scalar)));
        }
    }
}
