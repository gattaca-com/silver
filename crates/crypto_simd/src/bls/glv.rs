//! GLV decomposition for the multi-scalar multiplication: k ≡ k₁ + k₂·λ (mod
//! r) with |k₁|, |k₂| < 2^127, where [λ]P = σ(P) = (β·x, y) for P in G1.
//! Halving the scalars halves the windows, and with them the window sums and
//! the final doublings.
//!
//! λ = z² − 1 is a cube root of unity mod r, r = λ² + λ + 1. The lattice of
//! (a, b) with a + bλ ≡ 0 has the short basis (λ, −1), (1, z²). Rounding
//! (k, 0) to it gives c₁ = round(k·z²/r), c₂ = round(k/r) = [k ≥ r/2], and
//! k₁ = k − c₁·λ − c₂, k₂ = c₁ − c₂·z². Then k₁ + k₂·λ = k − c₂·r whatever
//! c₁ and c₂ are; the rounding only keeps the halves short. With c₁ from
//! the fixed-point Z2_OVER_R, |c₁ − k·z²/r| < 0.62 for k below 2^255, so
//! |k₁| < 0.83·2^127 and |k₂| < 0.68·2^127.

/// λ = z² − 1, little-endian words.
const LAMBDA: [u64; 2] = [0xffff_ffff, 0xac45_a401_0001_a402];
/// z², little-endian words.
const Z2: [u64; 2] = [0x1_0000_0000, 0xac45_a401_0001_a402];
/// round(z²·2^256 / r), little-endian words.
const Z2_OVER_R: [u64; 3] = [0x63f6_e522_f6cf_ee30, 0x7c6b_ecf1_e01f_aadd, 0x1];
/// ceil(r / 2), little-endian words.
const HALF_R_UP: [u64; 4] =
    [0x7fff_ffff_8000_0001, 0xa9de_d201_7fff_2dff, 0x199c_ec04_04d0_ec02, 0x39f6_d3a9_94ce_bea4];

pub const HALF_SCALAR_BITS: usize = 127;

/// A half scalar's magnitude, below 2^127, and its sign.
pub struct Half {
    pub magnitude: [u64; 4],
    pub negative: bool,
}

/// (k₁, k₂) of a little-endian scalar below 2^255.
pub fn decompose(k: &[u64; 4]) -> (Half, Half) {
    // c₁ = (k·Z2_OVER_R + 2^255) >> 256, which is below 2^128.
    let product = times_z2_over_r(k);
    let low = product[4] as u128 + (product[3] >> 63) as u128;
    let c1 = [low as u64, product[5] + (low >> 64) as u64];
    let c2 = at_least_half_r(k) as u64;
    let k1 = signed_difference(k, c2, &c1, &LAMBDA);
    let k2 = signed_difference(&[c1[0], c1[1], 0, 0], 0, &[c2, 0], &Z2);
    (k1, k2)
}

/// k·Z2_OVER_R, whose top word is 0 for k below 2^255.
fn times_z2_over_r(k: &[u64; 4]) -> [u64; 7] {
    let mut product = [0u64; 7];
    let mut i = 0;
    while i < 4 {
        let mut carry = 0u128;
        let mut j = 0;
        while j < 3 {
            let t = k[i] as u128 * Z2_OVER_R[j] as u128 + product[i + j] as u128 + carry;
            product[i + j] = t as u64;
            carry = t >> 64;
            j += 1;
        }
        product[i + 3] = carry as u64;
        i += 1;
    }
    product
}

/// k ≥ ceil(r / 2).
fn at_least_half_r(k: &[u64; 4]) -> bool {
    let mut i = 4;
    while i > 0 && k[i - 1] == HALF_R_UP[i - 1] {
        i -= 1;
    }
    i == 0 || k[i - 1] > HALF_R_UP[i - 1]
}

/// a − b − c·d as a magnitude below 2^127 and a sign.
fn signed_difference(a: &[u64; 4], b: u64, c: &[u64; 2], d: &[u64; 2]) -> Half {
    let mut cd = [0u64; 4];
    let mut i = 0;
    while i < 2 {
        let mut carry = 0u128;
        let mut j = 0;
        while j < 2 {
            let t = c[i] as u128 * d[j] as u128 + cd[i + j] as u128 + carry;
            cd[i + j] = t as u64;
            carry = t >> 64;
            j += 1;
        }
        cd[i + 2] = carry as u64;
        i += 1;
    }
    let subtrahend = [b, 0, 0, 0];
    let mut difference = [0u64; 4];
    // Each word's borrow out is 0, 1 or 2; offset by 2^65, no step goes below 0.
    let mut borrow = 0u64;
    i = 0;
    while i < 4 {
        let t =
            (2u128 << 64) + a[i] as u128 - subtrahend[i] as u128 - cd[i] as u128 - borrow as u128;
        difference[i] = t as u64;
        borrow = 2 - (t >> 64) as u64;
        i += 1;
    }
    let negative = borrow != 0;
    let magnitude = if negative { negated(&difference) } else { difference };
    assert!(
        magnitude[2] == 0 && magnitude[3] == 0 && magnitude[1] >> 63 == 0,
        "a half scalar is below 2^127"
    );
    Half { magnitude, negative }
}

/// 2^256 − words: the magnitude of a negative two's-complement value.
fn negated(words: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 1u128;
    let mut i = 0;
    while i < 4 {
        let t = !words[i] as u128 + carry;
        out[i] = t as u64;
        carry = t >> 64;
        i += 1;
    }
    out
}
