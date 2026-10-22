//! Compressed G1 encodings, one or two at a time: decode x, recover y by a
//! square root, pick the root the sign flag names, then Scott's membership
//! test. Every verdict is blst's: `blst_p1_uncompress`, then
//! `blst_p1_affine_in_g1`.

use blst::{blst_fp, blst_p1_affine};

use crate::{
    bls::{
        COMPRESSED_LEN,
        decompress_g2::{FLAG_COMPRESSED, FLAG_INFINITY, FLAG_LARGER_ROOT, fp_words, less_than_p},
    },
    portable::{
        constants::{FOUR, R2},
        fp::Fp,
        g1::G1,
        g1_pair::G1Pair,
    },
};

/// `Some` iff blst accepts the encoding as a point of G1.
#[target_feature(enable = "bmi2,adx")]
pub fn uncompress_in_g1(bytes: &[u8; COMPRESSED_LEN]) -> Option<blst_p1_affine> {
    let Some((words, larger)) = ordinary(bytes) else {
        return extraordinary(bytes);
    };
    let x = Fp::from_plain(&words);
    let y = signed_root(&x.square().mul(&x).add(&FOUR).sqrt()?, larger)?;
    member(&x, &y)
}

/// Sets each `out[i]` to `uncompress_in_g1(&inputs[i])`, two at a time.
#[target_feature(enable = "bmi2,adx")]
pub fn uncompress_all_in_g1(inputs: &[[u8; COMPRESSED_LEN]], out: &mut [Option<blst_p1_affine>]) {
    assert!(out.len() == inputs.len(), "one verdict slot per input");
    let pairs = inputs.len() / 2 * 2;
    let mut i = 0;
    while i < pairs {
        let two = uncompress_pair_in_g1(&inputs[i], &inputs[i + 1]);
        out[i] = two[0];
        out[i + 1] = two[1];
        i += 2;
    }
    if i < inputs.len() {
        out[i] = uncompress_in_g1(&inputs[i]);
    }
}

/// `uncompress_in_g1` of two encodings, in lockstep where both are ordinary.
#[target_feature(enable = "bmi2,adx")]
pub fn uncompress_pair_in_g1(
    a: &[u8; COMPRESSED_LEN],
    b: &[u8; COMPRESSED_LEN],
) -> [Option<blst_p1_affine>; 2] {
    let (Some((words_a, larger_a)), Some((words_b, larger_b))) = (ordinary(a), ordinary(b)) else {
        return [uncompress_in_g1(a), uncompress_in_g1(b)];
    };
    let x = Fp::mul_pair(&[Fp(words_a), Fp(words_b)], &[Fp(R2), Fp(R2)]);
    let x_cubed = Fp::mul_pair(&Fp::mul_pair(&x, &x), &x);
    let roots = Fp::sqrt_pair(&[x_cubed[0].add(&FOUR), x_cubed[1].add(&FOUR)]);
    let y_a = match roots[0] {
        Some(root) => signed_root(&root, larger_a),
        None => None,
    };
    let y_b = match roots[1] {
        Some(root) => signed_root(&root, larger_b),
        None => None,
    };
    match (y_a, y_b) {
        (Some(y_a), Some(y_b)) => {
            let members = G1Pair::in_g1(&x, &[y_a, y_b]);
            [
                if members[0] { Some(point(&x[0], &y_a)) } else { None },
                if members[1] { Some(point(&x[1], &y_b)) } else { None },
            ]
        }
        (Some(y_a), None) => [member(&x[0], &y_a), None],
        (None, Some(y_b)) => [None, member(&x[1], &y_b)],
        (None, None) => [None, None],
    }
}

/// x's plain words and the sign flag, for a compressed encoding of a finite
/// point whose x is canonical and nonzero; `None` for every other encoding.
fn ordinary(bytes: &[u8; COMPRESSED_LEN]) -> Option<([u64; 6], bool)> {
    let flags = bytes[0] & 0xe0;
    if flags & FLAG_COMPRESSED == 0 || flags & FLAG_INFINITY != 0 {
        return None;
    }
    let mut words = fp_words(bytes);
    words[5] &= 0x1fff_ffff_ffff_ffff;
    if !less_than_p(&words) || words == [0; 6] {
        return None;
    }
    Some((words, flags & FLAG_LARGER_ROOT != 0))
}

/// The verdict on an encoding `ordinary` declines: blst accepts only the
/// canonical encoding of infinity. It rejects x = 0, whose points (0, ±2)
/// have order 3.
fn extraordinary(bytes: &[u8; COMPRESSED_LEN]) -> Option<blst_p1_affine> {
    let mut i = 1;
    while i < COMPRESSED_LEN && bytes[i] == 0 {
        i += 1;
    }
    if bytes[0] == FLAG_COMPRESSED | FLAG_INFINITY && i == COMPRESSED_LEN {
        Some(blst_p1_affine::default())
    } else {
        None
    }
}

/// The root the sign flag names; `None` for y = 0, which has order 2.
#[target_feature(enable = "bmi2,adx")]
fn signed_root(root: &Fp, larger: bool) -> Option<Fp> {
    if root.is_zero() {
        return None;
    }
    Some(if root.is_larger_root() == larger { *root } else { root.neg() })
}

#[target_feature(enable = "bmi2,adx")]
fn member(x: &Fp, y: &Fp) -> Option<blst_p1_affine> {
    if G1::in_g1(x, y) { Some(point(x, y)) } else { None }
}

fn point(x: &Fp, y: &Fp) -> blst_p1_affine {
    blst_p1_affine { x: blst_fp { l: x.0 }, y: blst_fp { l: y.0 } }
}

#[cfg(test)]
mod tests;
