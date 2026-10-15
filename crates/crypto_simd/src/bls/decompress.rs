//! Eight compressed G1 encodings at a time: decode x, recover y by one shared
//! square-root exponentiation, pick the root the sign flag names, then run the
//! membership test on the eight points together.

use std::arch::x86_64::__mmask8;

use blst::{blst_fp, blst_p1_affine};

use crate::bls::{
    COMPRESSED_LEN,
    constants::FOUR_MONT,
    decompress_g2::{FLAG_COMPRESSED, FLAG_INFINITY, FLAG_LARGER_ROOT, fp_words, less_than_p},
    fp8::{Fp8, LANES, Limbs, unpack52},
    g1x8::G1x8,
};

/// Per-lane verdicts for one batch of eight.
pub struct Batch {
    pub points: [blst_p1_affine; LANES],
    /// Lanes holding a valid G1 point in `points`.
    pub valid: __mmask8,
    /// Lanes the vector path could not judge; the caller decides them with
    /// blst.
    pub undecided: __mmask8,
}

struct Decoded {
    x: [Limbs; LANES],
    larger_root: __mmask8,
    /// Encodings no x can rescue: flags wrong, or x not canonical.
    invalid: __mmask8,
    /// Infinity encodings; the scalar path handles their flag rules.
    undecided: __mmask8,
}

fn decode(inputs: &[[u8; COMPRESSED_LEN]; LANES]) -> Decoded {
    let mut d = Decoded { x: [[0; 8]; LANES], larger_root: 0, invalid: 0, undecided: 0 };
    for lane in 0..LANES {
        let bytes = &inputs[lane];
        let bit = 1u8 << lane;
        let flags = bytes[0] & 0xe0;
        if flags & FLAG_COMPRESSED == 0 {
            d.invalid |= bit;
            continue;
        }
        if flags & FLAG_INFINITY != 0 {
            d.undecided |= bit;
            continue;
        }
        if flags & FLAG_LARGER_ROOT != 0 {
            d.larger_root |= bit;
        }
        let mut words = fp_words(bytes);
        words[5] &= 0x1fff_ffff_ffff_ffff;
        if !less_than_p(&words) {
            d.invalid |= bit;
            continue;
        }
        d.x[lane] = unpack52(&words);
    }
    d
}

fn point(x: [u64; 6], y: [u64; 6]) -> blst_p1_affine {
    blst_p1_affine { x: blst_fp { l: x }, y: blst_fp { l: y } }
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub fn decompress(inputs: &[[u8; COMPRESSED_LEN]; LANES]) -> Batch {
    let decoded = decode(inputs);
    let x = Fp8::from_plain(&decoded.x);

    // y^2 = x^3 + 4; the candidate squares back only for residues.
    let rhs = x.square().mul(&x).add(&Fp8::splat_limbs(&FOUR_MONT));
    let root = rhs.sqrt_candidate();
    let on_curve = root.square().eq_mask(&rhs);
    let flip = root.is_larger_root_mask() ^ decoded.larger_root;
    let y = Fp8::select(flip, &root, &root.neg());
    // y = 0 makes the sign flag meaningless; leave those to blst.
    let undecided = decoded.undecided | y.is_zero_mask();

    let membership = G1x8::scott_membership(&x, &y);
    let undecided = (undecided | membership.undecided) & !decoded.invalid;
    let valid = on_curve & membership.members & !undecided & !decoded.invalid;

    let xs = x.to_blst_limbs();
    let ys = y.to_blst_limbs();
    let mut points = [blst_p1_affine::default(); LANES];
    for lane in 0..LANES {
        points[lane] = point(xs[lane], ys[lane]);
    }
    Batch { points, valid, undecided }
}
