//! Eight compressed G2 encodings at a time: decode x, recover y with blst's
//! Fp2 square root on every lane at once, pick the root the sign flag names,
//! then run Scott's membership test on the eight points together.

use std::arch::x86_64::__mmask8;

use blst::{blst_fp, blst_fp2, blst_p2_affine};

use crate::{
    G2_COMPRESSED_LEN,
    constants::{FOUR_MONT, P_U64},
    fp2x8::Fp2x8,
    fp8::{Fp8, LANES, Limbs, unpack52},
    g2x8::G2x8,
};

const FP_BYTES: usize = G2_COMPRESSED_LEN / 2;
const FLAG_COMPRESSED: u8 = 0x80;
const FLAG_INFINITY: u8 = 0x40;
const FLAG_LARGER_ROOT: u8 = 0x20;

/// Per-lane verdicts for one batch of eight.
pub struct Batch {
    /// Decoded points, meaningful on the `valid` lanes.
    pub points: [blst_p2_affine; LANES],
    /// Lanes whose encoding blst would decompress, member of G2 or not.
    pub on_curve: __mmask8,
    /// Lanes holding a point of G2 in `points`.
    pub valid: __mmask8,
    /// Lanes the vector path could not judge; the caller decides them with
    /// blst.
    pub undecided: __mmask8,
}

struct Decoded {
    x0: [Limbs; LANES],
    x1: [Limbs; LANES],
    larger_root: __mmask8,
    /// Encodings no x can rescue: flags wrong, or a coordinate not canonical.
    invalid: __mmask8,
    /// Infinity encodings; the scalar path handles their flag rules.
    undecided: __mmask8,
}

#[inline]
fn decode(inputs: &[[u8; G2_COMPRESSED_LEN]; LANES]) -> Decoded {
    let mut d = Decoded {
        x0: [[0; 8]; LANES],
        x1: [[0; 8]; LANES],
        larger_root: 0,
        invalid: 0,
        undecided: 0,
    };
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
        let (x1_bytes, x0_bytes) = bytes.split_at(FP_BYTES);
        let mut x1 = fp_words(x1_bytes);
        x1[5] &= 0x1fff_ffff_ffff_ffff;
        let x0 = fp_words(x0_bytes);
        if !less_than_p(&x1) || !less_than_p(&x0) {
            d.invalid |= bit;
            continue;
        }
        d.x0[lane] = unpack52(&x0);
        d.x1[lane] = unpack52(&x1);
    }
    d
}

#[inline]
fn point(x0: [u64; 6], x1: [u64; 6], y0: [u64; 6], y1: [u64; 6]) -> blst_p2_affine {
    blst_p2_affine {
        x: blst_fp2 { fp: [blst_fp { l: x0 }, blst_fp { l: x1 }] },
        y: blst_fp2 { fp: [blst_fp { l: y0 }, blst_fp { l: y1 }] },
    }
}

/// A 48-byte big-endian coordinate as little-endian 64-bit words.
#[inline]
fn fp_words(be: &[u8]) -> [u64; 6] {
    let mut words = [0u64; 6];
    for w in 0..6 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&be[FP_BYTES - 8 * (w + 1)..FP_BYTES - 8 * w]);
        words[w] = u64::from_be_bytes(bytes);
    }
    words
}

#[inline]
fn less_than_p(x: &[u64; 6]) -> bool {
    let mut w = 6;
    while w > 0 {
        w -= 1;
        if x[w] != P_U64[w] {
            return x[w] < P_U64[w];
        }
    }
    false
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub fn decompress(inputs: &[[u8; G2_COMPRESSED_LEN]; LANES]) -> Batch {
    let decoded = decode(inputs);
    let mut batch = Batch {
        points: [blst_p2_affine::default(); LANES],
        on_curve: 0,
        valid: 0,
        undecided: decoded.undecided,
    };
    // Malformed encodings would otherwise cost a full batch of field work.
    let decodable = !(decoded.invalid | decoded.undecided);
    if decodable == 0 {
        return batch;
    }

    let x = Fp2x8 { c0: Fp8::from_plain(&decoded.x0), c1: Fp8::from_plain(&decoded.x1) };
    let four = Fp8::splat_limbs(&FOUR_MONT);
    let rhs = x.square().mul(&x).add(&Fp2x8 { c0: four, c1: four });
    let (root, has_root) = rhs.sqrt();
    batch.on_curve = has_root & decodable;
    if batch.on_curve == 0 {
        return batch;
    }

    let flip = root.is_larger_root_mask() ^ decoded.larger_root;
    let y = Fp2x8::select(flip, &root, &root.neg());
    let membership = G2x8::scott_membership(&x, &y);
    batch.undecided |= membership.undecided & batch.on_curve;
    batch.valid = membership.members & batch.on_curve & !batch.undecided;

    let (x0, x1) = (x.c0.to_blst_limbs(), x.c1.to_blst_limbs());
    let (y0, y1) = (y.c0.to_blst_limbs(), y.c1.to_blst_limbs());
    for lane in 0..LANES {
        batch.points[lane] = point(x0[lane], x1[lane], y0[lane], y1[lane]);
    }
    batch
}
