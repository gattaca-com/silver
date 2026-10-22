//! The trusted-setup points the cell verifier uses: the G1 points decoded
//! once, the two G2 points as literals.

use blst::{blst_fp, blst_fp2};

use crate::{
    bls::{blst_p1_affine, blst_p2_affine, uncompress_in_g1},
    kzg::{FIELD_ELEMENTS_PER_CELL, trusted_setup::G1_MONOMIAL},
};

/// [s^64] in G2, `G2_MONOMIAL_64` decoded, in blst's Montgomery form.
pub const G2_S_POW_CELL: blst_p2_affine = blst_p2_affine {
    x: blst_fp2 {
        fp: [
            blst_fp {
                l: [
                    0xc0b3d27b16a3640b,
                    0xace3fa1ffc86682b,
                    0x533831bb8af82f36,
                    0xb04049d0baad5520,
                    0xb7b7a0cd6e353592,
                    0x105956acf773013b,
                ],
            },
            blst_fp {
                l: [
                    0x400a96a17290e706,
                    0x2d92fc169e6085d6,
                    0xcb48449e82fd9627,
                    0x6463852ef6e582a0,
                    0xd1c38da04c0f254a,
                    0x13d2c8b4b80b8f54,
                ],
            },
        ],
    },
    y: blst_fp2 {
        fp: [
            blst_fp {
                l: [
                    0xa14dd902d0c036fc,
                    0xaa16b4532ce039d2,
                    0xc9a38eb6477d2ee3,
                    0x94060859ee3b25f2,
                    0x911ea5483e24cadf,
                    0x1268d588701c449f,
                ],
            },
            blst_fp {
                l: [
                    0x1e1d07b20f3a0b68,
                    0x5d6d22b125cc5716,
                    0xb7c8bda9efe3655d,
                    0xaa4032886c427640,
                    0x880cb9e55b9b2304,
                    0x15fcee3b528d2639,
                ],
            },
        ],
    },
};

/// −[1] in G2, `G2_MONOMIAL_0` decoded and negated, in blst's Montgomery form.
pub const G2_NEG_GENERATOR: blst_p2_affine = blst_p2_affine {
    x: blst_fp2 {
        fp: [
            blst_fp {
                l: [
                    0xf5f28fa202940a10,
                    0xb3f5fb2687b4961a,
                    0xa1a893b53e2ae580,
                    0x9894999d1a3caee9,
                    0x6f67b7631863366b,
                    0x058191924350bcd7,
                ],
            },
            blst_fp {
                l: [
                    0xa5a9c0759e23f606,
                    0xaaa0c59dbccd60c3,
                    0x3bb17e18e2867806,
                    0x1b1ab6cc8541b367,
                    0xc2b6ed0ef2158547,
                    0x11922a097360edf3,
                ],
            },
        ],
    },
    y: blst_fp2 {
        fp: [
            blst_fp {
                l: [
                    0x6d8bf5079fb65e61,
                    0xc52f05df531d63a5,
                    0x7f4a4d344ca692c9,
                    0xa887959b8577c95f,
                    0x4347fe40525c8734,
                    0x197d145bbaff0bb5,
                ],
            },
            blst_fp {
                l: [
                    0x0c3e036d209afa4e,
                    0x0601d8f4863f9e23,
                    0xe0832636bacc0a84,
                    0xeb2def362a476f84,
                    0x64044f659f0ee1e9,
                    0x0ed54f48d5a1caa7,
                ],
            },
        ],
    },
};

pub struct Setup {
    /// [s^i] in G1 for i < 64.
    pub g1_monomial: Vec<blst_p1_affine>,
}

impl Setup {
    pub fn decode() -> Self {
        let mut decoded = Vec::with_capacity(FIELD_ELEMENTS_PER_CELL);
        decoded.resize(FIELD_ELEMENTS_PER_CELL, None);
        uncompress_in_g1(&G1_MONOMIAL, &mut decoded);
        let mut g1_monomial = Vec::with_capacity(FIELD_ELEMENTS_PER_CELL);
        for i in 0..FIELD_ELEMENTS_PER_CELL {
            match decoded[i] {
                Some(point) => g1_monomial.push(point),
                None => panic!("a trusted-setup G1 point is invalid"),
            }
        }
        Self { g1_monomial }
    }
}
