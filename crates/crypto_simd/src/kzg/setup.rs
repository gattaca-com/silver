//! The trusted-setup points the cell verifier uses, decoded once.

use crate::{
    bls::{blst_p1_affine, blst_p2_affine, uncompress_in_g1, uncompress_in_g2_blst},
    kzg::{
        FIELD_ELEMENTS_PER_CELL,
        blst_ops::g2_neg,
        trusted_setup::{G1_MONOMIAL, G2_MONOMIAL_0, G2_MONOMIAL_64},
    },
};

pub struct Setup {
    /// [s^i] in G1 for i < 64.
    pub g1_monomial: Vec<blst_p1_affine>,
    /// [s^64] in G2.
    pub g2_s_pow_cell: blst_p2_affine,
    /// −[1] in G2.
    pub g2_neg_generator: blst_p2_affine,
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
        let g2_s_pow_cell = match uncompress_in_g2_blst(&G2_MONOMIAL_64) {
            Some(point) => point,
            None => panic!("trusted-setup G2 point 64 is invalid"),
        };
        let g2_generator = match uncompress_in_g2_blst(&G2_MONOMIAL_0) {
            Some(point) => point,
            None => panic!("trusted-setup G2 point 0 is invalid"),
        };
        Self { g1_monomial, g2_s_pow_cell, g2_neg_generator: g2_neg(&g2_generator) }
    }
}
