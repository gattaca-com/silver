//! The final pairing check against two fixed G2 points, with their Miller-loop
//! lines precomputed.

use blst::{
    blst_final_exp, blst_fp6, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_miller_loop_lines,
    blst_p1_affine_is_inf, blst_precompute_lines,
};

use crate::bls::{blst_p1_affine, blst_p2_affine};

const LINES: usize = 68;

struct Lines(Box<[blst_fp6; LINES]>);

impl Lines {
    fn new(q: &blst_p2_affine) -> Self {
        let mut lines = Box::new([blst_fp6::default(); LINES]);
        // SAFETY: blst writes `LINES` values and reads one point.
        unsafe { blst_precompute_lines(lines.as_mut_ptr(), q) };
        Self(lines)
    }

    fn miller_loop(&self, p: &blst_p1_affine) -> blst_fp12 {
        let mut out = blst_fp12::default();
        // SAFETY: blst reads `LINES` values and one point.
        unsafe { blst_miller_loop_lines(&mut out, self.0.as_ptr(), p) };
        out
    }
}

pub struct PairingLines {
    left: Lines,
    right: Lines,
}

impl PairingLines {
    pub fn new(left: &blst_p2_affine, right: &blst_p2_affine) -> Self {
        Self { left: Lines::new(left), right: Lines::new(right) }
    }

    /// e(ll, left)·e(rl, right) = 1, skipping a pair whose G1 point is
    /// infinity, as `blst_ops::pairing_check` does. The G2 points are never
    /// infinity.
    pub fn check(&self, ll: &blst_p1_affine, rl: &blst_p1_affine) -> bool {
        // SAFETY: valid pointers to single values.
        let (ll_inf, rl_inf) = unsafe { (blst_p1_affine_is_inf(ll), blst_p1_affine_is_inf(rl)) };
        let miller = match (ll_inf, rl_inf) {
            (true, true) => return true,
            (false, true) => self.left.miller_loop(ll),
            (true, false) => self.right.miller_loop(rl),
            (false, false) => {
                let (a, b) = (self.left.miller_loop(ll), self.right.miller_loop(rl));
                let mut product = blst_fp12::default();
                // SAFETY: valid pointers to single values.
                unsafe { blst_fp12_mul(&mut product, &a, &b) };
                product
            }
        };
        let mut result = blst_fp12::default();
        // SAFETY: valid pointers to single values.
        unsafe {
            blst_final_exp(&mut result, &miller);
            blst_fp12_is_one(&result)
        }
    }
}

#[cfg(test)]
mod tests {
    use blst::{
        blst_p1, blst_p1_affine_generator, blst_p1_from_affine, blst_p1_mult,
        blst_p2_affine_generator,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::kzg::{
        blst_ops::{g1_neg, g1_to_affine, pairing_check},
        setup::Setup,
    };

    fn random_g1(rng: &mut ChaCha8Rng) -> blst_p1_affine {
        let scalar: [u8; 32] = rng.r#gen();
        let mut base = blst_p1::default();
        let mut point = blst_p1::default();
        // SAFETY: blst returns a pointer to its static generator; valid pointers to
        // single values, and blst reads 255 bits of the 32-byte scalar.
        unsafe {
            blst_p1_from_affine(&mut base, blst_p1_affine_generator());
            blst_p1_mult(&mut point, &base, scalar.as_ptr(), 255);
        }
        g1_to_affine(&point)
    }

    #[test]
    fn matches_pairing_check_on_random_points() {
        let setup = Setup::decode();
        let lines = PairingLines::new(&setup.g2_s_pow_cell, &setup.g2_neg_generator);
        let mut rng = ChaCha8Rng::seed_from_u64(0x11e5);
        for _ in 0..16 {
            let (ll, rl) = (random_g1(&mut rng), random_g1(&mut rng));
            let expected = pairing_check(&ll, &setup.g2_s_pow_cell, &rl, &setup.g2_neg_generator);
            assert!(!expected);
            assert_eq!(lines.check(&ll, &rl), expected);
        }
    }

    #[test]
    fn accepts_a_balanced_pair_and_the_infinity_cases() {
        // SAFETY: blst returns pointers to its static generators.
        let (g1, g2) = unsafe { (*blst_p1_affine_generator(), *blst_p2_affine_generator()) };
        let mut projective = blst_p1::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_p1_from_affine(&mut projective, &g1) };
        let minus_g1 = g1_to_affine(&g1_neg(&projective));
        let infinity = blst_p1_affine::default();

        let lines = PairingLines::new(&g2, &g2);
        let expected = |p: &blst_p1_affine, q: &blst_p1_affine| pairing_check(p, &g2, q, &g2);
        let cases = [
            (g1, minus_g1, true),
            (g1, g1, false),
            (g1, infinity, false),
            (infinity, g1, false),
            (infinity, infinity, true),
        ];
        for (index, (p, q, verdict)) in cases.iter().enumerate() {
            assert_eq!(expected(p, q), *verdict, "case {index}");
            assert_eq!(lines.check(p, q), *verdict, "case {index}");
        }
    }
}
