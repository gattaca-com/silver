use blst::{blst_final_exp, blst_fp, blst_fp2, blst_fp6, blst_fp12};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use super::Fp12;
use crate::{
    bls::fp12::tests::{
        blst_conjugate, blst_cyclotomic_square, blst_frobenius, blst_inverse, blst_mul,
        blst_mul_by_line, blst_square, cyclotomic, extreme_fp12, random_fp12, random_line,
    },
    portable::{fp::Fp, fp2::Fp2, fp6::Fp6},
};

fn fp2(a: &blst_fp2) -> Fp2 {
    Fp2 { c0: Fp(a.fp[0].l), c1: Fp(a.fp[1].l) }
}

fn fp6(a: &blst_fp6) -> Fp6 {
    Fp6 { c0: fp2(&a.fp2[0]), c1: fp2(&a.fp2[1]), c2: fp2(&a.fp2[2]) }
}

pub(crate) fn ours(f: &blst_fp12) -> Fp12 {
    Fp12 { c0: fp6(&f.fp6[0]), c1: fp6(&f.fp6[1]) }
}

pub(crate) fn blst_of(f: &Fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    let halves = [&f.c0, &f.c1];
    for h in 0..2 {
        let coefficients = [&halves[h].c0, &halves[h].c1, &halves[h].c2];
        for k in 0..3 {
            out.fp6[h].fp2[k] = blst_fp2 {
                fp: [blst_fp { l: coefficients[k].c0.0 }, blst_fp { l: coefficients[k].c1.0 }],
            };
        }
    }
    out
}

fn final_exp(f: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_final_exp(&mut out, f) };
    out
}

/// Every operation against blst's, on random values and on every coefficient
/// p − 1.
#[test]
fn operations_match_blst() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x12);
    let mut values: Vec<blst_fp12> = (0..6).map(|_| random_fp12(&mut rng)).collect();
    values.push(extreme_fp12());
    for (i, a) in values.iter().enumerate() {
        let b = &values[(i + 1) % values.len()];
        let line = random_line(&mut rng);
        let (x, y, z) = (fp2(&line.fp2[0]), fp2(&line.fp2[1]), fp2(&line.fp2[2]));
        assert_eq!(blst_of(&ours(a).mul(&ours(b))), blst_mul(a, b), "mul {i}");
        assert_eq!(blst_of(&ours(a).square()), blst_square(a), "square {i}");
        assert_eq!(
            blst_of(&ours(a).mul_by_line(&x, &y, &z)),
            blst_mul_by_line(a, &line),
            "mul_by_line {i}"
        );
        assert_eq!(
            blst_of(&ours(a).cyclotomic_square()),
            blst_cyclotomic_square(a),
            "cyclotomic_square {i}"
        );
        assert_eq!(blst_of(&ours(a).conjugate()), blst_conjugate(a), "conjugate {i}");
        assert_eq!(blst_of(&ours(a).frobenius()), blst_frobenius(a, 1), "frobenius {i}");
        assert_eq!(blst_of(&ours(a).inverse()), blst_inverse(a), "inverse {i}");
    }
}

/// The final exponentiation against blst's, which also cubes the spec's, on
/// random values and on values already in the cyclotomic subgroup.
#[test]
fn final_exponentiation_matches_blst() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x13);
    for i in 0..4 {
        let f = random_fp12(&mut rng);
        let g = cyclotomic(&f);
        assert_eq!(blst_of(&ours(&f).final_exponentiation()), final_exp(&f), "random {i}");
        assert_eq!(blst_of(&ours(&g).final_exponentiation()), final_exp(&g), "cyclotomic {i}");
    }
    assert!(Fp12::ONE.final_exponentiation().is_one());
}
