//! The scalar Miller loop and pairing check against the spec's and blst's,
//! as the lanes' tests do.

use blst::{blst_fp, blst_p1, blst_p2_affine};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use super::PairingLines;
use crate::{
    bls::{
        fp8::LANES,
        g1x8::tests::{affine, negated, random_points, rescaled},
        pairing::{
            LINE_COUNT,
            tests::{
                blst_pairing_check, final_exp, g1_times, g2_times, jacobian, line_values,
                random_g2, random_scalar,
            },
        },
        spec_pairing::{self, pairing_product},
    },
    kzg::{
        pairing_lines::PAIRING_LINES,
        setup::{G2_NEG_GENERATOR, G2_S_POW_CELL},
    },
    portable::{fp::Fp, fp2::Fp2, fp12::tests::blst_of, g1::G1, portable_available},
};

fn lines_from_values(values: &[[[u64; 6]; LANES]; LINE_COUNT]) -> PairingLines {
    let mut out = [[[Fp2::ZERO; 2]; 2]; LINE_COUNT];
    for step in 0..LINE_COUNT {
        for pair in 0..2 {
            for l in 0..2 {
                let lane = 4 * pair + 2 * l;
                out[step][pair][l] =
                    Fp2 { c0: Fp(values[step][lane]), c1: Fp(values[step][lane + 1]) };
            }
        }
    }
    PairingLines(out)
}

fn lines_of(q: &[blst_p2_affine; 2]) -> PairingLines {
    lines_from_values(&line_values(q))
}

fn points(p: &[blst_p1; 2]) -> [G1; 2] {
    [G1::from_blst(&p[0]), G1::from_blst(&p[1])]
}

/// The verifier's lines, converted from Fp8's form, are the spec's.
#[test]
fn pairing_lines_convert_to_the_spec_lines() {
    if !portable_available() {
        return;
    }
    // SAFETY: `portable_available` held.
    let converted = unsafe { PairingLines::new(&PAIRING_LINES) };
    let spec = lines_of(&[G2_S_POW_CELL, G2_NEG_GENERATOR]);
    assert!(converted.0 == spec.0);
}

#[test]
fn miller_loop_matches_the_spec_after_the_final_exponentiation() {
    if !portable_available() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x4d12);
    for _ in 0..3 {
        let p = random_points(&mut rng, 2);
        let p = [p[0], p[1]];
        let q = [random_g2(&mut rng), random_g2(&mut rng)];
        let a = [affine(&p[0]), affine(&p[1])];
        let want = final_exp(&pairing_product(&[(a[0], q[0]), (a[1], q[1])]));
        let scales =
            [p, [jacobian(&a[0]), jacobian(&a[1])], [rescaled(&p[0], 3), rescaled(&p[1], 5)]];
        let lines = lines_of(&q);
        for (case, scaled) in scales.iter().enumerate() {
            // SAFETY: `portable_available` held.
            let got = blst_of(&unsafe { lines.miller_loop(&points(scaled)) });
            assert!(final_exp(&got) == want, "scale {case}");
        }
    }
}

/// On a balanced product, the same with a wrong sign, unrelated points, and
/// points at infinity.
#[test]
fn pairing_check_matches_the_spec() {
    if !portable_available() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x9d);
    let p = random_points(&mut rng, 3);
    let q = [random_g2(&mut rng), random_g2(&mut rng)];
    let a = random_scalar(&mut rng);
    let (ap, aq) = (g1_times(&p[0], &a), g2_times(&q[0], &a));
    let infinity = blst_p1 { z: blst_fp::default(), ..p[0] };
    let cases = [
        ("balanced", [ap, negated(&p[0])], [q[0], aq], true),
        ("wrong sign", [ap, p[0]], [q[0], aq], false),
        ("unrelated", [p[1], p[2]], q, false),
        ("first at infinity", [infinity, p[1]], q, false),
        ("second at infinity", [p[1], infinity], q, false),
        ("both at infinity", [infinity, infinity], q, true),
    ];
    for (name, g1, g2, want) in cases {
        let pairs = [(affine(&g1[0]), g2[0]), (affine(&g1[1]), g2[1])];
        assert_eq!(spec_pairing::pairing_check(&pairs), want, "{name}: the spec");
        assert_eq!(blst_pairing_check(&pairs), want, "{name}: blst");
        // SAFETY: `portable_available` held.
        let got = unsafe { lines_of(&g2).pairing_check(&points(&g1)) };
        assert_eq!(got, want, "{name}");
    }
}
