use blst::{
    blst_p1, blst_p1_add_or_double, blst_p1_add_or_double_affine, blst_p1_affine, blst_p1_cneg,
    blst_p1_double, blst_p1_from_affine, blst_p1_to_affine, blst_p1_uncompress,
};
use rand::{SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;

use super::G1;
use crate::{
    bls::tests::{G1Torsion, H1_PRIMES, curve_points_outside_g1, g1_points},
    portable::{fp::Fp, portable_available},
};

fn affine(bytes: &[u8; 48]) -> blst_p1_affine {
    let mut a = blst_p1_affine::default();
    // SAFETY: valid pointers; the encodings are blst's own.
    unsafe { blst_p1_uncompress(&mut a, bytes.as_ptr()) };
    a
}

fn jacobian(a: &blst_p1_affine) -> blst_p1 {
    let mut p = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_from_affine(&mut p, a) };
    p
}

fn ours(p: &blst_p1) -> G1 {
    G1 { x: Fp(p.x.l), y: Fp(p.y.l), z: Fp(p.z.l) }
}

fn blst_affine(p: &blst_p1) -> (Fp, Fp) {
    let mut a = blst_p1_affine::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_to_affine(&mut a, p) };
    (Fp(a.x.l), Fp(a.y.l))
}

fn add(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_add_or_double(&mut out, a, b) };
    out
}

/// G1 members, with z ≠ 1 after an addition, and their affine forms.
fn members(n: usize) -> Vec<(blst_p1, blst_p1_affine)> {
    let points: Vec<_> = g1_points(n + 1).iter().map(affine).collect();
    (0..n)
        .map(|i| {
            let sum = add(&jacobian(&points[i]), &jacobian(&points[i + 1]));
            let mut a = blst_p1_affine::default();
            // SAFETY: valid pointers to single values.
            unsafe { blst_p1_to_affine(&mut a, &sum) };
            (sum, a)
        })
        .collect()
}

#[test]
fn formulas_match_blst() {
    if !portable_available() {
        return;
    }
    let points = members(12);
    for i in 0..points.len() {
        let (p, pa) = &points[i];
        let (q, qa) = &points[(i + 5) % points.len()];
        let (qx, qy) = (Fp(qa.x.l), Fp(qa.y.l));
        let mut doubled = blst_p1::default();
        let mut sum_affine = blst_p1::default();
        let mut negated = *p;
        // SAFETY: valid pointers to single values.
        unsafe {
            blst_p1_double(&mut doubled, p);
            blst_p1_add_or_double_affine(&mut sum_affine, p, qa);
            blst_p1_cneg(&mut negated, true);
        }
        // SAFETY: `portable_available` held.
        unsafe {
            let ours_p = ours(p);
            assert_eq!(ours_p.to_affine(), (Fp(pa.x.l), Fp(pa.y.l)), "to_affine {i}");
            assert_eq!(ours_p.double().to_affine(), blst_affine(&doubled), "double {i}");
            assert_eq!(ours_p.add(&ours(q)).to_affine(), blst_affine(&add(p, q)), "add {i}");
            assert_eq!(
                ours_p.add_affine(&qx, &qy).to_affine(),
                blst_affine(&sum_affine),
                "madd {i}"
            );
            assert_eq!(ours_p.neg().to_affine(), blst_affine(&negated), "neg {i}");
            assert!(ours_p.equals(&ours(&jacobian(pa))), "equals {i}");
            assert!(!ours_p.equals(&ours(q)), "not equals {i}");
        }
    }
}

/// The complete forms on the summands the plain ones exclude: equal points,
/// opposite points, and infinity on either side.
#[test]
fn complete_forms_match_blst_on_exceptional_summands() {
    if !portable_available() {
        return;
    }
    let infinity = blst_p1::default();
    for (p, pa) in members(4) {
        let mut negated = p;
        // SAFETY: a valid pointer to a single value.
        unsafe { blst_p1_cneg(&mut negated, true) };
        let negated_affine = {
            let mut a = blst_p1_affine::default();
            // SAFETY: valid pointers to single values.
            unsafe { blst_p1_to_affine(&mut a, &negated) };
            a
        };
        let cases = [(p, p), (p, negated), (p, infinity), (infinity, p), (infinity, infinity)];
        // SAFETY: `portable_available` held.
        unsafe {
            for (k, (a, b)) in cases.iter().enumerate() {
                let want = blst_affine(&add(a, b));
                assert_eq!(ours(a).add_complete(&ours(b)).to_affine(), want, "add_complete {k}");
            }
            let (x, y) = (Fp(pa.x.l), Fp(pa.y.l));
            let (nx, ny) = (Fp(negated_affine.x.l), Fp(negated_affine.y.l));
            assert_eq!(ours(&p).add_affine_complete(&x, &y).to_affine(), blst_affine(&add(&p, &p)));
            assert!(ours(&p).add_affine_complete(&nx, &ny).is_infinity());
            assert_eq!(ours(&infinity).add_affine_complete(&x, &y).to_affine(), (x, y));
            assert!(ours(&infinity).double().is_infinity());
            assert_eq!(ours(&infinity).to_affine(), (Fp::ZERO, Fp::ZERO));
        }
    }
}

#[test]
fn membership_matches_blst() {
    if !portable_available() {
        return;
    }
    let mut rng = StdRng::seed_from_u64(17);
    let mut cases: Vec<(blst_p1_affine, bool)> =
        g1_points(16).iter().map(|b| (affine(b), true)).collect();
    for b in curve_points_outside_g1(&mut rng, 16) {
        cases.push((affine(&b), false));
    }
    let mut torsion = G1Torsion(ChaCha8Rng::seed_from_u64(19));
    let member = jacobian(&cases[0].0);
    for prime_index in 0..H1_PRIMES.len() {
        let t = torsion.of_order(prime_index);
        let mut a = blst_p1_affine::default();
        let mut b = blst_p1_affine::default();
        // SAFETY: valid pointers to single values.
        unsafe {
            blst_p1_to_affine(&mut a, &t);
            blst_p1_to_affine(&mut b, &add(&member, &t));
        }
        cases.push((a, false));
        cases.push((b, false));
    }
    for (k, (point, member)) in cases.iter().enumerate() {
        // SAFETY: `portable_available` held.
        let got = unsafe { G1::in_g1(&Fp(point.x.l), &Fp(point.y.l)) };
        assert_eq!(got, *member, "case {k}");
    }
}
