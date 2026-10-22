use blst::{blst_p1, blst_p1_affine, blst_p1_double};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{CHUNK, Msm};
use crate::{
    bls::msm8::tests::{
        SEED, assert_same_point, distinct_points, finite_pippenger, glv_edges, lincomb,
        negated_point, random_points, random_scalars,
    },
    portable::portable_available,
};

fn assert_msm_matches(msm: &mut Msm, points: &[blst_p1_affine], scalars: &[[u64; 4]], case: &str) {
    // SAFETY: the callers checked `portable_available`.
    let got = unsafe { msm.msm(points, scalars) };
    assert_same_point(&got, &lincomb(points, scalars), case);
}

/// Sizes around every window width, a tenth of the points at infinity, and
/// scalars up to 2^255 − 1. One `Msm` serves every size.
#[test]
fn msm_matches_blst() {
    if !portable_available() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 25);
    let mut msm = Msm::default();
    for n in [0, 1, 2, 3, 7, 8, 9, 18, 63, 64, 65, 200, 511, 512, 600] {
        let mut points = random_points(&mut rng, n);
        for point in &mut points {
            if rng.gen_bool(0.1) {
                *point = blst_p1_affine::default();
            }
        }
        let scalars = random_scalars(&mut rng, n);
        assert_msm_matches(&mut msm, &points, &scalars, &format!("{n} points"));
    }
}

#[test]
fn msm_matches_blst_at_glv_edges() {
    if !portable_available() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 26);
    let mut msm = Msm::default();
    let edges = glv_edges();
    let points = random_points(&mut rng, 3 * edges.len());
    let scalars: Vec<[u64; 4]> = (0..points.len()).map(|i| edges[i % edges.len()]).collect();
    assert_msm_matches(&mut msm, &points, &scalars, "GLV edges");
}

/// Equal points fail the batched rounds, so the refilled buckets are summed
/// point by point; opposite points with equal scalars cancel.
#[test]
fn msm_matches_blst_with_repeated_and_opposite_points() {
    if !portable_available() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 27);
    let mut msm = Msm::default();
    for (n, distinct) in [(2, 1), (40, 1), (100, 3), (520, 2)] {
        let originals = random_points(&mut rng, distinct);
        let points: Vec<_> = (0..n).map(|i| originals[i % distinct]).collect();
        let scalars = random_scalars(&mut rng, n);
        assert_msm_matches(&mut msm, &points, &scalars, &format!("{n} copies of {distinct}"));
    }
    for n in [2, 30, 200, 600] {
        let originals = random_points(&mut rng, n / 2);
        let mut points = originals.clone();
        points.extend(originals.iter().map(negated_point));
        let mut scalars = random_scalars(&mut rng, n / 2);
        scalars.extend_from_within(..);
        // SAFETY: `portable_available` held.
        let got = unsafe { msm.msm(&points, &scalars) };
        assert_same_point(&got, &blst_p1::default(), &format!("{n} points and their negations"));
        points.push(originals[0]);
        scalars.push([3, 0, 0, 0]);
        assert_msm_matches(&mut msm, &points, &scalars, &format!("{n} cancelling, one left"));
    }
}

/// Inputs longer than a chunk: a last chunk of one point, and a second chunk
/// that repeats or negates the first, so that the chunk sums double or cancel.
#[test]
fn msm_sums_its_chunks() {
    if !portable_available() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 28);
    let mut msm = Msm::default();
    let first = distinct_points(&mut rng, CHUNK);
    let scalars = random_scalars(&mut rng, CHUNK);

    let mut points = first.clone();
    points.extend(random_points(&mut rng, 1));
    let mut longer = scalars.clone();
    longer.extend(random_scalars(&mut rng, 1));
    // SAFETY: `portable_available` held.
    let got = unsafe { msm.msm(&points, &longer) };
    assert_same_point(&got, &finite_pippenger(&points, &longer), "a chunk and one point");

    let once = finite_pippenger(&first, &scalars);
    let mut want = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_double(&mut want, &once) };
    let twice = [first.as_slice(), &first].concat();
    let doubled = [scalars.as_slice(), &scalars].concat();
    // SAFETY: `portable_available` held.
    let got = unsafe { msm.msm(&twice, &doubled) };
    assert_same_point(&got, &want, "a chunk twice");

    let mut opposite = first.clone();
    opposite.extend(first.iter().map(negated_point));
    // SAFETY: as above.
    let got = unsafe { msm.msm(&opposite, &doubled) };
    assert_same_point(&got, &blst_p1::default(), "a chunk and its negation");
}
