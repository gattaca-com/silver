use blst::{
    blst_fr, blst_p1, blst_p1_affine_generator, blst_p1_cneg, blst_p1_from_affine, blst_p1_mult,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::Msm8;
use crate::{
    bls::{blst_p1_affine, simd_available},
    kzg::{
        blst_msm::scalar_bytes,
        blst_ops::{LincombScratch, fr_from_bytes, fr_from_u64, fr_sub, g1_lincomb, g1_to_affine},
    },
};

const SEED: u64 = 0x4d53_4d38_7465_7374;

fn msm8() -> Option<Msm8> {
    let msm = Msm8::new();
    assert!(
        msm.is_some() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    assert_eq!(msm.is_some(), simd_available());
    msm
}

fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
    loop {
        let mut bytes: [u8; 32] = rng.r#gen();
        bytes[0] &= 0x7f;
        if let Some(fr) = fr_from_bytes(&bytes) {
            return fr;
        }
    }
}

fn random_points(rng: &mut ChaCha8Rng, count: usize) -> Vec<blst_p1_affine> {
    (0..count)
        .map(|_| {
            let scalar = scalar_bytes(&random_fr(rng));
            let mut base = blst_p1::default();
            let mut point = blst_p1::default();
            // SAFETY: blst returns a pointer to its static generator; valid pointers to
            // single values, and blst reads 255 bits of the 32-byte scalar.
            unsafe {
                blst_p1_from_affine(&mut base, blst_p1_affine_generator());
                blst_p1_mult(&mut point, &base, scalar.as_ptr(), 255);
            }
            g1_to_affine(&point)
        })
        .collect()
}

fn negated(point: &blst_p1_affine) -> blst_p1_affine {
    let mut projective = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe {
        blst_p1_from_affine(&mut projective, point);
        blst_p1_cneg(&mut projective, true);
    }
    g1_to_affine(&projective)
}

fn expected(points: &[blst_p1_affine], scalars: &[blst_fr]) -> blst_p1_affine {
    g1_to_affine(&g1_lincomb(points, scalars, &mut LincombScratch::new()))
}

fn bytes(scalars: &[blst_fr]) -> Vec<[u8; 32]> {
    scalars.iter().map(scalar_bytes).collect()
}

fn assert_matches(msm: &mut Msm8, points: &[blst_p1_affine], scalars: &[blst_fr], name: &str) {
    let sum = msm.msm(points, &bytes(scalars)).unwrap_or_else(|| panic!("{name}: exceptional"));
    assert!(g1_to_affine(&sum) == expected(points, scalars), "{name}");
}

#[test]
fn matches_blst_on_random_inputs() {
    let Some(mut msm) = msm8() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    for n in [1, 2, 3, 4, 7, 8, 9, 18, 63, 64, 100, 144, 1000, 1152, 2304] {
        let points = random_points(&mut rng, n);
        let scalars: Vec<_> = (0..n).map(|_| random_fr(&mut rng)).collect();
        assert_matches(&mut msm, &points, &scalars, &format!("n = {n}"));
    }
}

#[test]
fn matches_blst_on_edge_scalars() {
    let Some(mut msm) = msm8() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
    let (zero, one) = (fr_from_u64(0), fr_from_u64(1));
    let minus_one = fr_sub(&zero, &one);
    for n in [4, 9, 70, 600] {
        let points = random_points(&mut rng, n);
        for (name, scalars) in [
            ("zero", vec![zero; n]),
            ("one", vec![one; n]),
            ("minus one", vec![minus_one; n]),
            ("small", (0..n).map(|i| fr_from_u64(i as u64 % 7)).collect()),
            (
                "mixed",
                (0..n)
                    .map(|i| match i % 3 {
                        0 => zero,
                        1 => one,
                        _ => minus_one,
                    })
                    .collect(),
            ),
        ] {
            let sum = msm.msm(&points, &bytes(&scalars));
            match sum {
                Some(sum) => {
                    assert!(g1_to_affine(&sum) == expected(&points, &scalars), "{name}, n = {n}")
                }
                None => assert!(
                    name == "one" || name == "minus one" || name == "mixed",
                    "{name}, n = {n}: only equal scalars may collide"
                ),
            }
        }
    }
}

/// Distinct small scalars leave most buckets empty and make S equal T right
/// after an empty bucket.
#[test]
fn empty_buckets_are_summed_exactly() {
    let Some(mut msm) = msm8() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 2);
    for n in [4, 5, 6, 9, 20] {
        let points = random_points(&mut rng, n);
        let scalars: Vec<_> = (0..n).map(|i| fr_from_u64(i as u64 + 1)).collect();
        assert_matches(&mut msm, &points, &scalars, &format!("scalars 1..={n}"));
        let scalars: Vec<_> = (0..n).map(|i| fr_from_u64(1 << (3 * i))).collect();
        assert_matches(&mut msm, &points, &scalars, &format!("powers of eight, n = {n}"));
    }
}

#[test]
fn points_at_infinity_contribute_nothing() {
    let Some(mut msm) = msm8() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 3);
    let mut points = random_points(&mut rng, 40);
    let scalars: Vec<_> = (0..40).map(|_| random_fr(&mut rng)).collect();
    points[0] = blst_p1_affine::default();
    points[17] = blst_p1_affine::default();
    points[39] = blst_p1_affine::default();
    assert_matches(&mut msm, &points, &scalars, "three infinities");

    let all_infinite = vec![blst_p1_affine::default(); 10];
    assert_matches(&mut msm, &all_infinite, &scalars[..10], "only infinities");
    assert_matches(&mut msm, &points[..2], &scalars[..2], "an infinity and a point");
}

#[test]
fn a_point_and_its_negation_in_one_bucket_give_none() {
    let Some(mut msm) = msm8() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 4);
    let mut points = random_points(&mut rng, 12);
    points[7] = negated(&points[3]);
    let mut scalars: Vec<_> = (0..12).map(|_| random_fr(&mut rng)).collect();
    scalars[7] = scalars[3];
    assert!(msm.msm(&points, &bytes(&scalars)).is_none());
}

#[test]
fn repeated_points_are_exact_or_none() {
    let Some(mut msm) = msm8() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 5);
    let mut points = random_points(&mut rng, 100);
    for i in 1..100 {
        points[i] = points[i % 5];
    }
    let scalars: Vec<_> = (0..100).map(|_| random_fr(&mut rng)).collect();
    if let Some(sum) = msm.msm(&points, &bytes(&scalars)) {
        assert!(g1_to_affine(&sum) == expected(&points, &scalars));
    }
    let same = vec![points[0]; 6];
    let scalars: Vec<_> = (0..6).map(|_| fr_from_u64(5)).collect();
    assert!(msm.msm(&same, &bytes(&scalars)).is_none(), "equal points in equal buckets");
}

#[test]
fn one_instance_serves_many_sizes() {
    let Some(mut msm) = msm8() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 6);
    for n in [300, 5, 1500, 64, 9, 700] {
        let points = random_points(&mut rng, n);
        let scalars: Vec<_> = (0..n).map(|_| random_fr(&mut rng)).collect();
        assert_matches(&mut msm, &points, &scalars, &format!("n = {n}"));
    }
}
