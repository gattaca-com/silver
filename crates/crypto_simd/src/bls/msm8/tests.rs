use std::time::Instant;

use blst::{
    blst_fp, blst_fp_from_uint64, blst_p1, blst_p1_add_or_double_affine, blst_p1_cneg,
    blst_p1_from_affine, blst_p1_generator, blst_p1_mult, blst_p1_to_affine, blst_uint64_from_fp,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    bls::{
        blst_p1_affine,
        constants::TWO_POW_448_MOD_P,
        fp8::{Fp8, LANES, Limbs, unpack52},
        msm8::{
            pairs::{BatchedAdds, NEGATED},
            store::PointStore,
        },
    },
    kernels_run,
};

const SEED: u64 = 0x6d73_6d38_7061_6972;

fn random_points(rng: &mut ChaCha8Rng, n: usize) -> Vec<blst_p1_affine> {
    (0..n)
        .map(|_| {
            let mut scalar: [u8; 32] = rng.r#gen();
            scalar[31] &= 0x3f;
            let mut point = blst_p1::default();
            let mut affine = blst_p1_affine::default();
            // SAFETY: blst returns a pointer to its static generator; valid pointers to
            // single values, and blst reads 255 bits of the 32-byte scalar.
            unsafe {
                blst_p1_mult(&mut point, blst_p1_generator(), scalar.as_ptr(), 255);
                blst_p1_to_affine(&mut affine, &point);
            }
            affine
        })
        .collect()
}

fn plain(fp: &blst_fp) -> Limbs {
    let mut words = [0u64; 6];
    // SAFETY: blst writes six words for one value.
    unsafe { blst_uint64_from_fp(words.as_mut_ptr(), fp) };
    unpack52(&words)
}

fn coordinates(point: &blst_p1_affine) -> (Limbs, Limbs) {
    (plain(&point.x), plain(&point.y))
}

fn negated_point(point: &blst_p1_affine) -> blst_p1_affine {
    let mut projective = blst_p1::default();
    let mut affine = blst_p1_affine::default();
    // SAFETY: valid pointers to single values.
    unsafe {
        blst_p1_from_affine(&mut projective, point);
        blst_p1_cneg(&mut projective, true);
        blst_p1_to_affine(&mut affine, &projective);
    }
    affine
}

fn sum(a: &blst_p1_affine, b: &blst_p1_affine) -> blst_p1_affine {
    let (mut projective, mut total) = (blst_p1::default(), blst_p1::default());
    let mut affine = blst_p1_affine::default();
    // SAFETY: valid pointers to single values.
    unsafe {
        blst_p1_from_affine(&mut projective, a);
        blst_p1_add_or_double_affine(&mut total, &projective, b);
        blst_p1_to_affine(&mut affine, &total);
    }
    affine
}

/// [λ]P for λ = z² − 1, the eigenvalue of σ on G1.
fn times_lambda(point: &blst_p1_affine) -> blst_p1_affine {
    let lambda = 0xac45_a401_0001_a402_0000_0000_ffff_ffffu128.to_le_bytes();
    let (mut projective, mut product) = (blst_p1::default(), blst_p1::default());
    let mut affine = blst_p1_affine::default();
    // SAFETY: valid pointers to single values, and blst reads 128 bits of the
    // 16-byte scalar.
    unsafe {
        blst_p1_from_affine(&mut projective, point);
        blst_p1_mult(&mut product, &projective, lambda.as_ptr(), 128);
        blst_p1_to_affine(&mut affine, &product);
    }
    affine
}

/// The points in fresh slots of `store`, by their indices.
#[target_feature(enable = "avx512f,avx512ifma")]
fn push_points(store: &mut PointStore, points: &[blst_p1_affine]) -> Vec<u32> {
    let indices: Vec<u32> = points.iter().map(|_| store.allocate()).collect();
    for (chunk, slots) in points.chunks(LANES).zip(indices.chunks(LANES)) {
        let lane = |l: usize| l.min(chunk.len() - 1);
        let x = Fp8::from_plain(&std::array::from_fn(|l| plain(&chunk[lane(l)].x)));
        let y = Fp8::from_plain(&std::array::from_fn(|l| plain(&chunk[lane(l)].y)));
        store.store_points(&std::array::from_fn(|l| slots[lane(l)]), &x, &y);
    }
    indices
}

/// The plain coordinates of the point at `index`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn read_point(store: &PointStore, index: u32) -> (Limbs, Limbs) {
    let (x, y) = store.load_points(&[index; LANES]);
    (x.to_plain()[0], y.to_plain()[0])
}

#[test]
fn store_reads_back_its_points() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    let points = random_points(&mut rng, 21);
    let mut store = PointStore::new();
    store.reset(points.len());
    // SAFETY: `kernels_run` checked `simd_available`.
    let indices = unsafe { push_points(&mut store, &points) };
    for (k, point) in points.iter().enumerate() {
        // SAFETY: as above.
        let got = unsafe { read_point(&store, indices[k]) };
        assert!(got == coordinates(point), "point {k}");
    }
}

/// blst's Montgomery form of 2^64 is 2^64·2^384.
#[test]
fn two_pow_448_is_blst_montgomery_two_pow_64() {
    let mut two_pow_64 = blst_fp::default();
    // SAFETY: blst reads six words and writes one value.
    unsafe { blst_fp_from_uint64(&mut two_pow_64, [0, 1, 0, 0, 0, 0].as_ptr()) };
    assert!(unpack52(&two_pow_64.l) == TWO_POW_448_MOD_P);
}

/// Counts around the lane count, with signs at random, and σ.
#[test]
fn blst_points_convert_with_signs_and_sigma() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 4);
    for count in [1, 2, 7, 8, 9, 16, 17, 40] {
        for endomorphism in [false, true] {
            let points = random_points(&mut rng, count);
            let negated: Vec<bool> = (0..count).map(|_| rng.gen_bool(0.5)).collect();
            let mut store = PointStore::new();
            store.reset(count + 1);
            store.allocate();
            // SAFETY: `kernels_run` checked `simd_available`.
            unsafe { store.push_blst(&points, &negated, endomorphism) };
            assert!(store.len() == count + 1, "{count} points");
            for (k, point) in points.iter().enumerate() {
                let image = if endomorphism { times_lambda(point) } else { *point };
                let want = if negated[k] { negated_point(&image) } else { image };
                // SAFETY: as above.
                let got = unsafe { read_point(&store, k as u32 + 1) };
                assert!(got == coordinates(&want), "{count} points, σ {endomorphism}, point {k}");
            }
        }
    }
}

/// Pair counts around the group and chain sizes, signs at random, and half
/// the sums written over their first point, as a bucket round writes them.
#[test]
fn batched_adds_match_blst() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
    for pairs in [1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65, 257] {
        let points = random_points(&mut rng, 2 * pairs);
        let mut store = PointStore::new();
        store.reset(3 * pairs);
        // SAFETY: `kernels_run` checked `simd_available`.
        let indices = unsafe { push_points(&mut store, &points) };
        let mut adds = BatchedAdds::default();
        let mut expected = Vec::new();
        for i in 0..pairs {
            let (negate_a, negate_b) = (rng.gen_bool(0.5), rng.gen_bool(0.5));
            let sign = |negate: bool| if negate { NEGATED } else { 0 };
            let out = if i % 2 == 0 { store.allocate() } else { indices[2 * i] };
            adds.push(indices[2 * i] | sign(negate_a), indices[2 * i + 1] | sign(negate_b), out);
            let signed = |point: &blst_p1_affine, negate: bool| {
                if negate { negated_point(point) } else { *point }
            };
            let want =
                sum(&signed(&points[2 * i], negate_a), &signed(&points[2 * i + 1], negate_b));
            expected.push((out, want));
        }
        // SAFETY: as above.
        assert!(unsafe { adds.run(&mut store) }, "{pairs} pairs");
        for (k, (out, want)) in expected.iter().enumerate() {
            // SAFETY: as above.
            let got = unsafe { read_point(&store, *out) };
            assert!(got == coordinates(want), "{pairs} pairs, pair {k}");
        }
    }
}

/// A point added to itself or to its negation, in the first, a middle or the
/// last group: `run` fails and every output keeps its old point.
#[test]
fn equal_x_pairs_report_failure_and_write_nothing() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 2);
    for (pairs, at) in [(1, 0), (9, 8), (40, 0), (40, 21), (40, 39)] {
        for opposite in [false, true] {
            let points = random_points(&mut rng, 2 * pairs + 1);
            let mut store = PointStore::new();
            store.reset(3 * pairs + 1);
            // SAFETY: `kernels_run` checked `simd_available`.
            let indices = unsafe { push_points(&mut store, &points) };
            let sentinel = indices[2 * pairs];
            let mut adds = BatchedAdds::default();
            let mut outs = Vec::new();
            for i in 0..pairs {
                let b = if i == at {
                    indices[2 * i] | if opposite { NEGATED } else { 0 }
                } else {
                    indices[2 * i + 1]
                };
                let out = store.allocate();
                // SAFETY: as above.
                unsafe {
                    let (x, y) = store.load_points(&[sentinel; LANES]);
                    store.store_points(&[out; LANES], &x, &y);
                }
                adds.push(indices[2 * i], b, out);
                outs.push(out);
            }
            // SAFETY: as above.
            assert!(!unsafe { adds.run(&mut store) }, "{pairs} pairs, pair {at}, {opposite}");
            for out in outs {
                // SAFETY: as above.
                let got = unsafe { read_point(&store, out) };
                assert!(got == coordinates(&points[2 * pairs]), "{pairs} pairs, output {out}");
            }
        }
    }
}

#[test]
#[ignore = "timing; run with --ignored --nocapture"]
fn msm8_parts_timing() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 3);
    let pairs = 4096;
    let points = random_points(&mut rng, 2 * pairs);
    let mut store = PointStore::new();
    store.reset(3 * pairs);
    // SAFETY: `kernels_run` checked `simd_available`.
    let indices = unsafe { push_points(&mut store, &points) };
    let outs: Vec<u32> = (0..pairs).map(|_| store.allocate()).collect();
    let mut adds = BatchedAdds::default();
    let mut best = f64::MAX;
    for _ in 0..21 {
        adds.clear();
        for i in 0..pairs {
            adds.push(indices[2 * i], indices[2 * i + 1], outs[i]);
        }
        let start = Instant::now();
        // SAFETY: as above.
        assert!(unsafe { adds.run(&mut store) });
        best = best.min(start.elapsed().as_secs_f64());
    }
    println!("batched_adds: {pairs} pairs, best {:.1} ns per pair", best * 1e9 / pairs as f64);

    let unsigned = vec![false; points.len()];
    let mut best = f64::MAX;
    for _ in 0..21 {
        store.reset(points.len());
        let start = Instant::now();
        // SAFETY: as above.
        unsafe { store.push_blst(&points, &unsigned, false) };
        best = best.min(start.elapsed().as_secs_f64());
    }
    println!(
        "push_blst: {} points, best {:.1} ns per point",
        points.len(),
        best * 1e9 / points.len() as f64
    );

    let values: [Limbs; LANES] = std::array::from_fn(|l| plain(&points[l].x));
    let mut best = f64::MAX;
    for _ in 0..101 {
        let start = Instant::now();
        // SAFETY: as above.
        std::hint::black_box(unsafe { Fp8::from_plain(&values).inverse() });
        best = best.min(start.elapsed().as_secs_f64());
    }
    println!("Fp8::inverse: best {:.2} us per call of eight lanes", best * 1e6);
}
