use std::time::Instant;

use blst::{
    blst_fp, blst_fp_from_uint64, blst_p1, blst_p1_add_or_double, blst_p1_add_or_double_affine,
    blst_p1_cneg, blst_p1_double, blst_p1_from_affine, blst_p1_generator, blst_p1_is_equal,
    blst_p1_is_inf, blst_p1_mult, blst_p1_to_affine, blst_p1s_mult_pippenger,
    blst_p1s_mult_pippenger_scratch_sizeof, blst_uint64_from_fp, limb_t,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    bls::{
        blst_p1_affine,
        constants::TWO_POW_448_MOD_P,
        fp8::{Fp8, LANES, Limbs, unpack52},
        g1x8::G1x8,
        msm8::{
            Msm8,
            buckets::Buckets,
            lane_zero_in_blst,
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

fn random_scalars(rng: &mut ChaCha8Rng, n: usize) -> Vec<[u64; 4]> {
    (0..n)
        .map(|_| {
            let mut words: [u64; 4] = rng.r#gen();
            words[3] >>= 1;
            words
        })
        .collect()
}

/// Σ scalars[i]·points[i] by blst, one multiplication per point.
fn lincomb(points: &[blst_p1_affine], scalars: &[[u64; 4]]) -> blst_p1 {
    let mut total = blst_p1::default();
    for (point, scalar) in points.iter().zip(scalars) {
        let bytes: Vec<u8> = scalar.iter().flat_map(|word| word.to_le_bytes()).collect();
        let (mut projective, mut term) = (blst_p1::default(), blst_p1::default());
        // SAFETY: valid pointers to single values, and blst reads 255 bits of the
        // 32-byte scalar.
        unsafe {
            blst_p1_from_affine(&mut projective, point);
            blst_p1_mult(&mut term, &projective, bytes.as_ptr(), 255);
            let before = total;
            blst_p1_add_or_double(&mut total, &before, &term);
        }
    }
    total
}

/// The same point, z = 0 exactly when it is infinity.
fn assert_same_point(got: &blst_p1, want: &blst_p1, case: &str) {
    // SAFETY: valid pointers to single values.
    let (got_infinite, want_infinite, equal) =
        unsafe { (blst_p1_is_inf(got), blst_p1_is_inf(want), blst_p1_is_equal(got, want)) };
    assert!(got_infinite == want_infinite && equal, "{case}");
}

fn assert_msm_matches(msm: &mut Msm8, points: &[blst_p1_affine], scalars: &[[u64; 4]], case: &str) {
    // SAFETY: the callers checked `kernels_run`.
    let got = unsafe { msm.msm(points, scalars) };
    assert_same_point(&got, &lincomb(points, scalars), case);
}

/// Sizes around every window width and lane count, a tenth of the points at
/// infinity, and scalars up to 2^255 − 1. One `Msm8` serves every size.
#[test]
fn msm_matches_blst() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 5);
    let mut msm = Msm8::default();
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

/// Digits at the edges of each window width: every window at 2^(w−1), where
/// a digit stays positive, and at 2^(w−1) + 1, where it turns negative and
/// carries; and 0, 1, r − 1 and 2^255 − 1.
#[test]
fn msm_matches_blst_at_digit_edges() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 6);
    let mut msm = Msm8::default();
    let r_minus_1 = [
        0xffff_ffff_0000_0000,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];
    for (n, window_bits) in [(20, 4), (100, 6), (520, 8)] {
        let windows_value = |digit: u128| {
            let mut value = [0u64; 4];
            let mut bit = 0;
            while bit + window_bits < 255 {
                for k in 0..window_bits {
                    if (digit >> k) & 1 == 1 {
                        value[(bit + k) / 64] |= 1 << ((bit + k) % 64);
                    }
                }
                bit += window_bits;
            }
            value
        };
        let half = 1u128 << (window_bits - 1);
        let edges =
            [windows_value(half), windows_value(half + 1), [0; 4], [1, 0, 0, 0], r_minus_1, [
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX >> 1,
            ]];
        let points = random_points(&mut rng, n);
        let scalars: Vec<[u64; 4]> = (0..n).map(|i| edges[i % edges.len()]).collect();
        assert_msm_matches(&mut msm, &points, &scalars, &format!("{window_bits}-bit windows"));
    }
}

/// Equal points fail the batched rounds, so the refilled buckets are summed
/// point by point; opposite points with equal scalars cancel.
#[test]
fn msm_matches_blst_with_repeated_and_opposite_points() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 7);
    let mut msm = Msm8::default();
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
        // SAFETY: `kernels_run` checked `simd_available`.
        let got = unsafe { msm.msm(&points, &scalars) };
        assert_same_point(&got, &blst_p1::default(), &format!("{n} points and their negations"));
        points.push(originals[0]);
        scalars.push([3, 0, 0, 0]);
        assert_msm_matches(&mut msm, &points, &scalars, &format!("{n} cancelling, one left"));
    }
}

/// Distinct points never share x, so every batched round succeeds, which is
/// what makes `Msm8` fast; the buckets left then sum to blst's result.
#[test]
fn rounds_on_distinct_points_succeed() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 11);
    for n in [9, 70, 520] {
        let points = random_points(&mut rng, n);
        let scalars = random_scalars(&mut rng, n);
        let mut buckets = Buckets::default();
        buckets.fill(&scalars);
        let mut store = PointStore::new();
        store.reset(n + buckets.windows() * (n / 2));
        let mut adds = BatchedAdds::default();
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe { store.push_blst(&points, &vec![false; n], false) };
        buckets.queue_round(&mut adds, &mut store, n);
        let mut rounds = 0;
        while !adds.is_empty() {
            // SAFETY: as above.
            assert!(unsafe { adds.run(&mut store) }, "{n} points, round {rounds}");
            buckets.queue_round(&mut adds, &mut store, n);
            rounds += 1;
        }
        assert!(rounds > 0, "{n} points");
        // SAFETY: as above.
        let got = unsafe { lane_zero_in_blst(&buckets.sum(&store)) };
        assert_same_point(&got, &lincomb(&points, &scalars), &format!("{n} points"));
    }
}

#[test]
fn msm_of_nothing_is_infinity() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 8);
    let mut msm = Msm8::default();
    let points = random_points(&mut rng, 70);
    let infinities = vec![blst_p1_affine::default(); 70];
    let scalars = random_scalars(&mut rng, 70);
    // SAFETY: `kernels_run` checked `simd_available`.
    let sums = unsafe {
        [msm.msm(&[], &[]), msm.msm(&points, &vec![[0; 4]; 70]), msm.msm(&infinities, &scalars)]
    };
    for (k, sum) in sums.iter().enumerate() {
        assert_same_point(sum, &blst_p1::default(), &format!("case {k}"));
    }
}

/// Σ scalars[i]·points[i] by blst's Pippenger, as the verifier's
/// `g1_lincomb` calls it.
fn pippenger(
    points: &[blst_p1_affine],
    scalars: &[[u8; 32]],
    scratch: &mut Vec<limb_t>,
) -> blst_p1 {
    // SAFETY: a pure size query.
    let bytes = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(points.len()) };
    scratch.resize(bytes.div_ceil(size_of::<limb_t>()), 0);
    let points_arg = [points.as_ptr(), std::ptr::null()];
    let scalars_arg = [scalars.as_ptr().cast::<u8>(), std::ptr::null()];
    let mut out = blst_p1::default();
    // SAFETY: `points` and `scalars` hold the same number of values, and `scratch`
    // holds at least the size blst asked for.
    unsafe {
        blst_p1s_mult_pippenger(
            &mut out,
            points_arg.as_ptr(),
            points.len(),
            scalars_arg.as_ptr(),
            255,
            scratch.as_mut_ptr(),
        );
    }
    out
}

/// The verifier's sizes at 18 blobs: 18 for 1 column, 64 setup points, 2304
/// for 128 columns.
#[test]
#[ignore = "timing; run with --ignored --nocapture"]
fn msm8_timing() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 9);
    let mut msm = Msm8::default();
    let mut scratch = Vec::new();
    for n in [18, 64, 2304] {
        let points = random_points(&mut rng, n);
        let scalars = random_scalars(&mut rng, n);
        let bytes: Vec<[u8; 32]> = scalars
            .iter()
            .map(|words| std::array::from_fn(|k| words[k / 8].to_le_bytes()[k % 8]))
            .collect();
        // SAFETY: as above.
        let checked = unsafe { msm.msm(&points, &scalars) };
        assert_same_point(&checked, &pippenger(&points, &bytes, &mut scratch), "timed inputs");
        let (mut ours, mut theirs) = (f64::MAX, f64::MAX);
        for _ in 0..11 {
            let start = Instant::now();
            // SAFETY: as above.
            std::hint::black_box(unsafe { msm.msm(&points, &scalars) });
            ours = ours.min(start.elapsed().as_secs_f64());
            let start = Instant::now();
            std::hint::black_box(pippenger(&points, &bytes, &mut scratch));
            theirs = theirs.min(start.elapsed().as_secs_f64());
        }
        println!(
            "msm {n}: Msm8 best {:.1} us, blst Pippenger best {:.1} us",
            ours * 1e6,
            theirs * 1e6
        );
    }
}

/// The final combination of the window sums, Σ_j [2^(w·j)] S_j, as
/// `Buckets::sum` runs it after the window sums, against blst's doublings
/// and additions on one point.
#[test]
#[ignore = "timing; run with --ignored --nocapture"]
fn window_combination_timing() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 10);
    for window_bits in [4, 6, 8] {
        let windows = 255 / window_bits + 1;
        let groups = (windows - 1) / LANES + 1;
        let sums: Vec<blst_p1> = random_points(&mut rng, groups * LANES)
            .iter()
            .map(|point| {
                let mut projective = blst_p1::default();
                // SAFETY: valid pointers to single values.
                unsafe { blst_p1_from_affine(&mut projective, point) };
                projective
            })
            .collect();
        let vectors: Vec<G1x8> = sums
            .chunks(LANES)
            // SAFETY: as above.
            .map(|chunk| unsafe { jacobian_lanes(chunk.try_into().unwrap()) })
            .collect();
        let (mut ours, mut theirs) = (f64::MAX, f64::MAX);
        for _ in 0..21 {
            let start = Instant::now();
            // SAFETY: as above.
            std::hint::black_box(unsafe { combine(&vectors, window_bits) });
            ours = ours.min(start.elapsed().as_secs_f64());
            let start = Instant::now();
            let mut total = blst_p1::default();
            for sum in sums[..windows].iter().rev() {
                // SAFETY: valid pointers to single values.
                unsafe {
                    for _ in 0..window_bits {
                        let before = total;
                        blst_p1_double(&mut total, &before);
                    }
                    let before = total;
                    blst_p1_add_or_double(&mut total, &before, sum);
                }
            }
            std::hint::black_box(total);
            theirs = theirs.min(start.elapsed().as_secs_f64());
        }
        println!(
            "combination, {window_bits}-bit windows: G1x8 best {:.1} us, blst best {:.1} us",
            ours * 1e6,
            theirs * 1e6
        );
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn jacobian_lanes(points: &[blst_p1; LANES]) -> G1x8 {
    G1x8 {
        x: Fp8::from_plain(&points.map(|point| plain(&point.x))),
        y: Fp8::from_plain(&points.map(|point| plain(&point.y))),
        z: Fp8::from_plain(&points.map(|point| plain(&point.z))),
    }
}

/// `Buckets::sum`'s steps after the window sums.
#[target_feature(enable = "avx512f,avx512ifma")]
fn combine(vectors: &[G1x8], window_bits: usize) -> G1x8 {
    let top = &vectors[vectors.len() - 1];
    let mut total = G1x8 { x: top.x, y: top.y, z: top.z };
    for vector in vectors[..vectors.len() - 1].iter().rev() {
        total = total.times_two_pow(LANES * window_bits).add_complete(vector);
    }
    total.sum_lanes_shifted(window_bits)
}
