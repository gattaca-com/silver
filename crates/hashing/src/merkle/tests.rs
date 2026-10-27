use std::{hint::black_box, time::Instant};

use rand::{Rng, SeedableRng, rngs::StdRng};

use super::{AVX512_GROUP, B256, HASHTREE_READY, hash_concat_many};

fn random_pairs(rng: &mut StdRng, n: usize) -> Vec<B256> {
    (0..2 * n).map(|_| rng.r#gen()).collect()
}

#[test]
fn hash_concat_many_matches_sha256() {
    let mut rng = StdRng::seed_from_u64(7);
    let sizes = (0..=3 * AVX512_GROUP + 1).chain([100, 1000, 4096 + 5]);
    for n in sizes {
        let pairs = random_pairs(&mut rng, n);
        let mut out = vec![[0u8; 32]; n];
        hash_concat_many(&mut out, &pairs);
        for (i, digest) in out.iter().enumerate() {
            let expected = sha2_const_stable::Sha256::new()
                .update(&pairs[2 * i])
                .update(&pairs[2 * i + 1])
                .finalize();
            assert_eq!(*digest, expected, "{n} pairs, pair {i}");
        }
    }
}

fn best_nanos_per_pair(reps: usize, n: usize, mut f: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..reps {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed().as_nanos() as f64);
    }
    best / n as f64
}

/// Not a check: times `hash_concat_many` against hashtree's own pick, which
/// is SHA-NI on any CPU that has it.
///
///   cargo test --release -p silver_hashing --lib -- --ignored --nocapture
/// hash_concat_many_timing
#[test]
#[ignore]
fn hash_concat_many_timing() {
    assert!(*HASHTREE_READY, "this CPU lacks SHA-NI or AVX-512, so nothing changes");
    let mut rng = StdRng::seed_from_u64(7);
    let max = 1 << 16;
    let pairs = random_pairs(&mut rng, max);
    let mut out = vec![[0u8; 32]; max];
    // An idle core runs the first few hundred milliseconds below full clock.
    let started = Instant::now();
    while started.elapsed().as_millis() < 500 {
        hash_concat_many(black_box(&mut out), &pairs);
    }

    println!("{:>8} {:>16} {:>16} {:>8}", "pairs", "hashtree ns/pair", "split ns/pair", "speedup");
    for n in [1, 8, 15, 16, 17, 32, 64, 256, 1024, 1 << 16] {
        let reps = (1 << 22) / n.max(64);
        let in_bytes = pairs[..2 * n].as_flattened();
        let mut out_bytes = vec![0u8; 32 * n];
        let hashtree = best_nanos_per_pair(reps, n, || {
            hashtree_rs::hash(black_box(&mut out_bytes), in_bytes, n)
        });
        let split = best_nanos_per_pair(reps, n, || {
            hash_concat_many(black_box(&mut out[..n]), &pairs[..2 * n])
        });
        println!("{n:>8} {hashtree:>16.1} {split:>16.1} {:>7.2}x", hashtree / split);
    }
}
