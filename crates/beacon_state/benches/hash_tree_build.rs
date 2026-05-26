//! Benchmark `FinalizedHashTree::new` (the production constructor) across
//! realistic leaf counts and capacities. The hash primitive is whatever
//! `silver_common::ssz_hash::hash_concat` resolves to — currently `hashtree`.
//!
//! Run: cargo bench -p silver_beacon_state --bench hash_tree_build

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use silver_beacon_state::{hash_tree::FinalizedHashTree, types::B256};

fn random_leaves(n: usize, seed: u64) -> Vec<B256> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n)
        .map(|_| {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            b
        })
        .collect()
}

fn bench_build(c: &mut Criterion) {
    // (label, leaf_count, capacity_hint)
    let cases: &[(&str, usize, usize)] = &[
        ("sparse_1k_in_1m", 1_000, 1 << 20),
        ("dense_1m", 1 << 20, 1 << 20),
        ("dense_2m", 2 * (1 << 20), 2 * (1 << 20)),
        ("sparse_2m_in_16m", 2 * (1 << 20), 16 * (1 << 20)),
    ];

    let mut group = c.benchmark_group("FinalizedHashTree::new");
    for &(label, n, cap) in cases {
        let leaves = random_leaves(n, 0xC0FFEE);
        group.throughput(Throughput::Elements(cap as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &leaves, |b, l| {
            b.iter(|| FinalizedHashTree::new(black_box(l), cap));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_build);
criterion_main!(benches);

/*
Results with other sha256 libs
┌──────────────────────────────┬───────────────────┬──────────┬───────────────────┬──────────────────┬─────────────────┐
│ Case (max_elements / leaves) │              ring │   sha2   │ hashtree per-pair │ hashtree batched │ speedup vs ring │
├──────────────────────────────┼───────────────────┼──────────┼───────────────────┼──────────────────┼─────────────────┤
│ sparse_1k_in_1m (1M / 1k)    │          11.11 ms │ 11.09 ms │          11.19 ms │         11.02 ms │          ~1.00× │
├──────────────────────────────┼───────────────────┼──────────┼───────────────────┼──────────────────┼─────────────────┤
│ dense_1m (1M / 1M)           │          102.9 ms │  67.4 ms │          47.98 ms │         42.03 ms │           2.45× │
├──────────────────────────────┼───────────────────┼──────────┼───────────────────┼──────────────────┼─────────────────┤
│ dense_2m (2M / 2M)           │          206.2 ms │ 135.2 ms │          96.04 ms │         83.81 ms │           2.46× │
├──────────────────────────────┼───────────────────┼──────────┼───────────────────┼──────────────────┼─────────────────┤
│ sparse_2m_in_16m (16M / 2M)  │          366.8 ms │ 302.9 ms │          265.7 ms │         258.4 ms │           1.42× │
└──────────────────────────────┴───────────────────┴──────────┴───────────────────┴──────────────────┴─────────────────┘
*/
