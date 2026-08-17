//! Per-message attestation root derivation, memoized vs recomputed.
//!
//! Production shape: one tile thread, ~50k single attestations per slot
//! sharing D distinct AttestationData values (D is 1-3 honest, higher under
//! head splits).
//!
//! Run: cargo bench -p silver_beacon_state --bench attestation_root_memo

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use silver_beacon_state::{
    bls::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash::hash_attestation_data,
    tile::attestation_root_memo::AttestationRootMemo,
};
use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

const MESSAGES: usize = 50_000;

fn messages(distinct: usize) -> Vec<[u8; ATTESTATION_DATA_SIZE]> {
    (0..MESSAGES)
        .map(|i| {
            let mut d = [0u8; ATTESTATION_DATA_SIZE];
            d[..8].copy_from_slice(&100u64.to_le_bytes());
            d[16..24].copy_from_slice(&((i % distinct) as u64).to_le_bytes());
            d
        })
        .collect()
}

fn bench_root_derivation(c: &mut Criterion) {
    let domain = bls::compute_domain(DOMAIN_BEACON_ATTESTER, [0u8; 4], &[0u8; 32]);

    for distinct in [2usize, 64] {
        let msgs = messages(distinct);
        let mut group = c.benchmark_group(format!("root_derivation/50k_msgs/D={distinct}"));
        group.throughput(Throughput::Elements(MESSAGES as u64));

        group.bench_function("unmemoized", |b| {
            b.iter(|| {
                for m in &msgs {
                    let data_root = hash_attestation_data(black_box(m));
                    black_box(bls::compute_signing_root(&data_root, &domain));
                }
            })
        });

        group.bench_function("memoized", |b| {
            let mut memo = AttestationRootMemo::default();
            b.iter(|| {
                for m in &msgs {
                    black_box(memo.roots(black_box(m), &domain));
                }
            })
        });

        group.finish();
    }
}

criterion_group!(benches, bench_root_derivation);
criterion_main!(benches);
