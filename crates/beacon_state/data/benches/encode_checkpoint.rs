//! Benchmark the canonical SSZ encode of a mainnet checkpoint state into a
//! warm buffer — the CPU half of the streamed checkpoint persist.
//! The durable-write half lives in `silver_storage`'s
//! `checkpoint_persist_bench`, which drives the real
//! `Store::persist_finalized_checkpoint`.
//!
//! Needs the ~312 MiB mainnet fixture (gitignored):
//!   make -C crates/e2e checkpoint-fixtures
//! Override the state path with SILVER_CHECKPOINT_SSZ.
//!
//! Run: cargo bench -p silver_beacon_state_data --bench encode_checkpoint

use std::{fs, hint::black_box, path::PathBuf};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use silver_beacon_state_data::{BeaconState, SpecConfig};

fn fixture_path() -> PathBuf {
    std::env::var("SILVER_CHECKPOINT_SSZ").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../e2e/tests/example_checkpoints/finalized_state.ssz")
    })
}

fn bench(c: &mut Criterion) {
    let path = fixture_path();
    let Ok(ssz) = fs::read(&path) else {
        eprintln!(
            "skipping: fixture {} not present (make -C crates/e2e checkpoint-fixtures)",
            path.display()
        );
        return;
    };

    let bs = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).expect("decompose");
    let len = bs.ssz_len();
    assert_eq!(len, ssz.len(), "round-trip length mismatch");
    eprintln!("encoded size: {len} bytes ({} MiB)", len >> 20);

    let mut group = c.benchmark_group("checkpoint");
    group.throughput(Throughput::Bytes(len as u64));

    let mut buf = Vec::with_capacity(len);
    group.bench_function("encode_ssz", |b| {
        b.iter(|| {
            buf.clear();
            bs.encode_ssz(&mut buf).unwrap();
            black_box(buf.len())
        });
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
