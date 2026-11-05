//! `SharedList` compared with `milhouse::List` on a mainnet-sized list. Each
//! write scenario starts from a clone of a hashed list and times the writes
//! plus the new root.

use std::{
    slice,
    time::{Duration, Instant},
};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::index};
use rayon::{ThreadPool, ThreadPoolBuilder};
use silver_state_hashing::{B256, HashFormat, SharedList, TreeSpec};
use tree_hash::TreeHash;
use typenum::U1099511627776;

// Keeps freed memory warm for both. Under glibc, whether a build reuses
// freed pages depends on run order.
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const LEN: usize = 2_300_000;
const ACTIVE: usize = 900_000;
const BLOCK_WRITES: usize = 500;
const HEAVY_BLOCK_WRITES: usize = 2_000;
const MILHOUSE_THREADS: [usize; 2] = [1, 16];

struct Balances;

impl TreeSpec for Balances {
    type Val = u64;
    type Page = [B256; 128];
    const SSZ_LIMIT: usize = 1 << 40;
}

type Milhouse = milhouse::List<u64, U1099511627776>;
type Shared = SharedList<Balances>;

struct Registry {
    balances: Vec<u64>,
    active: Vec<usize>,
}

impl Registry {
    fn mainnet() -> Self {
        let mut rng = StdRng::seed_from_u64(0);
        let mut active = index::sample(&mut rng, LEN, ACTIVE).into_vec();
        active.sort_unstable();

        let mut balances = vec![0; LEN];
        for &i in &active {
            balances[i] = 32_000_000_000 + i as u64;
        }
        Self { balances, active }
    }

    fn random_blocks(&self, seed: u64, count: usize, writes: usize) -> Vec<Vec<usize>> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..count)
            .map(|_| {
                (0..writes).map(|_| self.active[rng.gen_range(0..self.active.len())]).collect()
            })
            .collect()
    }

    fn random_block(&self, seed: u64, writes: usize) -> Vec<usize> {
        self.random_blocks(seed, 1, writes).pop().unwrap()
    }
}

struct Runner {
    name: String,
    pool: Option<ThreadPool>,
}

impl Runner {
    fn milhouse(threads: usize) -> Self {
        let unit = if threads == 1 { "thread" } else { "threads" };
        let pool = ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
        Self { name: format!("milhouse_{threads}_{unit}"), pool: Some(pool) }
    }

    fn silver() -> Self {
        Self { name: "silver_state_hashing".to_owned(), pool: None }
    }

    fn run<R: Send>(&self, f: impl FnOnce() -> R + Send) -> R {
        match &self.pool {
            Some(pool) => pool.install(f),
            None => f(),
        }
    }
}

struct Runners {
    milhouse: [Runner; MILHOUSE_THREADS.len()],
    silver: Runner,
}

impl Runners {
    fn new() -> Self {
        Self { milhouse: MILHOUSE_THREADS.map(Runner::milhouse), silver: Runner::silver() }
    }
}

trait Candidate: Clone + Send + Sync {
    fn runners(runners: &Runners) -> &[Runner];

    fn build(vals: &[u64]) -> Self;

    fn write_and_hash(&mut self, indices: &[usize]) -> [u8; 32];

    fn sum(&self) -> u64;
}

impl Candidate for Milhouse {
    fn runners(runners: &Runners) -> &[Runner] {
        &runners.milhouse
    }

    fn build(vals: &[u64]) -> Self {
        let list = Self::try_from_iter(vals.iter().copied()).unwrap();
        list.tree_hash_root();
        list
    }

    fn write_and_hash(&mut self, indices: &[usize]) -> [u8; 32] {
        for &i in indices {
            *self.get_mut(i).unwrap() += 1;
        }
        self.apply_updates().unwrap();
        self.tree_hash_root().0
    }

    fn sum(&self) -> u64 {
        self.iter().sum()
    }
}

impl Candidate for Shared {
    fn runners(runners: &Runners) -> &[Runner] {
        slice::from_ref(&runners.silver)
    }

    fn build(vals: &[u64]) -> Self {
        Self::new(vals, HashFormat::Fixed).unwrap()
    }

    fn write_and_hash(&mut self, indices: &[usize]) -> [u8; 32] {
        for &i in indices {
            self.set(i, self.get(i).unwrap() + 1).unwrap();
        }
        self.commit();
        self.hash_root()
    }

    fn sum(&self) -> u64 {
        self.iter().sum()
    }
}

fn bench_build<L: Candidate>(c: &mut Criterion, registry: &Registry, runners: &Runners) {
    let vals = &registry.balances;
    for runner in L::runners(runners) {
        c.benchmark_group("build")
            .sample_size(10)
            .bench_function(&runner.name, |b| b.iter(|| runner.run(|| L::build(vals))));
    }
}

/// Iteration is sequential on both sides, so only the first runner is timed.
fn bench_iter<L: Candidate>(c: &mut Criterion, registry: &Registry, runners: &Runners) {
    let runner = &L::runners(runners)[0];
    let head = runner.run(|| L::build(&registry.balances));
    c.benchmark_group("iter_all")
        .sample_size(10)
        .bench_function(&runner.name, |b| b.iter(|| head.sum()));
}

fn bench_writes<L: Candidate>(
    c: &mut Criterion,
    registry: &Registry,
    runners: &Runners,
    group: &str,
    indices: &[usize],
) {
    for runner in L::runners(runners) {
        let head = runner.run(|| L::build(&registry.balances));
        c.benchmark_group(group).sample_size(10).bench_function(&runner.name, |b| {
            b.iter_batched(
                || head.clone(),
                |mut list| runner.run(|| list.write_and_hash(indices)),
                BatchSize::LargeInput,
            )
        });
    }
}

fn bench_reorg<L: Candidate>(
    c: &mut Criterion,
    registry: &Registry,
    runners: &Runners,
    depth: usize,
) {
    for runner in L::runners(runners) {
        bench_reorg_on::<L>(c, registry, runner, depth);
    }
}

/// Times a block on branch B right after one on branch A, both `depth` blocks
/// past a common ancestor.
fn bench_reorg_on<L: Candidate>(
    c: &mut Criterion,
    registry: &Registry,
    runner: &Runner,
    depth: usize,
) {
    let base = runner.run(|| L::build(&registry.balances));
    let extend = |seed| {
        let mut head = base.clone();
        for block in registry.random_blocks(seed, depth, BLOCK_WRITES) {
            runner.run(|| head.write_and_hash(&block));
        }
        head
    };
    let (head_a, head_b) = (extend(2), extend(3));
    let next = registry.random_block(4, BLOCK_WRITES);

    let group = format!("reorg_depth_{depth}");
    c.benchmark_group(group).sample_size(10).bench_function(&runner.name, |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut on_a = head_a.clone();
                runner.run(|| on_a.write_and_hash(&next));

                let mut on_b = head_b.clone();
                let start = Instant::now();
                runner.run(|| on_b.write_and_hash(&next));
                total += start.elapsed();
            }
            total
        })
    });
}

fn mainnet(c: &mut Criterion) {
    let registry = Registry::mainnet();
    let runners = Runners::new();

    bench_build::<Milhouse>(c, &registry, &runners);
    bench_build::<Shared>(c, &registry, &runners);

    bench_iter::<Milhouse>(c, &registry, &runners);
    bench_iter::<Shared>(c, &registry, &runners);

    let one = [registry.active[registry.active.len() / 2]];
    let block = registry.random_block(0, BLOCK_WRITES);
    let heavy_block = registry.random_block(1, HEAVY_BLOCK_WRITES);
    for (group, indices) in [
        ("write_1", &one[..]),
        ("write_500_random", &block),
        ("write_2000_random", &heavy_block),
        ("write_all_active", &registry.active),
    ] {
        bench_writes::<Milhouse>(c, &registry, &runners, group, indices);
        bench_writes::<Shared>(c, &registry, &runners, group, indices);
    }

    for depth in [1, 8, 32] {
        bench_reorg::<Milhouse>(c, &registry, &runners, depth);
        bench_reorg::<Shared>(c, &registry, &runners, depth);
    }
}

criterion_group!(benches, mainnet);
criterion_main!(benches);
