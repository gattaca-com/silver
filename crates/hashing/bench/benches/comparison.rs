//! `SharedList` compared with `milhouse::List` and `ssz::PersistentList` on a
//! mainnet-sized list. Each write scenario starts from a clone of a hashed
//! list and times the writes plus the new root.
//!
//! `ssz::PersistentList` hashes single-threaded. It uses the 64-value bundle
//! its client uses for balances, not the 4-value default.

use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::index};
use rayon::{ThreadPool, ThreadPoolBuilder};
use silver_state_hashing::{B256, HashFormat, SharedList, TreeSpec};
use ssz::{PersistentList, SszHash, SszListMut};
use tree_hash::TreeHash;
use try_from_iterator::TryFromIterator;
use typenum::{U64, U1099511627776};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const LEN: usize = 2_300_000;
const ACTIVE: usize = 900_000;
const BLOCK_WRITES: usize = 500;
const HEAVY_BLOCK_WRITES: usize = 2_000;

struct Balances;

impl TreeSpec for Balances {
    type Val = u64;
    type Page = [B256; 128];
    const SSZ_LIMIT: usize = 1 << 40;
}

type Shared = SharedList<Balances>;
type Milhouse = milhouse::List<u64, U1099511627776>;
type Persistent = PersistentList<u64, U1099511627776, U64>;

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
    fn all<L: Candidate>() -> Vec<Self> {
        if L::RAYON_THREADS.is_empty() {
            return vec![Self { name: L::NAME.to_owned(), pool: None }];
        }
        L::RAYON_THREADS
            .iter()
            .map(|&threads| {
                let unit = if threads == 1 { "thread" } else { "threads" };
                let pool = ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
                Self { name: format!("{}_{threads}_{unit}", L::NAME), pool: Some(pool) }
            })
            .collect()
    }

    fn run<R: Send>(&self, f: impl FnOnce() -> R + Send) -> R {
        match &self.pool {
            Some(pool) => pool.install(f),
            None => f(),
        }
    }
}

trait Candidate: Clone + Send + Sync {
    const NAME: &str;
    /// Empty for a library without a parallel hashing path: it runs on the
    /// bench thread.
    const RAYON_THREADS: &[usize] = &[];

    fn build(vals: &[u64]) -> Self;

    fn write_and_hash(&mut self, indices: &[usize]) -> [u8; 32];

    fn sum(&self) -> u64;
}

impl Candidate for Shared {
    const NAME: &str = "silver_state_hashing";

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

impl Candidate for Milhouse {
    const NAME: &str = "milhouse";
    const RAYON_THREADS: &[usize] = &[1, 16];

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

impl Candidate for Persistent {
    const NAME: &str = "persistent_list";

    fn build(vals: &[u64]) -> Self {
        let list = Self::try_from_iter(vals.iter().copied()).unwrap();
        list.hash_tree_root();
        list
    }

    fn write_and_hash(&mut self, indices: &[usize]) -> [u8; 32] {
        for &i in indices {
            *self.get_mut(i as u64).unwrap() += 1;
        }
        self.hash_tree_root().0
    }

    fn sum(&self) -> u64 {
        self.into_iter().sum()
    }
}

/// Panics instead of benchmarking a tree that differs from ours.
fn assert_roots_match<L: Candidate>(registry: &Registry) {
    let block = registry.random_block(0, BLOCK_WRITES);
    let mut ours = Shared::build(&registry.balances);
    let mut theirs = L::build(&registry.balances);
    assert_eq!(theirs.write_and_hash(&[]), ours.write_and_hash(&[]), "{}: build root", L::NAME);
    assert_eq!(
        theirs.write_and_hash(&block),
        ours.write_and_hash(&block),
        "{}: 500 writes",
        L::NAME
    );
}

fn bench_build<L: Candidate>(c: &mut Criterion, registry: &Registry, runner: &Runner) {
    let vals = &registry.balances;
    c.benchmark_group("build")
        .sample_size(10)
        .bench_function(&runner.name, |b| b.iter(|| runner.run(|| L::build(vals))));
}

fn bench_iter<L: Candidate>(c: &mut Criterion, registry: &Registry, runner: &Runner) {
    let head = runner.run(|| L::build(&registry.balances));
    c.benchmark_group("iter_all")
        .sample_size(10)
        .bench_function(&runner.name, |b| b.iter(|| head.sum()));
}

fn bench_writes<L: Candidate>(
    c: &mut Criterion,
    registry: &Registry,
    runner: &Runner,
    group: &str,
    indices: &[usize],
) {
    let head = runner.run(|| L::build(&registry.balances));
    c.benchmark_group(group).sample_size(10).bench_function(&runner.name, |b| {
        b.iter_batched(
            || head.clone(),
            |mut list| runner.run(|| list.write_and_hash(indices)),
            BatchSize::LargeInput,
        )
    });
}

/// Times a block on branch B right after one on branch A, both `depth` blocks
/// past a common ancestor.
fn bench_reorg<L: Candidate>(
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

fn bench_all<L: Candidate>(c: &mut Criterion, registry: &Registry) {
    assert_roots_match::<L>(registry);

    let block = registry.random_block(0, BLOCK_WRITES);
    let heavy_block = registry.random_block(1, HEAVY_BLOCK_WRITES);
    let runners = Runner::all::<L>();

    // Iteration is sequential everywhere, so one runner suffices.
    bench_iter::<L>(c, registry, &runners[0]);
    for runner in &runners {
        bench_build::<L>(c, registry, runner);
        for (group, indices) in [
            ("write_500_random", &block),
            ("write_2000_random", &heavy_block),
            ("write_all_active", &registry.active),
        ] {
            bench_writes::<L>(c, registry, runner, group, indices);
        }
        for depth in [1, 4, 32] {
            bench_reorg::<L>(c, registry, runner, depth);
        }
    }
}

fn mainnet(c: &mut Criterion) {
    let registry = Registry::mainnet();
    bench_all::<Shared>(c, &registry);
    bench_all::<Milhouse>(c, &registry);
    bench_all::<Persistent>(c, &registry);
}

criterion_group!(benches, mainnet);
criterion_main!(benches);
