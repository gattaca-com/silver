//! Cycles per pair for `hash_concat_many` against hashtree's own pick (SHA-NI
//! where the CPU has it). Both run interleaved on one pinned core.
//!
//!   cargo bench -p silver_hashing --bench hash_concat_many -- [core]
//!
//! For stable numbers, pick an isolated core (`isolcpus=`, `nohz_full=`) whose
//! SMT sibling is idle.

use std::{
    arch::x86_64::{_mm_lfence, _rdtsc},
    hint::black_box,
    time::{Duration, Instant},
};

use silver_hashing::{B256, merkle::hash_concat_many};

const SAMPLES: usize = 20_001;
const WARM_UP: Duration = Duration::from_millis(300);
/// Larger than the last-level cache, so `cold` inputs come from DRAM.
const COLD_BYTES: usize = 512 << 20;

fn main() {
    // `cargo bench` also passes `--bench`.
    let core = std::env::args().find_map(|a| a.parse().ok()).unwrap_or(2);
    pin(core);
    let ghz = tsc_ghz();
    let overhead = (0..SAMPLES).map(|_| timed(|| {})).min().unwrap();
    println!(
        "core {core}, TSC cycles per pair at {ghz:.3} GHz, timer overhead {overhead} subtracted"
    );
    println!(
        "{:>6} {:>5}   {:>23}   {:>23}   {:>7}",
        "pairs", "cache", "SHA-NI min/p50/p99", "split min/p50/p99", "p50 x"
    );

    // Written, so its pages are not all the shared zero page.
    let mut arena = vec![[0u8; 32]; COLD_BYTES / 32];
    for (i, chunk) in arena.iter_mut().enumerate() {
        chunk[..8].copy_from_slice(&(i as u64).to_le_bytes());
    }
    let row = |s: [f64; 3]| s.map(|c| format!("{c:>7.0}")).join(" ");
    for n in [1, 8, 15, 16, 17, 32, 64, 256, 1024, 16384] {
        for cold in [false, true] {
            let (sha_ni, split) = run(&arena, n, cold, overhead);
            let (a, b) = (stats(sha_ni, n), stats(split, n));
            let cache = if cold { "cold" } else { "hot" };
            println!("{n:>6} {cache:>5}   {}   {}   {:>6.2}x", row(a), row(b), a[1] / b[1]);
        }
    }
}

/// Per-call cycles for both kernels, alternating so drift hits both alike.
/// Hot reuses one input; cold jumps around the arena so neither the cache nor
/// the prefetcher holds the next input.
fn run(arena: &[B256], n: usize, cold: bool, overhead: u64) -> (Vec<u64>, Vec<u64>) {
    let mut out = vec![[0u8; 32]; n];
    let slots = if cold { arena.len() / (2 * n) } else { 1 };
    let input =
        |i: usize| &arena[(i.wrapping_mul(0x9e37_79b9_7f4a_7c15) % slots) * 2 * n..][..2 * n];

    let started = Instant::now();
    let mut i = 0;
    while started.elapsed() < WARM_UP {
        hash_concat_many(&mut out, input(i));
        sha_ni(&mut out, input(i + 1));
        i += 2;
    }

    let (mut a, mut b) = (Vec::with_capacity(SAMPLES), Vec::with_capacity(SAMPLES));
    for s in 0..SAMPLES {
        let (x, y) = (input(i + 2 * s), input(i + 2 * s + 1));
        a.push(timed(|| sha_ni(black_box(&mut out), x)).saturating_sub(overhead));
        b.push(timed(|| hash_concat_many(black_box(&mut out), y)).saturating_sub(overhead));
    }
    (a, b)
}

fn sha_ni(out: &mut [B256], pairs: &[B256]) {
    let n = out.len();
    hashtree_rs::hash(out.as_flattened_mut(), pairs.as_flattened(), n);
}

/// `lfence` on both sides keeps `f` from overlapping either `rdtsc`.
#[inline(always)]
fn timed(f: impl FnOnce()) -> u64 {
    unsafe {
        _mm_lfence();
        let start = _rdtsc();
        _mm_lfence();
        f();
        _mm_lfence();
        let end = _rdtsc();
        _mm_lfence();
        end - start
    }
}

/// min, p50, p99 in cycles per pair.
fn stats(mut cycles: Vec<u64>, n: usize) -> [f64; 3] {
    cycles.sort_unstable();
    let at = |q: f64| cycles[((cycles.len() - 1) as f64 * q) as usize] as f64 / n as f64;
    [at(0.0), at(0.5), at(0.99)]
}

fn tsc_ghz() -> f64 {
    let (t, c) = (Instant::now(), unsafe { _rdtsc() });
    while t.elapsed() < Duration::from_millis(200) {}
    (unsafe { _rdtsc() } - c) as f64 / t.elapsed().as_nanos() as f64
}

fn pin(core: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        assert_eq!(libc::sched_setaffinity(0, size_of_val(&set), &set), 0, "pin to core {core}");
    }
}
