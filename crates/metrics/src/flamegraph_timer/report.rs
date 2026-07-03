//! Per-path stats over drained `#[timed]` call paths. Each path is a measured
//! timed-frame chain, so a child's time is contained in its parent's.

use flux::timing::Nanos;
use rustc_hash::FxHashMap;

use crate::{
    Schema,
    flamegraph_timer::{
        aggregator::CallStackSamples, call_tree, counters::Counters, names::leaf_name,
    },
};

pub(super) struct PathStat {
    pub(super) path: Vec<u64>,
    pub(super) metrics: PathMetrics,
}

#[derive(serde::Serialize)]
pub(super) struct PathMetrics {
    pub(super) count: u64,
    tracked_avg_ns: Nanos,
    tracked_p50_ns: Nanos,
    tracked_p99_ns: Nanos,
    tracked_max_ns: Nanos,
    pub(super) tracked_sum_ns: Nanos,
    pub(super) total_untracked_ns: Nanos,
    /// Summed counter deltas (perf, alloc bytes) over all calls on this path;
    /// `untracked` excludes timed children, like `total_untracked_ns`. A
    /// dimension is all-zero unless its feature was built (and, for perf,
    /// `perf_event_open` permitted).
    pub(super) tracked: Counters,
    pub(super) untracked: Counters,
}

impl PathMetrics {
    fn from_samples(samples: CallStackSamples) -> Self {
        let mut times = samples.tracked_ns;
        times.sort_unstable();
        let count = times.len() as u64;
        let sum: u128 = times.iter().map(|&x| x as u128).sum();
        Self {
            count,
            tracked_avg_ns: if count > 0 {
                Nanos((sum / count as u128) as u64)
            } else {
                Nanos::ZERO
            },
            tracked_p50_ns: Nanos(percentile(&times, 0.50)),
            tracked_p99_ns: Nanos(percentile(&times, 0.99)),
            tracked_max_ns: Nanos(times.last().copied().unwrap_or(0)),
            tracked_sum_ns: Nanos(u64::try_from(sum).unwrap_or(u64::MAX)),
            total_untracked_ns: Nanos(samples.total_untracked_ns),
            tracked: samples.tracked,
            untracked: samples.total_untracked,
        }
    }
}

#[derive(serde::Serialize)]
struct PathStatJson<'a> {
    path: String,
    #[serde(flatten)]
    metrics: &'a PathMetrics,
}

/// A fold's render/match labels: frame-id → resolved name, and the perf event
/// vocabulary the counter samples are positional in.
#[derive(Clone)]
pub(crate) struct FlamegraphMeta {
    pub names: FxHashMap<u64, String>,
    pub schema: Schema,
}

/// How much of a thread's stream was lost: `missed` events were overwritten
/// in a ring before the reader drained them (producer outran reader), and
/// `dropped` drained closes were discarded because a gap took their open.
/// The gaps themselves are retained as `<missed>` frames.
#[derive(Clone, Copy, Default)]
pub(crate) struct Loss {
    pub(crate) missed: u64,
    pub(crate) dropped: u64,
}

impl Loss {
    pub(crate) fn is_lossy(&self) -> bool {
        self.missed > 0 || self.dropped > 0
    }
}

/// One producing thread's folded paths, plus how much of its stream was lost.
pub(crate) struct ThreadTimings {
    name: String,
    paths: Vec<PathStat>,
    loss: Loss,
}

impl ThreadTimings {
    pub(crate) fn new(
        name: String,
        paths: FxHashMap<Vec<u64>, CallStackSamples>,
        loss: Loss,
        meta: &FlamegraphMeta,
    ) -> Self {
        let mut paths: Vec<PathStat> = paths
            .into_iter()
            .map(|(path, samples)| PathStat { path, metrics: PathMetrics::from_samples(samples) })
            .collect();
        // Ids are ASLR'd pointers; sort on resolved names so output is
        // deterministic across runs.
        paths.sort_by(|a, b| {
            a.path.iter().map(|id| &meta.names[id]).cmp(b.path.iter().map(|id| &meta.names[id]))
        });
        Self { name, paths, loss }
    }
}

/// Per-thread `#[timed]` stats for one run. Frame ids stay opaque in each
/// thread's `paths`; `meta` resolves them only at the render/match boundary, so
/// the threshold gauges and the call tree share one model.
pub struct TimingStats {
    threads: Vec<ThreadTimings>,
    meta: FlamegraphMeta,
}

impl TimingStats {
    pub(crate) fn from_threads(mut threads: Vec<ThreadTimings>, meta: FlamegraphMeta) -> Self {
        // Ring discovery order is nondeterministic, so sort for a stable report.
        threads.sort_by(|a, b| a.name.cmp(&b.name));
        Self { threads, meta }
    }

    /// Any thread's mark stream was unreliable, so the run is incomplete and
    /// any gate built on it is invalid. Per-thread detail rides in
    /// [`call_tree`].
    ///
    /// [`call_tree`]: Self::call_tree
    pub fn missed_events(&self) -> bool {
        self.threads.iter().any(|t| t.loss.is_lossy())
    }

    fn matching_paths<'a>(&'a self, leaf: &'a str) -> impl Iterator<Item = &'a PathStat> {
        self.threads.iter().flat_map(|t| &t.paths).filter(move |s| {
            s.path.last().is_some_and(|id| leaf_name(&self.meta.names[id]).as_ref() == leaf)
        })
    }

    /// Sum tracked time + call count across every path whose leaf is
    /// `leaf` — for normalising a cross-cutting function (e.g.
    /// `hash_validators`) against a workload unit regardless of call site.
    pub fn aggregate_leaf(&self, leaf: &str) -> (Nanos, u64) {
        self.matching_paths(leaf).fold((Nanos::ZERO, 0), |(sum, cnt), s| {
            (sum + s.metrics.tracked_sum_ns, cnt + s.metrics.count)
        })
    }

    /// Slowest single tracked sample across every path whose leaf is `leaf`
    /// — the worst-case call, regardless of call site. `None` if no such path.
    pub fn aggregate_leaf_max(&self, leaf: &str) -> Option<Nanos> {
        self.matching_paths(leaf).map(|s| s.metrics.tracked_max_ns).max()
    }

    /// Median (p50) tracked sample for `leaf`. Percentiles aren't combinable
    /// across call sites, so this takes the max p50 over matching paths — exact
    /// for a single-call-site leaf (e.g. the top-level `apply_block`). `None`
    /// if no such path.
    pub fn aggregate_leaf_p50(&self, leaf: &str) -> Option<Nanos> {
        self.matching_paths(leaf).map(|s| s.metrics.tracked_p50_ns).max()
    }

    /// One call tree per producing thread, each under a centered `thread: name`
    /// rule that flags the thread if its stream lost events. Rules share one
    /// width across threads, and a blank line between threads keeps the stacked
    /// tables from reading as one block.
    pub fn call_tree(&self) -> String {
        let tables: Vec<_> = self
            .threads
            .iter()
            .map(|t| (t, call_tree::thread_table(&t.paths, &self.meta)))
            .collect();
        let width = tables
            .iter()
            .flat_map(|(_, table)| table.lines())
            .map(|l| l.chars().count())
            .max()
            .unwrap_or(0);
        tables
            .iter()
            .map(|(t, table)| {
                format!("{}\n{table}", call_tree::thread_rule(&t.name, t.loss, width))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Deterministic JSON `{label, threads: [{thread, lost, paths}]}` — see
    /// `PathMetrics` for the per-path schema; the path is its frame names
    /// joined by `;`.
    pub fn to_json(&self, label: &str) -> String {
        let threads: Vec<_> = self
            .threads
            .iter()
            .map(|t| {
                let paths: Vec<_> = t
                    .paths
                    .iter()
                    .map(|s| PathStatJson { path: self.path_name(&s.path), metrics: &s.metrics })
                    .collect();
                serde_json::json!({
                    "thread": t.name,
                    "lost": t.loss.is_lossy(),
                    "missed_events": t.loss.missed,
                    "dropped_marks": t.loss.dropped,
                    "paths": paths,
                })
            })
            .collect();
        serde_json::json!({ "label": label, "threads": threads }).to_string()
    }

    fn path_name(&self, path: &[u64]) -> String {
        path.iter().map(|id| self.meta.names[id].as_str()).collect::<Vec<_>>().join(";")
    }
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((q * sorted.len() as f64).ceil() as usize).saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flamegraph_timer::LocalReader, test_shmem::ShmemGuard, timed};

    #[timed]
    fn leaf_work(spin: u64) -> u64 {
        let mut acc = 0u64;
        for i in 0..spin {
            acc = acc.wrapping_add(i.wrapping_mul(0x9E3779B97F4A7C15));
        }
        acc
    }

    #[timed]
    fn parent_work() -> u64 {
        leaf_work(2_000).wrapping_add(leaf_work(2_000))
    }

    #[test]
    fn records_call_paths_with_self_time() {
        let _guard = ShmemGuard::new();
        let reader = LocalReader::start();
        // 3 parent invocations × 2 leaf calls each = 6 leaf total.
        for _ in 0..3 {
            std::hint::black_box(parent_work());
        }

        let stats = reader.collect();
        let names = &stats.meta.names;
        let paths = || stats.threads.iter().flat_map(|t| &t.paths);
        let parent = paths()
            .find(|s| s.path.len() == 1 && names[&s.path[0]].ends_with("parent_work"))
            .expect("parent path recorded");
        let child = paths()
            .find(|s| s.path.len() == 2 && names[&s.path[1]].ends_with("leaf_work"))
            .expect("nested leaf path recorded");

        assert_eq!(parent.metrics.count, 3);
        assert_eq!(child.metrics.count, 6);
        // Parent's untracked time excludes the children it called.
        assert!(parent.metrics.total_untracked_ns < parent.metrics.tracked_sum_ns);

        let json = stats.to_json("test");
        assert!(json.contains("\"label\":\"test\""));

        // Call tree: leaf row shows avg-per-parent and total when they differ
        // (6 leaf calls / 3 parent invocations → ×2  (6 total)); parent row
        // has no parent context → plain count; untracked sibling is present.
        let tree = stats.call_tree();
        assert!(tree.contains("parent_work"), "missing parent: {tree}");
        assert!(tree.contains("×3"), "parent should render plain ×3: {tree}");
        assert!(tree.contains("×2  (6 total)"), "leaf split missing: {tree}");
        assert!(tree.contains("untracked"), "untracked row missing: {tree}");
    }

    #[test]
    fn percentile_corners() {
        let v = [10u64, 20, 30, 40, 50];
        assert_eq!(percentile(&v, 0.0), 10);
        assert_eq!(percentile(&v, 0.50), 30);
        assert_eq!(percentile(&v, 1.0), 50);
        assert_eq!(percentile(&[], 0.5), 0);
    }
}
