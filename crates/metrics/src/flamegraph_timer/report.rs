//! Per-path stats over drained `#[timed]` call paths. Each path is a measured
//! timed-frame chain, so a child's time is contained in its parent's.

use flux::timing::Nanos;
use rustc_hash::FxHashMap;

use crate::{
    flamegraph_timer::{aggregator::CallStackSamples, call_tree, names::leaf_name},
    perf::PerfSample,
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
    /// Summed counter deltas over all calls on this path; `untracked_perf`
    /// excludes timed children, like `total_untracked_ns`. All-zero unless the
    /// `perf` feature is built and `perf_event_open` is permitted.
    pub(super) tracked_perf: PerfSample,
    pub(super) untracked_perf: PerfSample,
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
            tracked_perf: samples.tracked_perf,
            untracked_perf: samples.total_untracked_perf,
        }
    }
}

#[derive(serde::Serialize)]
struct PathStatJson<'a> {
    path: String,
    #[serde(flatten)]
    metrics: &'a PathMetrics,
}

/// Per-path `#[timed]` stats for one run. Frame ids stay opaque in `paths`;
/// `names` resolves them only at the render/match boundary, so the threshold
/// gauges and the call tree share one model.
pub struct TimingStats {
    paths: Vec<PathStat>,
    names: FxHashMap<u64, String>,
    lost: bool,
}

impl TimingStats {
    pub(crate) fn from_timings(
        paths: FxHashMap<Vec<u64>, CallStackSamples>,
        names: FxHashMap<u64, String>,
        lost: bool,
    ) -> Self {
        let mut paths: Vec<PathStat> = paths
            .into_iter()
            .map(|(path, samples)| PathStat { path, metrics: PathMetrics::from_samples(samples) })
            .collect();
        // Ids are ASLR'd pointers; sort on resolved names so JSON output is
        // deterministic across runs.
        paths.sort_by(|a, b| {
            a.path.iter().map(|id| &names[id]).cmp(b.path.iter().map(|id| &names[id]))
        });
        Self { paths, names, lost }
    }

    /// The mark stream was unreliable — a ring wrapped before the reader
    /// drained it (marks lost), or a close popped a non-matching open (stream
    /// desync, e.g. a producer crash/restart). Either way these stats are
    /// incomplete and any gate built on them is invalid.
    pub fn missed_events(&self) -> bool {
        self.lost
    }

    fn matching_paths<'a>(&'a self, leaf: &'a str) -> impl Iterator<Item = &'a PathStat> {
        self.paths.iter().filter(move |s| {
            s.path.last().is_some_and(|id| leaf_name(&self.names[id]).as_ref() == leaf)
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

    pub fn call_tree(&self) -> String {
        call_tree::render(&self.paths, &self.names)
    }

    /// Deterministic JSON `{label, paths}` — see `PathMetrics` for the per-path
    /// schema; the path is its frame names joined by `;`.
    pub fn to_json(&self, label: &str) -> String {
        let paths: Vec<_> = self
            .paths
            .iter()
            .map(|s| PathStatJson { path: self.path_name(&s.path), metrics: &s.metrics })
            .collect();
        serde_json::json!({ "label": label, "paths": paths }).to_string()
    }

    fn path_name(&self, path: &[u64]) -> String {
        path.iter().map(|id| self.names[id].as_str()).collect::<Vec<_>>().join(";")
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
        let names = &stats.names;
        let parent = stats
            .paths
            .iter()
            .find(|s| s.path.len() == 1 && names[&s.path[0]].ends_with("parent_work"))
            .expect("parent path recorded");
        let child = stats
            .paths
            .iter()
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
