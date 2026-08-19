//! Per-path stats over drained `#[timed]` call paths. Each path is a measured
//! timed-frame chain, so a child's time is contained in its parent's.

use flux::timing::Nanos;
use rustc_hash::FxHashMap;

use super::{
    aggregator::{Aggregator, CallStackSamples},
    call_tree,
    counters::Counters,
    names::leaf_name,
};
use crate::profiler::{EventsDrainer, FlamegraphMeta, Loss};

pub(super) struct PathStat {
    pub(super) path: Vec<u64>,
    pub(super) metrics: PathMetrics,
}

#[derive(serde::Serialize)]
pub(super) struct PathMetrics {
    pub(super) count: u64,
    tracked_avg_ns: Nanos,
    /// `None` once merged: percentiles need the samples a live consumer drops.
    tracked_p50_ns: Option<Nanos>,
    tracked_p99_ns: Option<Nanos>,
    pub(super) tracked_max_ns: Nanos,
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
            tracked_p50_ns: Some(Nanos(percentile(&times, 0.50))),
            tracked_p99_ns: Some(Nanos(percentile(&times, 0.99))),
            tracked_max_ns: Nanos(times.last().copied().unwrap_or(0)),
            tracked_sum_ns: Nanos(u64::try_from(sum).unwrap_or(u64::MAX)),
            total_untracked_ns: Nanos(samples.total_untracked_ns),
            tracked: samples.tracked,
            untracked: samples.total_untracked,
        }
    }

    fn merge(&mut self, later: &Self) {
        self.count += later.count;
        self.tracked_sum_ns += later.tracked_sum_ns;
        self.total_untracked_ns += later.total_untracked_ns;
        self.tracked_max_ns = self.tracked_max_ns.max(later.tracked_max_ns);
        self.tracked = self.tracked.add(&later.tracked);
        self.untracked = self.untracked.add(&later.untracked);
        self.tracked_avg_ns = Nanos(self.tracked_sum_ns.0 / self.count.max(1));
        self.tracked_p50_ns = None;
        self.tracked_p99_ns = None;
    }
}

#[derive(serde::Serialize)]
struct PathStatJson<'a> {
    path: String,
    #[serde(flatten)]
    metrics: &'a PathMetrics,
}

pub fn fold_stats(events: &EventsDrainer) -> TimingStats {
    let threads = events
        .threads()
        .map(|t| {
            let paths = Aggregator::new(t.marks, t.perf, t.alloc).paths;
            ThreadTimings::new(t.name.to_owned(), paths, t.loss, events.meta())
        })
        .collect();
    TimingStats::from_threads(threads, events.meta().clone())
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
        let mut paths: Vec<_> = paths
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

    fn merge(&mut self, later: Self, meta: &FlamegraphMeta) {
        self.loss.missed += later.loss.missed;
        self.loss.dropped += later.loss.dropped;

        for stat in later.paths {
            match self.paths.iter_mut().find(|held| held.path == stat.path) {
                Some(held) => held.metrics.merge(&stat.metrics),
                None => self.paths.push(stat),
            }
        }
        self.paths.sort_by(|a, b| {
            a.path.iter().map(|id| &meta.names[id]).cmp(b.path.iter().map(|id| &meta.names[id]))
        });
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

    pub fn merge(&mut self, later: Self) {
        self.meta.names.extend(later.meta.names);
        for thread in later.threads {
            match self.threads.iter_mut().find(|held| held.name == thread.name) {
                Some(held) => held.merge(thread, &self.meta),
                None => self.threads.push(thread),
            }
        }
        self.threads.sort_by(|a, b| a.name.cmp(&b.name));
    }

    /// Any thread's mark stream was unreliable, so the run is incomplete and
    /// any gate built on it is invalid.
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
        self.matching_paths(leaf).filter_map(|s| s.metrics.tracked_p50_ns).max()
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

    /// Deterministic JSON `{label, threads: [{thread, lost, paths}]}`; the path
    /// is its frame names joined by `;`.
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
    use crate::{profiler::InProcessReader, test_shmem::ShmemGuard, timed};

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
        let reader = InProcessReader::start();
        // 3 parent invocations × 2 leaf calls each = 6 leaf total.
        for _ in 0..3 {
            std::hint::black_box(parent_work());
        }

        let stats = fold_stats(&reader.collect());
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
    fn merging_adds_the_totals_and_drops_the_percentiles() {
        let drain = |count, ns| PathMetrics {
            count,
            tracked_avg_ns: Nanos(ns / count),
            tracked_p50_ns: Some(Nanos(ns)),
            tracked_p99_ns: Some(Nanos(ns)),
            tracked_max_ns: Nanos(ns),
            tracked_sum_ns: Nanos(ns),
            total_untracked_ns: Nanos(1),
            tracked: Counters::default(),
            untracked: Counters::default(),
        };

        let mut merged = drain(2, 10);
        merged.merge(&drain(3, 30));

        assert_eq!(merged.count, 5);
        assert_eq!(merged.tracked_sum_ns, Nanos(40));
        assert_eq!(merged.total_untracked_ns, Nanos(2));
        assert_eq!(merged.tracked_max_ns, Nanos(30), "the worst call survives");
        assert_eq!(merged.tracked_avg_ns, Nanos(8), "recovered from the totals, not averaged");
        assert_eq!(merged.tracked_p50_ns, None);
    }

    #[timed]
    fn tick() {}

    /// Full-stack overrun stress against the report surface: a producer
    /// thread hammers `#[timed]` calls while the reader drains at its
    /// production cadence. The run must be flagged lossy, and the reported
    /// numbers must account for all production: every call is folded, dropped,
    /// or missed. A call spanning a gap counts once as folded (its synthetic
    /// close) and once as missed (its real close fell in the hole), so the
    /// bound carries one call of slack per `<missed>` gap.
    #[test]
    fn stress_reported_loss_accounts_for_all_production() {
        let _guard = ShmemGuard::new();
        let reader = InProcessReader::start();

        const CALLS: u64 = 10_000_000;
        std::thread::Builder::new()
            .name("stress-producer".to_owned())
            .spawn(|| {
                for _ in 0..CALLS {
                    tick();
                }
            })
            .unwrap()
            .join()
            .unwrap();

        let stats = fold_stats(&reader.collect());
        assert!(stats.missed_events(), "overrun must be reported");

        let report: serde_json::Value = serde_json::from_str(&stats.to_json("stress")).unwrap();
        let thread = report["threads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["thread"] == "stress-producer")
            .expect("producer thread reported");
        let missed = thread["missed_events"].as_u64().unwrap();
        let dropped = thread["dropped_marks"].as_u64().unwrap();
        let (_, retained) = stats.aggregate_leaf("tick");
        let (_, gaps) = stats.aggregate_leaf("<missed>");

        let produced_marks = 2 * CALLS;
        println!(
            "produced={produced_marks} retained_calls={retained} missed={missed} \
             dropped={dropped} gaps={gaps}"
        );
        assert!(retained > 0, "reader retained nothing despite polling throughout");
        assert!(retained <= CALLS, "more calls folded than were made");
        assert!(
            missed + 2 * retained + dropped <= produced_marks + gaps,
            "reported loss exceeds production: missed={missed} retained_calls={retained} \
             dropped={dropped} gaps={gaps} produced_marks={produced_marks}"
        );
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
