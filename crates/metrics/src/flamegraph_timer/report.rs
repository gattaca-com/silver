//! Summarise drained #[timed] call paths into a deterministic call tree; each
//! path is the measured timed-frame chain, so containment holds by
//! construction.

use std::{collections::HashMap, fmt::Write as _};

use flux::timing::Nanos;

use crate::flamegraph_timer::collect::drain;

#[derive(serde::Serialize)]
struct PathStat {
    #[serde(serialize_with = "join_path")]
    path: Vec<String>,
    count: u64,
    tracked_avg_ns: Nanos,
    tracked_p99_ns: Nanos,
    tracked_max_ns: Nanos,
    tracked_sum_ns: Nanos,
    total_untracked_ns: Nanos,
}

fn join_path<S: serde::Serializer>(path: &[String], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&path.join(";"))
}

/// Summarised `#[timed]` call paths for one run. Build with
/// [`TimingStats::collect`], then render to a call tree or JSON.
pub struct TimingStats(Vec<PathStat>);

impl TimingStats {
    pub fn collect() -> Self {
        let mut paths: Vec<_> = drain()
            .into_iter()
            .map(|timing| {
                let mut samples = timing.samples.tracked_ns;
                samples.sort_unstable();
                let count = samples.len() as u64;
                let sum: u128 = samples.iter().map(|&x| x as u128).sum();
                PathStat {
                    path: timing.call_stack.iter().map(|name| name.to_string()).collect(),
                    count,
                    tracked_avg_ns: if count > 0 {
                        Nanos((sum / count as u128) as u64)
                    } else {
                        Nanos::ZERO
                    },
                    tracked_p99_ns: Nanos(percentile(&samples, 0.99)),
                    tracked_max_ns: Nanos(samples.last().copied().unwrap_or(0)),
                    tracked_sum_ns: Nanos(u64::try_from(sum).unwrap_or(u64::MAX)),
                    total_untracked_ns: Nanos(timing.samples.total_untracked_ns),
                }
            })
            .collect();
        paths.sort_by(|a, b| a.path.cmp(&b.path));
        Self(paths)
    }

    /// Sum tracked time + call count across every path whose leaf is
    /// `leaf` — for normalising a cross-cutting function (e.g.
    /// `hash_validators`) against a workload unit regardless of call site.
    pub fn aggregate_leaf(&self, leaf: &str) -> (Nanos, u64) {
        self.0
            .iter()
            .filter(|s| s.path.last().is_some_and(|n| leaf_name(n) == leaf))
            .fold((Nanos::ZERO, 0), |(sum, cnt), s| (sum + s.tracked_sum_ns, cnt + s.count))
    }

    /// Slowest single tracked sample across every path whose leaf is `leaf`
    /// — the worst-case call, regardless of call site. `None` if no such path.
    pub fn aggregate_leaf_max(&self, leaf: &str) -> Option<Nanos> {
        self.0
            .iter()
            .filter(|s| s.path.last().is_some_and(|n| leaf_name(n) == leaf))
            .map(|s| s.tracked_max_ns)
            .max()
    }

    /// Indented call tree. A parent's untracked time is emitted as a
    /// synthetic `untracked` sibling so children sum to the parent's
    /// tracked time; low-coverage tail folded under `COVERAGE_PCT`.
    pub fn call_tree(&self) -> String {
        let mut root = Node::default();
        for s in &self.0 {
            let mut node = &mut root;
            for seg in &s.path {
                node = node.children.entry(seg.clone()).or_default();
            }
            node.count = s.count;
            node.total_untracked_ns = s.total_untracked_ns;
            node.tracked_sum_ns = s.tracked_sum_ns;
        }

        let mut out = String::new();
        root.render_children(0, &mut out);
        out
    }

    /// Deterministic JSON `{label, paths}` — see `PathStat` for the per-path
    /// schema.
    pub fn to_json(&self, label: &str) -> String {
        serde_json::json!({ "label": label, "paths": &self.0 }).to_string()
    }
}

fn leaf_name(qualified: &str) -> &str {
    qualified.rsplit("::").next().unwrap_or(qualified)
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((q * sorted.len() as f64).ceil() as usize).saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

#[derive(Default)]
struct Node {
    count: u64,
    total_untracked_ns: Nanos,
    tracked_sum_ns: Nanos,
    children: HashMap<String, Node>,
}

/// Children accounting for less than this fraction of a node's time are
/// folded into a single `...` row, keeping the tree focused on the
/// dominant costs.
const COVERAGE_PCT: u64 = 99;

impl Node {
    fn render_children(&self, depth: usize, out: &mut String) {
        if self.children.is_empty() {
            return;
        }
        let mut rows: Vec<Row> = self
            .children
            .iter()
            .map(|(name, c)| Row {
                label: leaf_name(name),
                sum_ns: c.tracked_sum_ns,
                count: c.count,
                child: Some(c),
            })
            .collect();
        if self.count > 0 {
            rows.push(Row {
                label: "untracked",
                sum_ns: self.total_untracked_ns,
                count: self.count,
                child: None,
            });
        }
        rows.sort_by(|a, b| b.sum_ns.cmp(&a.sum_ns));

        let total: Nanos = rows.iter().map(|r| r.sum_ns).sum();
        let threshold = Nanos((total.0 as u128 * COVERAGE_PCT as u128 / 100) as u64);

        let mut covered = Nanos::ZERO;
        let mut cut = rows.len();
        for (i, r) in rows.iter().enumerate() {
            if covered >= threshold {
                cut = i;
                break;
            }
            covered += r.sum_ns;
        }
        // Folding a single row saves no space — only fold 2+.
        if rows.len() - cut < 2 {
            cut = rows.len();
        }

        let indent = depth * 2;
        for r in &rows[..cut] {
            let avg = r.sum_ns / r.count.max(1);
            let count = Some(CallCount { total: r.count, per_parent: self.count });
            emit_row(out, indent, r.label, avg, count);
            if let Some(child) = r.child {
                child.render_children(depth + 1, out);
            }
        }
        if cut < rows.len() {
            let rem_sum: Nanos = rows[cut..].iter().map(|r| r.sum_ns).sum();
            let rem_avg = rem_sum / self.count.max(1);
            let label = format!("... ({} more)", rows.len() - cut);
            emit_row(out, indent, &label, rem_avg, None);
        }
    }
}

struct Row<'a> {
    label: &'a str,
    sum_ns: Nanos,
    count: u64,
    /// `None` for the synthetic `untracked` row (no subtree to recurse into).
    child: Option<&'a Node>,
}

/// `per_parent == 0` ⇒ no parent context (root row).
struct CallCount {
    total: u64,
    per_parent: u64,
}

fn emit_row(out: &mut String, indent: usize, label: &str, avg: Nanos, count: Option<CallCount>) {
    let width = 38usize.saturating_sub(indent);
    // `Nanos` Display ignores formatter width, so stringify then pad.
    let avg_str = avg.to_string();
    let suffix = match count {
        None => String::new(),
        // No parent (root) or parent ran once → avg == total; show plain count.
        Some(c) if c.per_parent <= 1 => format!("  ×{}", c.total),
        Some(c) => {
            // avg calls per parent invocation; integer when divisible.
            let avg = if c.total % c.per_parent == 0 {
                (c.total / c.per_parent).to_string()
            } else {
                format!("{:.1}", c.total as f64 / c.per_parent as f64)
            };
            format!("  ×{avg}  ({} total)", c.total)
        }
    };
    writeln!(out, "{pad:indent$}{label:<width$}  {avg_str:>10}{suffix}", pad = "").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flamegraph_timer::collect::enable, timed};

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
        enable();
        // 3 parent invocations × 2 leaf calls each = 6 leaf total.
        for _ in 0..3 {
            std::hint::black_box(parent_work());
        }

        let stats = TimingStats::collect();
        let parent = stats
            .0
            .iter()
            .find(|s| s.path.len() == 1 && s.path[0].ends_with("parent_work"))
            .expect("parent path recorded");
        let child = stats
            .0
            .iter()
            .find(|s| s.path.len() == 2 && s.path[1].ends_with("leaf_work"))
            .expect("nested leaf path recorded");

        assert_eq!(parent.count, 3);
        assert_eq!(child.count, 6);
        // Parent's untracked time excludes the children it called.
        assert!(parent.total_untracked_ns < parent.tracked_sum_ns);

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
