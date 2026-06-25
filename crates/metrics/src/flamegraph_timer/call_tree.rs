//! Render aggregated `#[timed]` paths as an indented, column-aligned call tree.
//! Each parent emits a synthetic `untracked` sibling (its time minus tracked
//! children) and folds its low-coverage tail into a single `...` row.

use std::borrow::Cow;

use flux::timing::Nanos;
use rustc_hash::FxHashMap;

use crate::{
    flamegraph_timer::{names::leaf_name, report::PathStat},
    perf::PerfSample,
    schema, slot,
};

pub(super) fn render(paths: &[PathStat], names: &FxHashMap<u64, String>) -> String {
    let mut root = Node::default();
    for s in paths {
        let mut node = &mut root;
        for id in &s.path {
            node = node.children.entry(*id).or_default();
        }
        node.count = s.metrics.count;
        node.total_untracked_ns = s.metrics.total_untracked_ns;
        node.tracked_sum_ns = s.metrics.tracked_sum_ns;
        node.perf = s.metrics.tracked_perf;
        node.untracked_perf = s.metrics.untracked_perf;
    }

    let mut lines = Vec::new();
    root.render_children(0, names, &mut lines);
    render_aligned(&lines)
}

#[derive(Default)]
struct Node {
    count: u64,
    total_untracked_ns: Nanos,
    tracked_sum_ns: Nanos,
    perf: PerfSample,
    untracked_perf: PerfSample,
    children: FxHashMap<u64, Node>,
}

/// Keep the rows covering this % of a node's time; fold the rest into `...`.
const COVERAGE_PCT: u64 = 99;

impl Node {
    fn render_children(&self, depth: usize, names: &FxHashMap<u64, String>, out: &mut Vec<Line>) {
        if self.children.is_empty() {
            return;
        }
        let mut rows: Vec<Row> = self
            .children
            .iter()
            .map(|(id, c)| Row {
                label: leaf_name(&names[id]),
                sum_ns: c.tracked_sum_ns,
                count: c.count,
                perf: c.perf,
                child: Some(c),
            })
            .collect();
        if self.count > 0 {
            rows.push(Row {
                label: Cow::Borrowed("untracked"),
                sum_ns: self.total_untracked_ns,
                count: self.count,
                perf: self.untracked_perf,
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
            out.push(make_line(indent, r.label.as_ref(), avg, count, &r.perf));
            if let Some(child) = r.child {
                child.render_children(depth + 1, names, out);
            }
        }
        if cut < rows.len() {
            let rem_sum: Nanos = rows[cut..].iter().map(|r| r.sum_ns).sum();
            let rem_avg = rem_sum / self.count.max(1);
            let label = format!("... ({} more)", rows.len() - cut);
            out.push(make_line(indent, &label, rem_avg, None, &PerfSample::default()));
        }
    }
}

struct Row<'a> {
    label: Cow<'a, str>,
    sum_ns: Nanos,
    count: u64,
    perf: PerfSample,
    /// `None` for the synthetic `untracked` row — no subtree to recurse into.
    child: Option<&'a Node>,
}

struct CallCount {
    total: u64,
    per_parent: u64,
}

/// A rendered row kept as separate parts so [`render_aligned`] can right-align
/// the ns and counter columns past the widest label that precedes them.
struct Line {
    name: String,
    avg: String,
    suffix: String,
    counters: Option<String>,
}

fn make_line(
    indent: usize,
    label: &str,
    avg: Nanos,
    count: Option<CallCount>,
    perf: &PerfSample,
) -> Line {
    let name = format!("{blank:indent$}{label}", blank = "");
    let avg = avg.to_string();
    let suffix = match &count {
        None => String::new(),
        // Root, or a parent that ran once → avg == total; show a plain count.
        Some(c) if c.per_parent <= 1 => format!("  ×{}", c.total),
        Some(c) => {
            let per = if c.total % c.per_parent == 0 {
                (c.total / c.per_parent).to_string()
            } else {
                format!("{:.1}", c.total as f64 / c.per_parent as f64)
            };
            format!("  ×{per}  ({} total)", c.total)
        }
    };
    let counters = counter_text(perf, count.map_or(0, |c| c.total));
    Line { name, avg, suffix, counters }
}

/// Per-call counter columns: each non-IPC-input event as `N label/call`, then
/// IPC derived from the instructions/cycles slots when both were measured.
/// `None` when no counters were collected (perf off, or a synthetic row).
fn counter_text(perf: &PerfSample, calls: u64) -> Option<String> {
    if calls == 0 || perf.vals.iter().all(|&v| v == 0) {
        return None;
    }
    let schema = schema();
    let is_ipc_input = |label: &str| matches!(label, "instructions" | "cpu-cycles" | "cycles");
    let mut parts: Vec<String> = schema
        .iter()
        .enumerate()
        .filter(|(_, e)| !is_ipc_input(&e.label))
        .map(|(i, e)| format!("{:>9} {}/call", perf.vals[i] / calls, e.label))
        .collect();
    if let (Some(i), Some(c)) =
        (slot("instructions"), slot("cpu-cycles").or_else(|| slot("cycles"))) &&
        perf.vals[c] > 0
    {
        parts.push(format!("ipc {:.2}", perf.vals[i] as f64 / perf.vals[c] as f64));
    }
    (!parts.is_empty()).then(|| parts.join("  "))
}

fn width(s: &str) -> usize {
    s.chars().count()
}

fn render_aligned(lines: &[Line]) -> String {
    let name_w = lines.iter().map(|l| width(&l.name)).max().unwrap_or(0);
    let prefix = |l: &Line| {
        format!("{name:<name_w$}  {avg:>10}{suffix}", name = l.name, avg = l.avg, suffix = l.suffix)
    };
    let counter_w = lines
        .iter()
        .filter(|l| l.counters.is_some())
        .map(|l| width(&prefix(l)))
        .max()
        .map_or(0, |w| w + 3);
    let mut out = String::new();
    for l in lines {
        let p = prefix(l);
        out.push_str(&p);
        if let Some(c) = &l.counters {
            for _ in 0..counter_w.saturating_sub(width(&p)) {
                out.push(' ');
            }
            out.push_str(c);
        }
        out.push('\n');
    }
    out
}
