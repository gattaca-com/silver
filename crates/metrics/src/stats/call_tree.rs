//! Render aggregated `#[timed]` paths as an indented call tree — one row per
//! frame, with per-call metrics laid out as aligned table columns (headers on
//! top, values below). Each parent emits a synthetic `untracked` sibling (its
//! time minus tracked children) and folds its low-coverage tail into a single
//! `...` row.

use std::borrow::Cow;

use flux::timing::Nanos;
use rustc_hash::FxHashMap;

use super::{counters::Counters, names::leaf_name, report::PathStat};
use crate::{
    fmt_bytes,
    profiler::{FlamegraphMeta, Loss},
    table::{Column, Table},
};

/// A centered `thread: name` rule, flagged when the thread's mark stream lost
/// events (so the reader knows the thread's numbers are incomplete). `width`
/// is shared across threads so every rule lands at the same length.
pub(super) fn thread_rule(name: &str, loss: Loss, width: usize) -> String {
    let tag = if loss.is_lossy() {
        format!(
            " — LOSSY: ~{} events missed, {} unmatched closes dropped (producer outran reader)",
            loss.missed, loss.dropped
        )
    } else {
        String::new()
    };
    let label = format!(" thread: {name}{tag} ");
    let pad = width.saturating_sub(label.chars().count());
    let left = "─".repeat(pad / 2);
    let right = "─".repeat(pad - pad / 2);
    format!("{left}{label}{right}")
}

pub(super) fn thread_table(paths: &[PathStat], meta: &FlamegraphMeta) -> String {
    let mut root = Node::default();
    for s in paths {
        let mut node = &mut root;
        for id in &s.path {
            node = node.children.entry(*id).or_default();
        }
        node.count = s.metrics.count;
        node.total_untracked_ns = s.metrics.total_untracked_ns;
        node.tracked_sum_ns = s.metrics.tracked_sum_ns;
        node.tracked_max_ns = s.metrics.tracked_max_ns;
        node.counters = s.metrics.tracked;
        node.untracked_counters = s.metrics.untracked;
    }

    let mut rows = Vec::new();
    root.render_children(0, meta, &mut rows);
    render_table(&rows, meta)
}

#[derive(Default)]
struct Node {
    count: u64,
    total_untracked_ns: Nanos,
    tracked_sum_ns: Nanos,
    tracked_max_ns: Nanos,
    counters: Counters,
    untracked_counters: Counters,
    children: FxHashMap<u64, Node>,
}

const MIN_TIME_PCT: u64 = 1;
const MIN_PEAK: Nanos = Nanos::from_millis(1);

impl Node {
    fn render_children(&self, depth: usize, meta: &FlamegraphMeta, out: &mut Vec<RenderRow>) {
        if self.children.is_empty() {
            return;
        }
        let mut rows: Vec<Row> = self
            .children
            .iter()
            .map(|(id, c)| Row {
                label: leaf_name(&meta.names[id]),
                sum_ns: c.tracked_sum_ns,
                max_ns: c.tracked_max_ns,
                count: c.count,
                counters: c.counters,
                child: Some(c),
            })
            .collect();
        if self.count > 0 {
            rows.push(Row {
                label: Cow::Borrowed("untracked"),
                sum_ns: self.total_untracked_ns,
                max_ns: Nanos::ZERO,
                count: self.count,
                counters: self.untracked_counters,
                child: None,
            });
        }
        rows.sort_by(|a, b| b.max_ns.cmp(&a.max_ns));
        let (kept, folded) = split_for_render(&rows);

        let indent = depth * 2;
        for r in kept {
            out.push(RenderRow {
                name: format!("{blank:indent$}{label}", blank = "", label = r.label),
                avg: r.sum_ns / r.count.max(1),
                max: r.max_ns,
                calls: CallCount { total: r.count, per_parent: self.count },
                counters: r.counters,
            });
            if let Some(child) = r.child {
                child.render_children(depth + 1, meta, out);
            }
        }
        if !folded.is_empty() {
            let rem_sum: Nanos = folded.iter().map(|r| r.sum_ns).sum();
            let rem_calls: u64 = folded.iter().map(|r| r.count).sum();
            let label = format!("... ({} more)", folded.len());
            out.push(RenderRow {
                name: format!("{blank:indent$}{label}", blank = ""),
                avg: rem_sum / rem_calls.max(1),
                max: folded.iter().map(|r| r.max_ns).max().unwrap_or(Nanos::ZERO),
                calls: CallCount { total: rem_calls, per_parent: self.count },
                counters: Counters::default(),
            });
        }
    }
}

fn split_for_render<'r, 'a>(rows: &'r [Row<'a>]) -> (Vec<&'r Row<'a>>, Vec<&'r Row<'a>>) {
    let total: Nanos = rows.iter().map(|r| r.sum_ns).sum();
    let time_floor = total * MIN_TIME_PCT / 100u64;
    let shown = |r: &Row| r.max_ns >= MIN_PEAK || r.sum_ns >= time_floor;

    // Folding a single row saves no space — only fold 2+.
    let fold = rows.iter().filter(|r| !shown(r)).count() >= 2;
    rows.iter().partition(|r| !fold || shown(r))
}

struct Row<'a> {
    label: Cow<'a, str>,
    sum_ns: Nanos,
    max_ns: Nanos,
    count: u64,
    counters: Counters,
    /// `None` for the synthetic `untracked` row — no subtree to recurse into.
    child: Option<&'a Node>,
}

struct CallCount {
    total: u64,
    per_parent: u64,
}

impl CallCount {
    fn cell(&self) -> String {
        // Root, or a parent that ran once → avg == total; show a plain count.
        if self.per_parent <= 1 {
            return format!("×{}", self.total);
        }
        let per = if self.total.is_multiple_of(self.per_parent) {
            (self.total / self.per_parent).to_string()
        } else {
            format!("{:.1}", self.total as f64 / self.per_parent as f64)
        };
        format!("×{per}  ({} total)", self.total)
    }
}

struct RenderRow {
    name: String,
    avg: Nanos,
    max: Nanos,
    calls: CallCount,
    counters: Counters,
}

/// `instructions`/`cycles` feed the derived `ipc` column, so they aren't given
/// their own per-call column.
fn is_ipc_input(label: &str) -> bool {
    matches!(label, "instructions" | "cpu-cycles" | "cycles")
}

fn render_table(rows: &[RenderRow], meta: &FlamegraphMeta) -> String {
    let calls = |r: &RenderRow| r.calls.total;
    let any =
        |present: &dyn Fn(&RenderRow) -> bool| rows.iter().any(|r| calls(r) > 0 && present(r));

    let show_alloc = any(&|r| r.counters.alloc.allocated > 0 || r.counters.alloc.freed > 0);
    // A perf event earns a column only when some row actually measured it, so an
    // unmeasured schema slot doesn't add an all-blank column.
    let perf_slots: Vec<_> = meta
        .schema
        .iter()
        .enumerate()
        .filter(|(_, e)| !is_ipc_input(&e.label))
        .filter(|(i, _)| any(&|r| r.counters.perf.vals[*i] > 0))
        .map(|(i, e)| (i, e.label.as_str()))
        .collect();
    let show_ipc = rows.iter().any(|r| meta.schema.ipc(&r.counters.perf.vals) > 0.0);

    let mut columns = vec![
        Column::left("call path"),
        Column::right("avg"),
        Column::right("max"),
        Column::left("calls"),
    ];
    if show_alloc {
        columns.push(Column::right("alloc/call"));
        columns.push(Column::right("freed/call"));
    }
    columns.extend(perf_slots.iter().map(|(_, label)| Column::right(format!("{label}/call"))));
    if show_ipc {
        columns.push(Column::right("ipc"));
    }

    let mut table = Table::new(columns);
    for r in rows {
        let n = calls(r);
        let max = if r.max == Nanos::ZERO { String::new() } else { r.max.to_string() };
        let mut cells = vec![r.name.clone(), r.avg.to_string(), max, r.calls.cell()];
        if show_alloc {
            cells.push(per_call(r.counters.alloc.allocated, n, fmt_bytes));
            cells.push(per_call(r.counters.alloc.freed, n, fmt_bytes));
        }
        cells.extend(
            perf_slots
                .iter()
                .map(|(i, _)| per_call(r.counters.perf.vals[*i], n, |v| v.to_string())),
        );
        if show_ipc {
            let ipc = meta.schema.ipc(&r.counters.perf.vals);
            cells.push(if ipc > 0.0 { format!("{ipc:.2}") } else { String::new() });
        }
        table.row(cells);
    }
    table.render()
}

/// Blank rather than `0` when a row didn't measure a dimension (synthetic
/// `...`/`untracked` rows, or perf/alloc off) so empty cells stay quiet.
fn per_call(total: u64, calls: u64, fmt: impl Fn(u64) -> String) -> String {
    if calls == 0 || total == 0 { String::new() } else { fmt(total / calls) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row<'a>(label: &'a str, sum: u64, max: u64, child: Option<&'a Node>) -> Row<'a> {
        Row {
            label: Cow::Borrowed(label),
            sum_ns: Nanos(sum),
            max_ns: Nanos(max),
            count: 1,
            counters: Counters::default(),
            child,
        }
    }

    fn names(rows: Vec<&Row>) -> Vec<String> {
        rows.iter().map(|r| r.label.to_string()).collect()
    }

    /// `insert_verified` is kept by time share, `rare_stall` by peak; the
    /// self-time row gets no exemption and folds on the same terms.
    #[test]
    fn time_and_peak_each_keep_a_row_the_other_folds() {
        let node = Node::default();
        let rows = vec![
            row("verify_all", 1_740_000_000, 12_167_000, Some(&node)),
            row("untracked", 100_000, 0, None),
            row("insert_verified", 36_700_000, 6_772, Some(&node)),
            row("rare_stall", 2_000_000, 1_500_000, Some(&node)),
            row("noise_a", 260_000, 8_495, Some(&node)),
            row("noise_b", 1_000, 500, Some(&node)),
        ];

        let (kept, folded) = split_for_render(&rows);

        assert_eq!(names(kept), ["verify_all", "insert_verified", "rare_stall"]);
        assert_eq!(names(folded), ["untracked", "noise_a", "noise_b"]);
    }

    #[test]
    fn a_lone_dull_row_shows_rather_than_folding() {
        let node = Node::default();
        let rows = vec![row("hot", 1_000_000_000, 0, Some(&node)), row("dull", 1, 0, Some(&node))];

        let (kept, folded) = split_for_render(&rows);

        assert_eq!(names(kept), ["hot", "dull"]);
        assert!(folded.is_empty());
    }
}
