//! Render aggregated `#[timed]` paths as an indented call tree — one row per
//! frame, with per-call metrics laid out as aligned table columns (headers on
//! top, values below). Each parent emits a synthetic `untracked` sibling (its
//! time minus tracked children) and folds its low-coverage tail into a single
//! `...` row.

use std::borrow::Cow;

use flux::timing::Nanos;
use rustc_hash::FxHashMap;

use crate::{
    flamegraph_timer::{
        counters::Counters,
        names::leaf_name,
        report::{FlamegraphMeta, Loss, PathStat},
    },
    fmt_bytes,
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
    counters: Counters,
    untracked_counters: Counters,
    children: FxHashMap<u64, Node>,
}

/// Keep the rows covering this % of a node's time; fold the rest into `...`.
const COVERAGE_PCT: u64 = 99;

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
                count: c.count,
                counters: c.counters,
                child: Some(c),
            })
            .collect();
        if self.count > 0 {
            rows.push(Row {
                label: Cow::Borrowed("untracked"),
                sum_ns: self.total_untracked_ns,
                count: self.count,
                counters: self.untracked_counters,
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
            out.push(RenderRow {
                name: format!("{blank:indent$}{label}", blank = "", label = r.label),
                avg: r.sum_ns / r.count.max(1),
                calls: Some(CallCount { total: r.count, per_parent: self.count }),
                counters: r.counters,
            });
            if let Some(child) = r.child {
                child.render_children(depth + 1, meta, out);
            }
        }
        if cut < rows.len() {
            let rem_sum: Nanos = rows[cut..].iter().map(|r| r.sum_ns).sum();
            let label = format!("... ({} more)", rows.len() - cut);
            out.push(RenderRow {
                name: format!("{blank:indent$}{label}", blank = ""),
                avg: rem_sum / self.count.max(1),
                calls: None,
                counters: Counters::default(),
            });
        }
    }
}

struct Row<'a> {
    label: Cow<'a, str>,
    sum_ns: Nanos,
    count: u64,
    counters: Counters,
    /// `None` for the synthetic `untracked` row — no subtree to recurse into.
    child: Option<&'a Node>,
}

struct CallCount {
    total: u64,
    per_parent: u64,
}

struct RenderRow {
    name: String,
    avg: Nanos,
    calls: Option<CallCount>,
    counters: Counters,
}

/// `instructions`/`cycles` feed the derived `ipc` column, so they aren't given
/// their own per-call column.
fn is_ipc_input(label: &str) -> bool {
    matches!(label, "instructions" | "cpu-cycles" | "cycles")
}

fn render_table(rows: &[RenderRow], meta: &FlamegraphMeta) -> String {
    let calls = |r: &RenderRow| r.calls.as_ref().map_or(0, |c| c.total);
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

    let mut columns = vec![Column::left("call path"), Column::right("avg"), Column::left("calls")];
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
        let mut cells = vec![r.name.clone(), r.avg.to_string(), calls_cell(&r.calls)];
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

fn calls_cell(calls: &Option<CallCount>) -> String {
    match calls {
        None => String::new(),
        // Root, or a parent that ran once → avg == total; show a plain count.
        Some(c) if c.per_parent <= 1 => format!("×{}", c.total),
        Some(c) => {
            let per = if c.total % c.per_parent == 0 {
                (c.total / c.per_parent).to_string()
            } else {
                format!("{:.1}", c.total as f64 / c.per_parent as f64)
            };
            format!("×{per}  ({} total)", c.total)
        }
    }
}
