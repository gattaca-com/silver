//! Summarise drained #[timed] call paths into a deterministic call tree; each
//! path is the measured timed-frame chain, so containment holds by
//! construction.

use std::{borrow::Cow, collections::HashMap};

use flux::timing::Nanos;

use crate::{flamegraph_timer::collect::drain, perf::PerfSample, slot};

#[derive(serde::Serialize)]
struct PathStat {
    #[serde(serialize_with = "join_path")]
    path: Vec<String>,
    count: u64,
    tracked_avg_ns: Nanos,
    tracked_p50_ns: Nanos,
    tracked_p99_ns: Nanos,
    tracked_max_ns: Nanos,
    tracked_sum_ns: Nanos,
    total_untracked_ns: Nanos,
    /// Summed counter deltas over all calls on this path, and the same
    /// excluding timed children (mirroring `total_untracked_ns`). All-zero
    /// unless built with the `perf` feature (and `perf_event_open` permitted).
    tracked_perf: PerfSample,
    untracked_perf: PerfSample,
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
                    tracked_p50_ns: Nanos(percentile(&samples, 0.50)),
                    tracked_p99_ns: Nanos(percentile(&samples, 0.99)),
                    tracked_max_ns: Nanos(samples.last().copied().unwrap_or(0)),
                    tracked_sum_ns: Nanos(u64::try_from(sum).unwrap_or(u64::MAX)),
                    total_untracked_ns: Nanos(timing.samples.total_untracked_ns),
                    tracked_perf: timing.samples.tracked_perf,
                    untracked_perf: timing.samples.total_untracked_perf,
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
            .filter(|s| s.path.last().is_some_and(|n| leaf_name(n).as_ref() == leaf))
            .fold((Nanos::ZERO, 0), |(sum, cnt), s| (sum + s.tracked_sum_ns, cnt + s.count))
    }

    /// Slowest single tracked sample across every path whose leaf is `leaf`
    /// — the worst-case call, regardless of call site. `None` if no such path.
    pub fn aggregate_leaf_max(&self, leaf: &str) -> Option<Nanos> {
        self.0
            .iter()
            .filter(|s| s.path.last().is_some_and(|n| leaf_name(n).as_ref() == leaf))
            .map(|s| s.tracked_max_ns)
            .max()
    }

    /// Median (p50) tracked sample for `leaf`. Percentiles aren't combinable
    /// across call sites, so this takes the max p50 over matching paths — exact
    /// for a single-call-site leaf (e.g. the top-level `apply_block`). `None`
    /// if no such path.
    pub fn aggregate_leaf_p50(&self, leaf: &str) -> Option<Nanos> {
        self.0
            .iter()
            .filter(|s| s.path.last().is_some_and(|n| leaf_name(n).as_ref() == leaf))
            .map(|s| s.tracked_p50_ns)
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
            node.perf = s.tracked_perf;
            node.untracked_perf = s.untracked_perf;
        }

        let mut lines = Vec::new();
        root.render_children(0, &mut lines);
        render_aligned(&lines)
    }

    /// Deterministic JSON `{label, paths}` — see `PathStat` for the per-path
    /// schema.
    pub fn to_json(&self, label: &str) -> String {
        serde_json::json!({ "label": label, "paths": &self.0 }).to_string()
    }
}

/// Display/identity leaf for a frame path segment.
///
/// A plain `#[timed]` free-function frame is `module::path::fn` → the trailing
/// `::fn`. A `#[timed]` method frame embeds its receiver as a
/// `…::fn::__TimedTy<ConcreteSelf>` marker (so each monomorphization is a
/// distinct frame — the type a string-keyed sink can't otherwise tell apart);
/// here we unwrap it into a `fn<Type>` label. Plain frames stay borrowed — the
/// threshold gauges match on these and must be unaffected.
fn leaf_name(qualified: &str) -> Cow<'_, str> {
    const MARK: &str = "::__TimedTy<";
    if let Some(at) = qualified.find(MARK) {
        let func = qualified[..at].rsplit("::").next().unwrap_or(&qualified[..at]);
        // The marker wraps exactly the receiver type; drop its closing `>`.
        let ty = &qualified[at + MARK.len()..];
        let ty = ty.strip_suffix('>').unwrap_or(ty);
        return Cow::Owned(format!("{func}<{}>", strip_module_paths(&strip_lifetimes(ty))));
    }
    Cow::Borrowed(qualified.rsplit("::").next().unwrap_or(qualified))
}

/// Minimal "short type name": `type_name` is fully qualified
/// (`crate::col::ColumnGroup<crate::col::Balances>`); keep only the last `::`
/// segment of each path, preserving generic punctuation — yielding
/// `ColumnGroup<Balances>`. (Same job as `disqualified::ShortName` / `tynm`,
/// inlined to keep this low-level crate dependency-free.)
///
/// `rsplit("::")` alone won't do — `::` also appears inside generic args — so
/// we split on the generic punctuation first, then take each path's leaf.
fn strip_module_paths(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for chunk in s.split_inclusive(['<', '>', ',', ' ']) {
        // `split_inclusive` keeps the delimiter as the chunk's last char, so a
        // chunk is one path plus a trailing delimiter, e.g. `crate::mod::T<`
        // (the final chunk may have none). The delimiters are ASCII, so the
        // split below always lands on a char boundary.
        let (path, delim) = match chunk.as_bytes().last() {
            Some(b'<' | b'>' | b',' | b' ') => {
                (&chunk[..chunk.len() - 1], &chunk[chunk.len() - 1..])
            }
            _ => (chunk, ""),
        };
        out.push_str(path.rsplit("::").next().unwrap_or(path));
        out.push_str(delim);
    }
    out
}

/// Drop lifetime arguments from a `type_name` string so a receiver renders
/// `ColumnWriteView<Current>` rather than `ColumnWriteView<'_, Current>`. A
/// lifetime is `'` + ident; a following `, ` separator (the lifetime was a
/// leading generic arg) is dropped with it.
fn strip_lifetimes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        if bytes[i] == b'\'' {
            i += 1;
            while i < s.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            if s[i..].starts_with(", ") {
                i += 2;
            } else if i < s.len() && bytes[i] == b',' {
                i += 1;
            }
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
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
    perf: PerfSample,
    untracked_perf: PerfSample,
    children: HashMap<String, Node>,
}

/// Children accounting for less than this fraction of a node's time are
/// folded into a single `...` row, keeping the tree focused on the
/// dominant costs.
const COVERAGE_PCT: u64 = 99;

/// One rendered row, held as parts so [`render_aligned`] can line up the avg
/// (ns) column past the widest label and the counter column past the widest
/// prefix — both vary with label length, so neither can use a fixed column.
struct Line {
    name: String,
    avg: String,
    suffix: String,
    /// Counter text; `None` for synthetic rows and when `perf` is off.
    counters: Option<String>,
}

fn width(s: &str) -> usize {
    s.chars().count()
}

/// Assemble rows into the tree: avg right-aligned just past the widest label,
/// then the counter column just past the widest prefix that carries counters.
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

impl Node {
    fn render_children(&self, depth: usize, out: &mut Vec<Line>) {
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
            out.push(make_line(indent, r.label.as_ref(), avg, count, &r.perf, r.count));
            if let Some(child) = r.child {
                child.render_children(depth + 1, out);
            }
        }
        if cut < rows.len() {
            let rem_sum: Nanos = rows[cut..].iter().map(|r| r.sum_ns).sum();
            let rem_avg = rem_sum / self.count.max(1);
            let label = format!("... ({} more)", rows.len() - cut);
            out.push(make_line(indent, &label, rem_avg, None, &PerfSample::default(), 0));
        }
    }
}

struct Row<'a> {
    label: Cow<'a, str>,
    sum_ns: Nanos,
    count: u64,
    /// Summed counter deltas for this frame; all-zero for the synthetic
    /// `untracked`/fold rows and when the `perf` feature is off.
    perf: PerfSample,
    /// `None` for the synthetic `untracked` row (no subtree to recurse into).
    child: Option<&'a Node>,
}

/// `per_parent == 0` ⇒ no parent context (root row).
struct CallCount {
    total: u64,
    per_parent: u64,
}

fn make_line(
    indent: usize,
    label: &str,
    avg: Nanos,
    count: Option<CallCount>,
    perf: &PerfSample,
    calls: u64,
) -> Line {
    let name = format!("{blank:indent$}{label}", blank = "");
    let avg = avg.to_string();
    let suffix = match count {
        None => String::new(),
        // No parent (root) or parent ran once → avg == total; show plain count.
        Some(c) if c.per_parent <= 1 => format!("  ×{}", c.total),
        Some(c) => {
            // avg calls per parent invocation; integer when divisible.
            let per = if c.total % c.per_parent == 0 {
                (c.total / c.per_parent).to_string()
            } else {
                format!("{:.1}", c.total as f64 / c.per_parent as f64)
            };
            format!("  ×{per}  ({} total)", c.total)
        }
    };
    let counters = counter_text(perf, calls);
    Line { name, avg, suffix, counters }
}

/// Per-call counter columns from the runtime [`schema`](crate::schema): each
/// non-IPC-input event as `N label/call`, then IPC derived from the
/// `instructions`/`cpu-cycles` slots if both were measured. `None` when no
/// counters were collected (the `perf` feature is off or this is a synthetic
/// row).
fn counter_text(perf: &PerfSample, calls: u64) -> Option<String> {
    if calls == 0 || perf.vals.iter().all(|&v| v == 0) {
        return None;
    }
    let schema = crate::schema();
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
