//! Pretty-print one perf run to stderr and dump JSON + flamegraph-folded
//! artifacts to disk.

use std::path::PathBuf;

use silver_common::Nanos;

use crate::perf::{BlockWorkload, Fixtures, fixtures_dir::Thresholds, replay::ReplayOutcome};

pub struct PerfReport {
    outcome: ReplayOutcome,
    workloads: Vec<BlockWorkload>,
    finalized_slot: u64,
    out_dir: PathBuf,
    thresholds: Thresholds,
}

impl PerfReport {
    pub fn new(outcome: ReplayOutcome, fixtures: &Fixtures, out_dir: PathBuf) -> Self {
        let workloads = fixtures.blocks.iter().map(|b| BlockWorkload::from_block_ssz(b)).collect();
        Self {
            outcome,
            workloads,
            finalized_slot: fixtures.finalized_slot,
            out_dir,
            thresholds: fixtures.thresholds,
        }
    }

    pub fn emit(&self) {
        self.print_replay_timing();
        self.print_workload();
        self.print_key_metrics();
        self.print_call_tree();
        self.write_artifacts();
    }

    /// `Err` lists every breached threshold; `None` thresholds are report-only.
    pub fn check_thresholds(&self) -> Result<(), String> {
        let breaches: Vec<Gauge> = self.gauges().into_iter().filter(|g| g.breached()).collect();
        if breaches.is_empty() {
            return Ok(());
        }
        let mut out = String::from("thresholds breached:\n");
        for g in &breaches {
            out.push_str(&g.render_breach());
            out.push('\n');
        }
        Err(out)
    }

    /// Shared by `print_key_metrics` and `check_thresholds` so both views
    /// agree on the same set of metrics in the same order.
    fn gauges(&self) -> Vec<Gauge> {
        let t = &self.thresholds;
        vec![
            Gauge {
                label: "decompose_beacon_state",
                actual: self.frame_total_ns("decompose_beacon_state"),
                threshold: t.max_decompose_beacon_state,
            },
            Gauge {
                label: "apply_block (mean)",
                actual: self.frame_mean_ns("apply_block"),
                threshold: t.max_apply_block_mean,
            },
            Gauge {
                label: "hash_tree_root_state (mean)",
                actual: self.frame_mean_ns("hash_tree_root_state"),
                threshold: t.max_hash_tree_root_state_mean,
            },
        ]
    }

    fn frame_total_ns(&self, frame: &str) -> Option<u64> {
        let (sum, count) = self.outcome.stats.aggregate_leaf(frame);
        (count > 0).then_some(sum)
    }

    fn frame_mean_ns(&self, frame: &str) -> Option<u64> {
        let (sum, count) = self.outcome.stats.aggregate_leaf(frame);
        (count > 0).then(|| sum / count)
    }

    fn n_blocks(&self) -> u64 {
        self.workloads.len() as u64
    }

    fn print_replay_timing(&self) {
        let wall_ns = self.outcome.wall_elapsed.as_nanos() as u64;
        let n = self.n_blocks();
        eprintln!(
            "\nperf: replay {} over {n} blocks ({}/block)\n",
            Nanos(wall_ns),
            Nanos(wall_ns / n)
        );
    }

    /// Per-block averages — workload normalises timings as the finalized slot
    /// moves.
    fn print_workload(&self) {
        let n_blocks = self.workloads.len();
        let sum = |f: fn(&BlockWorkload) -> usize| self.workloads.iter().map(f).sum::<usize>();
        let per_block = |total: usize| total as f64 / n_blocks as f64;
        eprintln!("Workload (finalized slot {}, {n_blocks} blocks):", self.finalized_slot);
        eprintln!("  validators (head)         {}", self.outcome.validator_count);
        eprintln!("  attestations              {:.1}/block", per_block(sum(|w| w.attestations)));
        eprintln!(
            "  sync bits set             {:.0}/block of 512",
            per_block(sum(|w| w.sync_bits_set))
        );
    }

    /// Renders the same gauge set `check_thresholds` panics on, so success
    /// runs and failures show the same numbers.
    fn print_key_metrics(&self) {
        eprintln!("\nKey metrics (thresholded):");
        for g in self.gauges() {
            eprintln!("  {}", g.render_row());
        }
    }

    fn print_call_tree(&self) {
        eprintln!("\nCall tree:");
        eprint!("{}", self.outcome.stats.call_tree());
    }

    /// Writes the structured per-path JSON only. Folded stacks aren't
    /// persisted: each path's `total_untracked_ns` lives in the JSON, so a
    /// flamegraph can be regenerated on demand with e.g.
    /// `jq -r '.paths[] | "\(.path) \(.total_untracked_ns)"' perf-*.json`.
    fn write_artifacts(&self) {
        let label = format!("finalized_{}_blocks_{}", self.finalized_slot, self.n_blocks());
        std::fs::create_dir_all(&self.out_dir).expect("create perf output dir");
        let json_path = self.out_dir.join(format!("perf-{label}.json"));
        std::fs::write(&json_path, self.outcome.stats.to_json(&label)).expect("write perf JSON");
        let display = std::fs::canonicalize(&json_path).unwrap_or_else(|_| json_path.clone());
        eprintln!("\nperf: JSON {}", display.display());
    }
}

struct Gauge {
    label: &'static str,
    actual: Option<u64>,
    threshold: Option<u64>,
}

impl Gauge {
    fn breached(&self) -> bool {
        matches!((self.actual, self.threshold), (Some(a), Some(c)) if a > c)
    }

    fn render_row(&self) -> String {
        let actual = self.actual.map(|v| Nanos(v).to_string()).unwrap_or_else(|| "n/a".into());
        let (threshold, status) = match (self.actual, self.threshold) {
            (_, None) => ("—".to_string(), "(no threshold)"),
            (Some(a), Some(c)) if a > c => (Nanos(c).to_string(), "BREACH"),
            (_, Some(c)) => (Nanos(c).to_string(), "ok"),
        };
        format!(
            "{label:<32}  actual {actual:>10}   threshold {threshold:>10}   {status}",
            label = self.label,
        )
    }

    /// Breach-panic row — same layout as `render_row`, sans the status
    /// suffix (every row in the panic is a breach by construction).
    fn render_breach(&self) -> String {
        let actual = self.actual.map(|v| Nanos(v).to_string()).unwrap_or_else(|| "n/a".into());
        let threshold = self.threshold.map(|v| Nanos(v).to_string()).unwrap_or_else(|| "—".into());
        format!(
            "  {label:<32}  actual {actual:>10}   threshold {threshold:>10}",
            label = self.label,
        )
    }
}
