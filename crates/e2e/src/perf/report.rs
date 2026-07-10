//! Pretty-print one perf run to stderr and dump the JSON artifact to disk.

use std::path::PathBuf;

use silver_common::Nanos;
use silver_metrics::table::{Column, Table};

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

    pub fn check_thresholds(&self) -> Result<(), String> {
        if self.outcome.stats.missed_events() {
            return Err("perf gate failed: a timing ring lost marks and the measurement is \
                        invalid; raise RING_CAPACITY in profiler::queue_dir"
                .into());
        }
        let failures: Vec<String> = self.gauges().iter().filter_map(Gauge::failure).collect();
        if failures.is_empty() {
            return Ok(());
        }
        Err(format!("perf gate failed:\n{}\n", failures.join("\n")))
    }

    /// Shared by `print_key_metrics` and `check_thresholds` so both views
    /// agree on the same set of metrics in the same order.
    fn gauges(&self) -> Vec<Gauge> {
        let t = &self.thresholds;
        vec![
            Gauge {
                label: "decompose",
                actual: self.frame_total_ns("decompose"),
                threshold: t.max_decompose,
            },
            Gauge {
                label: "apply_and_commit (p50)",
                actual: self
                    .outcome
                    .stats
                    .aggregate_leaf_p50("apply_stf_and_commit<BeaconStateTile>"),
                threshold: t.max_apply_and_commit_p50,
            },
            Gauge {
                label: "apply_and_commit (max)",
                actual: self
                    .outcome
                    .stats
                    .aggregate_leaf_max("apply_stf_and_commit<BeaconStateTile>"),
                threshold: t.max_apply_and_commit_max,
            },
            Gauge {
                label: "process_epoch (avg)",
                actual: self.frame_avg_ns("process_epoch"),
                threshold: t.max_process_epoch_avg,
            },
            Gauge {
                label: "hash_tree_root_state (avg)",
                actual: self.frame_avg_ns("hash_tree_root_state"),
                threshold: t.max_hash_tree_root_state_avg,
            },
            Gauge {
                label: "finalize (avg)",
                actual: self.frame_avg_ns("finalize<BeaconStateTile>"),
                threshold: t.max_finalize_avg,
            },
        ]
    }

    fn frame_total_ns(&self, frame: &str) -> Option<Nanos> {
        let (sum, count) = self.outcome.stats.aggregate_leaf(frame);
        (count > 0).then_some(sum)
    }

    fn frame_avg_ns(&self, frame: &str) -> Option<Nanos> {
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
        let mut table = Table::new(vec![
            Column::left("metric"),
            Column::right("actual"),
            Column::right("threshold"),
            Column::left("status"),
        ]);
        for g in self.gauges() {
            table.row(g.cells());
        }
        eprint!("{}", table.render());
    }

    fn print_call_tree(&self) {
        eprintln!("\nCall tree:");
        eprint!("{}", self.outcome.stats.call_tree());
    }

    /// Writes the structured per-thread/per-path JSON only. Folded stacks
    /// aren't persisted: each path's `total_untracked_ns` lives in the
    /// JSON, so a flamegraph can be regenerated on demand with e.g.
    /// `jq -r '.threads[].paths[] | "\(.path) \(.total_untracked_ns)"'
    /// perf-*.json`.
    fn write_artifacts(&self) {
        let label = format!("finalized_{}_blocks_{}", self.finalized_slot, self.n_blocks());
        std::fs::create_dir_all(&self.out_dir).expect("create perf output dir");
        let json_path = self.out_dir.join(format!("perf-{label}.json"));
        std::fs::write(&json_path, self.outcome.stats.to_json(&label)).expect("write perf JSON");
        let display = std::fs::canonicalize(&json_path).unwrap_or_else(|_| json_path.clone());
        eprintln!("\nperf: JSON {}", display.display());

        if let (Some(fxt_path), Some(bytes)) = (crate::perf::replay::fxt_path(), &self.outcome.fxt)
        {
            std::fs::write(&fxt_path, bytes).expect("write perf FXT");
            let display = std::fs::canonicalize(&fxt_path).unwrap_or(fxt_path);
            eprintln!("perf: FXT  {} ({} MiB)", display.display(), bytes.len() >> 20);
        }
    }
}

struct Gauge {
    label: &'static str,
    actual: Option<Nanos>,
    threshold: Option<Nanos>,
}

impl Gauge {
    fn failure(&self) -> Option<String> {
        match (self.actual, self.threshold) {
            (_, None) => None,
            (None, Some(_)) => Some(format!(
                "  {label:<32}  MISSING — `#[timed]` frame absent (renamed?)",
                label = self.label,
            )),
            (Some(a), Some(c)) if a > c => Some(self.render_breach()),
            (Some(_), Some(_)) => None,
        }
    }

    fn cells(&self) -> Vec<String> {
        let actual = self.actual.map(|v| v.to_string()).unwrap_or_else(|| "n/a".into());
        let (threshold, status) = match (self.actual, self.threshold) {
            (_, None) => ("—".to_string(), "(no threshold)"),
            (None, Some(c)) => (c.to_string(), "MISSING"),
            (Some(a), Some(c)) if a > c => (c.to_string(), "BREACH"),
            (_, Some(c)) => (c.to_string(), "ok"),
        };
        vec![self.label.to_string(), actual, threshold, status.to_string()]
    }

    /// Breach-panic row: a self-contained line for the failure message, which
    /// isn't rendered through the key-metrics table.
    fn render_breach(&self) -> String {
        let actual = self.actual.map(|v| v.to_string()).unwrap_or_else(|| "n/a".into());
        let threshold = self.threshold.map(|v| v.to_string()).unwrap_or_else(|| "—".into());
        format!(
            "  {label:<32}  actual {actual:>10}   threshold {threshold:>10}",
            label = self.label,
        )
    }
}
