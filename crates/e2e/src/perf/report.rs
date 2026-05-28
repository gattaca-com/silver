//! Pretty-print one perf run to stderr and dump JSON + flamegraph-folded
//! artifacts to disk.

use std::path::{Path, PathBuf};

use silver_common::Nanos;

use crate::perf::{BlockWorkload, Fixtures, replay::ReplayOutcome};

pub struct PerfReport {
    outcome: ReplayOutcome,
    workloads: Vec<BlockWorkload>,
    anchor_slot: u64,
    out_dir: PathBuf,
}

impl PerfReport {
    pub fn new(outcome: ReplayOutcome, fixtures: &Fixtures, out_dir: PathBuf) -> Self {
        let workloads = fixtures.blocks.iter().map(|b| BlockWorkload::from_block_ssz(b)).collect();
        Self { outcome, workloads, anchor_slot: fixtures.anchor_slot, out_dir }
    }

    pub fn emit(&self) {
        self.print_replay_timing();
        self.print_workload();
        self.print_hash_validators_cost();
        self.print_call_tree();
        self.write_artifacts();
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

    /// The anchor moves run-to-run, so record the work the timings were paid
    /// against; per-block averages let CI compare across moving anchors.
    fn print_workload(&self) {
        let n_blocks = self.workloads.len();
        let sum = |f: fn(&BlockWorkload) -> usize| self.workloads.iter().map(f).sum::<usize>();
        let per_block = |total: usize| total as f64 / n_blocks as f64;
        eprintln!("Workload (anchor slot {}, {n_blocks} blocks):", self.anchor_slot);
        eprintln!("  validators (head)         {}", self.outcome.validator_count);
        eprintln!("  attestations              {:.1}/block", per_block(sum(|w| w.attestations)));
        eprintln!(
            "  sync bits set             {:.0}/block of 512",
            per_block(sum(|w| w.sync_bits_set))
        );
    }

    /// Cost normalised by work — stable across moving anchors, so the
    /// headline regression signal. `hash_validators` fires from several call
    /// sites and dominates, so sum it across every path.
    fn print_hash_validators_cost(&self) {
        let (hv_sum, hv_count) = self.outcome.stats.aggregate_leaf("hash_validators");
        if hv_count > 0 && self.outcome.validator_count > 0 {
            eprintln!(
                "\n  hash_validators   {:.1} ns/validator ({hv_count} calls)",
                (hv_sum / hv_count) as f64 / self.outcome.validator_count as f64,
            );
        }
    }

    fn print_call_tree(&self) {
        eprint!("{}", self.outcome.stats.call_tree());
    }

    fn write_artifacts(&self) {
        let label = format!("anchor_{}_blocks_{}", self.anchor_slot, self.n_blocks());
        let _ = std::fs::create_dir_all(&self.out_dir);
        let json_path = self.out_dir.join(format!("perf-{label}.json"));
        std::fs::write(&json_path, self.outcome.stats.to_json(&label)).expect("write perf JSON");
        let folded_path = self.out_dir.join(format!("perf-{label}.folded"));
        std::fs::write(&folded_path, self.outcome.stats.flamegraph_stacks())
            .expect("write folded stacks");
        eprintln!(
            "\nperf: JSON {}\nperf: flamegraph stacks {}",
            json_path.display(),
            folded_path.display()
        );
    }
}

/// Resolve the artifact directory from the user-supplied JSON path env
/// (defaults to the workspace `target/`).
pub fn default_output_dir(json_env: Option<&str>, fallback: &Path) -> PathBuf {
    match json_env {
        Some(v) => {
            PathBuf::from(v).parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
        }
        None => fallback.to_path_buf(),
    }
}
