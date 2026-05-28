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
        self.print_hash_validators_cost();
        self.print_call_tree();
        self.write_artifacts();
    }

    /// `Err` lists every breached ceiling; `None` ceilings are report-only.
    pub fn check_thresholds(&self) -> Result<(), String> {
        let mut breaches: Vec<String> = Vec::new();
        if let Some(max) = self.thresholds.max_ns_per_block {
            let per_block = self.outcome.wall_elapsed.as_nanos() as u64 / self.n_blocks();
            if per_block > max {
                breaches.push(format!(
                    "ns/block {} > ceiling {} (max_ns_per_block)",
                    Nanos(per_block),
                    Nanos(max),
                ));
            }
        }
        if let Some(max) = self.thresholds.max_hash_validators_ns_per_validator &&
            let Some(actual) = self.hash_validators_ns_per_validator() &&
            actual > max
        {
            breaches.push(format!(
                "hash_validators ns/validator {actual} > ceiling {max} \
                 (max_hash_validators_ns_per_validator)",
            ));
        }
        if breaches.is_empty() { Ok(()) } else { Err(breaches.join("; ")) }
    }

    fn hash_validators_ns_per_validator(&self) -> Option<u64> {
        let (sum, count) = self.outcome.stats.aggregate_leaf("hash_validators");
        let validators = self.outcome.validator_count as u64;
        (count > 0 && validators > 0).then(|| sum / count / validators)
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

    /// `hash_validators` summed across all call paths — the headline regression
    /// signal.
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
        let label = format!("finalized_{}_blocks_{}", self.finalized_slot, self.n_blocks());
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
