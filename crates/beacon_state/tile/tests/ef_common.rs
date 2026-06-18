#![cfg(feature = "ef_tests")]
#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use silver_beacon_state::{
    ssz_hash::{StateHashScratch, hash_tree_root_state},
    state_transition,
};
use silver_beacon_state_data::{
    EpochGroup, EpochView, LongtailGroup, SpecConfig, StateId, StateWriterView,
    effective_randao_mixes_into, effective_slashings_into,
};

#[path = "support/loaded_state.rs"]
mod loaded_state;
#[allow(unused_imports)]
pub use loaded_state::{LoadedState, load_state, snappy_decode};

impl LoadedState {
    /// The loaded state's working slot number (resolved through the slot
    /// group, keyed by the bundle's `slot_idx`).
    pub fn slot(&self) -> u64 {
        self.bs.slot_states.view(self.state_id.slot_idx).slot_number()
    }

    /// hash_tree_root of the loaded state (single-leaf merkle-proof checks).
    pub fn state_root(&mut self) -> [u8; 32] {
        let sid = self.state_id;
        let (view, epoch, longtail) = self.view();
        let rv = view.read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx));
        hash_tree_root_state(&rv, &mut StateHashScratch::new())
    }

    /// Roll a fork, run `f` over its writer view, then commit with the
    /// inherited epoch/longtail ids and write the bundle back.
    pub fn with_view<R>(&mut self, f: impl FnOnce(&mut StateWriterView<'_>) -> R) -> R {
        let sid = self.state_id;
        let (mut view, _, _) = self.view();
        let r = f(&mut view);
        self.state_id = view.commit(sid.epoch_idx, sid.longtail_idx);
        r
    }

    /// [`with_view`](Self::with_view) with the inherited epoch view resolved
    /// alongside.
    pub fn with_view_and_epoch<R>(
        &mut self,
        f: impl FnOnce(&mut StateWriterView<'_>, &EpochView<'_>) -> R,
    ) -> R {
        let sid = self.state_id;
        let (mut view, epoch, _) = self.view();
        let epoch_view = epoch.view_opt(sid.epoch_idx);
        let r = f(&mut view, &epoch_view);
        self.state_id = view.commit(sid.epoch_idx, sid.longtail_idx);
        r
    }

    /// Roll a fork, apply a signed block (slot advance + STF), then commit
    /// the (possibly epoch/longtail-rolled) bundle and write it back so the
    /// next block / the post-state comparison sees it.
    pub fn apply_block(&mut self, cfg: &SpecConfig, block_ssz: &[u8]) -> Result<(), String> {
        let parent = self.state_id;
        let (mut view, epoch, longtail) = self.view();
        match state_transition::apply_signed_block_debug(
            cfg, &mut view, epoch, longtail, parent, block_ssz,
        ) {
            Ok((epoch_idx, longtail_idx)) => {
                self.state_id = view.commit(epoch_idx, longtail_idx);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

const MAX_DIFFS: usize = 150;

/// Walk two iterators in lockstep, appending a formatted diff per mismatch.
/// Saturating: pushes a trailing `(truncated)` marker and returns once the
/// global cap is hit.
fn diff_iter<T, I, J>(
    diffs: &mut Vec<String>,
    n: usize,
    mut a: I,
    mut b: J,
    fmt: impl Fn(usize, T, T) -> String,
) where
    T: Eq,
    I: Iterator<Item = T>,
    J: Iterator<Item = T>,
{
    for i in 0..n {
        let (av, bv) = (a.next().unwrap(), b.next().unwrap());
        if av != bv {
            if diffs.len() >= MAX_DIFFS {
                diffs.push("  ... (truncated)".to_string());
                return;
            }
            diffs.push(fmt(i, av, bv));
        }
    }
}

pub fn compare_states(label: &str, a: &mut LoadedState, b: &mut LoadedState) -> Vec<String> {
    let mut diffs = Vec::new();

    let sid_a = a.state_id;
    let sid_b = b.state_id;
    let (va, epoch_a, longtail_a) = a.view();
    let (vb, epoch_b, longtail_b) = b.view();

    let mut scratch = StateHashScratch::new();
    let mut root_of =
        |view: &StateWriterView, sid: StateId, epoch: &EpochGroup, longtail: &LongtailGroup| {
            let rv = view.read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx));
            hash_tree_root_state(&rv, &mut scratch)
        };
    let root_a = root_of(&va, sid_a, epoch_a, longtail_a);
    let root_b = root_of(&vb, sid_b, epoch_b, longtail_b);
    if root_a == root_b {
        return diffs;
    }
    diffs.push(format!(
        "{label}: state root mismatch: got {}, expected {}",
        hex(&root_a),
        hex(&root_b)
    ));

    let ea = epoch_a.view_opt(sid_a.epoch_idx);
    let eb = epoch_b.view_opt(sid_b.epoch_idx);

    diff_scalars(&mut diffs, &va, &ea, &vb, &eb);

    let n = va.validators.count().min(vb.validators.count());
    diff_validator_columns(&mut diffs, &va, &vb, n);
    diff_rings(&mut diffs, &va, &ea, &vb, &eb);
    diff_latest_block_header(&mut diffs, &va, &vb);
    diff_proposer_lookahead(&mut diffs, &ea, &eb);

    diffs
}

fn diff_scalars(
    diffs: &mut Vec<String>,
    va: &StateWriterView,
    ea: &EpochView,
    vb: &StateWriterView,
    eb: &EpochView,
) {
    if va.slot.state().slot != vb.slot.state().slot {
        diffs.push(format!("  slot: {} vs {}", va.slot.state().slot, vb.slot.state().slot));
    }
    let a_cnt = va.validators.count();
    let b_cnt = vb.validators.count();
    if a_cnt != b_cnt {
        diffs.push(format!("  validator_count: {a_cnt} vs {b_cnt}"));
    }
    let a_epoch = ea.state();
    let b_epoch = eb.state();
    if a_epoch.justification_bits != b_epoch.justification_bits {
        diffs.push(format!(
            "  justification_bits: {:#06b} vs {:#06b}",
            a_epoch.justification_bits, b_epoch.justification_bits
        ));
    }
    if a_epoch.finalized_checkpoint != b_epoch.finalized_checkpoint {
        diffs.push(format!(
            "  finalized_checkpoint: epoch {} vs {}",
            a_epoch.finalized_checkpoint.epoch, b_epoch.finalized_checkpoint.epoch
        ));
    }
    if a_epoch.current_justified_checkpoint != b_epoch.current_justified_checkpoint {
        diffs.push(format!(
            "  current_justified: epoch {} vs {}",
            a_epoch.current_justified_checkpoint.epoch, b_epoch.current_justified_checkpoint.epoch
        ));
    }
    if a_epoch.previous_justified_checkpoint != b_epoch.previous_justified_checkpoint {
        diffs.push(format!(
            "  previous_justified: epoch {} vs {}",
            a_epoch.previous_justified_checkpoint.epoch,
            b_epoch.previous_justified_checkpoint.epoch
        ));
    }
    let a_slot = va.slot.state();
    let b_slot = vb.slot.state();
    if a_slot.earliest_exit_epoch != b_slot.earliest_exit_epoch {
        diffs.push(format!(
            "  earliest_exit_epoch: {} vs {}",
            a_slot.earliest_exit_epoch, b_slot.earliest_exit_epoch
        ));
    }
    if a_slot.exit_balance_to_consume != b_slot.exit_balance_to_consume {
        diffs.push(format!(
            "  exit_balance_to_consume: {} vs {}",
            a_slot.exit_balance_to_consume, b_slot.exit_balance_to_consume
        ));
    }
    if a_slot.randao_mix_current != b_slot.randao_mix_current {
        diffs.push(format!(
            "  randao_mix_current: {} vs {}",
            hex(&a_slot.randao_mix_current),
            hex(&b_slot.randao_mix_current),
        ));
    }
}

fn diff_validator_columns(
    diffs: &mut Vec<String>,
    va: &StateWriterView,
    vb: &StateWriterView,
    n: usize,
) {
    diff_iter(diffs, n, va.balances.iter(), vb.balances.iter(), |i, av, bv| {
        format!("  balance[{i}]: {av} vs {bv}")
    });
    diff_iter(diffs, n, va.inactivity.iter(), vb.inactivity.iter(), |i, av, bv| {
        format!("  inactivity[{i}]: {av} vs {bv}")
    });
    diff_iter(
        diffs,
        n,
        va.current_participation.iter(),
        vb.current_participation.iter(),
        |i, av, bv| format!("  curr_participation[{i}]: {av:#04x} vs {bv:#04x}"),
    );
    diff_iter(
        diffs,
        n,
        va.previous_participation.iter(),
        vb.previous_participation.iter(),
        |i, av, bv| format!("  prev_participation[{i}]: {av:#04x} vs {bv:#04x}"),
    );
    diff_iter(
        diffs,
        n,
        va.validators.iter_effective_balances(),
        vb.validators.iter_effective_balances(),
        |i, av, bv| format!("  effective_balance[{i}]: {av} vs {bv}"),
    );
    diff_iter(
        diffs,
        n,
        va.validators.iter_exit_epochs(),
        vb.validators.iter_exit_epochs(),
        |i, av, bv| format!("  exit_epoch[{i}]: {av} vs {bv}"),
    );
    diff_iter(
        diffs,
        n,
        va.validators.iter_withdrawable_epochs(),
        vb.validators.iter_withdrawable_epochs(),
        |i, av, bv| format!("  withdrawable_epoch[{i}]: {av} vs {bv}"),
    );
    diff_iter(
        diffs,
        n,
        va.validators.iter_activation_epochs(),
        vb.validators.iter_activation_epochs(),
        |i, av, bv| format!("  activation_epoch[{i}]: {av} vs {bv}"),
    );
    diff_iter(diffs, n, va.validators.iter_slashed(), vb.validators.iter_slashed(), |i, av, bv| {
        format!("  slashed[{i}]: {av} vs {bv}")
    });
}

fn diff_rings(
    diffs: &mut Vec<String>,
    va: &StateWriterView,
    ea: &EpochView,
    vb: &StateWriterView,
    eb: &EpochView,
) {
    let (mut sa, mut sb) = (Vec::new(), Vec::new());
    effective_slashings_into(ea, &va.slot.reader(), &mut sa);
    effective_slashings_into(eb, &vb.slot.reader(), &mut sb);
    diff_iter(
        diffs,
        sa.len().min(sb.len()),
        sa.iter().copied(),
        sb.iter().copied(),
        |i, av, bv| format!("  slashings[{i}]: {av} vs {bv}"),
    );
    let (mut ra, mut rb) = (Vec::new(), Vec::new());
    effective_randao_mixes_into(ea, &va.slot.reader(), &mut ra);
    effective_randao_mixes_into(eb, &vb.slot.reader(), &mut rb);
    diff_iter(
        diffs,
        ra.len().min(rb.len()),
        ra.iter().copied(),
        rb.iter().copied(),
        |i, av, bv| format!("  randao[{i}]: {} vs {}", hex(&av), hex(&bv)),
    );
}

fn diff_latest_block_header(diffs: &mut Vec<String>, va: &StateWriterView, vb: &StateWriterView) {
    let alh = va.slot.state().latest_block_header;
    let blh = vb.slot.state().latest_block_header;
    if alh.slot == blh.slot &&
        alh.proposer_index == blh.proposer_index &&
        alh.parent_root == blh.parent_root &&
        alh.state_root == blh.state_root &&
        alh.body_root == blh.body_root
    {
        return;
    }
    diffs.push(format!("  latest_block_header.slot: {} vs {}", alh.slot, blh.slot));
    if alh.body_root != blh.body_root {
        diffs.push(format!(
            "  latest_block_header.body_root: {} vs {}",
            hex(&alh.body_root),
            hex(&blh.body_root)
        ));
    }
    if alh.state_root != blh.state_root {
        diffs.push(format!(
            "  latest_block_header.state_root: {} vs {}",
            hex(&alh.state_root),
            hex(&blh.state_root)
        ));
    }
}

fn diff_proposer_lookahead(diffs: &mut Vec<String>, ea: &EpochView, eb: &EpochView) {
    let a = &ea.state().proposer_lookahead;
    let b = &eb.state().proposer_lookahead;
    if a == b {
        return;
    }
    diff_iter(diffs, a.len(), a.iter().copied(), b.iter().copied(), |i, av, bv| {
        format!("  proposer_lookahead[{i}]: {av} vs {bv}")
    });
}

pub fn iter_test_cases(handler_path: &Path) -> Vec<(String, PathBuf)> {
    let mut cases = Vec::new();
    let Ok(suites) = fs::read_dir(handler_path) else {
        return cases;
    };
    for suite in suites.flatten() {
        if !suite.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(tests) = fs::read_dir(suite.path()) else {
            continue;
        };
        for test in tests.flatten() {
            if test.file_type().is_ok_and(|t| t.is_dir()) {
                let name = format!(
                    "{}/{}",
                    suite.file_name().to_string_lossy(),
                    test.file_name().to_string_lossy()
                );
                cases.push((name, test.path()));
            }
        }
    }
    cases.sort_by(|a, b| a.0.cmp(&b.0));
    cases
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn spec_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("consensus-spec-tests")
}
