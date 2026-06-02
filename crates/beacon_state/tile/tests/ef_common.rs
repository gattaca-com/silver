#![cfg(feature = "ef_tests")]
#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use silver_beacon_state::ssz_hash::{StateHashScratch, hash_tree_root_state};
use silver_beacon_state_data::{
    DeltaBuffer, EPOCHS_RING_N, EpochStateDelta, Finalized, LONGTAILS_RING_N, LongtailState,
    SlotStateDelta, SpecConfig, StateDelta, StateDeltaView, ValidatorsDelta,
};

pub type EpochRing = DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>;
pub type LongtailRing = DeltaBuffer<LongtailState, LONGTAILS_RING_N>;

/// Snappy-decompress a file.
pub fn snappy_decode(path: &Path) -> Vec<u8> {
    let compressed = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    snap::Decoder::new()
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("{}: snappy: {e}", path.display()))
}

/// EF test state: a `Finalized` snapshot decoded from SSZ + an empty
/// `StateDelta` anchored on top, plus this fork's epoch/longtail rings.
/// State-transition runs mutate the delta; post-state comparison hashes via
/// `hash_tree_root_state` over a `StateDeltaView`.
pub struct LoadedState {
    pub finalized: Box<Finalized>,
    pub delta: StateDelta,
    pub epochs: EpochRing,
    pub longtails: LongtailRing,
}

fn anchored_delta(f: &Finalized) -> StateDelta {
    StateDelta {
        validators: ValidatorsDelta::new_at(&f.validators),
        // The delta carries a full working `SlotState`, seeded from the
        // finalized base (the tile does this via cow-from-parent). Copying
        // only the slot number would leave every other scalar
        // (`eth1_deposit_index`, `earliest_exit_epoch`, `randao_mix_current`,
        // …) at its default, which the view reads back as zero.
        slot: SlotStateDelta { slot: f.slot.slot, ..Default::default() },
        ..StateDelta::default()
    }
}

impl LoadedState {
    /// Merged read+write view over this loaded state.
    pub fn view(&mut self) -> StateDeltaView<'_> {
        StateDeltaView::new(&self.finalized, &mut self.delta, &mut self.epochs, &mut self.longtails)
    }
}

pub fn load_state(path: &Path) -> LoadedState {
    let ssz = snappy_decode(path);
    let mut finalized = Box::new(Finalized::empty());
    finalized
        .decompose(&ssz, &SpecConfig::mainnet())
        .unwrap_or_else(|e| panic!("{}: decompose failed: {e}", path.display()));
    let delta = anchored_delta(&finalized);
    LoadedState {
        finalized,
        delta,
        epochs: DeltaBuffer::default(),
        longtails: DeltaBuffer::default(),
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

    let va = a.view();
    let vb = b.view();

    let mut scratch = StateHashScratch::new();
    let root_a = hash_tree_root_state(&va, &mut scratch);
    let root_b = hash_tree_root_state(&vb, &mut scratch);
    if root_a == root_b {
        return diffs;
    }
    diffs.push(format!(
        "{label}: state root mismatch: got {}, expected {}",
        hex(&root_a),
        hex(&root_b)
    ));

    diff_scalars(&mut diffs, &va, &vb);

    let n = va.validators_count().min(vb.validators_count());
    diff_validator_columns(&mut diffs, &va, &vb, n);
    diff_rings(&mut diffs, &va, &vb);
    diff_latest_block_header(&mut diffs, &va, &vb);
    diff_proposer_lookahead(&mut diffs, &va, &vb);

    diffs
}

fn diff_scalars(diffs: &mut Vec<String>, va: &StateDeltaView, vb: &StateDeltaView) {
    if va.slot() != vb.slot() {
        diffs.push(format!("  slot: {} vs {}", va.slot(), vb.slot()));
    }
    let a_cnt = va.validators_count();
    let b_cnt = vb.validators_count();
    if a_cnt != b_cnt {
        diffs.push(format!("  validator_count: {a_cnt} vs {b_cnt}"));
    }
    let a_epoch = va.epoch_state();
    let b_epoch = vb.epoch_state();
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
    if va.earliest_exit_epoch() != vb.earliest_exit_epoch() {
        diffs.push(format!(
            "  earliest_exit_epoch: {} vs {}",
            va.earliest_exit_epoch(),
            vb.earliest_exit_epoch()
        ));
    }
    if va.exit_balance_to_consume() != vb.exit_balance_to_consume() {
        diffs.push(format!(
            "  exit_balance_to_consume: {} vs {}",
            va.exit_balance_to_consume(),
            vb.exit_balance_to_consume()
        ));
    }
    if va.randao_mix_current() != vb.randao_mix_current() {
        diffs.push(format!(
            "  randao_mix_current: {} vs {}",
            hex(&va.randao_mix_current()),
            hex(&vb.randao_mix_current()),
        ));
    }
}

fn diff_validator_columns(
    diffs: &mut Vec<String>,
    va: &StateDeltaView,
    vb: &StateDeltaView,
    n: usize,
) {
    diff_iter(diffs, n, va.iter_validator_balances(), vb.iter_validator_balances(), |i, av, bv| {
        format!("  balance[{i}]: {av} vs {bv}")
    });
    diff_iter(diffs, n, va.iter_inactivity_scores(), vb.iter_inactivity_scores(), |i, av, bv| {
        format!("  inactivity[{i}]: {av} vs {bv}")
    });
    diff_iter(
        diffs,
        n,
        va.iter_current_epoch_participants(),
        vb.iter_current_epoch_participants(),
        |i, av, bv| format!("  curr_participation[{i}]: {av:#04x} vs {bv:#04x}"),
    );
    diff_iter(
        diffs,
        n,
        va.iter_previous_epoch_participants(),
        vb.iter_previous_epoch_participants(),
        |i, av, bv| format!("  prev_participation[{i}]: {av:#04x} vs {bv:#04x}"),
    );
    diff_iter(
        diffs,
        n,
        va.iter_validator_effective_balances(),
        vb.iter_validator_effective_balances(),
        |i, av, bv| format!("  effective_balance[{i}]: {av} vs {bv}"),
    );
    diff_iter(diffs, n, va.iter_exit_epochs(), vb.iter_exit_epochs(), |i, av, bv| {
        format!("  exit_epoch[{i}]: {av} vs {bv}")
    });
    diff_iter(
        diffs,
        n,
        va.iter_withdrawable_epochs(),
        vb.iter_withdrawable_epochs(),
        |i, av, bv| format!("  withdrawable_epoch[{i}]: {av} vs {bv}"),
    );
    diff_iter(diffs, n, va.iter_activation_epochs(), vb.iter_activation_epochs(), |i, av, bv| {
        format!("  activation_epoch[{i}]: {av} vs {bv}")
    });
    diff_iter(diffs, n, va.iter_slashed(), vb.iter_slashed(), |i, av, bv| {
        format!("  slashed[{i}]: {av} vs {bv}")
    });
}

fn diff_rings(diffs: &mut Vec<String>, va: &StateDeltaView, vb: &StateDeltaView) {
    let (mut sa, mut sb) = (Vec::new(), Vec::new());
    va.effective_slashings_into(&mut sa);
    vb.effective_slashings_into(&mut sb);
    diff_iter(
        diffs,
        sa.len().min(sb.len()),
        sa.iter().copied(),
        sb.iter().copied(),
        |i, av, bv| format!("  slashings[{i}]: {av} vs {bv}"),
    );
    let (mut ra, mut rb) = (Vec::new(), Vec::new());
    va.effective_randao_mixes_into(&mut ra);
    vb.effective_randao_mixes_into(&mut rb);
    diff_iter(
        diffs,
        ra.len().min(rb.len()),
        ra.iter().copied(),
        rb.iter().copied(),
        |i, av, bv| format!("  randao[{i}]: {} vs {}", hex(&av), hex(&bv)),
    );
}

fn diff_latest_block_header(diffs: &mut Vec<String>, va: &StateDeltaView, vb: &StateDeltaView) {
    let alh = va.latest_block_header();
    let blh = vb.latest_block_header();
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

fn diff_proposer_lookahead(diffs: &mut Vec<String>, va: &StateDeltaView, vb: &StateDeltaView) {
    let a = &va.epoch_state().proposer_lookahead;
    let b = &vb.epoch_state().proposer_lookahead;
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
