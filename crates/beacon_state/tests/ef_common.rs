#![cfg(feature = "ef_tests")]
#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use silver_beacon_state::{
    decompose::decompose_beacon_state,
    ssz_hash::hash_tree_root_state,
    types::{
        B256, EpochData, HistoricalLongtail, Immutable, PendingQueues, SlotData, SlotRoots,
        ValidatorIdentity, box_zeroed,
    },
};

/// Snappy-decompress a file.
pub fn snappy_decode(path: &Path) -> Vec<u8> {
    let compressed = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    snap::Decoder::new()
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("{}: snappy: {e}", path.display()))
}

pub struct LoadedState {
    pub imm: Box<Immutable>,
    pub vid: Box<ValidatorIdentity>,
    pub longtail: Box<HistoricalLongtail>,
    pub epoch: Box<EpochData>,
    pub roots: Box<SlotRoots>,
    pub sd: Box<SlotData>,
    pub pq: PendingQueues,
}

impl LoadedState {
    pub fn blank_pub() -> Self {
        Self {
            imm: box_zeroed(),
            vid: box_zeroed(),
            longtail: box_zeroed(),
            epoch: box_zeroed(),
            roots: box_zeroed(),
            sd: box_zeroed(),
            pq: PendingQueues::new(),
        }
    }
}

pub fn load_state(path: &Path, zh: &[B256]) -> LoadedState {
    let ssz = snappy_decode(path);
    let mut s = LoadedState::blank_pub();
    let pq = decompose_beacon_state(
        &ssz,
        zh,
        &mut s.imm,
        &mut s.vid,
        &mut s.longtail,
        &mut s.epoch,
        &mut s.roots,
        &mut s.sd,
    )
    .unwrap_or_else(|| panic!("{}: decompose failed", path.display()));
    s.pq = pq;
    s
}

pub fn compare_states(label: &str, a: &LoadedState, b: &LoadedState, zh: &[B256]) -> Vec<String> {
    let mut diffs = Vec::new();

    let root_a =
        hash_tree_root_state(&a.imm, &a.vid, &a.longtail, &a.epoch, &a.roots, &a.sd, &a.pq, zh);
    let root_b =
        hash_tree_root_state(&b.imm, &b.vid, &b.longtail, &b.epoch, &b.roots, &b.sd, &b.pq, zh);
    if root_a != root_b {
        diffs.push(format!(
            "{label}: state root mismatch: got {}, expected {}",
            hex(&root_a),
            hex(&root_b)
        ));

        if a.sd.slot != b.sd.slot {
            diffs.push(format!("  slot: {} vs {}", a.sd.slot, b.sd.slot));
        }
        if a.vid.validator_cnt != b.vid.validator_cnt {
            diffs.push(format!(
                "  validator_cnt: {} vs {}",
                a.vid.validator_cnt, b.vid.validator_cnt
            ));
        }
        if a.sd.justification_bits != b.sd.justification_bits {
            diffs.push(format!(
                "  justification_bits: {:#06b} vs {:#06b}",
                a.sd.justification_bits, b.sd.justification_bits
            ));
        }
        if a.sd.finalized_checkpoint != b.sd.finalized_checkpoint {
            diffs.push(format!(
                "  finalized_checkpoint: epoch {} vs {}",
                a.sd.finalized_checkpoint.epoch, b.sd.finalized_checkpoint.epoch
            ));
        }
        if a.sd.current_justified_checkpoint != b.sd.current_justified_checkpoint {
            diffs.push(format!(
                "  current_justified: epoch {} vs {}",
                a.sd.current_justified_checkpoint.epoch, b.sd.current_justified_checkpoint.epoch
            ));
        }
        if a.sd.previous_justified_checkpoint != b.sd.previous_justified_checkpoint {
            diffs.push(format!(
                "  previous_justified: epoch {} vs {}",
                a.sd.previous_justified_checkpoint.epoch, b.sd.previous_justified_checkpoint.epoch
            ));
        }
        if a.sd.earliest_exit_epoch != b.sd.earliest_exit_epoch {
            diffs.push(format!(
                "  earliest_exit_epoch: {} vs {}",
                a.sd.earliest_exit_epoch, b.sd.earliest_exit_epoch
            ));
        }
        if a.sd.exit_balance_to_consume != b.sd.exit_balance_to_consume {
            diffs.push(format!(
                "  exit_balance_to_consume: {} vs {}",
                a.sd.exit_balance_to_consume, b.sd.exit_balance_to_consume
            ));
        }
        for (idx, (x, y)) in a.epoch.slashings.iter().zip(b.epoch.slashings.iter()).enumerate() {
            if x != y {
                diffs.push(format!("  slashings[{idx}]: {x} vs {y}"));
                if diffs.len() > 15 {
                    diffs.push("  ... (truncated)".to_string());
                    break;
                }
            }
        }

        let n = a.vid.validator_cnt.min(b.vid.validator_cnt);
        for i in 0..n {
            if a.sd.balances[i] != b.sd.balances[i] {
                diffs.push(format!("  balance[{i}]: {} vs {}", a.sd.balances[i], b.sd.balances[i]));
                if diffs.len() > 20 {
                    diffs.push("  ... (truncated)".to_string());
                    break;
                }
            }
        }
        for i in 0..n {
            if a.epoch.val_slashed(i) != b.epoch.val_slashed(i) {
                diffs.push(format!(
                    "  val_slashed[{i}]: {} vs {}",
                    a.epoch.val_slashed(i),
                    b.epoch.val_slashed(i)
                ));
            }
            if a.epoch.val_exit_epoch[i] != b.epoch.val_exit_epoch[i] {
                diffs.push(format!(
                    "  val_exit_epoch[{i}]: {} vs {}",
                    a.epoch.val_exit_epoch[i], b.epoch.val_exit_epoch[i]
                ));
            }
            if a.epoch.val_withdrawable_epoch[i] != b.epoch.val_withdrawable_epoch[i] {
                diffs.push(format!(
                    "  val_withdrawable_epoch[{i}]: {} vs {}",
                    a.epoch.val_withdrawable_epoch[i], b.epoch.val_withdrawable_epoch[i]
                ));
            }
            if a.epoch.val_effective_balance[i] != b.epoch.val_effective_balance[i] {
                diffs.push(format!(
                    "  eff_balance[{i}]: {} vs {}",
                    a.epoch.val_effective_balance[i], b.epoch.val_effective_balance[i]
                ));
                if diffs.len() > 30 {
                    diffs.push("  ... (truncated)".to_string());
                    break;
                }
            }
        }
        for i in 0..n {
            if a.epoch.inactivity_scores[i] != b.epoch.inactivity_scores[i] {
                diffs.push(format!(
                    "  inactivity[{i}]: {} vs {}",
                    a.epoch.inactivity_scores[i], b.epoch.inactivity_scores[i]
                ));
                if diffs.len() > 40 {
                    diffs.push("  ... (truncated)".to_string());
                    break;
                }
            }
        }
    }
    diffs
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
