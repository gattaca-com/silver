#![cfg(feature = "ef_tests")]
//! EF `sync/optimistic` vector harness. Same step driver as `ef_fork_choice`
//! plus a `payload_status` step that programs the mock execution engine's
//! verdict for a block's execution payload hash. Blocks import optimistically;
//! an `INVALID` verdict prunes the branch and reroutes the head, a `VALID`
//! verdict clears the optimistic flag.

mod ef_common;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use ef_common::{case_file, ef_tile, iter_test_cases, parse_root, snappy_decode, spec_tests_dir};
use serde_yml::{Mapping, Value};
use silver_beacon_state::{BeaconStateTile, ExecutionStatus};
use silver_beacon_state_data::{B256, BeaconState, SpecConfig};
use silver_common::PayloadValidationStatus;

fn optimistic_dir() -> PathBuf {
    spec_tests_dir().join("tests").join("mainnet").join("fulu").join("sync").join("optimistic")
}

/// `SYNCING`/`ACCEPTED` keep the block optimistic (no verdict to apply).
fn parse_status(s: &str) -> Option<PayloadValidationStatus> {
    match s {
        "VALID" => Some(PayloadValidationStatus::Valid),
        "INVALID" => Some(PayloadValidationStatus::Invalid),
        "SYNCING" | "ACCEPTED" => None,
        other => panic!("unknown payload status {other}"),
    }
}

/// Execution payload hash silver recorded for a resident block.
fn node_exec_hash(tile: &BeaconStateTile, root: &B256) -> Option<B256> {
    let fc = tile.ef_fork_choice();
    fc.find_node_idx(root).map(|i| fc.node(i).execution_block_hash)
}

/// Beacon root of the resident node carrying `exec` (EF programs payload status
/// by execution hash).
fn node_root_by_exec(tile: &BeaconStateTile, exec: &B256) -> Option<B256> {
    tile.ef_fork_choice()
        .nodes
        .iter()
        .find(|n| n.execution_block_hash == *exec)
        .map(|n| n.block_root)
}

fn run_case(name: &str, dir: &Path) {
    let anchor = snappy_decode(&dir.join("anchor_state.ssz_snappy"));
    let state = BeaconState::decompose(&anchor, &SpecConfig::mainnet(), None)
        .unwrap_or_else(|e| panic!("{name}: decompose anchor_state: {e}"));
    let genesis_time = state.immutable.genesis_time;
    let mut tile = ef_tile(state);

    let yaml = std::fs::read_to_string(dir.join("steps.yaml")).unwrap();
    let steps: Vec<Value> = serde_yml::from_str(&yaml).unwrap();

    // EL verdicts keyed by execution block hash, applied once the matching block
    // is resident — the `payload_status` step may precede or follow its block.
    let mut programmed: HashMap<B256, (PayloadValidationStatus, B256)> = HashMap::new();

    for (si, step) in steps.iter().enumerate() {
        let m = step.as_mapping().unwrap_or_else(|| panic!("{name} step {si}: not a mapping"));
        if let Some(t) = m.get("tick").and_then(Value::as_u64) {
            tile.ef_tick(t.saturating_sub(genesis_time) * 1000);
        } else if let Some(bh) = m.get("block_hash").and_then(Value::as_str) {
            let ps = m.get("payload_status").and_then(Value::as_mapping).unwrap();
            let Some(status) = parse_status(ps.get("status").and_then(Value::as_str).unwrap())
            else {
                continue;
            };
            let lvh = ps
                .get("latest_valid_hash")
                .and_then(Value::as_str)
                .map(parse_root)
                .unwrap_or([0u8; 32]);
            let exec = parse_root(bh);
            // Apply now if the block is already resident, else defer to import.
            let resident = node_root_by_exec(&tile, &exec);
            if let Some(root) = resident {
                tile.ef_payload_verdict(root, status, lvh);
            } else {
                programmed.insert(exec, (status, lvh));
            }
        } else if let Some(b) = m.get("block").and_then(Value::as_str) {
            let valid = m.get("valid").and_then(Value::as_bool).unwrap_or(true);
            let root = tile.ef_apply_block(&case_file(dir, b));
            // Optimistic import: a `valid: true` block must enter the store. A
            // `valid: false` block may still be imported optimistically and then
            // invalidated by its EL verdict (or rejected outright) — the head
            // checks verify the outcome, so don't assert non-acceptance here.
            if valid {
                assert!(root.is_some(), "{name} step {si}: block {b} should import");
            }
            if let Some(root) = root &&
                let Some(exec) = node_exec_hash(&tile, &root) &&
                let Some((status, lvh)) = programmed.remove(&exec)
            {
                tile.ef_payload_verdict(root, status, lvh);
            }
        } else if let Some(checks) = m.get("checks").and_then(Value::as_mapping) {
            run_checks(name, si, &tile, checks);
        }
    }
}

fn run_checks(name: &str, si: usize, tile: &BeaconStateTile, checks: &Mapping) {
    let epoch_root = |m: &Mapping| {
        (
            m.get("epoch").and_then(Value::as_u64).unwrap(),
            parse_root(m.get("root").and_then(Value::as_str).unwrap()),
        )
    };

    let fc = tile.ef_fork_choice();
    let head = fc.find_head();
    if let Some(h) = checks.get("head").and_then(Value::as_mapping) {
        let slot = fc.find_node_idx(&head).map(|i| fc.node(i).slot).unwrap_or(0);
        assert_eq!(
            slot,
            h.get("slot").and_then(Value::as_u64).unwrap(),
            "{name} step {si}: head slot"
        );
        assert_eq!(
            head,
            parse_root(h.get("root").and_then(Value::as_str).unwrap()),
            "{name} step {si}: head root"
        );
    }
    if let Some(c) = checks.get("justified_checkpoint").and_then(Value::as_mapping) {
        let cp = fc.justified_checkpoint;
        assert_eq!((cp.epoch, cp.root), epoch_root(c), "{name} step {si}: justified_checkpoint");
    }
    if let Some(c) = checks.get("finalized_checkpoint").and_then(Value::as_mapping) {
        let cp = fc.finalized_checkpoint;
        assert_eq!((cp.epoch, cp.root), epoch_root(c), "{name} step {si}: finalized_checkpoint");
    }
    if let Some(pbr) = checks.get("proposer_boost_root").and_then(Value::as_str) {
        assert_eq!(
            fc.proposer_boost_root,
            parse_root(pbr),
            "{name} step {si}: proposer_boost_root"
        );
    }
    if let Some(opt) = checks.get("optimistic").and_then(Value::as_bool) {
        let is_opt = fc
            .find_node_idx(&head)
            .map(|i| fc.node(i).execution_status != ExecutionStatus::Valid)
            .unwrap_or(false);
        assert_eq!(is_opt, opt, "{name} step {si}: head optimistic");
    }
}

#[test]
fn fulu_sync_optimistic() {
    let cases = iter_test_cases(&optimistic_dir());
    assert!(!cases.is_empty(), "no sync/optimistic cases found");
    for (name, path) in &cases {
        run_case(&format!("optimistic/{name}"), path);
    }
    eprintln!("optimistic: {} run", cases.len());
}
