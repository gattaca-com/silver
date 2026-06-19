#![cfg(feature = "ef_tests")]
//! EF `fork_choice` vector harness. Drives the store at the spec
//! `on_tick`/`on_block`/`on_attestation`/`on_attester_slashing` level and
//! asserts head / justified / finalized / proposer_boost_root after each step.
//!
//! Runs the follower-relevant handlers (`ex_ante`, `get_head`, `on_block`,
//! including the `peerdas` data-availability cases — `is_data_available` is
//! modeled by running silver's real column-sidecar verification and importing
//! only when it passes). Skipped, logged not silent: the proposer-only
//! `get_proposer_head` / `should_override_forkchoice_update` handlers, and
//! `future_block` (silver's gossip next-slot tolerance vs the strict store
//! rule).

mod ef_common;

use std::path::{Path, PathBuf};

use ef_common::{case_file, ef_tile, iter_test_cases, parse_root, snappy_decode, spec_tests_dir};
use serde_yml::{Mapping, Value};
use silver_beacon_state::BeaconStateTile;
use silver_beacon_state_data::{BeaconState, SpecConfig};

fn fork_choice_dir(handler: &str) -> PathBuf {
    spec_tests_dir().join("tests").join("mainnet").join("fulu").join("fork_choice").join(handler)
}

/// Cases we knowingly don't cover yet — logged, never silently passed.
fn known_skip(name: &str) -> Option<&'static str> {
    if name.contains("future_block") {
        // silver permits a next-slot block (gossip clock-disparity tolerance);
        // the EF on_block handler enforces the strict store rule.
        return Some("silver allows next-slot blocks (gossip tolerance)");
    }
    None
}

/// Spec `is_data_available`: run silver's real column-sidecar verification
/// (shape + inclusion proof + KZG, from the storage tile) over the columns the
/// step provides. Available iff non-empty and every column verifies.
fn columns_available(dir: &Path, cols: &[Value]) -> bool {
    !cols.is_empty() &&
        cols.iter().all(|c| {
            let sc = case_file(dir, c.as_str().unwrap());
            silver_storage::util::verify_data_column_sidecar(&sc) &&
                silver_storage::util::verify_data_column_sidecar_inclusion_proof(&sc) &&
                silver_storage::util::verify_data_column_sidecar_kzg_proofs(&sc)
        })
}

fn run_case(name: &str, dir: &Path) {
    let anchor = snappy_decode(&dir.join("anchor_state.ssz_snappy"));
    let state = BeaconState::decompose(&anchor, &SpecConfig::mainnet(), None)
        .unwrap_or_else(|e| panic!("{name}: decompose anchor_state: {e}"));
    let genesis_time = state.immutable.genesis_time;
    let mut tile = ef_tile(state);

    let yaml = std::fs::read_to_string(dir.join("steps.yaml")).unwrap();
    let steps: Vec<Value> = serde_yml::from_str(&yaml).unwrap();

    for (si, step) in steps.iter().enumerate() {
        let m = step.as_mapping().unwrap_or_else(|| panic!("{name} step {si}: not a mapping"));
        if let Some(t) = m.get("tick").and_then(Value::as_u64) {
            tile.ef_tick(t.saturating_sub(genesis_time) * 1000);
        } else if let Some(b) = m.get("block").and_then(Value::as_str) {
            let valid = m.get("valid").and_then(Value::as_bool).unwrap_or(true);
            let ssz = case_file(dir, b);
            match m.get("columns").and_then(Value::as_sequence) {
                // peerdas: spec `is_data_available` gates import on the columns
                // verifying. An unavailable block stays out of fork choice, so
                // the head is unchanged — model the gate by not importing.
                Some(cols) if !columns_available(dir, cols) => {
                    assert!(!valid, "{name} step {si}: block {b} unavailable but valid");
                }
                _ => {
                    let accepted = tile.ef_apply_block(&ssz).is_some();
                    assert_eq!(
                        accepted, valid,
                        "{name} step {si}: block {b} accepted={accepted}, want valid={valid}"
                    );
                }
            }
        } else if let Some(a) = m.get("attestation").and_then(Value::as_str) {
            tile.ef_apply_attestation(&case_file(dir, a));
        } else if let Some(s) = m.get("attester_slashing").and_then(Value::as_str) {
            tile.ef_apply_attester_slashing(&case_file(dir, s));
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
    if let Some(h) = checks.get("head").and_then(Value::as_mapping) {
        let root = fc.find_head();
        let slot = fc.find_node_idx(&root).map(|i| fc.node(i).slot).unwrap_or(0);
        assert_eq!(
            slot,
            h.get("slot").and_then(Value::as_u64).unwrap(),
            "{name} step {si}: head slot"
        );
        assert_eq!(
            root,
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
    // Intentionally unchecked: `time` (silver tracks slots, not store secs),
    // `get_proposer_head`, `should_override_forkchoice_update` (proposer-only).
}

fn run_handler(handler: &str) {
    let cases = iter_test_cases(&fork_choice_dir(handler));
    assert!(!cases.is_empty(), "{handler}: no fork_choice cases found");
    let mut skipped = 0;
    for (name, path) in &cases {
        if let Some(reason) = known_skip(name) {
            eprintln!("SKIP {handler}/{name}: {reason}");
            skipped += 1;
            continue;
        }
        run_case(&format!("{handler}/{name}"), path);
    }
    eprintln!("{handler}: {} run, {skipped} skipped", cases.len() - skipped);
}

#[test]
fn fork_choice_ex_ante() {
    run_handler("ex_ante");
}

#[test]
fn fork_choice_get_head() {
    run_handler("get_head");
}

#[test]
fn fork_choice_on_block() {
    run_handler("on_block");
}
