#![cfg(feature = "ef_tests")]
//! EF `fork_choice` vector harness. Drives the store at the spec
//! `on_tick`/`on_block`/`on_attestation`/`on_attester_slashing` level and
//! asserts head / justified / finalized / proposer_boost_root after each step.
//!
//! Runs the follower-relevant handlers (`ex_ante`, `get_head`, `on_block`,
//! including the `future_block` and `peerdas` cases — `is_data_available` is
//! modeled by running silver's real column-sidecar verification and importing
//! only when it passes). The proposer-only `get_proposer_head` /
//! `should_override_forkchoice_update` handlers are not driven at all.

mod ef_common;

use std::path::{Path, PathBuf};

use ef_common::{case_file, ef_tile, iter_test_cases, parse_root, snappy_decode, spec_tests_dir};
use serde_yml::{Mapping, Value};
use silver_beacon_state::BeaconStateTile;
use silver_beacon_state_data::{BeaconState, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::ssz_view::DataColumnSidecarFuluView;

fn fork_choice_dir(fork: &str, handler: &str) -> PathBuf {
    spec_tests_dir().join("tests").join("mainnet").join(fork).join("fork_choice").join(handler)
}

/// Spec `is_data_available`: run silver's real column-sidecar verification
/// (shape + inclusion proof + KZG, from the storage tile) over the columns the
/// step provides. Available iff non-empty and every column verifies.
fn columns_available(dir: &Path, cols: &[Value], spec: &SpecConfig) -> bool {
    !cols.is_empty() &&
        cols.iter().all(|c| {
            let sc = case_file(dir, c.as_str().unwrap());
            let epoch = DataColumnSidecarFuluView::slot(&sc) / SLOTS_PER_EPOCH;
            let max_blobs = spec.blob_params_at(epoch).max_blobs_per_block as usize;
            silver_common::column_util::verify_data_column_sidecar_fulu(&sc, max_blobs) &&
                silver_common::column_util::verify_data_column_sidecar_inclusion_proof(&sc) &&
                silver_common::column_util::verify_data_column_sidecar_kzg_proofs_fulu(&sc)
        })
}

fn run_case(name: &str, dir: &Path) {
    let spec = SpecConfig::mainnet();
    let anchor = snappy_decode(&dir.join("anchor_state.ssz_snappy"));
    let state = BeaconState::decompose(&anchor, &spec, None)
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
                Some(cols) if !columns_available(dir, cols, &spec) => {
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
        } else if let Some(e) = m.get("execution_payload").and_then(Value::as_str) {
            // [Gloas] reveal an execution payload envelope.
            let valid = m.get("valid").and_then(Value::as_bool).unwrap_or(true);
            let accepted = tile.ef_apply_execution_payload(&case_file(dir, e));
            assert_eq!(
                accepted, valid,
                "{name} step {si}: execution_payload {e} accepted={accepted}, want valid={valid}"
            );
        } else if let Some(p) = m.get("payload_attestation_message").and_then(Value::as_str) {
            // [Gloas] record a PTC timeliness/DA vote.
            tile.ef_apply_payload_attestation(&case_file(dir, p));
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
        // [Gloas] the head's resolved payload side (1 = FULL, 0 = EMPTY).
        if let Some(ps) = h.get("payload_status").and_then(Value::as_u64) {
            assert_eq!(
                fc.head_payload_present() as u64,
                ps,
                "{name} step {si}: head payload_status"
            );
        }
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
    // [Gloas] PTC timeliness / data-availability votes, as
    // `{block_root, votes: [true|false|null; PTC_SIZE]}` (null = not voted).
    let assert_votes = |label: &str, c: &Mapping, got: &[Option<bool>]| {
        let root = parse_root(c.get("block_root").and_then(Value::as_str).unwrap());
        let want = c.get("votes").and_then(Value::as_sequence).unwrap();
        assert_eq!(want.len(), got.len(), "{name} step {si}: {label} length ({root:?})");
        for (i, v) in want.iter().enumerate() {
            assert_eq!(got[i], v.as_bool(), "{name} step {si}: {label}[{i}]");
        }
    };
    if let Some(c) = checks.get("payload_timeliness_vote").and_then(Value::as_mapping) {
        let root = parse_root(c.get("block_root").and_then(Value::as_str).unwrap());
        assert_votes("payload_timeliness_vote", c, &fc.ptc_timeliness_votes(&root));
    }
    if let Some(c) = checks.get("payload_data_availability_vote").and_then(Value::as_mapping) {
        let root = parse_root(c.get("block_root").and_then(Value::as_str).unwrap());
        assert_votes("payload_data_availability_vote", c, &fc.ptc_data_availability_votes(&root));
    }
    // Intentionally unchecked: `time` (silver tracks slots, not store secs),
    // `get_proposer_head`, `should_override_forkchoice_update` (proposer-only).
}

fn run_handler(fork: &str, handler: &str) {
    let cases = iter_test_cases(&fork_choice_dir(fork, handler));
    assert!(!cases.is_empty(), "{fork}/{handler}: no fork_choice cases found");
    for (name, path) in &cases {
        run_case(&format!("{fork}/{handler}/{name}"), path);
    }
    eprintln!("{fork}/{handler}: {} run", cases.len());
}

#[test]
fn fulu_fork_choice_ex_ante() {
    run_handler("fulu", "ex_ante");
}

#[test]
fn fulu_fork_choice_get_head() {
    run_handler("fulu", "get_head");
}

#[test]
fn fulu_fork_choice_on_block() {
    run_handler("fulu", "on_block");
}

#[test]
fn gloas_fork_choice_ex_ante() {
    run_handler("gloas", "ex_ante");
}

#[test]
fn gloas_fork_choice_get_head() {
    run_handler("gloas", "get_head");
}

#[test]
fn gloas_fork_choice_on_block() {
    run_handler("gloas", "on_block");
}

#[test]
fn gloas_fork_choice_on_execution_payload_envelope() {
    run_handler("gloas", "on_execution_payload_envelope");
}
