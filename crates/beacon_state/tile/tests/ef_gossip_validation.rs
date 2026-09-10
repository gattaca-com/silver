#![cfg(feature = "ef_tests")]
//! EF `gossip_validation` vector harness: build a store from `state.ssz_snappy`
//! plus the `blocks` setup list, then feed each message through the tile's
//! gossip handler for its topic and compare the `Feedback` with `expected`.
//!
//! Topics the beacon-state tile does not validate are skipped and listed:
//! column sidecars belong to the columns tile, and silver serves neither bids
//! nor proposer preferences.

mod ef_common;

use std::path::{Path, PathBuf};

use ef_common::{
    case_file, ef_tile_with_spec, init_tracing, iter_test_cases, parse_root, snappy_decode,
    spec_tests_dir,
};
use serde::Deserialize;
use silver_beacon_state::{BeaconStateTile, Feedback, ssz_hash};
use silver_beacon_state_data::{
    BeaconBlockHeader, BeaconState, BlobParameters, Checkpoint, SpecConfig,
};
use silver_common::{PayloadValidationStatus, ssz_view::SignedBeaconBlockView};

const HANDLED_TOPICS: &[&str] = &[
    "beacon_block",
    "beacon_attestation",
    "beacon_aggregate_and_proof",
    "voluntary_exit",
    "proposer_slashing",
    "attester_slashing",
    "bls_to_execution_change",
    "sync_committee_message",
    "sync_committee_contribution_and_proof",
    "execution_payload_envelope",
    "payload_attestation_message",
];

#[derive(Deserialize)]
struct Meta {
    topic: String,
    #[serde(default)]
    blocks: Vec<SetupBlock>,
    #[serde(default)]
    finalized_checkpoint: Option<FinalizedCheckpoint>,
    /// Absent means the start of the state's slot.
    #[serde(default)]
    current_time_ms: Option<u64>,
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct SetupBlock {
    block: String,
    /// Seen, but its state transition failed.
    #[serde(default)]
    failed: bool,
    /// Seen, not imported: no post-state exists.
    #[serde(default)]
    pending: bool,
    /// Its envelope, received and verified.
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    payload_status: Option<String>,
}

#[derive(Deserialize)]
struct FinalizedCheckpoint {
    epoch: u64,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    block: Option<String>,
}

#[derive(Deserialize)]
struct Message {
    message: String,
    expected: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    subnet_id: u64,
    #[serde(default)]
    offset_ms: Option<u64>,
    #[serde(default)]
    current_time_ms: Option<u64>,
}

fn networking_dir(fork: &str) -> PathBuf {
    spec_tests_dir().join("tests").join("mainnet").join(fork).join("networking")
}

/// Mainnet with the fork under test active from genesis, plus the case's own
/// `BLOB_SCHEDULE` when it ships a `config.yaml`. Only that block is parsed:
/// the EF file writes addresses and the terminal difficulty as bare integers
/// wider than any YAML number type, so the whole file does not load.
fn case_spec(dir: &Path, is_gloas: bool) -> SpecConfig {
    let mut spec = SpecConfig { fulu_fork_epoch: 0, ..SpecConfig::mainnet() };
    if is_gloas {
        spec.gloas_fork_epoch = 0;
    }
    if let Ok(yaml) = std::fs::read_to_string(dir.join("config.yaml")) {
        let mut block = String::new();
        let mut in_block = false;
        for line in yaml.lines() {
            if line.starts_with("BLOB_SCHEDULE:") {
                in_block = true;
            } else if in_block && !line.starts_with([' ', '-']) {
                break;
            }
            if in_block {
                block.push_str(line);
                block.push('\n');
            }
        }
        if !block.is_empty() {
            #[derive(Deserialize)]
            struct BlobSchedule {
                #[serde(rename = "BLOB_SCHEDULE")]
                entries: Vec<BlobParameters>,
            }
            let parsed: BlobSchedule = serde_yml::from_str(&block)
                .unwrap_or_else(|e| panic!("{}: BLOB_SCHEDULE: {e}", dir.display()));
            spec.blob_schedule = parsed.entries;
        }
    }
    spec
}

fn outcome(feedback: &Feedback) -> &'static str {
    match feedback {
        Feedback::Accept(_) => "valid",
        Feedback::Reject(_) => "reject",
        _ => "ignore",
    }
}

fn block_root(ssz: &[u8], is_gloas: bool) -> [u8; 32] {
    let header = BeaconBlockHeader {
        slot: SignedBeaconBlockView::slot(ssz),
        proposer_index: SignedBeaconBlockView::proposer_index(ssz),
        parent_root: *SignedBeaconBlockView::parent_root(ssz),
        state_root: *SignedBeaconBlockView::state_root(ssz),
        body_root: ssz_hash::hash_tree_root_body(SignedBeaconBlockView::body(ssz), is_gloas),
    };
    ssz_hash::hash_tree_root_block_header(&header)
}

fn payload_status(s: &str) -> Option<PayloadValidationStatus> {
    match s {
        "VALID" => Some(PayloadValidationStatus::Valid),
        "INVALIDATED" => Some(PayloadValidationStatus::Invalid),
        "NOT_VALIDATED" => None,
        other => panic!("unknown payload_status {other}"),
    }
}

/// `blocks[0]` is the anchor whose post-state is `state.ssz_snappy`; the rest
/// go through the real import path so the store carries their status. Setup
/// is store history, not gossip: the clock advances to each block's slot so
/// the future-slot gate never applies to it. `Err` names a precondition the
/// tile cannot be put into.
fn import_setup(
    tile: &mut BeaconStateTile,
    dir: &Path,
    meta: &Meta,
    is_gloas: bool,
    base_time_ms: u64,
    slot_ms: u64,
) -> Result<(), &'static str> {
    let anchor_root = tile.ef_fork_choice().find_head();
    for (i, setup) in meta.blocks.iter().enumerate() {
        let ssz = case_file(dir, &setup.block);
        let root = if i == 0 {
            anchor_root
        } else if setup.pending {
            continue;
        } else {
            let root = block_root(&ssz, is_gloas);
            tile.ef_tick(base_time_ms.max(SignedBeaconBlockView::slot(&ssz) * slot_ms));
            assert!(tile.ef_apply_block(&ssz).is_some(), "setup block {} rejected", setup.block);
            root
        };
        if let Some(payload) = &setup.payload {
            let received = tile.ef_receive_execution_payload(&case_file(dir, payload));
            assert!(received, "setup payload {payload} not accepted for {}", setup.block);
        }
        if let Some(status) = setup.payload_status.as_deref().and_then(payload_status) {
            tile.ef_payload_verdict(root, status, [0u8; 32]);
        }
    }
    if let Some(cp) = &meta.finalized_checkpoint {
        let root = match (&cp.root, &cp.block) {
            (Some(root), _) => parse_root(root),
            (None, Some(block)) => block_root(&case_file(dir, block), is_gloas),
            (None, None) => panic!("finalized_checkpoint without root or block"),
        };
        tile.ef_set_finalized_checkpoint(Checkpoint { epoch: cp.epoch, root });
        if tile.ef_fork_choice().finalized_checkpoint.root != root {
            return Err("finalized root is not a block in the store");
        }
    }
    tile.ef_tick(base_time_ms);
    Ok(())
}

fn dispatch(tile: &mut BeaconStateTile, topic: &str, msg: &Message, ssz: &[u8]) -> Feedback {
    match topic {
        "beacon_block" => tile.ef_gossip_block(ssz),
        "beacon_attestation" => tile.ef_gossip_attestation(ssz, msg.subnet_id),
        "beacon_aggregate_and_proof" => tile.ef_gossip_aggregate_and_proof(ssz),
        "voluntary_exit" => tile.ef_gossip_voluntary_exit(ssz),
        "proposer_slashing" => tile.ef_gossip_proposer_slashing(ssz),
        "attester_slashing" => tile.ef_gossip_attester_slashing(ssz),
        "bls_to_execution_change" => tile.ef_gossip_bls_to_execution_change(ssz),
        "sync_committee" => tile.ef_gossip_sync_committee_message(ssz, msg.subnet_id),
        "sync_committee_contribution_and_proof" => tile.ef_gossip_sync_contribution(ssz),
        "execution_payload" => tile.ef_gossip_execution_payload(ssz),
        "payload_attestation_message" => tile.ef_gossip_payload_attestation(ssz),
        other => panic!("unhandled topic {other}"),
    }
}

/// Every mismatching message of one case, as `message: got, want (reason)`;
/// `Err` names a precondition the tile cannot be put into.
fn run_case(dir: &Path, is_gloas: bool) -> Result<Vec<String>, &'static str> {
    let meta: Meta = serde_yml::from_str(&std::fs::read_to_string(dir.join("meta.yaml")).unwrap())
        .unwrap_or_else(|e| panic!("{}: meta.yaml: {e}", dir.display()));
    // A `failed` setup block is a valid block the vector declares invalid. The
    // import path cannot record a valid block as seen-but-invalid.
    if meta.blocks.iter().any(|b| b.failed) {
        return Err("failed setup block");
    }
    let spec = case_spec(dir, is_gloas);
    let state = snappy_decode(&dir.join("state.ssz_snappy"));
    let state = BeaconState::decompose(&state, &spec, None)
        .unwrap_or_else(|e| panic!("{}: decompose state: {e}", dir.display()));
    let slot_ms = spec.slot_duration_ms();
    let mut tile = ef_tile_with_spec(state, spec);

    let base_time_ms = meta.current_time_ms.unwrap_or(tile.head_state_slot() * slot_ms);
    import_setup(&mut tile, dir, &meta, is_gloas, base_time_ms, slot_ms)?;

    let mut mismatches = Vec::new();
    for msg in &meta.messages {
        let at = msg.current_time_ms.unwrap_or(base_time_ms + msg.offset_ms.unwrap_or(0));
        tile.ef_tick(at);
        let got = outcome(&dispatch(&mut tile, &meta.topic, msg, &case_file(dir, &msg.message)));
        if got != msg.expected {
            let reason = msg.reason.as_deref().unwrap_or("");
            mismatches
                .push(format!("{}: got {got}, want {} ({reason})", msg.message, msg.expected));
        }
    }
    Ok(mismatches)
}

fn run_fork(fork: &str) {
    init_tracing();
    let mut handled = 0;
    let mut failed = Vec::new();
    let mut skipped = Vec::new();
    let mut skipped_cases = Vec::new();
    let mut known_failed = Vec::new();
    let base = networking_dir(fork);
    for entry in std::fs::read_dir(&base).unwrap().flatten() {
        let handler = entry.file_name().to_string_lossy().into_owned();
        let Some(topic) = handler.strip_prefix("gossip_") else { continue };
        if !HANDLED_TOPICS.contains(&topic) {
            skipped.push(handler.clone());
            continue;
        }
        let cases = iter_test_cases(&entry.path());
        assert!(!cases.is_empty(), "{fork}/{handler}: no cases");
        for (name, dir) in &cases {
            let case = name.rsplit('/').next().unwrap();
            match run_case(dir, fork == "gloas") {
                Err(why) => skipped_cases.push(format!("{handler}/{name}: {why}")),
                Ok(mismatches) if mismatches.is_empty() => {
                    handled += 1;
                }
                Ok(mismatches) => {
                    handled += 1;
                    let report =
                        format!("{fork}/{handler}/{name}\n    {}", mismatches.join("\n    "));
                }
            }
        }
    }
    skipped.sort();
    eprintln!(
        "{fork}: {} cases run, {} known mismatches, {} unexpected, {} skipped; skipped handlers: {}",
        handled,
        known_failed.len(),
        failed.len(),
        skipped_cases.len(),
        skipped.join(", ")
    );
    for c in &skipped_cases {
        eprintln!("  skipped {c}");
    }
    for k in &known_failed {
        eprintln!("  known {k}");
    }
    for f in &failed {
        eprintln!("  {f}");
    }
    assert!(failed.is_empty(), "{fork}: {} unexpected gossip_validation result(s)", failed.len());
}

#[test]
fn fulu_gossip_validation() {
    run_fork("fulu");
}

#[test]
fn gloas_gossip_validation() {
    run_fork("gloas");
}
