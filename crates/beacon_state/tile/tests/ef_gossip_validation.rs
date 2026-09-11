#![cfg(feature = "ef_tests")]
//! EF `gossip_validation` vector harness: build a store from `state.ssz_snappy`
//! plus the `blocks` setup list, then feed each message through the tile's
//! gossip handler for its topic and compare the `Feedback` with `expected`.
//!
//! The `data_column_sidecar` topic runs through a columns tile reading the same
//! beacon state. Topics silver does not validate are skipped and listed: it
//! serves neither bids nor proposer preferences, and partial columns are out.

mod ef_common;

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use ef_common::{
    case_file, ef_tile_with_spec, init_tracing, iter_test_cases, parse_root, snappy_decode,
    spec_tests_dir,
};
use flux::spine::SpineAdapter;
use serde::Deserialize;
use silver_beacon_state::{BeaconStateTile, Feedback, SlotTicker, ssz_hash};
use silver_beacon_state_data::{
    BeaconBlockHeader, BeaconState, BlobParameters, Checkpoint, SLOTS_PER_EPOCH, SpecConfig,
};
use silver_columns::tile::{ColumnConsumers, DataColumnsTile, EfVerdict};
use silver_common::{
    PayloadValidationStatus, SilverSpine, TCache, TCacheProducer, TCacheRead, TProducer,
    ssz_view::SignedBeaconBlockView,
};
use tempfile::TempDir;

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
    "data_column_sidecar",
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

/// A columns tile on its own spine, reading the beacon tile's state. Its
/// clock and finality follow the beacon tile before each message. Field order
/// is drop order: adapter before spine, spine before its directory.
struct ColumnsRig {
    adapter: SpineAdapter<SilverSpine>,
    tile: DataColumnsTile,
    gossip: TProducer,
    _spine: Box<SilverSpine>,
    _dir: TempDir,
}

impl ColumnsRig {
    fn new(beacon: &BeaconStateTile, spec: SpecConfig) -> Self {
        let gossip = TCache::producer("ef_columns_gossip", 1 << 24);
        let consumer = |name| gossip.cache_ref().random_access(name, true).unwrap();
        let consumers = ColumnConsumers {
            gossip: consumer("ef_columns_gossip_c"),
            persist_gossip: consumer("ef_columns_persist_gossip_c"),
            rpc: consumer("ef_columns_rpc_c"),
            persist_rpc: consumer("ef_columns_persist_rpc_c"),
        };
        let engine = TCache::producer("ef_columns_engine", 1 << 16);
        let ticker = SlotTicker::new(
            0,
            Duration::from_millis(spec.slot_duration_ms()),
            Duration::from_secs(4),
        );
        let tile = DataColumnsTile::new(
            consumers,
            beacon.reader(),
            u128::MAX,
            Arc::new(spec),
            engine.cache_ref().random_access("ef_columns_engine_c", true).unwrap(),
            TCache::producer("ef_columns_el", 1 << 16),
            ticker,
        );
        let dir = TempDir::new().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(dir.path(), None));
        let adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        Self { adapter, tile, gossip, _spine: spine, _dir: dir }
    }

    fn write(&mut self, bytes: &[u8]) -> TCacheRead {
        let mut reservation = self.gossip.reserve(bytes.len(), true).unwrap();
        reservation.write_all(bytes).unwrap();
        reservation.flush().unwrap();
        reservation.read()
    }

    fn block(&mut self, bytes: &[u8]) {
        let ssz = self.write(bytes);
        self.tile.ef_block(ssz, &mut self.adapter.producers);
    }

    fn sync_with(&mut self, beacon: &BeaconStateTile, since_genesis_ms: u64) {
        let fork_choice = beacon.ef_fork_choice();
        let finalized_slot = fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        self.tile.ef_set_status(fork_choice.find_head(), finalized_slot);
        self.tile.ef_tick(since_genesis_ms);
    }

    fn sidecar(&mut self, bytes: &[u8], subnet: u64) -> &'static str {
        let ssz = self.write(bytes);
        match self.tile.ef_gossip_sidecar(ssz, subnet, &mut self.adapter.producers) {
            EfVerdict::Valid => "valid",
            EfVerdict::Ignore => "ignore",
            EfVerdict::Reject => "reject",
        }
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
    let columns_spec = spec.clone();
    let mut tile = ef_tile_with_spec(state, spec);

    let base_time_ms = meta.current_time_ms.unwrap_or(tile.head_state_slot() * slot_ms);
    import_setup(&mut tile, dir, &meta, is_gloas, base_time_ms, slot_ms)?;

    // Reads the columns tile hands out point back at its consumers, so it is
    // fed only once it sits where it will stay.
    let mut columns =
        (meta.topic == "data_column_sidecar").then(|| ColumnsRig::new(&tile, columns_spec));
    if let Some(rig) = &mut columns {
        rig.sync_with(&tile, base_time_ms);
        for setup in meta.blocks.iter().filter(|b| !b.pending) {
            rig.block(&case_file(dir, &setup.block));
        }
    }

    let mut mismatches = Vec::new();
    for msg in &meta.messages {
        let at = msg.current_time_ms.unwrap_or(base_time_ms + msg.offset_ms.unwrap_or(0));
        tile.ef_tick(at);
        let bytes = case_file(dir, &msg.message);
        let got = match &mut columns {
            Some(rig) => {
                rig.sync_with(&tile, at);
                rig.sidecar(&bytes, msg.subnet_id)
            }
            None => outcome(&dispatch(&mut tile, &meta.topic, msg, &bytes)),
        };
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
            match run_case(dir, fork == "gloas") {
                Err(why) => skipped_cases.push(format!("{handler}/{name}: {why}")),
                Ok(mismatches) => {
                    handled += 1;
                    if !mismatches.is_empty() {
                        failed.push(format!(
                            "{fork}/{handler}/{name}\n    {}",
                            mismatches.join("\n    ")
                        ));
                    }
                }
            }
        }
    }
    skipped.sort();
    eprintln!(
        "{fork}: {} cases run, {} failed, {} skipped; skipped handlers: {}",
        handled,
        failed.len(),
        skipped_cases.len(),
        skipped.join(", ")
    );
    for c in &skipped_cases {
        eprintln!("  skipped {c}");
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
