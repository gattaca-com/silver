use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flux::timing::Nanos;
use silver_beacon_state_data::{
    BLSPubkey, BeaconBlockHeader, BeaconState, EPOCHS_PER_HISTORICAL_VECTOR, EpochState,
    EpochStateFinalized, Immutable, PROPOSER_LOOKAHEAD_SIZE, PendingDeposit, SlotStateId, ValSeed,
    Withdrawals,
};
use silver_common::{
    GossipTopic, MessageId, P2pStreamId, StreamProtocol, TCache, TCacheProducer, TProducer,
    ssz_view::{
        ATTESTATION_DATA_SIZE, AttestationView, PROPOSER_SLASHING_SIZE, SIGNED_AGG_PROOF_MIN,
        SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE, SignedAggregateAndProofView,
        SingleAttestationView,
    },
};

use super::*;
use crate::{
    fork_choice::{BlockImport, PayloadStatus},
    stf::AttestationVote,
    test_signing,
};

const MAX_EFFECTIVE_BALANCE: u64 = 32_000_000_000;
const ANCHOR_ROOT: B256 = [0x01u8; 32];

fn make_tile() -> BeaconStateTile {
    make_tile_at_wall_slot(1)
}

/// Tile whose ticker reports `wall_slot` as the current slot.
fn make_tile_at_wall_slot(wall_slot: u64) -> BeaconStateTile {
    make_tile_at_wall_slot_ws(wall_slot, true)
}

fn make_tile_at_wall_slot_ws(wall_slot: u64, verify_weak_subjectivity: bool) -> BeaconStateTile {
    let secs_per_slot = 12u64;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let genesis = now.saturating_sub(wall_slot * secs_per_slot + 1);
    let ticker = SlotTicker::new(genesis, Duration::from_secs(12), Duration::from_secs(4));
    let gossip_p = TCache::producer("test_gossip", 1 << 20);
    let event_p = TCache::producer("test_event", 1 << 20);
    let engine_p = TCache::producer("test_engine", 1 << 20);
    let replay_p = TCache::producer("test_replay", 1 << 20);
    let gossip_c = gossip_p.cache_ref().random_access("test_gossip", true).unwrap();
    let rpc_c = event_p.cache_ref().random_access("test_event", true).unwrap();
    let engine_c = engine_p.cache_ref().random_access("test_engine", true).unwrap();
    let replay_c = replay_p.cache_ref().random_access("test_replay", true).unwrap();
    BeaconStateTile::new(
        ticker,
        Arc::new(SpecConfig::mainnet()),
        &SyncingConfig::default(),
        gossip_c,
        rpc_c,
        engine_c,
        replay_c,
        verify_weak_subjectivity,
        BeaconState::empty_test(0),
    )
}

/// Like `make_tile_at_wall_slot` but returns the gossip producer so tests
/// can write real block buffers the tile's consumer can read back.
fn make_tile_with_gossip(wall_slot: u64) -> (BeaconStateTile, TProducer) {
    let secs_per_slot = 12u64;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let genesis = now.saturating_sub(wall_slot * secs_per_slot + 1);
    let ticker = SlotTicker::new(genesis, Duration::from_secs(12), Duration::from_secs(4));
    let gossip_p = TCache::producer("test_gossip_buf", 1 << 20);
    let event_p = TCache::producer("test_event_buf", 1 << 20);
    let engine_p = TCache::producer("test_engine", 1 << 20);
    let replay_p = TCache::producer("test_replay_buf", 1 << 20);
    let gossip_c = gossip_p.cache_ref().random_access("test_gossip_buf", true).unwrap();
    let rpc_c = event_p.cache_ref().random_access("test_event_buf", true).unwrap();
    let engine_c = engine_p.cache_ref().random_access("test_engine", true).unwrap();
    let replay_c = replay_p.cache_ref().random_access("test_replay_buf", true).unwrap();
    let tile = BeaconStateTile::new(
        ticker,
        Arc::new(SpecConfig::mainnet()),
        &SyncingConfig::default(),
        gossip_c,
        rpc_c,
        engine_c,
        replay_c,
        true,
        BeaconState::empty_test(0),
    );
    (tile, gossip_p)
}

/// Publish a minimal block (slot at offset 100) into `producer` and wrap it
/// as a buffered gossip orphan whose slot the tile can read back.
fn gossip_pending(producer: &mut TProducer, slot: u64) -> PendingBlock {
    let mut bytes = vec![0u8; 200];
    bytes[100..108].copy_from_slice(&slot.to_le_bytes());
    let mut r = producer.reserve(bytes.len(), true).expect("reserve");
    if let Ok(buf) = r.buffer() {
        buf[..bytes.len()].copy_from_slice(&bytes);
    }
    r.increment_offset(bytes.len());
    let read = r.read();
    producer.publish_head();
    PendingBlock::Gossip(NewGossipMsg {
        stream_id: P2pStreamId::new(0, 0, StreamProtocol::Unset, false),
        topic: GossipTopic::BeaconBlock,
        msg_hash: MessageId { id: [0u8; 20] },
        recv_ts: Nanos(0),
        ssz: read,
        protobuf: read,
    })
}

fn placeholder_pubkey(i: usize) -> BLSPubkey {
    let mut pk = [0u8; 48];
    pk[..4].copy_from_slice(&(i as u32).to_le_bytes());
    pk
}

/// Epoch-tier base with zeroed rings and the given checkpoints seeded —
/// the harness analog of a decomposed anchor.
fn epoch_base_with(justified: Checkpoint, finalized: Checkpoint) -> EpochStateFinalized {
    EpochStateFinalized::from_parts(
        EpochState {
            current_justified_checkpoint: justified,
            finalized_checkpoint: finalized,
            ..Default::default()
        },
        vec![[0u8; 32]; EPOCHS_PER_HISTORICAL_VECTOR].into_boxed_slice(),
    )
}

/// Build seed bases with `n` active validators (MAX effective balance,
/// activation epoch 0, exit FAR_FUTURE) at `start_slot`. With `real_keys`,
/// install spec BLS test pubkeys (+ BLS-prefix withdrawal creds) so
/// signature-checking handlers accept; otherwise collision-free
/// placeholder pubkeys.
fn build_seed_finalized(n: usize, real_keys: bool) -> (EpochStateFinalized, Vec<ValSeed>) {
    let cp_fin = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
    let seeds: Vec<ValSeed> = (0..n)
        .map(|i| {
            let (pubkey, withdrawal_credentials) = if real_keys {
                let sk_idx = i % test_signing::PRIVKEY_HEX.len();
                let pk_bytes = test_signing::pubkey_pk(sk_idx).to_bytes();
                // BLS-prefix creds: [0]=0x00, [1..]=hash(pk)[1..].
                let mut creds = Withdrawals(merkle::sha256(&pk_bytes));
                creds.0[0] = 0x00;
                (pk_bytes, creds)
            } else {
                (placeholder_pubkey(i), Withdrawals::default())
            };
            ValSeed {
                pubkey,
                withdrawal_credentials,
                effective_balance: MAX_EFFECTIVE_BALANCE,
                balance: MAX_EFFECTIVE_BALANCE,
                activation_epoch: 0,
                ..Default::default()
            }
        })
        .collect();
    // The finalized slot lives in the slot-group base (seeded in
    // `arm_tile` from `start_slot`); the validator registry rides its own
    // group (seeded in `arm_tile` from `seeds`); the epoch tier rides its
    // own group (built in `arm_tile` from this base).
    (epoch_base_with(cp_fin, cp_fin), seeds)
}

/// Install the seed bases as the tile's state, anchor an empty per-fork
/// delta seeded with the finalized slot scalars, and arm fork choice + the
/// start-epoch attester shuffling at the anchor.
fn arm_tile(
    tile: &mut BeaconStateTile,
    epoch_base: EpochStateFinalized,
    seeds: &[ValSeed],
    start_slot: Slot,
) {
    // Test-built state: epoch base from `epoch_base`, registry + balances
    // column from `seeds`, slot base anchored at `start_slot`, the rest
    // empty.
    let bs = BeaconState::for_test(epoch_base, seeds, start_slot);
    arm_tile_state(tile, bs, seeds, start_slot);
}

/// As `arm_tile`, for tests that mutate the built state (e.g. its immutable
/// tier) before the owner wraps it.
fn arm_tile_state(
    tile: &mut BeaconStateTile,
    mut bs: BeaconState,
    seeds: &[ValSeed],
    start_slot: Slot,
) {
    // Anchor each tier's fork at the base (the slot tier at `start_slot`);
    // epoch/longtail stay lazy. Rolled before the owner wraps the state.
    let anchor = bs.roll_fresh();
    let mut owner = BeaconStateOwner::new(bs);
    owner.publish_state_id(anchor);

    tile.state = owner;
    tile.shuffling_cache = ShufflingCache::with_capacity(seeds.len());
    tile.last_applied = anchor;
    tile.last_applied_block_root = ANCHOR_ROOT;
    tile.mode = Mode::Following;

    let cp = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
    tile.fork_choice =
        ForkChoice::init(cp, cp, start_slot, ANCHOR_ROOT, [0u8; 32], false, anchor, seeds.len());

    let view = tile.state.read_view(anchor);
    tile.shuffling_cache.ensure_window(&view, start_slot / SLOTS_PER_EPOCH);
}

fn seed_tile(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
    let (epoch_base, seeds) = build_seed_finalized(n, false);
    arm_tile(tile, epoch_base, &seeds, start_slot);
}

fn seed_tile_with_keys(tile: &mut BeaconStateTile, n: usize, start_slot: Slot) {
    let (epoch_base, seeds) = build_seed_finalized(n, true);
    arm_tile(tile, epoch_base, &seeds, start_slot);
}

/// Immutable tier the signed-object builders sign against. `seed_*` leave
/// the base immutable all-default, so a default crate `Immutable` matches
/// the common one the handlers read, field-for-field (fork versions + gvr
/// all zero → identical signing domains).
fn seed_immutable(_tile: &BeaconStateTile) -> Immutable {
    Immutable::default()
}

#[test]
fn slot_advance_skip_multiple() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 10);
    tile.on_slot_start(15);
    assert_eq!(tile.head_state_slot(), 15);
}

#[test]
fn slot_advance_noop_past_slot() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 10);
    tile.on_slot_start(5);
    assert_eq!(tile.head_state_slot(), 10);
}

#[test]
fn slot_advance_crosses_epoch_boundary() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 30);
    tile.on_slot_start(34);
    assert_eq!(tile.head_state_slot(), 34);
    // Crossing into epoch 1 allocated the head fork its own epoch delta.
    assert!(tile.last_applied.epoch_idx.is_some());
}

/// Sustained non-finality: slot advances far past the rings' initial
/// capacity (slot tiers past `SLOTS_RING_N` twice over, the epoch tier
/// past `EPOCHS_RING_N`) must grow the rings instead of panicking on
/// wrap, with the head still resolving after every advance.
#[test]
fn slot_advance_grows_rings_under_non_finality() {
    use silver_beacon_state_data::{SLOTS_PER_EPOCH, SLOTS_RING_N};

    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let target = SLOTS_RING_N as u64 * 2 + 3 * SLOTS_PER_EPOCH;
    for s in 1..=target {
        tile.on_slot_start(s);
        assert_eq!(tile.head_state_slot(), s);
    }
}

/// Regression: advancing the head over an empty epoch-boundary slot must
/// COW the epoch tier, not shift the parent's shared `proposer_lookahead`
/// in place. The parent stays a live fork-choice node the proposer
/// precheck reads; an in-place shift left its next-epoch slice one epoch
/// too far, rejecting valid boundary blocks.
#[test]
fn empty_slot_advance_preserves_parent_lookahead() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 31); // anchor at epoch-0's last slot

    // Give the anchor its own epoch entry with a recognizable lookahead —
    // rolled, mutated through the held writer, committed (append-only).
    // The anchor bundle is rebuilt with the new epoch id and re-installed
    // as the head (the fork-choice anchor node keeps the lazy bundle —
    // this test never reads it).
    let anchor_epoch_idx = {
        let mut g = tile.state.write();
        let mut w = g.epoch.roll_inheriting(tile.last_applied.epoch_idx);
        let es = w.state_mut();
        for i in 0..PROPOSER_LOOKAHEAD_SIZE {
            es.proposer_lookahead[i] = i as u64;
        }
        w.commit()
    };
    tile.last_applied.epoch_idx = Some(anchor_epoch_idx);
    let before = tile.state.state().epoch.view(anchor_epoch_idx).state().proposer_lookahead;

    // Advance across the epoch 0 -> 1 boundary on empty slots.
    tile.on_slot_start(32);
    assert_eq!(tile.head_state_slot(), 32);

    // Head forked onto a private epoch delta; the anchor's is untouched.
    let head_epoch_idx = tile.last_applied.epoch_idx.unwrap();
    assert_ne!(head_epoch_idx, anchor_epoch_idx, "head must COW its epoch delta");
    let after = tile.state.state().epoch.view(anchor_epoch_idx).state().proposer_lookahead;
    assert_eq!(before, after, "parent proposer_lookahead shifted in place");
}

#[test]
fn slot_advance_crosses_two_epoch_boundaries() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 30);
    tile.on_slot_start(66);
    assert_eq!(tile.head_state_slot(), 66);
}

#[test]
fn block_unknown_parent_rejected() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 10);

    // Minimal SignedBeaconBlock: message at fixed offset 100 (4-byte
    // offset + 96-byte signature), parent_root @ 116 set to an unknown
    // root so precheck bails with ParentMissing before any state change.
    let mut buf = vec![0u8; 200];
    buf[100..108].copy_from_slice(&11u64.to_le_bytes()); // slot
    buf[108..116].copy_from_slice(&0u64.to_le_bytes()); // proposer_index
    buf[116] = 0xFF; // parent_root[0]

    let head_before = tile.last_applied;
    let nodes_before = tile.fork_choice.nodes.len();

    let _ = match tile.parse_and_verify_block(&buf, false) {
        Ok(parsed) => tile.apply_and_publish(parsed, &buf, false, |_block_root| {}),
        Err(err) => err.feedback(),
    };

    assert_eq!(tile.last_applied, head_before, "head must be unchanged");
    assert_eq!(tile.fork_choice.nodes.len(), nodes_before, "no node added");
}

// ── pending-block bounds ──

#[test]
fn pending_admission_window_bounds() {
    let mut tile = make_tile_at_wall_slot(50);
    seed_tile(&mut tile, 4, 10);
    let fin = tile.head_finalized_checkpoint().epoch * SLOTS_PER_EPOCH;
    let tol = tile.pending_bounds.future_tolerance;
    // At/below the finalized boundary: rejected.
    assert!(!tile.within_pending_window(fin));
    // Above finalized and within the future tolerance: admitted.
    assert!(tile.within_pending_window(fin + 1));
    assert!(tile.within_pending_window(50 + tol));
    // Beyond the future tolerance: rejected.
    assert!(!tile.within_pending_window(50 + tol + 1));
}

/// Tile (seed separately) plus a spine + adapter, so tests can drive
/// `buffer_orphan`, which produces into `adapter.producers`. The spine is
/// returned to keep it alive for the adapter.
fn tile_with_producers(
    wall_slot: u64,
) -> (BeaconStateTile, TProducer, Box<SilverSpine>, SpineAdapter<SilverSpine>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let (tile, gp) = make_tile_with_gossip(wall_slot);
    let base = std::env::temp_dir().join(format!(
        "silver-pending-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&base).expect("temp base");
    let mut spine = Box::new(SilverSpine::new_with_base_dir(&base, None));
    let adapter = SpineAdapter::connect_tile(&tile, &mut spine);
    (tile, gp, spine, adapter)
}

fn root_with(idx: u64, tag: u8) -> B256 {
    let mut r = [0u8; 32];
    r[..8].copy_from_slice(&idx.to_le_bytes());
    r[31] = tag;
    r
}

/// Buffer an orphan under a distinct missing parent `idx`, just ahead of
/// the head so the slot-distance fallback stays clear. Its own root is in a
/// separate tag namespace so it never collides with another entry.
fn buffer_orphan_idx(
    tile: &mut BeaconStateTile,
    gp: &mut TProducer,
    producers: &mut Producers,
    idx: u64,
) {
    let parent = root_with(idx, 0x00);
    let block_root = root_with(idx, 0xFF);
    let slot = tile.head_state_slot() + 1;
    tile.buffer_orphan(parent, block_root, gossip_pending(gp, slot), slot, 0, producers);
}

#[test]
fn orphan_below_cap_is_buffered() {
    let (mut tile, mut gp, _spine, mut adapter) = tile_with_producers(200);
    seed_tile(&mut tile, 4, 10); // Following, finalized epoch 0
    let cap = tile.pending_bounds.max_parents;
    for i in 0..cap as u64 - 1 {
        buffer_orphan_idx(&mut tile, &mut gp, &mut adapter.producers, i);
    }
    assert_eq!(tile.pending_blocks.len(), cap - 1);
    // A new distinct missing parent while below the cap is buffered.
    buffer_orphan_idx(&mut tile, &mut gp, &mut adapter.producers, u64::MAX);
    assert_eq!(tile.pending_blocks.len(), cap, "orphan buffered below cap");
}

#[test]
fn orphan_at_cap_is_refused() {
    let (mut tile, mut gp, _spine, mut adapter) = tile_with_producers(200);
    seed_tile(&mut tile, 4, 10);
    let cap = tile.pending_bounds.max_parents;
    for i in 0..cap as u64 {
        buffer_orphan_idx(&mut tile, &mut gp, &mut adapter.producers, i);
    }
    assert_eq!(tile.pending_blocks.len(), cap);
    // At the cap, a new distinct missing parent is refused — chain capped.
    buffer_orphan_idx(&mut tile, &mut gp, &mut adapter.producers, u64::MAX);
    assert_eq!(tile.pending_blocks.len(), cap, "orphan refused at cap");
}

#[test]
fn orphan_too_far_ahead_falls_back_to_range_sync() {
    let (mut tile, mut gp, _spine, mut adapter) = tile_with_producers(200);
    seed_tile(&mut tile, 4, 10); // Following, head slot 10
    let head = tile.head_state_slot();
    let limit = tile.pending_bounds.max_chain_len as u64;

    // At the edge of the gap: still buffered (by-root backtrack).
    let edge = head + limit;
    tile.buffer_orphan(
        root_with(0, 0x00),
        root_with(0, 0xFF),
        gossip_pending(&mut gp, edge),
        edge,
        0,
        &mut adapter.producers,
    );
    assert_eq!(tile.pending_blocks.len(), 1, "edge orphan buffered");

    // One slot past the gap: refused before insert, range sync takes over.
    let beyond = head + limit + 1;
    tile.buffer_orphan(
        root_with(1, 0x00),
        root_with(1, 0xFF),
        gossip_pending(&mut gp, beyond),
        beyond,
        0,
        &mut adapter.producers,
    );
    assert_eq!(tile.pending_blocks.len(), 1, "too-far orphan not buffered");
}

#[test]
fn duplicate_orphan_not_rebuffered() {
    let (mut tile, mut gp, _spine, mut adapter) = tile_with_producers(200);
    seed_tile(&mut tile, 4, 10);
    let (parent, block_root) = (root_with(0, 0x00), root_with(0, 0xFF));
    let slot = tile.head_state_slot() + 1;
    let buffer = |tile: &mut BeaconStateTile, gp: &mut TProducer, prods: &mut Producers| {
        tile.buffer_orphan(parent, block_root, gossip_pending(gp, slot), slot, 0, prods);
    };
    buffer(&mut tile, &mut gp, &mut adapter.producers);
    buffer(&mut tile, &mut gp, &mut adapter.producers);
    assert_eq!(tile.pending_blocks.len(), 1, "same parent");
    assert_eq!(tile.pending_blocks[&parent].len(), 1, "duplicate block_root dropped");
}

// ── gossip handlers ──

#[test]
fn attestation_too_short_ignored() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 10);
    let buf = [0u8; 100];
    tile.handle_attestation(&buf, 0);
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_epoch, 0);
}

#[test]
fn ve_unknown_validator_ignored() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let mut buf = [0u8; SIGNED_VOLUNTARY_EXIT_SIZE];
    buf[8..16].copy_from_slice(&999u64.to_le_bytes());
    assert_eq!(tile.handle_voluntary_exit(&buf), Feedback::Ignore);
}

#[test]
fn ve_accept() {
    let mut tile = make_tile();
    // Past shard-committee-period so the exit is permitted.
    seed_tile_with_keys(&mut tile, 4, 256 * SLOTS_PER_EPOCH);
    let imm = seed_immutable(&tile);
    let buf = test_signing::sign_voluntary_exit(0, 0, 0, &imm);
    assert_eq!(tile.handle_voluntary_exit(&buf), Feedback::Accept(None));
}

#[test]
fn ps_identical_headers_rejected() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let buf = [0u8; PROPOSER_SLASHING_SIZE];
    assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
}

#[test]
fn ps_unknown_proposer_ignored() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
    buf[8..16].copy_from_slice(&999u64.to_le_bytes());
    buf[216..224].copy_from_slice(&999u64.to_le_bytes());
    buf[208 + 80] = 0xFF; // distinct body_root in h2
    assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Ignore);
}

#[test]
fn ps_accept() {
    let mut tile = make_tile();
    seed_tile_with_keys(&mut tile, 4, 0);
    let imm = seed_immutable(&tile);
    let buf = test_signing::sign_proposer_slashing(0, 0, 0, &imm);
    assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Accept(None));
}

#[test]
fn ps_mismatched_slot_rejected() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
    buf[208] = 1; // h2.slot differs
    assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
}

#[test]
fn ps_mismatched_proposer_rejected() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
    buf[208 + 8] = 1; // h2.proposer_index differs
    assert_eq!(tile.handle_proposer_slashing(&buf), Feedback::Reject(None));
}

/// IndexedAttestation with `attesting_indices = indices`, zero sig — for
/// structural / state-derived reject tests only.
fn build_ia_with_indices(target_epoch: u64, bbr_marker: u8, indices: &[u64]) -> Vec<u8> {
    let mut buf = vec![0u8; 228 + indices.len() * 8];
    buf[0..4].copy_from_slice(&228u32.to_le_bytes());
    buf[20] = bbr_marker;
    buf[92..100].copy_from_slice(&target_epoch.to_le_bytes());
    for (i, &vi) in indices.iter().enumerate() {
        buf[228 + i * 8..228 + (i + 1) * 8].copy_from_slice(&vi.to_le_bytes());
    }
    buf
}

fn wrap_attester_slashing(ia1: &[u8], ia2: &[u8]) -> Vec<u8> {
    let off1: u32 = 8;
    let off2: u32 = off1 + ia1.len() as u32;
    let mut buf = Vec::with_capacity(8 + ia1.len() + ia2.len());
    buf.extend_from_slice(&off1.to_le_bytes());
    buf.extend_from_slice(&off2.to_le_bytes());
    buf.extend_from_slice(ia1);
    buf.extend_from_slice(ia2);
    buf
}

#[test]
fn as_zero_intersection_rejected() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let ia1 = build_ia_with_indices(0, 0xAA, &[0]);
    let ia2 = build_ia_with_indices(0, 0xBB, &[1]);
    let buf = wrap_attester_slashing(&ia1, &ia2);
    assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Reject(None));
}

#[test]
fn as_accept() {
    let mut tile = make_tile();
    seed_tile_with_keys(&mut tile, 4, 0);
    let imm = seed_immutable(&tile);
    let buf = test_signing::sign_attester_slashing_double_vote(0, 0, 0, 0, &imm);
    assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Accept(None));
}

#[test]
fn as_zero_intersection_with_valid_sigs_rejected() {
    let mut tile = make_tile();
    seed_tile_with_keys(&mut tile, 4, 0);
    let imm = seed_immutable(&tile);
    let ia1 = test_signing::build_indexed_attestation(0, 0, 0, 0, 0, 0xAA, &imm);
    let ia2 = test_signing::build_indexed_attestation(1, 1, 0, 0, 0, 0xBB, &imm);
    let buf = wrap_attester_slashing(&ia1, &ia2);
    assert_eq!(tile.handle_attester_slashing(&buf), Feedback::Reject(None));
}

#[test]
fn bls_change_unknown_validator_ignored() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let mut buf = [0u8; SIGNED_BLS_CHANGE_SIZE];
    buf[0..8].copy_from_slice(&999u64.to_le_bytes());
    assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Ignore);
}

#[test]
fn bls_change_wrong_prefix_rejected() {
    let mut tile = make_tile();
    // Validator 0 has ETH1-prefixed credentials in the base; the
    // canonical head (anchor over the base) then rejects the change.
    let mut eth1 = Withdrawals([0u8; 32]);
    eth1.0[0] = 0x01;
    let seeds: Vec<ValSeed> = (0..4)
        .map(|i| ValSeed {
            pubkey: placeholder_pubkey(i),
            withdrawal_credentials: if i == 0 { eth1 } else { Withdrawals::default() },
            effective_balance: MAX_EFFECTIVE_BALANCE,
            balance: MAX_EFFECTIVE_BALANCE,
            activation_epoch: 0,
            ..Default::default()
        })
        .collect();
    let cp = Checkpoint { epoch: 0, root: ANCHOR_ROOT };
    let epoch_base = epoch_base_with(cp, cp);
    arm_tile(&mut tile, epoch_base, &seeds, 0);
    let buf = [0u8; SIGNED_BLS_CHANGE_SIZE]; // vi = 0
    assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Reject(None));
}

#[test]
fn bls_change_accept() {
    let mut tile = make_tile();
    seed_tile_with_keys(&mut tile, 4, 0);
    let imm = seed_immutable(&tile);
    let to_addr = [0x42u8; 20];
    let buf = test_signing::sign_bls_to_execution_change(0, 0, &to_addr, &imm);
    assert_eq!(tile.handle_bls_to_execution_change(&buf), Feedback::Accept(None));
}

#[test]
fn block_known_parent_bad_sig_rejected() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 128, 10);

    // Known latest_block_header → derive a realistic parent_root and
    // anchor fork choice on it.
    let genesis_header = BeaconBlockHeader {
        slot: 10,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0x01; 32],
        body_root: [0u8; 32],
    };
    {
        // Roll a fresh slot fork off the anchor with the known header set
        // on the writer, commit, and repoint the head bundle's slot index
        // — append-only, no re-open of the published anchor fork.
        let new_slot_idx = {
            let mut g = tile.state.write();
            let mut sw = g.slot_states.roll_from(tile.last_applied.slot_idx);
            sw.state_mut().latest_block_header = genesis_header;
            sw.commit()
        };
        tile.last_applied.slot_idx = new_slot_idx;
    }
    let parent_root = ssz_hash::hash_tree_root_block_header(&genesis_header);

    let cp = Checkpoint { epoch: 0, root: parent_root };
    tile.fork_choice =
        ForkChoice::init(cp, cp, 10, parent_root, [0u8; 32], false, tile.last_applied, 0);

    // Valid structure, zeroed BLS signature → precheck reaches and fails
    // signature verification, so no fork-choice node is added.
    let mut buf = vec![0u8; 200];
    buf[100..108].copy_from_slice(&11u64.to_le_bytes()); // slot
    buf[108..116].copy_from_slice(&0u64.to_le_bytes()); // proposer_index
    buf[116..148].copy_from_slice(&parent_root); // parent_root

    let _ = match tile.parse_and_verify_block(&buf, false) {
        Ok(parsed) => tile.apply_and_publish(parsed, &buf, false, |_block_root| {}),
        Err(err) => err.feedback(),
    };

    assert_eq!(tile.fork_choice.nodes.len(), 1);
}

// ── attestation / aggregate (committee resolution via shuffling cache) ──

/// Locate `(slot, committee_index, pos_in_committee, committee_size)` for
/// validator 0 in epoch 0. The seed arms exactly one cache entry per epoch.
fn find_committee_for_vi0(tile: &BeaconStateTile) -> (Slot, usize, usize, usize) {
    let shuffled = tile.shuffling_cache.shuffled_by_epoch(0).expect("shuffling for epoch 0");
    let shuffling = stf::EpochShuffling::new(shuffled, tile.head_validator_count());
    for s in 0..SLOTS_PER_EPOCH {
        for ci in 0..shuffling.committees_per_slot {
            let c = shuffling.committee(s, ci);
            if let Some(pos) = c.iter().position(|&v| v == 0) {
                return (s, ci, pos, c.len());
            }
        }
    }
    panic!("validator 0 in some committee")
}

/// Spec `compute_subnet_for_attestation`, recomputed independently of the
/// production helper.
fn expected_subnet(tile: &BeaconStateTile, slot: Slot, ci: usize) -> u64 {
    let shuffled = tile
        .shuffling_cache
        .shuffled_by_epoch(slot / SLOTS_PER_EPOCH)
        .expect("shuffling for epoch");
    let cps = stf::EpochShuffling::new(shuffled, tile.head_validator_count()).committees_per_slot;
    (cps as u64 * (slot % SLOTS_PER_EPOCH) + ci as u64) % 64
}

fn build_agg_for_vi0(tile: &BeaconStateTile) -> Vec<u8> {
    let imm = seed_immutable(tile);
    let beacon_block_root = tile.last_applied_block_root;
    let target_root = tile.last_applied_block_root;
    let (slot, ci, pos, csize) = find_committee_for_vi0(tile);
    test_signing::sign_aggregate_and_proof(
        0,
        0,
        slot,
        slot / SLOTS_PER_EPOCH,
        beacon_block_root,
        target_root,
        ci,
        pos,
        csize,
        &imm,
    )
}

#[test]
fn attestation_updates_vote_tracker() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    // Vote for the (known) anchor block; target is the anchor's checkpoint
    // block, so the spec target/ancestor checks accept.
    let bbr = tile.last_applied_block_root;
    let buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    // Assert against what the handler reads via the view (the view owns
    // the offsets), verifying the vote fold self-consistently.
    let want_root = *SingleAttestationView::beacon_block_root(&buf);
    let want_epoch = SingleAttestationView::target_epoch(&buf);
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Accept(None));
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_root, want_root);
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_epoch, want_epoch);
}

/// Spec `validate_on_attestation`: a single attestation for a block we
/// don't hold is dropped (Ignore), self-healing on the validator's next
/// vote.
#[test]
fn single_att_unknown_block_ignored() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let unknown = [0xAAu8; 32];
    let buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        unknown,
        slot / SLOTS_PER_EPOCH,
        unknown,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Ignore);
}

/// Spec `validate_on_attestation`: a known-block vote whose target does not
/// match the block's target-epoch ancestor is rejected.
#[test]
fn single_att_mismatched_target_rejected() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root; // known anchor
    let wrong_target = [0x77u8; 32];
    let buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        wrong_target,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Reject(None));
}

/// Fulu: a single attestation with a non-zero `AttestationData.index` is
/// rejected (the committee belongs in `committee_index`). Checked before
/// signature verification, so a zero-signed buffer suffices.
#[test]
fn single_att_nonzero_data_index_rejected() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    let mut buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    // AttestationData.index @ buf[24..32]; non-zero is illegal post-Electra.
    buf[24] = 1;
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Reject(None));
}

/// Spec `validate_on_attestation`: a current-slot vote is held until the
/// next slot. It is accepted but not folded until `drain_pending_votes`.
#[test]
fn current_slot_vote_deferred_until_drain() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    // Make the committee slot the current slot → the vote must defer.
    tile.ticker.set_current_slot(slot);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    let buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Accept(None));
    // Deferred: not yet folded into the tracker.
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_root, [0u8; 32]);
    let n = tile.head_validator_count();
    tile.fork_choice.drain_pending_votes(n);
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_root, bbr);
}

/// Spec [REJECT]: an attestation must arrive on the subnet its committee
/// maps to.
#[test]
fn single_att_wrong_subnet_rejected() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    let buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&buf, (subnet + 1) % 64), Feedback::Reject(None));
    // The reject must not have marked the attester seen.
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Accept(None));
}

/// Spec [IGNORE]: at most one attestation per (attester, target epoch) —
/// byte-identical or not — and the ignored resend never reaches the pool.
#[test]
fn single_att_repeat_attester_epoch_ignored() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    let mut buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Accept(None));
    let data_root = ssz_hash::hash_attestation_data(SingleAttestationView::data(&buf).as_bytes());
    let first = tile.attestation_pool.aggregate_ssz(slot, ci as u64, data_root).unwrap();

    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Ignore);
    assert_eq!(tile.attestation_pool.aggregate_ssz(slot, ci as u64, data_root).unwrap(), first);

    // Same attester+epoch, different source epoch (the one AttestationData
    // field the handler doesn't validate): first-seen keys on the pair,
    // not the content, so the variant must not open a new pool entry.
    buf[64..72].copy_from_slice(&1u64.to_le_bytes());
    test_signing::resign_single_attestation(0, &mut buf, &imm);
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Ignore);
    let new_root = ssz_hash::hash_attestation_data(SingleAttestationView::data(&buf).as_bytes());
    assert_eq!(tile.attestation_pool.aggregate_ssz(slot, ci as u64, new_root), None);
}

/// A rejected attestation must not mark the attester seen, or a forged
/// message would censor the validator's honest vote for the epoch.
#[test]
fn single_att_failed_validation_does_not_mark_seen() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    // Signed with sk 1; validator 0's registry key is pubkey_pk(0).
    let bad = test_signing::sign_single_attestation(
        1,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&bad, subnet), Feedback::Reject(None));

    let honest = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&honest, subnet), Feedback::Accept(None));
}

/// An accepted single attestation lands in the pool: participant bit at
/// the attester's committee position, bitlist sized to the real committee,
/// data bytes carried over verbatim.
#[test]
fn single_att_accept_inserts_into_pool() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, pos, csize) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    let buf = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Accept(None));

    let data_root = ssz_hash::hash_attestation_data(SingleAttestationView::data(&buf).as_bytes());
    let out =
        tile.attestation_pool.aggregate_ssz(slot, ci as u64, data_root).expect("pooled aggregate");
    let bits = AttestationView::aggregation_bits(&out);
    assert!(bits[pos / 8] & (1 << (pos % 8)) != 0);
    assert_eq!(merkle::bitlist_len(bits), csize);
    assert_eq!(
        AttestationView::data(&out).as_bytes(),
        SingleAttestationView::data(&buf).as_bytes()
    );
}

/// Marking a validator equivocating zeroes its live vote and blocks future
/// votes (spec `equivocating_indices` exclusion).
#[test]
fn equivocator_excluded_from_votes() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 8, 0);
    let anchor = tile.last_applied_block_root;
    let n = tile.head_validator_count();
    tile.fork_choice.record_vote(
        &AttestationVote {
            validator: 3,
            block_root: anchor,
            target_epoch: 0,
            attestation_slot: 0,
            payload_present: false,
        },
        n,
    );
    assert_eq!(tile.fork_choice.vote_tracker.votes[3].latest_root, anchor);

    tile.fork_choice.mark_equivocating(3);
    assert!(tile.fork_choice.is_equivocating(3));
    assert_eq!(tile.fork_choice.vote_tracker.votes[3].latest_root, [0u8; 32]);

    // A later attestation from an equivocator is ignored.
    tile.fork_choice.record_vote(
        &AttestationVote {
            validator: 3,
            block_root: [0x55u8; 32],
            target_epoch: 5,
            attestation_slot: 5,
            payload_present: false,
        },
        n,
    );
    assert_eq!(tile.fork_choice.vote_tracker.votes[3].latest_root, [0u8; 32]);
}

/// The justified-balance snapshot is rebuilt only when the justified
/// checkpoint moves; the first build is a full pass, the next is a no-op.
#[test]
fn justified_balances_rebuilt_on_checkpoint_change_only() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 8, 0);
    // Anchor justified checkpoint differs from the default → stale → rebuild.
    assert!(tile.fork_choice.justified_balances_stale());
    tile.refresh_justified_balances();
    assert!(!tile.fork_choice.justified_balances_stale());
    assert_eq!(tile.fork_choice.justified_balances.len(), 8);
    assert!(tile.fork_choice.justified_balances.iter().all(|&b| b == MAX_EFFECTIVE_BALANCE));
    // Total active balance is cached in the same sweep: all 8 active and
    // unslashed → 8 × MAX_EFFECTIVE_BALANCE (proposer boost reads this
    // instead of re-sweeping per block).
    assert_eq!(tile.fork_choice.justified_total_active_balance(), 8 * MAX_EFFECTIVE_BALANCE);
    // Unchanged checkpoint → no rebuild (idempotent).
    tile.refresh_justified_balances();
}

#[test]
fn agg_multi_committee_bits_rejected() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
    buf[436] = 0b0000_0011; // two committee bits
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
}

#[test]
fn agg_unknown_block_root_ignored() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
    buf[436] = 0b0000_0001; // single committee bit
    buf[228] = 0xFF; // beacon_block_root not in fork choice
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
}

#[test]
fn agg_accept() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let buf = build_agg_for_vi0(&tile);
    let beacon_block_root = tile.last_applied_block_root;
    let slot = SignedAggregateAndProofView::agg_slot(&buf);
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept(None));
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_root, beacon_block_root);
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_epoch, slot / SLOTS_PER_EPOCH);
}

/// `handle_attestation` derives the attester domain from the state's
/// `genesis_validators_root` (through the tile's `ForkDataRoots`). Every
/// other signing test runs with gvr = 0 (`seed_immutable`), so this is the
/// only pin on that wiring: a wrong or stale gvr rejects the attestation.
#[test]
fn single_att_accept_with_nonzero_genesis_validators_root() {
    const GVR: B256 = [0x77; 32];
    let mut tile = make_tile_at_wall_slot(31);
    let (epoch_base, seeds) = build_seed_finalized(128, true);
    let mut bs = BeaconState::for_test(epoch_base, &seeds, 0);
    bs.immutable.genesis_validators_root = GVR;
    arm_tile_state(&mut tile, bs, &seeds, 0);

    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let bbr = tile.last_applied_block_root;

    // Signed against the wrong gvr (= the zero one every other test uses),
    // the attestation must not verify. Runs first: a Reject leaves the
    // attester unseen.
    let bad = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &Immutable::default(),
    );
    assert_eq!(tile.handle_attestation(&bad, subnet), Feedback::Reject(None));

    let mut imm = Immutable::default();
    imm.genesis_validators_root = GVR;
    let good = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&good, subnet), Feedback::Accept(None));
}

/// The root memo is keyed on AttestationData alone, so the single and
/// aggregate paths deduplicate into one entry when they carry the same vote.
#[test]
fn att_root_memo_dedups_across_single_and_aggregate_paths() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let (slot, ci, _, _) = find_committee_for_vi0(&tile);
    let subnet = expected_subnet(&tile, slot, ci);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    let single = test_signing::sign_single_attestation(
        0,
        0,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    assert_eq!(tile.handle_attestation(&single, subnet), Feedback::Accept(None));
    assert_eq!(tile.attestation_root_memo.len(), 1);

    let agg = build_agg_for_vi0(&tile);
    assert_eq!(tile.handle_aggregate_and_proof(&agg), Feedback::Accept(None));
    assert_eq!(tile.attestation_root_memo.len(), 1);
}

/// The slot tick prunes the memo through the same floor as the pool.
#[test]
fn att_root_memo_pruned_on_slot_tick() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 30);
    let domain = [0xD0u8; 32];
    let mut expired = [0u8; ATTESTATION_DATA_SIZE];
    expired[..8].copy_from_slice(&30u64.to_le_bytes());
    let mut kept = [0u8; ATTESTATION_DATA_SIZE];
    kept[..8].copy_from_slice(&33u64.to_le_bytes());
    kept[16] = 1;
    tile.attestation_root_memo.roots(&expired, &domain);
    tile.attestation_root_memo.roots(&kept, &domain);
    assert_eq!(tile.attestation_root_memo.len(), 2);

    tile.slot_tick(34);
    assert_eq!(tile.attestation_root_memo.len(), 1);
}

#[test]
fn agg_respects_epoch_monotonicity() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);

    let preset_root = [0x99u8; 32];
    tile.fork_choice.vote_tracker.votes[0].latest_root = preset_root;
    tile.fork_choice.vote_tracker.votes[0].latest_epoch = 1;

    let buf = build_agg_for_vi0(&tile);
    assert_eq!(SignedAggregateAndProofView::agg_target_epoch(&buf), 0);
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept(None));

    // Older-epoch aggregate must not overwrite the newer vote.
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_root, preset_root);
    assert_eq!(tile.fork_choice.vote_tracker.votes[0].latest_epoch, 1);
}

#[test]
fn agg_slot_too_old_ignored() {
    let mut tile = make_tile_at_wall_slot(100);
    seed_tile_with_keys(&mut tile, 128, 0);
    let buf = build_agg_for_vi0(&tile);
    assert!(SignedAggregateAndProofView::agg_slot(&buf) < 100 - ATTESTATION_PROPAGATION_SLOT_RANGE);
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
}

#[test]
fn agg_slot_too_future_ignored() {
    let mut tile = make_tile_at_wall_slot(0);
    seed_tile(&mut tile, 128, 0);
    let mut buf = vec![0u8; SIGNED_AGG_PROOF_MIN];
    buf[436] = 0b0000_0001;
    buf[212] = 5; // slot = 5 > wall (0)
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
}

#[test]
fn agg_committee_index_oor_rejected() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let mut buf = build_agg_for_vi0(&tile);
    for i in 0..8 {
        buf[436 + i] = 0;
    }
    buf[436] = 0b0000_0010; // committee_index 1, OOR for committees_per_slot=1
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
}

#[test]
fn agg_is_aggregator_false_rejected() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 1024, 0);
    let mut buf = build_agg_for_vi0(&tile);
    let (_, _, _, csize) = find_committee_for_vi0(&tile);
    assert_eq!(csize, 32, "committee_len drives the aggregator modulo");

    let sp_off = 112usize;
    let mut sig_arr: [u8; 96] = buf[sp_off..sp_off + 96].try_into().unwrap();
    let mut b: u16 = 0;
    loop {
        sig_arr[0] = b as u8;
        if !gossip::is_aggregator(csize, &sig_arr) {
            break;
        }
        b += 1;
        assert!(b < 256, "no parity-flipping byte found (impossible)");
    }
    buf[sp_off..sp_off + 96].copy_from_slice(&sig_arr);
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Reject(None));
}

/// Spec [IGNORE]: at most one aggregate per (aggregator, target epoch) —
/// a byte-identical resend dies on the seen probe.
#[test]
fn agg_repeat_aggregator_epoch_ignored() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let buf = build_agg_for_vi0(&tile);
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept(None));
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Ignore);
}

/// A rejected aggregate must not mark the aggregator seen, or a forged
/// message would censor the aggregator's real aggregate for the epoch.
#[test]
fn agg_failed_validation_does_not_mark_aggregator() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let buf = build_agg_for_vi0(&tile);
    let mut forged = buf.clone();
    forged[50] ^= 0xFF; // outer signature = buf[4..100)
    assert_eq!(tile.handle_aggregate_and_proof(&forged), Feedback::Reject(None));
    assert_eq!(tile.handle_aggregate_and_proof(&buf), Feedback::Accept(None));
}

/// First committee (skipping the wall slot) holding two members whose
/// registry keys differ (vi % 3), so the aggregate is genuinely multi-key.
fn find_committee_with_two_signers(tile: &BeaconStateTile) -> (Slot, usize, u32, u32) {
    let shuffled = tile.shuffling_cache.shuffled_by_epoch(0).expect("shuffling for epoch 0");
    let shuffling = stf::EpochShuffling::new(shuffled, tile.head_validator_count());
    for s in 0..SLOTS_PER_EPOCH - 1 {
        for ci in 0..shuffling.committees_per_slot {
            let c = shuffling.committee(s, ci);
            for (i, &a) in c.iter().enumerate() {
                if let Some(&b) = c[i + 1..].iter().find(|&&b| b % 3 != a % 3) {
                    return (s, ci, a, b);
                }
            }
        }
    }
    panic!("two distinct-key members in some committee")
}

fn committee_of(tile: &BeaconStateTile, slot: Slot, ci: usize) -> Vec<u32> {
    let shuffled = tile
        .shuffling_cache
        .shuffled_by_epoch(slot / SLOTS_PER_EPOCH)
        .expect("shuffling for epoch");
    stf::EpochShuffling::new(shuffled, tile.head_validator_count()).committee(slot, ci).to_vec()
}

/// Wrap an inner aggregate with `vi` as aggregator (registry keys cycle
/// `vi % 3`).
fn wrap_by(imm: &Immutable, vi: u32, aggregate: &[u8]) -> Vec<u8> {
    test_signing::wrap_aggregate_and_proof(vi as usize % 3, vi as u64, aggregate, imm)
}

/// Sign `vi`'s single attestation for the anchor at `(slot, ci)`, feed it
/// through `handle_attestation`, and return the grown pooled aggregate.
fn pool_single_then_aggregate(
    tile: &mut BeaconStateTile,
    vi: u32,
    slot: Slot,
    ci: usize,
) -> Vec<u8> {
    let imm = seed_immutable(tile);
    let bbr = tile.last_applied_block_root;
    let buf = test_signing::sign_single_attestation(
        vi as usize % 3,
        vi as u64,
        ci as u64,
        slot,
        bbr,
        slot / SLOTS_PER_EPOCH,
        bbr,
        &imm,
    );
    let data_root = ssz_hash::hash_attestation_data(SingleAttestationView::data(&buf).as_bytes());
    let subnet = expected_subnet(tile, slot, ci);
    assert_eq!(tile.handle_attestation(&buf, subnet), Feedback::Accept(None));
    tile.attestation_pool.aggregate_ssz(slot, ci as u64, data_root).expect("pooled aggregate")
}

#[test]
fn pool_aggregate_accepted_by_aggregate_and_proof_path() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let imm = seed_immutable(&tile);
    let (slot, ci, vi_a, vi_b) = find_committee_with_two_signers(&tile);

    pool_single_then_aggregate(&mut tile, vi_a, slot, ci);
    let aggregate = pool_single_then_aggregate(&mut tile, vi_b, slot, ci);

    // Committee of 4 < 16 ⇒ any member trivially passes is_aggregator.
    let wrapped = wrap_by(&imm, vi_a, &aggregate);
    // Accept requires verify_aggregate_and_proof_sigs: selection proof,
    // outer signature, and the pooled aggregate signature against the two
    // participants' aggregated registry pubkeys.
    assert_eq!(tile.handle_aggregate_and_proof(&wrapped), Feedback::Accept(None));
}

/// First-seen keys on (aggregator, target epoch), not message bytes: a
/// second, different-but-valid aggregate from the same aggregator is
/// still ignored.
#[test]
fn agg_repeat_keys_on_aggregator_not_bytes() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let imm = seed_immutable(&tile);
    let (slot, ci, vi_a, vi_b) = find_committee_with_two_signers(&tile);

    let agg_one = pool_single_then_aggregate(&mut tile, vi_a, slot, ci);
    assert_eq!(
        tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_a, &agg_one)),
        Feedback::Accept(None)
    );

    // A second participant grows the pooled aggregate: different bytes,
    // fully valid, same (aggregator, target epoch).
    let agg_two = pool_single_then_aggregate(&mut tile, vi_b, slot, ci);
    assert_ne!(agg_two, agg_one);
    assert_eq!(tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_a, &agg_two)), Feedback::Ignore);
}

/// Neither admission rule keys on the attestation data alone: aggregates
/// over the same data from two distinct aggregators both accept, provided
/// the second grows bit coverage (equal bits die on the superset rule).
#[test]
fn agg_distinct_aggregators_same_data_both_accept() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let imm = seed_immutable(&tile);
    let (slot, ci, vi_a, vi_b) = find_committee_with_two_signers(&tile);

    let agg_one = pool_single_then_aggregate(&mut tile, vi_a, slot, ci);
    assert_eq!(
        tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_a, &agg_one)),
        Feedback::Accept(None)
    );

    let agg_two = pool_single_then_aggregate(&mut tile, vi_b, slot, ci);
    assert_eq!(
        tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_b, &agg_two)),
        Feedback::Accept(None)
    );
}

/// Spec [IGNORE]: bits ⊆ an already-seen valid aggregate's — equal or
/// strictly smaller — die on the coverage probe regardless of who
/// aggregated them.
#[test]
fn agg_subset_from_other_aggregator_ignored() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let imm = seed_immutable(&tile);
    let (slot, ci, vi_a, vi_b) = find_committee_with_two_signers(&tile);

    let agg_one = pool_single_then_aggregate(&mut tile, vi_a, slot, ci);
    let agg_two = pool_single_then_aggregate(&mut tile, vi_b, slot, ci);
    assert_eq!(
        tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_a, &agg_two)),
        Feedback::Accept(None)
    );

    // Both from an aggregator the epoch has not seen, so only the
    // coverage rule can be what ignores them.
    assert_eq!(tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_b, &agg_two)), Feedback::Ignore);
    assert_eq!(tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_b, &agg_one)), Feedback::Ignore);
}

/// The superset gate fires before signature verification: a covered
/// message with a corrupted outer signature probes Ignore instead of
/// reaching the Reject the signature would earn. Skipping that ~1 ms
/// batch verify is the point of the coverage rule.
#[test]
fn agg_superset_gate_precedes_signature_verify() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let imm = seed_immutable(&tile);
    let (slot, ci, vi_a, vi_b) = find_committee_with_two_signers(&tile);

    let agg_one = pool_single_then_aggregate(&mut tile, vi_a, slot, ci);
    let agg_two = pool_single_then_aggregate(&mut tile, vi_b, slot, ci);
    assert_eq!(
        tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_a, &agg_two)),
        Feedback::Accept(None)
    );

    let mut forged = wrap_by(&imm, vi_b, &agg_one);
    forged[50] ^= 0xFF; // outer signature = buf[4..100)
    assert_eq!(tile.handle_aggregate_and_proof(&forged), Feedback::Ignore);
}

/// Union-covered bits (inside the OR of seen patterns, ⊆ none singly)
/// must still verify and relay: union coverage sheds only the local vote
/// fold, never forwarding.
#[test]
fn agg_union_covered_still_relays() {
    let mut tile = make_tile_at_wall_slot(31);
    seed_tile_with_keys(&mut tile, 128, 0);
    let imm = seed_immutable(&tile);
    let bbr = tile.last_applied_block_root;
    let (slot, ci, vi_a, vi_b) = find_committee_with_two_signers(&tile);
    let committee = committee_of(&tile, slot, ci);
    let vi_c = *committee.iter().find(|&&v| v != vi_a && v != vi_b).expect("committee of 4");
    let pos_b = committee.iter().position(|&v| v == vi_b).unwrap();

    // {a} from aggregator a, then {b} alone from aggregator b: disjoint
    // patterns whose union is {a, b}.
    let agg_a = pool_single_then_aggregate(&mut tile, vi_a, slot, ci);
    assert_eq!(
        tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_a, &agg_a)),
        Feedback::Accept(None)
    );
    let agg_b_only = test_signing::sign_aggregate_and_proof(
        vi_b as usize % 3,
        vi_b as u64,
        slot,
        slot / SLOTS_PER_EPOCH,
        bbr,
        bbr,
        ci,
        pos_b,
        committee.len(),
        &imm,
    );
    assert_eq!(tile.handle_aggregate_and_proof(&agg_b_only), Feedback::Accept(None));

    // {a, b} from a third aggregator: within the union, inside neither.
    let agg_ab = pool_single_then_aggregate(&mut tile, vi_b, slot, ci);
    assert_eq!(
        tile.handle_aggregate_and_proof(&wrap_by(&imm, vi_c, &agg_ab)),
        Feedback::Accept(None)
    );
}

// ── finalization (deposit append lands on the delta, not the base) ──

/// A `PendingDeposit` for a brand-new validator (spec key 0), signed under
/// the genesis deposit domain (fork version + gvr both zero).
fn signed_new_validator_deposit() -> (BLSPubkey, PendingDeposit) {
    const DOMAIN_DEPOSIT: u32 = 0x03;
    let pk = test_signing::pubkey_bytes(0);
    let wc = Withdrawals([0xAAu8; 32]);
    let amount = 32_000_000_000u64;

    let msg_root =
        merkle::merkleize(&[merkle::hash_fixed_bytes(&pk), wc.0, merkle::uint64_chunk(amount)]);
    let domain = bls::compute_domain(DOMAIN_DEPOSIT, [0; 4], &[0u8; 32]);
    let signing_root = bls::compute_signing_root(&msg_root, &domain);
    let sig = test_signing::sign(0, &signing_root);

    (pk, PendingDeposit { pubkey: pk, withdrawal_credentials: wc, amount, signature: sig, slot: 0 })
}

/// Speculative validator appends from deposit processing must land on the
/// head fork's `validators` delta, not on the shared finalized base —
/// the base only advances at Casper finality.
#[test]
fn epoch_transition_keeps_base_until_finality() {
    let mut tile = make_tile();
    // Arm with epoch 1 already finalized in the base (finality lives in the
    // base, so this is equivalent to advancing it — and avoids mutating the
    // published base mid-test) so slot-0 deposits are eligible.
    let (_eb, seeds) = build_seed_finalized(1, false);
    let epoch_base = epoch_base_with(Checkpoint { epoch: 0, root: ANCHOR_ROOT }, Checkpoint {
        epoch: 1,
        root: ANCHOR_ROOT,
    });
    arm_tile(&mut tile, epoch_base, &seeds, 0);

    let (pk, deposit) = signed_new_validator_deposit();
    // Queue the deposit append-only: roll a fresh pending fork off the
    // head, push, and repoint the head bundle at the committed id.
    tile.last_applied.pending_idx = {
        let mut g = tile.state.write();
        let mut pw = g.pending.roll_from(tile.last_applied.pending_idx);
        pw.deposits.push(deposit);
        pw.commit()
    };

    tile.on_slot_start(SLOTS_PER_EPOCH);

    // Base unchanged; the new validator lives on the head fork's delta.
    assert_eq!(
        tile.state.state().validators.finalized().validator_count(),
        1,
        "base must wait for finality"
    );
    let head_validators = tile.state.state().validators.view(tile.last_applied.validators_idx);
    assert_eq!(head_validators.count(), 2);
    assert_eq!(*head_validators.pubkey(1), pk);
}

/// `maybe_finalize` with `fin_idx > 0` must (a) promote the finalized
/// delta into the base, (b) prune non-descendant siblings from fork
/// choice, (c) re-base the surviving descendant's cumulative edits against
/// the new base, and (d) hand the survivor its re-anchored bundle. This is
/// the only place the survivor re-base path is exercised — single-fork
/// tests take the no-promote branch (`fin_idx == 0`).
#[test]
fn multi_fork_finalize_promotes_and_rebases() {
    let mut tile = make_tile();
    seed_tile(&mut tile, 4, 0);
    let anchor_id = tile.last_applied;

    const F_ROOT: B256 = [0x0F; 32];
    const D_ROOT: B256 = [0x0D; 32];
    const F2_ROOT: B256 = [0xF2; 32];
    const ZERO_CP: Checkpoint = Checkpoint { epoch: 0, root: [0u8; 32] };
    let f_cp = Checkpoint { epoch: 0, root: F_ROOT };

    // Roll a slot-group fork off `parent` with a slot number + one
    // cumulative block root set on the writer, then commit — the
    // writer→commit path (no in-place re-open). `reset_from` carries the
    // parent's root tail, so a child appends onto it.
    let roll_slot = |st: &mut BeaconStateOwner, parent: SlotStateId, slot: Slot, root: B256| {
        let mut g = st.write();
        let mut sw = g.slot_states.roll_from(parent);
        sw.state_mut().slot = slot;
        sw.push_block_root(root);
        sw.commit()
    };
    let roll_balances = |st: &mut BeaconStateOwner, parent| {
        let mut g = st.write();
        g.balances.roll_from(parent).commit()
    };

    // F: child of anchor (to be finalized). One cumulative `block_root`.
    // Each fork's bundle copies its parent's and re-points the rolled
    // tiers (slot + balances here, the others shared for this test).
    let f_id = StateId {
        balances_idx: roll_balances(&mut tile.state, anchor_id.balances_idx),
        slot_idx: roll_slot(&mut tile.state, anchor_id.slot_idx, 1, F_ROOT),
        ..anchor_id
    };

    // D: child of F (head, survives). Inherits F's block_roots via
    // `reset_from`, appends its own → [F_ROOT, D_ROOT].
    let d_id = StateId {
        balances_idx: roll_balances(&mut tile.state, f_id.balances_idx),
        slot_idx: roll_slot(&mut tile.state, f_id.slot_idx, 2, D_ROOT),
        ..f_id
    };

    // F2: sibling of F (will be pruned by fork choice).
    let f2_id = StateId {
        balances_idx: roll_balances(&mut tile.state, anchor_id.balances_idx),
        slot_idx: roll_slot(&mut tile.state, anchor_id.slot_idx, 1, F2_ROOT),
        ..anchor_id
    };

    // Insert F2 first so its idx is below F's — fork choice's `prune`
    // only drops the prefix below the finalized node, so the sibling has
    // to live ahead of the to-be-finalized node to be reclaimed.
    tile.fork_choice.on_block(BlockImport {
        slot: 1,
        block_root: F2_ROOT,
        parent_root: ANCHOR_ROOT,
        execution_block_hash: [0u8; 32],
        justified: ZERO_CP,
        finalized: ZERO_CP,
        unrealized_justified: ZERO_CP,
        unrealized_finalized: ZERO_CP,
        state_id: f2_id,
        bid_block_hash: [0u8; 32],
        parent_payload_status: PayloadStatus::Full,
        payload_verified: true,
        is_gloas: false,
    });
    tile.fork_choice.on_block(BlockImport {
        slot: 1,
        block_root: F_ROOT,
        parent_root: ANCHOR_ROOT,
        execution_block_hash: [0u8; 32],
        justified: f_cp,
        finalized: f_cp,
        unrealized_justified: f_cp,
        unrealized_finalized: f_cp,
        state_id: f_id,
        bid_block_hash: [0u8; 32],
        parent_payload_status: PayloadStatus::Full,
        payload_verified: true,
        is_gloas: false,
    });
    tile.fork_choice.on_block(BlockImport {
        slot: 2,
        block_root: D_ROOT,
        parent_root: F_ROOT,
        execution_block_hash: [0u8; 32],
        justified: f_cp,
        finalized: f_cp,
        unrealized_justified: f_cp,
        unrealized_finalized: f_cp,
        state_id: d_id,
        bid_block_hash: [0u8; 32],
        parent_payload_status: PayloadStatus::Full,
        payload_verified: true,
        is_gloas: false,
    });

    // Head is D; finality target is F.
    tile.last_applied = d_id;
    tile.last_applied_block_root = D_ROOT;
    tile.fork_choice.finalized_checkpoint = f_cp;
    // Republish so the seqlock control matches the new head.
    tile.state.publish_state_id(d_id);

    // Sanity: pre-finalize state.
    assert_eq!(tile.state.state().slot_states.finalized_view().slot_number(), 0);
    let d_slot_view = tile.state.state().slot_states.view(d_id.slot_idx);
    assert_eq!(d_slot_view.delta_block_roots(), [F_ROOT, D_ROOT]);
    assert!(tile.fork_choice.find_node_idx(&F2_ROOT).is_some());

    tile.maybe_finalize();

    // (a) Base advanced to F's slot scalars; F's block_root landed in the
    //     circular buffer at the old finalized slot offset.
    let base = tile.state.state().slot_states.finalized_view();
    assert_eq!(base.slot_number(), 1, "base slot promoted to F's slot");
    assert_eq!(base.finalized_block_roots()[0], F_ROOT, "F's block_root in base circular buffer");

    // (b) F2 pruned from fork choice; F is now node 0 (anchor); D survives.
    assert!(tile.fork_choice.find_node_idx(&F2_ROOT).is_none(), "F2 dropped");
    assert_eq!(tile.fork_choice.find_node_idx(&F_ROOT), Some(0), "F is the new anchor");
    let d_node = tile.fork_choice.find_node_idx(&D_ROOT).expect("D survives");

    // (c) D's cumulative `block_roots` log re-based against the new base:
    //     F's prefix drained, only D's incremental entry remains. Finalize
    //     re-anchored D into a fresh slot fork, so re-read its bundle from
    //     the fork-choice node.
    let d_rebased = tile.fork_choice.node(d_node).state_id;
    let d_slot_view = tile.state.state().slot_states.view(d_rebased.slot_idx);
    assert_eq!(d_slot_view.delta_block_roots(), [D_ROOT], "D's block_roots drained of F's prefix");

    // (d) D was the head, so `last_applied` got the same re-anchored
    //     bundle (not the stale pre-finalize one).
    assert_eq!(tile.last_applied, d_rebased, "head bundle refreshed");
    assert_ne!(tile.last_applied, d_id, "stale head bundle replaced");
}

// ── fork_digest (standalone `compute_fork_digest`, no tile state) ──

const FD_SENTINEL: BlobParameters = BlobParameters { epoch: u64::MAX, max_blobs_per_block: 0 };

fn fd_genesis_validators_root(b: u8) -> B256 {
    [b; 32]
}

fn fd_ef_schedule() -> [BlobParameters; 6] {
    [
        BlobParameters { epoch: 9, max_blobs_per_block: 9 },
        BlobParameters { epoch: 100, max_blobs_per_block: 100 },
        BlobParameters { epoch: 150, max_blobs_per_block: 175 },
        BlobParameters { epoch: 200, max_blobs_per_block: 200 },
        BlobParameters { epoch: 250, max_blobs_per_block: 275 },
        BlobParameters { epoch: 300, max_blobs_per_block: 300 },
    ]
}

fn fd_ef_digest(epoch: Epoch, fork_version: Version, gvr: &B256) -> [u8; 4] {
    let schedule = fd_ef_schedule();
    let bp = get_blob_parameters(epoch, &schedule, FD_SENTINEL);
    compute_fork_digest(fork_version, gvr, Some(bp))
}

#[test]
fn ef_compute_fork_digest_vectors() {
    let v6 = [0x06, 0x00, 0x00, 0x00];
    let v61 = [0x06, 0x00, 0x00, 0x01];
    let v7 = [0x07, 0x00, 0x00, 0x00];
    let v71 = [0x07, 0x00, 0x00, 0x01];

    let cases: &[(Epoch, Version, B256, [u8; 4])] = &[
        (9, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
        (10, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
        (11, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
        (99, v6, fd_genesis_validators_root(0), [0xab, 0x3a, 0xe6, 0xc8]),
        (100, v6, fd_genesis_validators_root(0), [0xdf, 0x67, 0x55, 0x7b]),
        (101, v6, fd_genesis_validators_root(0), [0xdf, 0x67, 0x55, 0x7b]),
        (150, v6, fd_genesis_validators_root(0), [0x8a, 0xb3, 0x8b, 0x59]),
        (199, v6, fd_genesis_validators_root(0), [0x8a, 0xb3, 0x8b, 0x59]),
        (200, v6, fd_genesis_validators_root(0), [0xd9, 0xb8, 0x14, 0x38]),
        (201, v6, fd_genesis_validators_root(0), [0xd9, 0xb8, 0x14, 0x38]),
        (250, v6, fd_genesis_validators_root(0), [0x4e, 0xf3, 0x2a, 0x62]),
        (299, v6, fd_genesis_validators_root(0), [0x4e, 0xf3, 0x2a, 0x62]),
        (300, v6, fd_genesis_validators_root(0), [0xca, 0x10, 0x0d, 0x64]),
        (301, v6, fd_genesis_validators_root(0), [0xca, 0x10, 0x0d, 0x64]),
        (9, v6, fd_genesis_validators_root(1), [0x89, 0x67, 0x11, 0x11]),
        (9, v6, fd_genesis_validators_root(2), [0xf4, 0x9b, 0x0e, 0x24]),
        (9, v6, fd_genesis_validators_root(3), [0x86, 0x54, 0x4e, 0x4f]),
        (100, v6, fd_genesis_validators_root(1), [0xfd, 0x3a, 0xa2, 0xa2]),
        (100, v6, fd_genesis_validators_root(2), [0x80, 0xc6, 0xbd, 0x97]),
        (100, v6, fd_genesis_validators_root(3), [0xf2, 0x09, 0xfd, 0xfc]),
        (9, v61, fd_genesis_validators_root(0), [0x30, 0xf8, 0xc2, 0x5b]),
        (9, v7, fd_genesis_validators_root(0), [0x04, 0x32, 0xf5, 0xa9]),
        (9, v71, fd_genesis_validators_root(0), [0x6e, 0x69, 0xa6, 0x71]),
        (100, v61, fd_genesis_validators_root(0), [0x44, 0xa5, 0x71, 0xe8]),
        (100, v7, fd_genesis_validators_root(0), [0x70, 0x6f, 0x46, 0x1a]),
        (100, v71, fd_genesis_validators_root(0), [0x1a, 0x34, 0x15, 0xc2]),
    ];

    for (epoch, fv, g, expected) in cases {
        let got = fd_ef_digest(*epoch, *fv, g);
        assert_eq!(
            got, *expected,
            "epoch={epoch} fv={fv:02x?} gvr[0]={:#04x}: got {got:02x?}, want {expected:02x?}",
            g[0]
        );
    }
}

#[test]
fn mainnet_fulu_fork_digest_419072() {
    let mainnet_gvr: B256 = [
        0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd,
        0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b,
        0xfe, 0x95,
    ];
    let spec = SpecConfig::mainnet();
    let bp = get_blob_parameters(419072, &spec.blob_schedule, spec.default_blob_params());
    assert_eq!(bp, BlobParameters { epoch: 419072, max_blobs_per_block: 21 });

    let digest = compute_fork_digest(spec.fulu_fork_version, &mainnet_gvr, Some(bp));
    assert_eq!(digest, [0x8c, 0x9f, 0x62, 0xfe]);
}
