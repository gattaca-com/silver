use core::cmp::{max, min};

use blst::min_pk::PublicKey;
use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationDataView, AttestationView, BEACON_BLOCK_BODY_FIXED,
    BEACON_BLOCK_HEADER_SIZE, BLOCK_SYNC_AGGREGATE_SIZE, BeaconBlockBodyView,
    BeaconBlockHeaderView, CONSOLIDATION_REQUEST_SIZE, ConsolidationRequestView,
    DEPOSIT_CONTRACT_TREE_DEPTH, DEPOSIT_REQUEST_SIZE, DEPOSIT_SIZE, DepositDataView,
    DepositRequestView, DepositView, Eth1DataView, ExecutionPayloadView, PROPOSER_SLASHING_SIZE,
    ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE,
    SignedBeaconBlockView, SignedBlsToExecutionChangeView, SignedVoluntaryExitView,
    SyncAggregateView, WITHDRAWAL_REQUEST_SIZE, WITHDRAWAL_SIZE, WithdrawalRequestView,
    WithdrawalView,
};

use crate::{
    bls::{self, SigBatch},
    epoch_transition,
    error::{
        AttestationError, AttesterSlashingError, BlockError, BlsToExecutionChangeError, Error,
        ExecutionPayloadError, ProposerSlashingError, Result, SyncAggregateError,
        VoluntaryExitError, WithdrawalRecord, WithdrawalsError,
    },
    shuffling::{self, DOMAIN_BEACON_ATTESTER, MAX_EFFECTIVE_BALANCE},
    ssz_hash::{self, hash_tree_root_block_header, hash_tree_root_state},
    types::{
        self, B256, BeaconBlockHeader, EPOCHS_PER_ETH1_VOTING_PERIOD, EPOCHS_PER_SLASHINGS_VECTOR,
        Epoch, EpochData, Eth1Data, ExecutionPayloadHeader, HistoricalLongtail, Immutable,
        MAX_WITHDRAWALS_PER_PAYLOAD, PendingConsolidation, PendingDeposit,
        PendingPartialWithdrawal, PendingQueues, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
        SYNC_COMMITTEE_SIZE, Slot, SlotData, SlotRoots, ValidatorIdentity,
    },
    validate,
};

const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 4096;
const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 4096;
const FULL_EXIT_REQUEST_AMOUNT: u64 = 0;
const SHARD_COMMITTEE_PERIOD: u64 = 256;
const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
const MAX_SEED_LOOKAHEAD: u64 = 4;
const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: u64 = 256;
const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;
const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = u64::MAX;
const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
// BLS G2 point at infinity (compressed): 0xc0 followed by 95 zero bytes.
const G2_POINT_AT_INFINITY: [u8; 96] = {
    let mut buf = [0u8; 96];
    buf[0] = 0xc0;
    buf
};

#[allow(clippy::too_many_arguments)]
pub fn apply_block(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    block_bytes: &[u8],
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    body_root: B256,
    block_state_root: B256,
    shuffling: Option<&ShufflingRef<'_>>,
    zh: &[B256],
    active_scratch: &mut Vec<u32>,
    postponed_scratch: &mut Vec<types::PendingDeposit>,
    attestation_votes: &mut Vec<(u32, B256, Epoch)>,
    sig_batch: &mut SigBatch,
) -> Result<()> {
    let wrap = |kind: BlockError| Error::invalid_block(block_state_root, kind);

    if block_slot <= sd.latest_block_header.slot {
        return Err(wrap(BlockError::SlotNotAfterHeader {
            slot: block_slot,
            latest: sd.latest_block_header.slot,
        }));
    }

    // Proposer must match `proposer_lookahead` (Fulu, valid for
    // current_epoch and next_epoch — 64 slots from current_epoch start).
    let head_epoch = sd.slot / SLOTS_PER_EPOCH;
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    if block_epoch == head_epoch || block_epoch == head_epoch + 1 {
        let la_idx = (block_slot - head_epoch * SLOTS_PER_EPOCH) as usize;
        if la_idx < types::PROPOSER_LOOKAHEAD_SIZE &&
            proposer_index != sd.proposer_lookahead[la_idx]
        {
            return Err(wrap(BlockError::ProposerLookaheadMismatch {
                got: proposer_index,
                expected: sd.proposer_lookahead[la_idx],
            }));
        }
    }

    if block_slot > sd.slot {
        process_slots(
            imm,
            vid,
            longtail,
            epoch,
            roots,
            sd,
            pq,
            block_slot,
            zh,
            active_scratch,
            postponed_scratch,
        );
    }

    process_block_header(vid, epoch, sd, block_slot, proposer_index, parent_root, body_root, zh)
        .map_err(wrap)?;

    let body = if block_bytes.len() > 184 { &block_bytes[184..] } else { &[] };
    process_block_body(
        imm,
        vid,
        longtail,
        epoch,
        roots,
        sd,
        pq,
        active_scratch,
        sig_batch,
        body,
        block_state_root,
        block_slot,
        proposer_index,
        shuffling,
        zh,
        attestation_votes,
    )?;

    let actual = hash_tree_root_state(imm, vid, longtail, epoch, roots, sd, pq, zh);
    if actual != block_state_root {
        return Err(wrap(BlockError::PostStateRootMismatch {
            expected: block_state_root,
            got: actual,
        }));
    }
    Ok(())
}

/// Shuffle active indices for current and previous epoch into the caller's
/// buffers. Returns (cur_cps, prev_cps, current_epoch, prev_epoch).
fn build_shuffling(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &SlotData,
    cur: &mut Vec<u32>,
    prev: &mut Vec<u32>,
) -> (usize, usize, Epoch, Epoch) {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let prev_epoch = current_epoch.saturating_sub(1);
    let cur_seed = shuffling::get_seed(epoch, current_epoch, DOMAIN_BEACON_ATTESTER);
    let prev_seed = shuffling::get_seed(epoch, prev_epoch, DOMAIN_BEACON_ATTESTER);
    shuffling::get_active_validator_indices_into(epoch, vid.validator_cnt, current_epoch, cur);
    shuffling::get_active_validator_indices_into(epoch, vid.validator_cnt, prev_epoch, prev);
    let cur_cps = shuffling::committees_per_slot(cur.len());
    let prev_cps = shuffling::committees_per_slot(prev.len());
    shuffling::shuffle_list(cur, &cur_seed);
    shuffling::shuffle_list(prev, &prev_seed);
    (cur_cps, prev_cps, current_epoch, prev_epoch)
}

/// Test-only full-block apply path. Decomposes the block SSZ, builds a
/// shuffling from scratch, runs state transition, and compares the
/// post-state root against the block's `state_root`. Production path is
/// `apply_block` (called from the tile, which supplies cached shufflings
/// and pooled scratch buffers).
#[allow(clippy::too_many_arguments)]
pub fn apply_signed_block_debug(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    block_bytes: &[u8],
    zh: &[B256],
) -> Result<()> {
    if block_bytes.len() < 184 {
        return Err(Error::invalid_block([0; 32], BlockError::TooShort {
            len: block_bytes.len(),
            min: 184,
        }));
    }
    let block_slot = SignedBeaconBlockView::slot(block_bytes);
    let proposer_index = SignedBeaconBlockView::proposer_index(block_bytes);
    let parent_root: B256 = *SignedBeaconBlockView::parent_root(block_bytes);
    let state_root: B256 = *SignedBeaconBlockView::state_root(block_bytes);
    let body = SignedBeaconBlockView::body(block_bytes);
    let body_root = ssz_hash::hash_tree_root_body(body, zh);
    let wrap = |kind: BlockError| Error::invalid_block(state_root, kind);

    if block_slot <= sd.latest_block_header.slot {
        return Err(wrap(BlockError::SlotNotAfterHeader {
            slot: block_slot,
            latest: sd.latest_block_header.slot,
        }));
    }

    let mut active_scratch = Vec::new();
    let mut postponed_scratch = Vec::new();

    let head_epoch = sd.slot / SLOTS_PER_EPOCH;
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    if block_epoch == head_epoch || block_epoch == head_epoch + 1 {
        let la_idx = (block_slot - head_epoch * SLOTS_PER_EPOCH) as usize;
        if la_idx < types::PROPOSER_LOOKAHEAD_SIZE &&
            proposer_index != sd.proposer_lookahead[la_idx]
        {
            return Err(wrap(BlockError::ProposerLookaheadMismatch {
                got: proposer_index,
                expected: sd.proposer_lookahead[la_idx],
            }));
        }
    }

    if proposer_index as usize >= vid.validator_cnt {
        return Err(wrap(BlockError::ProposerOutOfRange {
            idx: proposer_index,
            cnt: vid.validator_cnt,
        }));
    }
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    let fork_version = bls::fork_version_at_epoch(
        imm.fork.epoch,
        imm.fork.previous_version,
        imm.fork.current_version,
        block_epoch,
    );
    let proposer_pubkey = &vid.val_pubkey_decompressed[proposer_index as usize];
    if !bls::verify_block_signature(
        block_bytes,
        proposer_pubkey,
        &body_root,
        fork_version,
        &imm.genesis_validators_root,
        zh,
    ) {
        return Err(Error::InvalidBlockSig);
    }

    if block_slot > sd.slot {
        process_slots(
            imm,
            vid,
            longtail,
            epoch,
            roots,
            sd,
            pq,
            block_slot,
            zh,
            &mut active_scratch,
            &mut postponed_scratch,
        );
    }
    process_block_header(vid, epoch, sd, block_slot, proposer_index, parent_root, body_root, zh)
        .map_err(wrap)?;

    let mut curr = Vec::new();
    let mut prev = Vec::new();
    let (cur_cps, prev_cps, ce, pe) = build_shuffling(vid, epoch, sd, &mut curr, &mut prev);
    let sref = ShufflingRef {
        current_epoch: ce,
        current_shuffled: &curr,
        current_cps: cur_cps,
        previous_epoch: pe,
        previous_shuffled: &prev,
        previous_cps: prev_cps,
    };
    let mut votes_sink: Vec<(u32, B256, Epoch)> = Vec::new();
    let mut sig_batch = SigBatch::new();
    process_block_body(
        imm,
        vid,
        longtail,
        epoch,
        roots,
        sd,
        pq,
        &mut active_scratch,
        &mut sig_batch,
        body,
        state_root,
        block_slot,
        proposer_index,
        Some(&sref),
        zh,
        &mut votes_sink,
    )?;

    let actual = hash_tree_root_state(imm, vid, longtail, epoch, roots, sd, pq, zh);
    if actual != state_root {
        return Err(wrap(BlockError::PostStateRootMismatch { expected: state_root, got: actual }));
    }
    Ok(())
}

/// Advance state from `sd.slot` to `target_slot`, processing empty slots.
/// Handles epoch transitions at boundaries (spec: process_epoch runs when
/// `(state.slot + 1) % SLOTS_PER_EPOCH == 0`).
#[allow(clippy::too_many_arguments)]
pub fn process_slots(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &mut HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    target_slot: Slot,
    zh: &[B256],
    active_scratch: &mut Vec<u32>,
    postponed_scratch: &mut Vec<types::PendingDeposit>,
) {
    while sd.slot < target_slot {
        process_slot(imm, vid, longtail, epoch, roots, sd, pq, zh);
        if (sd.slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
            epoch_transition::process_epoch(
                vid,
                longtail,
                epoch,
                sd,
                pq,
                roots,
                zh,
                active_scratch,
                postponed_scratch,
            );
        }
        sd.slot += 1;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn process_slot(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    longtail: &HistoricalLongtail,
    epoch: &EpochData,
    roots: &mut SlotRoots,
    sd: &mut SlotData,
    pq: &PendingQueues,
    zh: &[B256],
) {
    let idx = sd.slot as usize % SLOTS_PER_HISTORICAL_ROOT;

    let prev_state_root = hash_tree_root_state(imm, vid, longtail, epoch, roots, sd, pq, zh);
    roots.state_roots[idx] = prev_state_root;

    if sd.latest_block_header.state_root == [0u8; 32] {
        sd.latest_block_header.state_root = prev_state_root;
    }

    let block_root = hash_tree_root_block_header(&sd.latest_block_header, zh);
    roots.block_roots[idx] = block_root;
}

#[allow(clippy::too_many_arguments)]
pub fn process_block_header(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &mut SlotData,
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    body_root: B256,
    zh: &[B256],
) -> Result<(), BlockError> {
    if block_slot != sd.slot {
        return Err(BlockError::SlotStateMismatch { block: block_slot, state: sd.slot });
    }
    if block_slot <= sd.latest_block_header.slot {
        return Err(BlockError::SlotNotAfterHeader {
            slot: block_slot,
            latest: sd.latest_block_header.slot,
        });
    }
    if proposer_index as usize >= vid.validator_cnt {
        return Err(BlockError::ProposerOutOfRange { idx: proposer_index, cnt: vid.validator_cnt });
    }

    let expected_proposer = sd.proposer_lookahead[(block_slot % SLOTS_PER_EPOCH) as usize];
    if proposer_index != expected_proposer {
        return Err(BlockError::ProposerLookaheadMismatch {
            got: proposer_index,
            expected: expected_proposer,
        });
    }
    if epoch.val_slashed(proposer_index as usize) {
        return Err(BlockError::ProposerSlashed {
            idx: proposer_index,
            pubkey: vid.val_pubkey[proposer_index as usize],
        });
    }

    let expected_parent = hash_tree_root_block_header(&sd.latest_block_header, zh);
    if parent_root != expected_parent {
        return Err(BlockError::ParentRootMismatch { expected: expected_parent, got: parent_root });
    }

    sd.latest_block_header = BeaconBlockHeader {
        slot: block_slot,
        proposer_index,
        parent_root,
        state_root: [0u8; 32],
        body_root,
    };

    Ok(())
}

/// Shuffled indices for current and previous epoch, needed for attestation
/// processing.
pub struct ShufflingRef<'a> {
    pub current_epoch: Epoch,
    pub current_shuffled: &'a [u32],
    pub current_cps: usize,
    pub previous_epoch: Epoch,
    pub previous_shuffled: &'a [u32],
    pub previous_cps: usize,
}

struct BodyOffsets<'a> {
    body: &'a [u8],
    exec_off: usize,
    bls_changes_off: usize,
    proposer_slashings_off: usize,
    attester_slashings_off: usize,
    attestations_off: usize,
    deposits_off: usize,
    voluntary_exits_off: usize,
    blob_off: usize,
    exec_requests_off: usize,
}

impl<'a> BodyOffsets<'a> {
    fn new(body: &'a [u8]) -> Option<Self> {
        if body.len() < BEACON_BLOCK_BODY_FIXED {
            return None;
        }
        Some(Self {
            body,
            exec_off: BeaconBlockBodyView::execution_payload_offset(body) as usize,
            bls_changes_off: BeaconBlockBodyView::bls_to_execution_changes_offset(body) as usize,
            proposer_slashings_off: BeaconBlockBodyView::proposer_slashings_offset(body) as usize,
            attester_slashings_off: BeaconBlockBodyView::attester_slashings_offset(body) as usize,
            attestations_off: BeaconBlockBodyView::attestations_offset(body) as usize,
            deposits_off: BeaconBlockBodyView::deposits_offset(body) as usize,
            voluntary_exits_off: BeaconBlockBodyView::voluntary_exits_offset(body) as usize,
            blob_off: BeaconBlockBodyView::blob_kzg_commitments_offset(body) as usize,
            exec_requests_off: BeaconBlockBodyView::execution_requests_offset(body) as usize,
        })
    }
    #[inline]
    fn payload(&self) -> &'a [u8] {
        if self.exec_off <= self.bls_changes_off && self.bls_changes_off <= self.body.len() {
            &self.body[self.exec_off..self.bls_changes_off]
        } else {
            &[]
        }
    }
    #[inline]
    fn slice(&self, start: usize, end: usize) -> &'a [u8] {
        if start <= end && end <= self.body.len() { &self.body[start..end] } else { &[] }
    }
}

/// Two-pass block body processing.
///
/// Pass 1 — `collect_sigs_block_body` walks every op with a BLS signature and
/// pushes `(pubkey, sig, signing_root)` tuples into `sig_batch`. The only
/// state reads are validator pubkey lookups.
///
/// Verify — `sig_batch.verify_all()` runs one
/// `Signature::verify_multiple_aggregate_signatures` over the whole block
/// (except for deposits).
///
/// Pass 2 — `process_*` functions run in spec order. Each does its own
/// data + state-dependent validation and mutation, returning `Err` on any
/// spec-assertion failure.
#[allow(clippy::too_many_arguments)]
pub fn process_block_body(
    imm: &Immutable,
    vid: &mut ValidatorIdentity,
    longtail: &HistoricalLongtail,
    epoch: &mut EpochData,
    roots: &SlotRoots,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    body: &[u8],
    state_root: B256,
    block_slot: Slot,
    proposer_index: u64,
    shuffling: Option<&ShufflingRef<'_>>,
    zh: &[B256],
    attestation_votes: &mut Vec<(u32, B256, Epoch)>,
) -> Result<()> {
    let wrap = |kind: BlockError| Error::invalid_block(state_root, kind);
    validate::validate_operation_counts(body).map_err(wrap)?;
    let offsets = BodyOffsets::new(body).ok_or_else(|| {
        wrap(BlockError::BodyTooShort { len: body.len(), min: BEACON_BLOCK_BODY_FIXED })
    })?;
    if (proposer_index as usize) >= vid.validator_cnt {
        return Err(wrap(BlockError::ProposerOutOfRange {
            idx: proposer_index,
            cnt: vid.validator_cnt,
        }));
    }

    sig_batch.clear();

    // Pass 1 — sig collection.
    collect_sigs_block_body(
        imm,
        vid,
        longtail,
        roots,
        active_scratch,
        sig_batch,
        &offsets,
        block_slot,
        proposer_index,
        shuffling,
        zh,
    )?;

    // Verify all collected sigs at once (multi-pairing).
    if !sig_batch.verify_all() {
        return Err(Error::SigBatchFailed);
    }

    // Pass 2 — spec-order data + state-dep validate + mutate.
    let body = offsets.body;
    let payload = offsets.payload();

    process_withdrawals(vid, epoch, sd, pq, payload)?;
    process_execution_payload(imm, sd, payload, block_slot, zh)?;
    process_randao(body, sd);
    process_eth1_data(sd, body);

    if offsets.proposer_slashings_off <= offsets.attester_slashings_off &&
        offsets.attester_slashings_off <= body.len()
    {
        process_proposer_slashings(
            vid,
            epoch,
            sd,
            offsets.slice(offsets.proposer_slashings_off, offsets.attester_slashings_off),
        )?;
    }
    if offsets.attester_slashings_off <= offsets.attestations_off &&
        offsets.attestations_off <= body.len()
    {
        process_attester_slashings(
            vid,
            epoch,
            sd,
            offsets.slice(offsets.attester_slashings_off, offsets.attestations_off),
        )?;
    }
    if offsets.attestations_off <= offsets.deposits_off && offsets.deposits_off <= body.len() {
        process_attestations(
            vid,
            epoch,
            roots,
            sd,
            offsets.slice(offsets.attestations_off, offsets.deposits_off),
            block_slot,
            proposer_index,
            shuffling,
            attestation_votes,
            active_scratch,
        )?;
    }
    if offsets.deposits_off <= offsets.voluntary_exits_off &&
        offsets.voluntary_exits_off <= body.len()
    {
        process_deposits(
            vid,
            epoch,
            sd,
            pq,
            offsets.slice(offsets.deposits_off, offsets.voluntary_exits_off),
            zh,
        )?;
    }
    if offsets.voluntary_exits_off <= offsets.exec_off && offsets.exec_off <= body.len() {
        process_voluntary_exits(
            vid,
            epoch,
            sd,
            pq,
            offsets.slice(offsets.voluntary_exits_off, offsets.exec_off),
        )?;
    }
    if offsets.bls_changes_off <= offsets.blob_off && offsets.blob_off <= body.len() {
        process_bls_to_execution_changes(
            vid,
            offsets.slice(offsets.bls_changes_off, offsets.blob_off),
        )?;
    }

    if offsets.exec_requests_off <= body.len() {
        process_execution_requests(vid, epoch, sd, pq, &body[offsets.exec_requests_off..]);
    }
    process_sync_aggregate(vid, longtail, epoch, sd, &body[220..380], proposer_index)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_sigs_block_body(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    longtail: &HistoricalLongtail,
    roots: &SlotRoots,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    offsets: &BodyOffsets<'_>,
    block_slot: Slot,
    proposer_index: u64,
    shuffling: Option<&ShufflingRef<'_>>,
    zh: &[B256],
) -> Result<()> {
    let body = offsets.body;

    let proposer_pubkey = &vid.val_pubkey_decompressed[proposer_index as usize];
    collect_sigs_randao(imm, body, block_slot, proposer_pubkey, sig_batch);

    if offsets.proposer_slashings_off <= offsets.attester_slashings_off &&
        offsets.attester_slashings_off <= body.len()
    {
        collect_sigs_proposer_slashings(
            imm,
            vid,
            offsets.slice(offsets.proposer_slashings_off, offsets.attester_slashings_off),
            sig_batch,
            zh,
        )?;
    }
    if offsets.attester_slashings_off <= offsets.attestations_off &&
        offsets.attestations_off <= body.len()
    {
        collect_sigs_attester_slashings(
            imm,
            vid,
            offsets.slice(offsets.attester_slashings_off, offsets.attestations_off),
            active_scratch,
            sig_batch,
            zh,
        )?;
    }
    if offsets.attestations_off <= offsets.deposits_off && offsets.deposits_off <= body.len() {
        collect_sigs_attestations(
            imm,
            vid,
            offsets.slice(offsets.attestations_off, offsets.deposits_off),
            block_slot,
            shuffling,
            active_scratch,
            sig_batch,
            zh,
        )?;
    }
    // deposits skipped — these are verified inline in `apply_deposit`.
    if offsets.voluntary_exits_off <= offsets.exec_off && offsets.exec_off <= body.len() {
        collect_sigs_voluntary_exits(
            imm,
            vid,
            offsets.slice(offsets.voluntary_exits_off, offsets.exec_off),
            sig_batch,
            zh,
        );
    }
    if offsets.bls_changes_off <= offsets.blob_off && offsets.blob_off <= body.len() {
        collect_sigs_bls_to_execution_changes(
            imm,
            vid,
            offsets.slice(offsets.bls_changes_off, offsets.blob_off),
            sig_batch,
            zh,
        )?;
    }
    collect_sigs_sync_aggregate(
        imm,
        vid,
        longtail,
        &body[220..380],
        block_slot,
        roots,
        active_scratch,
        sig_batch,
    );
    Ok(())
}

pub fn collect_sigs_randao(
    imm: &Immutable,
    body: &[u8],
    block_slot: Slot,
    proposer_pubkey: &PublicKey,
    sig_batch: &mut SigBatch,
) {
    if body.len() < 96 {
        return;
    }
    let reveal: &[u8; 96] = body[0..96].try_into().unwrap();
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    let fork_version = bls::fork_version_at_epoch(
        imm.fork.epoch,
        imm.fork.previous_version,
        imm.fork.current_version,
        block_epoch,
    );
    let mut epoch_chunk = [0u8; 32];
    epoch_chunk[..8].copy_from_slice(&block_epoch.to_le_bytes());
    let domain =
        bls::compute_domain(bls::DOMAIN_RANDAO, fork_version, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&epoch_chunk, &domain);
    sig_batch.push_one(proposer_pubkey, reveal, signing_root);
}

/// Pass 2 — XOR reveal hash into the mix accumulator. BLS already verified
/// in pass 1; if it failed, we never reach here.
fn process_randao(body: &[u8], sd: &mut SlotData) {
    let reveal: &[u8; 96] = body[0..96].try_into().unwrap();
    let reveal_hash = ssz_hash::sha256(reveal);
    for (byte, &rh) in sd.randao_mix_current.iter_mut().zip(reveal_hash.iter()) {
        *byte ^= rh;
    }
}

fn process_eth1_data(sd: &mut SlotData, body: &[u8]) {
    // BeaconBlockBody.eth1_data at body[96..168].
    let eth1: &[u8; 72] = body[96..168].try_into().unwrap();
    let deposit_root: B256 = *Eth1DataView::deposit_root(eth1);
    let deposit_count = Eth1DataView::deposit_count(eth1);
    let block_hash: B256 = *Eth1DataView::block_hash(eth1);

    let vote = Eth1Data { deposit_root, deposit_count, block_hash };
    sd.eth1_votes.push(vote);

    // Check if this vote reaches majority.
    let mut count = 0usize;
    for i in 0..sd.eth1_votes.len() {
        if sd.eth1_votes[i].deposit_root == deposit_root &&
            sd.eth1_votes[i].deposit_count == deposit_count &&
            sd.eth1_votes[i].block_hash == block_hash
        {
            count += 1;
        }
    }
    // Majority = more than half of the voting period slots.
    let slots_per_eth1_voting_period = EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH;
    if count * 2 > slots_per_eth1_voting_period as usize {
        sd.eth1_data = vote;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn collect_sigs_attestations(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    attestation_data: &[u8],
    block_slot: Slot,
    shuffling: Option<&ShufflingRef<'_>>,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    zh: &[B256],
) -> Result<(), AttestationError> {
    if attestation_data.is_empty() {
        return Ok(());
    }
    let first_offset =
        u32::from_le_bytes(attestation_data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > attestation_data.len()
    {
        return Ok(());
    }
    let count = first_offset / 4;
    let current_epoch = block_slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let att_start =
            u32::from_le_bytes(attestation_data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let att_end = if i + 1 < count {
            u32::from_le_bytes(attestation_data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap())
                as usize
        } else {
            attestation_data.len()
        };
        if att_start >= att_end || att_end > attestation_data.len() {
            return Err(AttestationError::BadOffsets {
                start: att_start,
                end: att_end,
                parent_len: attestation_data.len(),
            });
        }
        let att = &attestation_data[att_start..att_end];
        collect_sigs_single_attestation(
            imm,
            vid,
            att,
            current_epoch,
            shuffling,
            active_scratch,
            sig_batch,
            zh,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn collect_sigs_single_attestation(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    att: &[u8],
    current_epoch: Epoch,
    shuffling: Option<&ShufflingRef<'_>>,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    zh: &[B256],
) -> Result<(), AttestationError> {
    let data = AttestationView::data(att);
    let att_slot = AttestationDataView::slot(data);
    let target_epoch = AttestationDataView::target_epoch(data);
    let is_current = target_epoch == current_epoch;
    let shuffling = shuffling.ok_or(AttestationError::MissingShuffling)?;
    let (shuffled, cps) = if is_current {
        (shuffling.current_shuffled, shuffling.current_cps)
    } else {
        (shuffling.previous_shuffled, shuffling.previous_cps)
    };
    if shuffled.is_empty() || cps == 0 {
        return Err(AttestationError::EmptyShuffling);
    }
    let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(att));
    let agg_bits = AttestationView::aggregation_bits(att);
    if committee_bits == 0 {
        return Err(AttestationError::EmptyCommitteeBits);
    }

    active_scratch.clear();
    let mut agg_offset = 0usize;
    for ci in 0..cps {
        if committee_bits & (1u64 << ci) == 0 {
            continue;
        }
        let committee = shuffling::get_beacon_committee(shuffled, att_slot, ci, cps);
        for (j, &validator_idx) in committee.iter().enumerate() {
            let bit_pos = agg_offset + j;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx >= agg_bits.len() || agg_bits[byte_idx] & (1 << bit_idx) == 0 {
                continue;
            }
            let vi = validator_idx as usize;
            if vi >= vid.validator_cnt {
                return Err(AttestationError::ValidatorOutOfRange { vi, cnt: vid.validator_cnt });
            }
            active_scratch.push(validator_idx);
        }
        agg_offset += committee.len();
    }

    let fork_version = bls::fork_version_at_epoch(
        imm.fork.epoch,
        imm.fork.previous_version,
        imm.fork.current_version,
        target_epoch,
    );
    let sig = AttestationView::signature(att);
    let object_root = ssz_hash::hash_attestation_data(data, zh);
    let domain = bls::compute_domain(
        bls::DOMAIN_BEACON_ATTESTER,
        fork_version,
        &imm.genesis_validators_root,
    );
    let signing_root = bls::compute_signing_root(&object_root, &domain);
    sig_batch.push_aggregate(
        active_scratch.iter().map(|&vi| &vid.val_pubkey_decompressed[vi as usize]),
        sig,
        signing_root,
    );
    Ok(())
}

/// Pass 2 — full data + state-dep validation, apply participation flags +
/// proposer rewards. BLS verified in pass 1.
#[allow(clippy::too_many_arguments)]
pub fn process_attestations(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    roots: &SlotRoots,
    sd: &mut SlotData,
    attestation_data: &[u8],
    block_slot: Slot,
    proposer_index: u64,
    shuffling: Option<&ShufflingRef<'_>>,
    votes_sink: &mut Vec<(u32, B256, Epoch)>,
    active_scratch: &mut Vec<u32>,
) -> Result<(), AttestationError> {
    if attestation_data.is_empty() {
        return Ok(());
    }
    let first_offset =
        u32::from_le_bytes(attestation_data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > attestation_data.len()
    {
        return Ok(());
    }
    let count = first_offset / 4;
    let current_epoch = block_slot / SLOTS_PER_EPOCH;
    let previous_epoch = current_epoch.saturating_sub(1);
    for i in 0..count {
        let att_start =
            u32::from_le_bytes(attestation_data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let att_end = if i + 1 < count {
            u32::from_le_bytes(attestation_data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap())
                as usize
        } else {
            attestation_data.len()
        };
        if att_start >= att_end || att_end > attestation_data.len() {
            return Err(AttestationError::BadOffsets {
                start: att_start,
                end: att_end,
                parent_len: attestation_data.len(),
            });
        }
        let att = &attestation_data[att_start..att_end];
        let reward = process_single_attestation(
            vid,
            epoch,
            roots,
            sd,
            att,
            current_epoch,
            previous_epoch,
            shuffling,
            votes_sink,
            active_scratch,
        )?;
        if reward > 0 && (proposer_index as usize) < vid.validator_cnt {
            const PROPOSER_WEIGHT: u64 = 8;
            const WEIGHT_DENOMINATOR: u64 = 64;
            let proposer_reward_denominator =
                (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
            let proposer_reward = reward / proposer_reward_denominator;
            sd.balances[proposer_index as usize] =
                sd.balances[proposer_index as usize].saturating_add(proposer_reward);
        }
    }
    Ok(())
}

/// Pass 2 single-attestation worker — full data + state-dep validation +
/// participation flag updates. Returns the proposer reward numerator on
/// success.
#[allow(clippy::too_many_arguments)]
pub fn process_single_attestation(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    roots: &SlotRoots,
    sd: &mut SlotData,
    att: &[u8],
    current_epoch: Epoch,
    previous_epoch: Epoch,
    shuffling: Option<&ShufflingRef<'_>>,
    votes_sink: &mut Vec<(u32, B256, Epoch)>,
    active_scratch: &mut Vec<u32>,
) -> Result<u64, AttestationError> {
    validate::validate_attestation_data(att, sd.slot, current_epoch, previous_epoch)?;
    let data = AttestationView::data(att);
    let att_slot = AttestationDataView::slot(data);
    let beacon_block_root: B256 = *AttestationDataView::beacon_block_root(data);
    let source_epoch = AttestationDataView::source_epoch(data);
    let source_root: B256 = *AttestationDataView::source_root(data);
    let target_epoch = AttestationDataView::target_epoch(data);
    let target_root: B256 = *AttestationDataView::target_root(data);

    let is_current = target_epoch == current_epoch;
    if !is_current && target_epoch != previous_epoch {
        return Err(AttestationError::TargetEpochOutOfWindow {
            target: target_epoch,
            prev: previous_epoch,
            cur: current_epoch,
        });
    }
    let justified =
        if is_current { sd.current_justified_checkpoint } else { sd.previous_justified_checkpoint };
    if source_epoch != justified.epoch || source_root != justified.root {
        return Err(AttestationError::SourceMismatch {
            expected_epoch: justified.epoch,
            expected_root: justified.root,
            got_epoch: source_epoch,
            got_root: source_root,
        });
    }

    let expected_target_root = get_block_root_at_epoch(roots, target_epoch);
    let is_matching_target = target_root == expected_target_root;
    let expected_head_root = roots.block_roots[att_slot as usize % SLOTS_PER_HISTORICAL_ROOT];
    let is_matching_head = is_matching_target && beacon_block_root == expected_head_root;
    let inclusion_delay = sd.slot.saturating_sub(att_slot);
    let mut flag_weights = [false; 3];
    if inclusion_delay <= 5 {
        flag_weights[0] = true;
    }
    if is_matching_target {
        flag_weights[1] = true;
    }
    if is_matching_head && inclusion_delay == 1 {
        flag_weights[2] = true;
    }

    let shuffling = shuffling.ok_or(AttestationError::MissingShuffling)?;
    let (shuffled, cps) = if is_current {
        (shuffling.current_shuffled, shuffling.current_cps)
    } else {
        (shuffling.previous_shuffled, shuffling.previous_cps)
    };
    if shuffled.is_empty() || cps == 0 {
        return Err(AttestationError::EmptyShuffling);
    }
    let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(att));
    let agg_bits = AttestationView::aggregation_bits(att);
    if committee_bits == 0 {
        return Err(AttestationError::EmptyCommitteeBits);
    }
    if cps < 64 && (committee_bits >> cps) != 0 {
        return Err(AttestationError::CommitteeBitsOverflow { cps, bits: committee_bits });
    }

    active_scratch.clear();
    let mut agg_offset = 0usize;
    for ci in 0..cps {
        if committee_bits & (1u64 << ci) == 0 {
            continue;
        }
        let committee = shuffling::get_beacon_committee(shuffled, att_slot, ci, cps);
        let before = active_scratch.len();
        for (j, &validator_idx) in committee.iter().enumerate() {
            let bit_pos = agg_offset + j;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx >= agg_bits.len() || agg_bits[byte_idx] & (1 << bit_idx) == 0 {
                continue;
            }
            let vi = validator_idx as usize;
            if vi >= vid.validator_cnt {
                return Err(AttestationError::ValidatorOutOfRange { vi, cnt: vid.validator_cnt });
            }
            active_scratch.push(validator_idx);
        }
        if active_scratch.len() == before {
            return Err(AttestationError::EmptyCommittee);
        }
        agg_offset += committee.len();
    }
    let bitlist_len = ssz_hash::bitlist_len(agg_bits);
    if bitlist_len != agg_offset {
        return Err(AttestationError::BitlistLenMismatch { expected: agg_offset, got: bitlist_len });
    }

    for &validator_idx in active_scratch.iter() {
        votes_sink.push((validator_idx, beacon_block_root, target_epoch));
    }

    let any_flag = flag_weights[0] | flag_weights[1] | flag_weights[2];
    if !any_flag {
        return Ok(0);
    }

    let total_active = {
        let n = vid.validator_cnt;
        let mut t = 0u64;
        for i in 0..n {
            if epoch.val_activation_epoch[i] <= current_epoch &&
                current_epoch < epoch.val_exit_epoch[i]
            {
                t += epoch.val_effective_balance[i];
            }
        }
        t.max(1_000_000_000)
    };
    let sqrt_total = epoch_transition::integer_sqrt(total_active);
    let base_reward_per_increment = 1_000_000_000u64 * 64 / sqrt_total;

    const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14];
    let mut proposer_reward_numerator = 0u64;
    let participation_arr = if is_current {
        &mut sd.current_epoch_participation
    } else {
        &mut sd.previous_epoch_participation
    };
    for &validator_idx in active_scratch.iter() {
        let vi = validator_idx as usize;
        let participation = &mut participation_arr[vi];
        let base_reward =
            (epoch.val_effective_balance[vi] / 1_000_000_000) * base_reward_per_increment;
        for (fi, &weight) in PARTICIPATION_WEIGHTS.iter().enumerate() {
            let flag_bit = 1u8 << fi;
            if flag_weights[fi] && *participation & flag_bit == 0 {
                *participation |= flag_bit;
                proposer_reward_numerator += base_reward * weight;
            }
        }
    }
    Ok(proposer_reward_numerator)
}

#[inline]
fn get_block_root_at_epoch(roots: &SlotRoots, epoch: Epoch) -> B256 {
    let slot = epoch * SLOTS_PER_EPOCH;
    roots.block_roots[slot as usize % SLOTS_PER_HISTORICAL_ROOT]
}

/// Validate header sanity then cache the execution payload header.
/// No BLS sigs; everything happens in pass 2.
pub fn process_execution_payload(
    imm: &Immutable,
    sd: &mut SlotData,
    payload_bytes: &[u8],
    block_slot: Slot,
    zh: &[B256],
) -> Result<(), ExecutionPayloadError> {
    if payload_bytes.len() < 528 {
        return Err(ExecutionPayloadError::TooShort { len: payload_bytes.len(), min: 528 });
    }
    validate::validate_execution_payload(imm, sd, payload_bytes, block_slot)?;

    let extra_data_off = ExecutionPayloadView::extra_data_offset(payload_bytes) as usize;
    let transactions_off = ExecutionPayloadView::transactions_offset(payload_bytes) as usize;
    let extra_data_len = if extra_data_off < transactions_off {
        (transactions_off - extra_data_off).min(32)
    } else {
        0
    };
    let mut extra_data = [0u8; 32];
    if extra_data_len > 0 && extra_data_off + extra_data_len <= payload_bytes.len() {
        extra_data[..extra_data_len]
            .copy_from_slice(&payload_bytes[extra_data_off..extra_data_off + extra_data_len]);
    }

    sd.latest_execution_payload_header = ExecutionPayloadHeader {
        parent_hash: *ExecutionPayloadView::parent_hash(payload_bytes),
        fee_recipient: *ExecutionPayloadView::fee_recipient(payload_bytes),
        state_root: *ExecutionPayloadView::state_root(payload_bytes),
        receipts_root: *ExecutionPayloadView::receipts_root(payload_bytes),
        logs_bloom: *ExecutionPayloadView::logs_bloom(payload_bytes),
        prev_randao: *ExecutionPayloadView::prev_randao(payload_bytes),
        block_number: ExecutionPayloadView::block_number(payload_bytes),
        gas_limit: ExecutionPayloadView::gas_limit(payload_bytes),
        gas_used: ExecutionPayloadView::gas_used(payload_bytes),
        timestamp: ExecutionPayloadView::timestamp(payload_bytes),
        extra_data_len: extra_data_len as u8,
        extra_data,
        base_fee_per_gas: *ExecutionPayloadView::base_fee_per_gas(payload_bytes),
        block_hash: *ExecutionPayloadView::block_hash(payload_bytes),
        transactions_root: ssz_hash::hash_transactions_from_payload(payload_bytes, zh),
        withdrawals_root: ssz_hash::hash_withdrawals_from_payload(payload_bytes, zh),
        blob_gas_used: ExecutionPayloadView::blob_gas_used(payload_bytes),
        excess_blob_gas: ExecutionPayloadView::excess_blob_gas(payload_bytes),
    };
    Ok(())
}

/// Process withdrawals from the execution payload.
/// Withdrawal SSZ: index(8) + validator_index(8) + address(20) + amount(8) = 44
/// bytes.
pub fn process_withdrawals(
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    payload_bytes: &[u8],
) -> Result<(), WithdrawalsError> {
    if payload_bytes.len() < 528 {
        return Err(WithdrawalsError::PayloadTooShort { len: payload_bytes.len(), min: 528 });
    }
    let withdrawals_off = ExecutionPayloadView::withdrawals_offset(payload_bytes) as usize;
    if withdrawals_off > payload_bytes.len() {
        return Err(WithdrawalsError::BadOffsets {
            withdrawals_off,
            payload_len: payload_bytes.len(),
        });
    }
    let withdrawals_data = &payload_bytes[withdrawals_off..];

    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16384;
    const MAX_PENDING_PARTIALS_PER_SWEEP: usize = 8;
    let payload_count = withdrawals_data.len() / WITHDRAWAL_SIZE;
    if payload_count > MAX_WITHDRAWALS_PER_PAYLOAD {
        return Err(WithdrawalsError::TooMany {
            count: payload_count,
            max: MAX_WITHDRAWALS_PER_PAYLOAD,
        });
    }
    let n_validators = vid.validator_cnt as u64;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;

    let payload_at = |i: usize| -> WithdrawalRecord {
        if i >= payload_count {
            return WithdrawalRecord::default();
        }
        let w: &[u8; WITHDRAWAL_SIZE] =
            withdrawals_data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE].try_into().unwrap();
        WithdrawalRecord {
            index: WithdrawalView::index(w),
            validator_index: WithdrawalView::validator_index(w),
            address: *WithdrawalView::address(w),
            amount: WithdrawalView::amount(w),
        }
    };
    let matches = |i: usize, expected: &WithdrawalRecord| -> bool {
        i < payload_count && payload_at(i) == *expected
    };

    // Phase 1: pending partial withdrawals.
    let partial_limit = min(MAX_PENDING_PARTIALS_PER_SWEEP, MAX_WITHDRAWALS_PER_PAYLOAD - 1);
    let mut processed_partial_count: usize = 0;
    let mut partials_emitted: usize = 0;
    let mut selected: [(u64, u64); MAX_PENDING_PARTIALS_PER_SWEEP] =
        [(0, 0); MAX_PENDING_PARTIALS_PER_SWEEP];
    let mut expected_count = 0usize;
    let mut withdrawal_index = sd.next_withdrawal_index;
    let mut last_emitted_vi: u64 = 0;

    for qi in 0..pq.pending_partial_withdrawals.len() {
        let pw = &pq.pending_partial_withdrawals[qi];
        if pw.withdrawable_epoch > current_epoch || partials_emitted >= partial_limit {
            break;
        }
        let vi = pw.index as usize;
        if vi < vid.validator_cnt {
            let mut total_withdrawn = 0u64;
            for &(svi, samt) in &selected[..partials_emitted] {
                if svi == pw.index {
                    total_withdrawn = total_withdrawn.saturating_add(samt);
                }
            }
            let balance = sd.balances[vi].saturating_sub(total_withdrawn);
            let eligible = epoch.val_exit_epoch[vi] == u64::MAX &&
                epoch.val_effective_balance[vi] >= MIN_ACTIVATION_BALANCE &&
                balance > MIN_ACTIVATION_BALANCE;
            if eligible {
                let amount = min(balance - MIN_ACTIVATION_BALANCE, pw.amount);
                let address: &[u8; 20] =
                    vid.val_withdrawal_credentials[vi][12..32].try_into().unwrap();
                let expected = WithdrawalRecord {
                    index: withdrawal_index,
                    validator_index: pw.index,
                    address: *address,
                    amount,
                };
                if !matches(expected_count, &expected) {
                    return Err(WithdrawalsError::PartialMismatch {
                        payload_index: expected_count,
                        expected,
                        got: payload_at(expected_count),
                    });
                }
                selected[partials_emitted] = (pw.index, amount);
                partials_emitted += 1;
                expected_count += 1;
                withdrawal_index += 1;
                last_emitted_vi = pw.index;
            }
        }
        processed_partial_count += 1;
    }

    // Phase 2: validator sweep.
    let mut sweep_validator_index = sd.next_withdrawal_validator_index;
    if n_validators > 0 {
        let bound = min(n_validators, MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
        for _ in 0..bound {
            let vi = sweep_validator_index as usize;
            if vi < vid.validator_cnt && has_execution_withdrawal_credential(vid, vi) {
                let mut partial_drawn = 0u64;
                for &(svi, samt) in &selected[..partials_emitted] {
                    if svi == sweep_validator_index {
                        partial_drawn = partial_drawn.saturating_add(samt);
                    }
                }
                let balance = sd.balances[vi].saturating_sub(partial_drawn);
                let max_eb = if has_compounding_credential(vid, vi) {
                    MAX_EFFECTIVE_BALANCE
                } else {
                    MIN_ACTIVATION_BALANCE
                };
                let address: &[u8; 20] =
                    vid.val_withdrawal_credentials[vi][12..32].try_into().unwrap();
                if epoch.val_withdrawable_epoch[vi] <= current_epoch && balance > 0 {
                    let expected = WithdrawalRecord {
                        index: withdrawal_index,
                        validator_index: sweep_validator_index,
                        address: *address,
                        amount: balance,
                    };
                    if !matches(expected_count, &expected) {
                        return Err(WithdrawalsError::SweepMismatchFull {
                            vi: sweep_validator_index,
                            pubkey: vid.val_pubkey[vi],
                            expected,
                            got: payload_at(expected_count),
                        });
                    }
                    expected_count += 1;
                    withdrawal_index += 1;
                    last_emitted_vi = sweep_validator_index;
                } else if epoch.val_effective_balance[vi] == max_eb && balance > max_eb {
                    let amount = balance - max_eb;
                    let expected = WithdrawalRecord {
                        index: withdrawal_index,
                        validator_index: sweep_validator_index,
                        address: *address,
                        amount,
                    };
                    if !matches(expected_count, &expected) {
                        return Err(WithdrawalsError::SweepMismatchExcess {
                            vi: sweep_validator_index,
                            pubkey: vid.val_pubkey[vi],
                            expected,
                            got: payload_at(expected_count),
                        });
                    }
                    expected_count += 1;
                    withdrawal_index += 1;
                    last_emitted_vi = sweep_validator_index;
                }
            }
            if expected_count >= MAX_WITHDRAWALS_PER_PAYLOAD {
                break;
            }
            sweep_validator_index = (sweep_validator_index + 1) % n_validators;
        }
    }

    if expected_count != payload_count {
        return Err(WithdrawalsError::CountMismatch {
            expected: expected_count,
            actual: payload_count,
        });
    }

    // Apply: debit balances + advance cursors.
    for i in 0..payload_count {
        let w: &[u8; WITHDRAWAL_SIZE] =
            withdrawals_data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE].try_into().unwrap();
        let validator_index = WithdrawalView::validator_index(w) as usize;
        let amount = WithdrawalView::amount(w);
        debug_assert!(validator_index < vid.validator_cnt);
        sd.balances[validator_index] = sd.balances[validator_index].saturating_sub(amount);
    }
    if expected_count > 0 {
        sd.next_withdrawal_index = withdrawal_index;
    }
    if processed_partial_count > 0 {
        pq.pending_partial_withdrawals.drain(..processed_partial_count);
    }
    if n_validators > 0 {
        if expected_count == MAX_WITHDRAWALS_PER_PAYLOAD {
            sd.next_withdrawal_validator_index = (last_emitted_vi + 1) % n_validators;
        } else {
            sd.next_withdrawal_validator_index = (sd.next_withdrawal_validator_index +
                MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) %
                n_validators;
        }
    }
    Ok(())
}

/// Pass 1 — resolve sync committee participants from
/// `sync_committee_indices` × bits, push aggregate sig (eth_aggregate
/// semantics — empty + G2-∞ ok).
#[allow(clippy::too_many_arguments)]
pub fn collect_sigs_sync_aggregate(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    longtail: &HistoricalLongtail,
    sync_agg: &[u8],
    block_slot: Slot,
    roots: &SlotRoots,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) {
    if sync_agg.len() < BLOCK_SYNC_AGGREGATE_SIZE {
        return;
    }
    let sync_agg_fixed: &[u8; BLOCK_SYNC_AGGREGATE_SIZE] =
        sync_agg[..BLOCK_SYNC_AGGREGATE_SIZE].try_into().unwrap();
    let bits = SyncAggregateView::sync_committee_bits(sync_agg_fixed);
    let sig = SyncAggregateView::sync_committee_signature(sync_agg_fixed);

    let previous_slot = block_slot.saturating_sub(1);
    let previous_block_root = roots.block_roots[previous_slot as usize % SLOTS_PER_HISTORICAL_ROOT];
    let previous_epoch = previous_slot / SLOTS_PER_EPOCH;
    let fork_version = bls::fork_version_at_epoch(
        imm.fork.epoch,
        imm.fork.previous_version,
        imm.fork.current_version,
        previous_epoch,
    );

    active_scratch.clear();
    for i in 0..SYNC_COMMITTEE_SIZE {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if bits[byte_idx] & (1 << bit_idx) != 0 {
            let vi = longtail.sync_committee_indices[i] as usize;
            if vi >= vid.validator_cnt {
                sig_batch.poison();
                return;
            }
            active_scratch.push(longtail.sync_committee_indices[i]);
        }
    }
    let domain =
        bls::compute_domain(bls::DOMAIN_SYNC_COMMITTEE, fork_version, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&previous_block_root, &domain);
    sig_batch.push_eth_aggregate(
        active_scratch.len(),
        active_scratch.iter().map(|&vi| &vid.val_pubkey_decompressed[vi as usize]),
        sig,
        signing_root,
    );
}

/// Pass 2 — apply sync_aggregate balance updates. BLS verified in pass 1.
pub fn process_sync_aggregate(
    vid: &ValidatorIdentity,
    longtail: &HistoricalLongtail,
    epoch: &EpochData,
    sd: &mut SlotData,
    sync_agg: &[u8],
    proposer_index: u64,
) -> Result<(), SyncAggregateError> {
    if sync_agg.len() < BLOCK_SYNC_AGGREGATE_SIZE {
        return Ok(());
    }
    if (proposer_index as usize) >= vid.validator_cnt {
        return Err(SyncAggregateError::ProposerOutOfRange {
            idx: proposer_index,
            cnt: vid.validator_cnt,
        });
    }
    let sync_agg_fixed: &[u8; BLOCK_SYNC_AGGREGATE_SIZE] =
        sync_agg[..BLOCK_SYNC_AGGREGATE_SIZE].try_into().unwrap();
    let bits = SyncAggregateView::sync_committee_bits(sync_agg_fixed);

    let total_active = {
        let mut t = 0u64;
        let current_epoch = sd.slot / SLOTS_PER_EPOCH;
        for i in 0..vid.validator_cnt {
            if epoch.val_activation_epoch[i] <= current_epoch &&
                current_epoch < epoch.val_exit_epoch[i]
            {
                t += epoch.val_effective_balance[i];
            }
        }
        t.max(1_000_000_000)
    };
    let sqrt_total = epoch_transition::integer_sqrt(total_active);
    let base_reward_per_increment = 1_000_000_000u64 * 64 / sqrt_total;
    let total_active_increments = total_active / 1_000_000_000;

    const SYNC_REWARD_WEIGHT: u64 = 2;
    const WEIGHT_DENOMINATOR: u64 = 64;
    const PROPOSER_WEIGHT: u64 = 8;

    let total_base_rewards = base_reward_per_increment * total_active_increments;
    let participant_reward = if total_active_increments > 0 {
        total_base_rewards * SYNC_REWARD_WEIGHT /
            WEIGHT_DENOMINATOR /
            SLOTS_PER_EPOCH /
            SYNC_COMMITTEE_SIZE as u64
    } else {
        0
    };
    let proposer_reward_per =
        participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

    let mut proposer_reward_sum = 0u64;
    for i in 0..SYNC_COMMITTEE_SIZE {
        let vi = longtail.sync_committee_indices[i] as usize;
        if vi >= vid.validator_cnt {
            continue;
        }
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let participated = bits[byte_idx] & (1 << bit_idx) != 0;
        if participated {
            sd.balances[vi] = sd.balances[vi].saturating_add(participant_reward);
            proposer_reward_sum += proposer_reward_per;
        } else {
            sd.balances[vi] = sd.balances[vi].saturating_sub(participant_reward);
        }
    }
    sd.balances[proposer_index as usize] =
        sd.balances[proposer_index as usize].saturating_add(proposer_reward_sum);
    Ok(())
}

/// Pass 1 — push voluntary-exit sigs. Each exit's signing root is the
/// `(epoch, validator_index)` pair under `DOMAIN_VOLUNTARY_EXIT` pinned to
/// `CAPELLA_FORK_VERSION`. Returns false on out-of-range vi (early reject).
pub fn collect_sigs_voluntary_exits(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    data: &[u8],
    sig_batch: &mut SigBatch,
    zh: &[B256],
) {
    let count = data.len() / SIGNED_VOLUNTARY_EXIT_SIZE;
    for i in 0..count {
        let exit: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] = data
            [i * SIGNED_VOLUNTARY_EXIT_SIZE..(i + 1) * SIGNED_VOLUNTARY_EXIT_SIZE]
            .try_into()
            .unwrap();
        let exit_epoch_msg = SignedVoluntaryExitView::epoch(exit);
        let vi_u = SignedVoluntaryExitView::validator_index(exit);
        let vi = vi_u as usize;
        if vi >= vid.validator_cnt {
            // Push a poison sig so verify_all fails — clearer than a side
            // channel and keeps collect_sigs_* infallible.
            sig_batch.poison();
            return;
        }
        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch_msg, vi_u, zh);
        let domain = bls::compute_domain(
            bls::DOMAIN_VOLUNTARY_EXIT,
            imm.capella_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(exit);
        sig_batch.push_one(&vid.val_pubkey_decompressed[vi], sig, signing_root);
    }
}

/// Pass 2 — validate state-dependent preconditions (post-block-mutation
/// state evolution may change `is_slashable` / pending-balance), apply
/// `initiate_validator_exit` per accepted entry. BLS already verified.
pub fn process_voluntary_exits(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &PendingQueues,
    data: &[u8],
) -> Result<(), VoluntaryExitError> {
    let count = data.len() / SIGNED_VOLUNTARY_EXIT_SIZE;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let n = vid.validator_cnt;
    for i in 0..count {
        let exit: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] = data
            [i * SIGNED_VOLUNTARY_EXIT_SIZE..(i + 1) * SIGNED_VOLUNTARY_EXIT_SIZE]
            .try_into()
            .unwrap();
        let exit_epoch_msg = SignedVoluntaryExitView::epoch(exit);
        let vi = SignedVoluntaryExitView::validator_index(exit) as usize;
        validate::validate_voluntary_exit(vid, epoch, vi, exit_epoch_msg, current_epoch)?;
        if get_pending_balance_to_withdraw(pq, vi) != 0 {
            return Err(VoluntaryExitError::HasPendingBalance { vi, pubkey: vid.val_pubkey[vi] });
        }
        initiate_validator_exit(epoch, sd, n, vi, current_epoch);
    }
    Ok(())
}

fn process_execution_requests(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
) {
    if data.len() < 12 {
        return;
    }
    let off = |pos: usize| -> usize {
        u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize
    };
    let offsets = [off(0), off(4), off(8)];
    let field = |idx: usize| -> &[u8] {
        let start = offsets[idx];
        let end = if idx + 1 < offsets.len() { offsets[idx + 1] } else { data.len() };
        if start <= end && end <= data.len() { &data[start..end] } else { &[] }
    };
    process_deposit_requests(sd, pq, field(0));
    process_withdrawal_requests(vid, epoch, sd, pq, field(1));
    process_consolidation_requests(vid, epoch, sd, pq, field(2));
}

pub fn process_deposit_requests(sd: &mut SlotData, pq: &mut PendingQueues, data: &[u8]) {
    let count = data.len() / DEPOSIT_REQUEST_SIZE;

    for i in 0..count {
        let d: &[u8; DEPOSIT_REQUEST_SIZE] =
            data[i * DEPOSIT_REQUEST_SIZE..(i + 1) * DEPOSIT_REQUEST_SIZE].try_into().unwrap();
        let pubkey = *DepositRequestView::pubkey(d);
        let credentials: B256 = *DepositRequestView::withdrawal_credentials(d);
        let amount = DepositRequestView::amount(d);
        let signature = *DepositRequestView::signature(d);
        let index = DepositRequestView::index(d);

        if sd.deposit_requests_start_index == UNSET_DEPOSIT_REQUESTS_START_INDEX {
            sd.deposit_requests_start_index = index;
        }

        pq.pending_deposits.push(PendingDeposit {
            pubkey,
            withdrawal_credentials: credentials,
            amount,
            signature,
            slot: sd.slot,
        });
    }
}

pub fn process_withdrawal_requests(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
) {
    let count = data.len() / WITHDRAWAL_REQUEST_SIZE;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let n = vid.validator_cnt;

    for i in 0..count {
        let r: &[u8; WITHDRAWAL_REQUEST_SIZE] = data
            [i * WITHDRAWAL_REQUEST_SIZE..(i + 1) * WITHDRAWAL_REQUEST_SIZE]
            .try_into()
            .unwrap();
        let source_address = WithdrawalRequestView::source_address(r);
        let validator_pubkey = WithdrawalRequestView::validator_pubkey(r);
        let amount = WithdrawalRequestView::amount(r);
        let is_full_exit = amount == FULL_EXIT_REQUEST_AMOUNT;

        if pq.pending_partial_withdrawals.len() >= types::PENDING_PARTIAL_WITHDRAWALS_LIMIT &&
            !is_full_exit
        {
            return;
        }

        let vi = match find_validator_by_pubkey(vid, validator_pubkey) {
            Some(idx) => idx,
            None => continue,
        };

        if !has_execution_withdrawal_credential(vid, vi) {
            continue;
        }
        if vid.val_withdrawal_credentials[vi][12..32] != *source_address {
            continue;
        }
        if !is_active(epoch, vi, current_epoch) {
            continue;
        }
        if epoch.val_exit_epoch[vi] != u64::MAX {
            continue;
        }
        if current_epoch < epoch.val_activation_epoch[vi] + SHARD_COMMITTEE_PERIOD {
            continue;
        }

        let pending_balance = get_pending_balance_to_withdraw(pq, vi);

        if is_full_exit {
            if pending_balance == 0 {
                initiate_validator_exit(epoch, sd, n, vi, current_epoch);
            }
            continue;
        }

        let has_sufficient_eff = epoch.val_effective_balance[vi] >= MIN_ACTIVATION_BALANCE;
        let has_excess = sd.balances[vi] > MIN_ACTIVATION_BALANCE + pending_balance;

        if has_compounding_credential(vid, vi) && has_sufficient_eff && has_excess {
            let to_withdraw =
                min(sd.balances[vi] - MIN_ACTIVATION_BALANCE - pending_balance, amount);
            let exit_queue_epoch =
                compute_exit_epoch_and_update_churn(epoch, sd, n, to_withdraw, current_epoch);
            let withdrawable_epoch = exit_queue_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
            pq.pending_partial_withdrawals.push_back(PendingPartialWithdrawal {
                index: vi as u64,
                amount: to_withdraw,
                withdrawable_epoch,
            });
        }
    }
}

pub fn process_consolidation_requests(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
) {
    let count = data.len() / CONSOLIDATION_REQUEST_SIZE;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let n = vid.validator_cnt;

    for i in 0..count {
        let r: &[u8; CONSOLIDATION_REQUEST_SIZE] = data
            [i * CONSOLIDATION_REQUEST_SIZE..(i + 1) * CONSOLIDATION_REQUEST_SIZE]
            .try_into()
            .unwrap();
        let source_address = ConsolidationRequestView::source_address(r);
        let source_pubkey = ConsolidationRequestView::source_pubkey(r);
        let target_pubkey = ConsolidationRequestView::target_pubkey(r);

        if source_pubkey == target_pubkey {
            if let Some(src) = find_validator_by_pubkey(vid, source_pubkey) {
                if vid.val_withdrawal_credentials[src][12..32] == *source_address &&
                    vid.val_withdrawal_credentials[src][0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX &&
                    is_active(epoch, src, current_epoch) &&
                    epoch.val_exit_epoch[src] == u64::MAX
                {
                    switch_to_compounding_validator(vid, sd, pq, src);
                }
            }
            continue;
        }

        // Full consolidation.
        if pq.pending_consolidations.len() >= types::PENDING_CONSOLIDATIONS_LIMIT {
            continue;
        }
        let churn_limit = get_consolidation_churn_limit(epoch, n, current_epoch);
        if churn_limit <= MIN_ACTIVATION_BALANCE {
            continue;
        }

        let source_idx = match find_validator_by_pubkey(vid, source_pubkey) {
            Some(idx) => idx,
            None => continue,
        };
        let target_idx = match find_validator_by_pubkey(vid, target_pubkey) {
            Some(idx) => idx,
            None => continue,
        };

        if !has_execution_withdrawal_credential(vid, source_idx) {
            continue;
        }
        if vid.val_withdrawal_credentials[source_idx][12..32] != *source_address {
            continue;
        }
        if !has_compounding_credential(vid, target_idx) {
            continue;
        }
        if !is_active(epoch, source_idx, current_epoch) ||
            !is_active(epoch, target_idx, current_epoch)
        {
            continue;
        }
        if epoch.val_exit_epoch[source_idx] != u64::MAX ||
            epoch.val_exit_epoch[target_idx] != u64::MAX
        {
            continue;
        }
        if current_epoch < epoch.val_activation_epoch[source_idx] + SHARD_COMMITTEE_PERIOD {
            continue;
        }
        if get_pending_balance_to_withdraw(pq, source_idx) > 0 {
            continue;
        }

        let exit_epoch = compute_consolidation_epoch_and_update_churn(
            epoch,
            sd,
            n,
            epoch.val_effective_balance[source_idx],
            current_epoch,
        );
        epoch.val_exit_epoch[source_idx] = exit_epoch;
        epoch.val_withdrawable_epoch[source_idx] = exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
        pq.pending_consolidations.push(PendingConsolidation {
            source_index: source_idx as u64,
            target_index: target_idx as u64,
        });
    }
}

/// Pass 1 — push both header sigs per slashing entry.
pub fn collect_sigs_proposer_slashings(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    data: &[u8],
    sig_batch: &mut SigBatch,
    zh: &[B256],
) -> Result<(), ProposerSlashingError> {
    let count = data.len() / PROPOSER_SLASHING_SIZE;
    let n = vid.validator_cnt;
    for i in 0..count {
        let s: &[u8; PROPOSER_SLASHING_SIZE] =
            data[i * PROPOSER_SLASHING_SIZE..(i + 1) * PROPOSER_SLASHING_SIZE].try_into().unwrap();
        let vi = ProposerSlashingView::h1_proposer_index(s) as usize;
        if vi >= n {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi, cnt: n });
        }
        let h1_slot = ProposerSlashingView::h1_slot(s);
        let h2_slot = ProposerSlashingView::h2_slot(s);
        let fv1 = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            h1_slot / SLOTS_PER_EPOCH,
        );
        let fv2 = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            h2_slot / SLOTS_PER_EPOCH,
        );
        let sr1 = signing_root_for_block_header(&s[0..208], fv1, &imm.genesis_validators_root, zh);
        let sr2 =
            signing_root_for_block_header(&s[208..416], fv2, &imm.genesis_validators_root, zh);
        let sig1 = ProposerSlashingView::h1_signature(s);
        let sig2 = ProposerSlashingView::h2_signature(s);
        sig_batch.push_one(&vid.val_pubkey_decompressed[vi], sig1, sr1);
        sig_batch.push_one(&vid.val_pubkey_decompressed[vi], sig2, sr2);
    }
    Ok(())
}

/// Pass 2 — validate per-entry preconditions and slash. BLS already
/// verified. `is_slashable_validator` re-check picks up within-block
/// mutations (a same-vi double slashing rejects on the second entry
/// because the first one already set the slashed flag).
pub fn process_proposer_slashings(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    data: &[u8],
) -> Result<(), ProposerSlashingError> {
    let count = data.len() / PROPOSER_SLASHING_SIZE;
    let n = vid.validator_cnt;
    let proposer_index = get_beacon_proposer_index(sd);
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let s: &[u8; PROPOSER_SLASHING_SIZE] =
            data[i * PROPOSER_SLASHING_SIZE..(i + 1) * PROPOSER_SLASHING_SIZE].try_into().unwrap();
        validate::validate_proposer_slashing(s)?;
        let vi = ProposerSlashingView::h1_proposer_index(s) as usize;
        if vi >= n {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi, cnt: n });
        }
        if !is_slashable_validator(epoch, vi, current_epoch) {
            return Err(ProposerSlashingError::NotSlashable {
                vi,
                pubkey: vid.val_pubkey[vi],
                epoch: current_epoch,
            });
        }
        slash_validator(epoch, sd, n, vi, proposer_index);
    }
    Ok(())
}

/// Compute signing root for a `BeaconBlockHeader` (208-byte SSZ): slot,
/// proposer_index, parent_root, state_root, body_root.
pub(crate) fn signing_root_for_block_header(
    header: &[u8],
    fork_version: [u8; 4],
    genesis_validators_root: &B256,
    zh: &[B256],
) -> B256 {
    let hb: &[u8; BEACON_BLOCK_HEADER_SIZE] =
        header[..BEACON_BLOCK_HEADER_SIZE].try_into().unwrap();
    let h = BeaconBlockHeader {
        slot: BeaconBlockHeaderView::slot(hb),
        proposer_index: BeaconBlockHeaderView::proposer_index(hb),
        parent_root: *BeaconBlockHeaderView::parent_root(hb),
        state_root: *BeaconBlockHeaderView::state_root(hb),
        body_root: *BeaconBlockHeaderView::body_root(hb),
    };
    let object_root = hash_tree_root_block_header(&h, zh);
    let domain =
        bls::compute_domain(bls::DOMAIN_BEACON_PROPOSER, fork_version, genesis_validators_root);
    bls::compute_signing_root(&object_root, &domain)
}

/// Spec: process_deposit. Verify each Deposit's 33-level Merkle branch
/// against `state.eth1_data.deposit_root` at leaf index
/// `state.eth1_deposit_index` before queueing. A bad proof fails the block.
pub fn process_deposits(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    data: &[u8],
    zh: &[B256],
) -> Result<()> {
    let count = data.len() / DEPOSIT_SIZE;

    for i in 0..count {
        let d: &[u8; DEPOSIT_SIZE] =
            data[i * DEPOSIT_SIZE..(i + 1) * DEPOSIT_SIZE].try_into().unwrap();
        let dd = DepositView::data(d);
        let proof = DepositView::proof(d);
        let leaf = ssz_hash::hash_tree_root_deposit_data(dd, zh);
        if !ssz_hash::is_valid_merkle_branch(
            &leaf,
            proof,
            (DEPOSIT_CONTRACT_TREE_DEPTH as u32) + 1,
            sd.eth1_deposit_index,
            &sd.eth1_data.deposit_root,
        ) {
            return Err(Error::InvalidDepositProof { index: sd.eth1_deposit_index });
        }

        let pubkey = DepositDataView::pubkey(dd);
        let credentials: B256 = *DepositDataView::withdrawal_credentials(dd);
        let amount = DepositDataView::amount(dd);
        let signature = *DepositDataView::signature(dd);

        // apply_deposit is skippable on bad BLS sig — propagate fatal only.
        if let Err(e) =
            apply_deposit(vid, epoch, sd, pq, pubkey, &credentials, amount, &signature, zh)
        {
            if e.is_fatal() {
                return Err(e);
            }
        }
        sd.eth1_deposit_index += 1;
    }
    Ok(())
}

/// Pass 1 — push bls_to_execution_change sigs. Signer is the validator's
/// BLS withdrawal key (the `from_bls_pubkey` in the message itself) — not
/// the signing key cached in `vid.val_pubkey_decompressed`, so we
/// decompress inline.
///
/// Cred-prefix check (`creds[0] == 0x00 && creds[1..] == hash(from_pk)[1..]`)
/// runs here BEFORE BLS — cheap (one sha256) and avoids burning a
/// multi-pairing on a structurally-doomed block. Skipped when the validator
/// doesn't exist yet. Pass
/// 2's `process_bls_to_execution_changes` re-runs the full cred check
/// against post-deposit / post-prior-change state, so a same-block
/// duplicate still rejects.
pub fn collect_sigs_bls_to_execution_changes(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    data: &[u8],
    sig_batch: &mut SigBatch,
    zh: &[B256],
) -> Result<(), BlsToExecutionChangeError> {
    let count = data.len() / SIGNED_BLS_CHANGE_SIZE;
    for i in 0..count {
        let c: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            data[i * SIGNED_BLS_CHANGE_SIZE..(i + 1) * SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();
        let validator_index_u = SignedBlsToExecutionChangeView::validator_index(c);
        let from_bls_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(c);
        let to_execution_address = SignedBlsToExecutionChangeView::to_execution_address(c);
        let sig = SignedBlsToExecutionChangeView::signature(c);

        if (validator_index_u as usize) < vid.validator_cnt {
            validate::validate_bls_to_execution_change(
                vid,
                validator_index_u as usize,
                from_bls_pubkey,
            )?;
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(
            validator_index_u,
            from_bls_pubkey,
            to_execution_address,
            zh,
        );
        let domain = bls::compute_domain(
            bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            imm.genesis_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let Ok(from_pk) = PublicKey::from_bytes(from_bls_pubkey) else {
            return Err(BlsToExecutionChangeError::BadPubkey { from_pubkey: *from_bls_pubkey });
        };
        sig_batch.push_one(&from_pk, sig, signing_root);
    }
    Ok(())
}

/// Pass 2 — validate creds-prefix invariant against current state and
/// rewrite credentials. Same-block duplicate change for the same vi: the
/// first one flips the prefix to 0x01, the second's `validate` call sees
/// the now-non-BLS prefix and rejects → block invalid.
pub fn process_bls_to_execution_changes(
    vid: &mut ValidatorIdentity,
    data: &[u8],
) -> Result<(), BlsToExecutionChangeError> {
    let count = data.len() / SIGNED_BLS_CHANGE_SIZE;
    for i in 0..count {
        let c: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            data[i * SIGNED_BLS_CHANGE_SIZE..(i + 1) * SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();
        let validator_index = SignedBlsToExecutionChangeView::validator_index(c) as usize;
        let from_bls_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(c);
        let to_execution_address = SignedBlsToExecutionChangeView::to_execution_address(c);

        validate::validate_bls_to_execution_change(vid, validator_index, from_bls_pubkey)?;
        let cred = &mut vid.val_withdrawal_credentials[validator_index];
        cred[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        cred[1..12].fill(0);
        cred[12..32].copy_from_slice(to_execution_address);
    }
    Ok(())
}

/// Pass 1 — push both IndexedAttestation aggregate sigs per slashing entry.
pub fn collect_sigs_attester_slashings(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    data: &[u8],
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    zh: &[B256],
) -> Result<(), AttesterSlashingError> {
    if data.is_empty() {
        return Ok(());
    }
    let first_offset = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > data.len() {
        return Ok(());
    }
    let count = first_offset / 4;
    for i in 0..count {
        let start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        if start >= end || end > data.len() {
            return Err(AttesterSlashingError::BadOffsets { start, end, parent_len: data.len() });
        }
        let slashing = &data[start..end];
        if slashing.len() < 8 {
            return Err(AttesterSlashingError::TooShort { len: slashing.len(), min: 8 });
        }
        let off1 = u32::from_le_bytes(slashing[0..4].try_into().unwrap()) as usize;
        let off2 = u32::from_le_bytes(slashing[4..8].try_into().unwrap()) as usize;
        if off1 + 132 > slashing.len() || off2 + 132 > slashing.len() || off2 < off1 + 132 {
            return Err(AttesterSlashingError::BadInnerOffsets {
                off1,
                off2,
                slashing_len: slashing.len(),
            });
        }
        let i1 = attesting_indices_bytes(slashing, off1, off2);
        let i2 = attesting_indices_bytes(slashing, off2, slashing.len());

        for (ia_off, ia_end, indices) in [(off1, off2, i1), (off2, slashing.len(), i2)] {
            let ia = &slashing[ia_off..ia_end];
            let target_epoch = silver_common::ssz_view::IndexedAttestationView::target_epoch(ia);
            let fv = bls::fork_version_at_epoch(
                imm.fork.epoch,
                imm.fork.previous_version,
                imm.fork.current_version,
                target_epoch,
            );
            active_scratch.clear();
            let n_idx = indices.len() / 8;
            for k in 0..n_idx {
                let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap());
                if vi as usize >= vid.validator_cnt {
                    return Err(AttesterSlashingError::ValidatorOutOfRange {
                        vi: vi as usize,
                        cnt: vid.validator_cnt,
                    });
                }
                active_scratch.push(vi as u32);
            }
            let data_chunk: &[u8; 128] = silver_common::ssz_view::IndexedAttestationView::data(ia);
            let sig: &[u8; 96] = silver_common::ssz_view::IndexedAttestationView::signature(ia);
            let object_root = ssz_hash::hash_attestation_data(data_chunk, zh);
            let domain =
                bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &imm.genesis_validators_root);
            let signing_root = bls::compute_signing_root(&object_root, &domain);
            sig_batch.push_aggregate(
                active_scratch.iter().map(|&vi| &vid.val_pubkey_decompressed[vi as usize]),
                sig,
                signing_root,
            );
        }
    }
    Ok(())
}

/// Walk two strictly-ascending u64-LE-packed lists in lockstep, invoking
/// `f(vi)` for each value present in both. O(n+m). Returning `true` from
/// `f` short-circuits — used by the gossip path on first slashable match;
/// the block path always returns `false` and traverses the full intersection.
pub(crate) fn for_each_sorted_intersection(i1: &[u8], i2: &[u8], mut f: impl FnMut(usize) -> bool) {
    let read = |s: &[u8], i: usize| u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
    let (n1, n2) = (i1.len() / 8, i2.len() / 8);
    let (mut a, mut b) = (0usize, 0usize);
    while a < n1 && b < n2 {
        let x = read(i1, a);
        let y = read(i2, b);
        match x.cmp(&y) {
            core::cmp::Ordering::Less => a += 1,
            core::cmp::Ordering::Greater => b += 1,
            core::cmp::Ordering::Equal => {
                if f(x as usize) {
                    return;
                }
                a += 1;
                b += 1;
            }
        }
    }
}

/// Pass 2 — validate data + state, slash the intersection. BLS verified.
pub fn process_attester_slashings(
    vid: &ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    data: &[u8],
) -> Result<(), AttesterSlashingError> {
    if data.is_empty() {
        return Ok(());
    }
    let first_offset = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > data.len() {
        return Ok(());
    }
    let count = first_offset / 4;
    let proposer_index = get_beacon_proposer_index(sd);
    let n = vid.validator_cnt;
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;

    for i in 0..count {
        let start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        if start >= end || end > data.len() {
            return Err(AttesterSlashingError::BadOffsets { start, end, parent_len: data.len() });
        }
        let slashing = &data[start..end];
        if slashing.len() < 8 {
            return Err(AttesterSlashingError::TooShort { len: slashing.len(), min: 8 });
        }
        let off1 = u32::from_le_bytes(slashing[0..4].try_into().unwrap()) as usize;
        let off2 = u32::from_le_bytes(slashing[4..8].try_into().unwrap()) as usize;
        if off1 + 132 > slashing.len() || off2 + 132 > slashing.len() || off2 < off1 + 132 {
            return Err(AttesterSlashingError::BadInnerOffsets {
                off1,
                off2,
                slashing_len: slashing.len(),
            });
        }
        let d1 = &slashing[off1 + 4..off1 + 132];
        let d2 = &slashing[off2 + 4..off2 + 132];
        if !is_slashable_attestation_data(d1, d2) {
            return Err(AttesterSlashingError::NotSlashableData);
        }
        let i1 = attesting_indices_bytes(slashing, off1, off2);
        let i2 = attesting_indices_bytes(slashing, off2, slashing.len());
        if !indices_sorted_unique(i1) || !indices_sorted_unique(i2) {
            return Err(AttesterSlashingError::IndicesNotSorted);
        }

        // Spec requires ≥1 currently-slashable validator in the intersection;
        // a no-op slashing makes the block invalid.
        let mut slashed_any = false;
        for_each_sorted_intersection(i1, i2, |vi| {
            if vi < n && is_slashable_validator(epoch, vi, current_epoch) {
                slash_validator(epoch, sd, n, vi, proposer_index);
                slashed_any = true;
            }
            false
        });
        if !slashed_any {
            return Err(AttesterSlashingError::NoSlashedIntersection);
        }
    }
    Ok(())
}

/// Gossip-side `AttesterSlashing` validator (single slashing, not the
/// block-body list form).
pub fn validate_attester_slashing_for_gossip(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    epoch: &EpochData,
    sd: &SlotData,
    slashing: &[u8],
    sig_batch: &mut SigBatch,
    zh: &[B256],
) -> bool {
    if slashing.len() < 8 {
        return false;
    }
    let off1 = u32::from_le_bytes(slashing[0..4].try_into().unwrap()) as usize;
    let off2 = u32::from_le_bytes(slashing[4..8].try_into().unwrap()) as usize;
    if off1 + 132 > slashing.len() || off2 + 132 > slashing.len() || off2 < off1 + 132 {
        return false;
    }
    let d1 = &slashing[off1 + 4..off1 + 132];
    let d2 = &slashing[off2 + 4..off2 + 132];
    if !is_slashable_attestation_data(d1, d2) {
        return false;
    }
    let i1 = attesting_indices_bytes(slashing, off1, off2);
    let i2 = attesting_indices_bytes(slashing, off2, slashing.len());
    if i1.len() / 8 > silver_common::ssz_view::MAX_ATTESTING_INDICES ||
        i2.len() / 8 > silver_common::ssz_view::MAX_ATTESTING_INDICES
    {
        return false;
    }
    if !indices_sorted_unique(i1) || !indices_sorted_unique(i2) {
        return false;
    }

    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let mut any_slashable = false;
    for_each_sorted_intersection(i1, i2, |vi| {
        if vi < vid.validator_cnt && is_slashable_validator(epoch, vi, current_epoch) {
            any_slashable = true;
            true
        } else {
            false
        }
    });
    if !any_slashable {
        return false;
    }

    sig_batch.clear();
    for (ia_off, ia_end, indices) in [(off1, off2, i1), (off2, slashing.len(), i2)] {
        let ia = &slashing[ia_off..ia_end];
        let target_epoch = silver_common::ssz_view::IndexedAttestationView::target_epoch(ia);
        let fv = bls::fork_version_at_epoch(
            imm.fork.epoch,
            imm.fork.previous_version,
            imm.fork.current_version,
            target_epoch,
        );
        let n_idx = indices.len() / 8;
        // Pre-validate bounds so the sig_batch closure can index unchecked.
        for k in 0..n_idx {
            let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as usize;
            if vi >= vid.validator_cnt {
                return false;
            }
        }
        let data_chunk: &[u8; 128] = silver_common::ssz_view::IndexedAttestationView::data(ia);
        let sig: &[u8; 96] = silver_common::ssz_view::IndexedAttestationView::signature(ia);
        let object_root = ssz_hash::hash_attestation_data(data_chunk, zh);
        let domain =
            bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &imm.genesis_validators_root);
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        sig_batch.push_aggregate(
            (0..n_idx).map(|k| {
                let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as usize;
                &vid.val_pubkey_decompressed[vi]
            }),
            sig,
            signing_root,
        );
    }
    sig_batch.verify_all()
}

/// View an IndexedAttestation's attesting_indices SSZ bytes (skips the 228
/// byte fixed part: indices_offset(4) + data(128) + sig(96)).
#[inline]
pub(crate) fn attesting_indices_bytes(data: &[u8], start: usize, end: usize) -> &[u8] {
    if start + 228 > end || end > data.len() {
        return &[];
    }
    let slice = &data[start + 228..end];
    let whole = slice.len() - slice.len() % 8;
    &slice[..whole]
}

fn slash_validator(
    epoch: &mut EpochData,
    sd: &mut SlotData,
    n: usize,
    vi: usize,
    proposer_index: usize,
) {
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;

    initiate_validator_exit(epoch, sd, n, vi, current_epoch);
    epoch.set_val_slashed(vi, true);
    epoch.val_withdrawable_epoch[vi] =
        max(epoch.val_withdrawable_epoch[vi], current_epoch + EPOCHS_PER_SLASHINGS_VECTOR as u64);
    epoch.slashings[current_epoch as usize % EPOCHS_PER_SLASHINGS_VECTOR] +=
        epoch.val_effective_balance[vi];

    let penalty = epoch.val_effective_balance[vi] / MIN_SLASHING_PENALTY_QUOTIENT;
    sd.balances[vi] = sd.balances[vi].saturating_sub(penalty);

    // Spec: increase_balance(proposer, proposer_reward); increase_balance(
    // whistleblower, whistleblower_reward - proposer_reward). With no
    // explicit whistleblower (block-included slashings), whistleblower_index
    // defaults to proposer_index, so the proposer receives the full
    // whistleblower_reward.
    let whistleblower_reward = epoch.val_effective_balance[vi] / WHISTLEBLOWER_REWARD_QUOTIENT;
    sd.balances[proposer_index] = sd.balances[proposer_index].saturating_add(whistleblower_reward);
}

fn initiate_validator_exit(
    epoch: &mut EpochData,
    sd: &mut SlotData,
    n: usize,
    vi: usize,
    current_epoch: Epoch,
) {
    if epoch.val_exit_epoch[vi] != u64::MAX {
        return;
    }
    let exit_epoch = compute_exit_epoch_and_update_churn(
        epoch,
        sd,
        n,
        epoch.val_effective_balance[vi],
        current_epoch,
    );
    epoch.val_exit_epoch[vi] = exit_epoch;
    epoch.val_withdrawable_epoch[vi] = exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
}

fn compute_exit_epoch_and_update_churn(
    epoch: &EpochData,
    sd: &mut SlotData,
    n: usize,
    exit_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + MAX_SEED_LOOKAHEAD;
    let mut earliest = max(sd.earliest_exit_epoch, activation_exit_epoch);
    let per_epoch_churn = get_activation_exit_churn_limit(epoch, n, current_epoch);

    let mut balance_to_consume = if sd.earliest_exit_epoch < earliest {
        per_epoch_churn
    } else {
        sd.exit_balance_to_consume
    };

    if exit_balance > balance_to_consume {
        let to_process = exit_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    sd.exit_balance_to_consume = balance_to_consume - exit_balance;
    sd.earliest_exit_epoch = earliest;
    earliest
}

fn compute_consolidation_epoch_and_update_churn(
    epoch: &EpochData,
    sd: &mut SlotData,
    n: usize,
    consolidation_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + MAX_SEED_LOOKAHEAD;
    let mut earliest = max(sd.earliest_consolidation_epoch, activation_exit_epoch);
    let per_epoch_churn = get_consolidation_churn_limit(epoch, n, current_epoch);

    let mut balance_to_consume = if sd.earliest_consolidation_epoch < earliest {
        per_epoch_churn
    } else {
        sd.consolidation_balance_to_consume
    };

    if consolidation_balance > balance_to_consume {
        let to_process = consolidation_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    sd.consolidation_balance_to_consume = balance_to_consume - consolidation_balance;
    sd.earliest_consolidation_epoch = earliest;
    earliest
}

fn get_balance_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    let total = total_active_balance(epoch, n, current_epoch);
    let churn = max(128_000_000_000u64, total / (1u64 << 16));
    churn - churn % EFFECTIVE_BALANCE_INCREMENT
}

fn get_activation_exit_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    min(256_000_000_000u64, get_balance_churn_limit(epoch, n, current_epoch))
}

fn get_consolidation_churn_limit(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    get_balance_churn_limit(epoch, n, current_epoch) -
        get_activation_exit_churn_limit(epoch, n, current_epoch)
}

fn total_active_balance(epoch: &EpochData, n: usize, current_epoch: Epoch) -> u64 {
    let mut total: u64 = 0;
    for i in 0..n {
        if is_active(epoch, i, current_epoch) {
            total += epoch.val_effective_balance[i];
        }
    }
    total.max(EFFECTIVE_BALANCE_INCREMENT)
}

pub(crate) fn get_pending_balance_to_withdraw(pq: &PendingQueues, vi: usize) -> u64 {
    let mut total = 0u64;
    for pw in &pq.pending_partial_withdrawals {
        if pw.index == vi as u64 {
            total += pw.amount;
        }
    }
    total
}

#[inline]
fn is_active(epoch: &EpochData, vi: usize, e: Epoch) -> bool {
    epoch.val_activation_epoch[vi] <= e && e < epoch.val_exit_epoch[vi]
}

#[inline]
pub(crate) fn is_slashable_validator(epoch: &EpochData, vi: usize, e: Epoch) -> bool {
    !epoch.val_slashed(vi) &&
        epoch.val_activation_epoch[vi] <= e &&
        e < epoch.val_withdrawable_epoch[vi]
}

pub(crate) fn is_slashable_attestation_data(d1: &[u8], d2: &[u8]) -> bool {
    if d1.len() < ATTESTATION_DATA_SIZE || d2.len() < ATTESTATION_DATA_SIZE {
        return false;
    }
    let d1f: &[u8; ATTESTATION_DATA_SIZE] = d1[..ATTESTATION_DATA_SIZE].try_into().unwrap();
    let d2f: &[u8; ATTESTATION_DATA_SIZE] = d2[..ATTESTATION_DATA_SIZE].try_into().unwrap();
    let s1 = AttestationDataView::source_epoch(d1f);
    let t1 = AttestationDataView::target_epoch(d1f);
    let s2 = AttestationDataView::source_epoch(d2f);
    let t2 = AttestationDataView::target_epoch(d2f);

    // Double vote: distinct data, same target epoch.
    if d1 != d2 && t1 == t2 {
        return true;
    }
    // Surround vote: data_1 surrounds data_2.
    s1 < s2 && t2 < t1
}

/// Spec: SSZ List[uint64] invariant — strictly ascending.
pub(crate) fn indices_sorted_unique(indices: &[u8]) -> bool {
    let n = indices.len() / 8;
    if n < 2 {
        return true;
    }
    let read = |i: usize| u64::from_le_bytes(indices[i * 8..i * 8 + 8].try_into().unwrap());
    let mut prev = read(0);
    for i in 1..n {
        let cur = read(i);
        if cur <= prev {
            return false;
        }
        prev = cur;
    }
    true
}

#[inline]
fn has_execution_withdrawal_credential(vid: &ValidatorIdentity, vi: usize) -> bool {
    let prefix = vid.val_withdrawal_credentials[vi][0];
    prefix == ETH1_ADDRESS_WITHDRAWAL_PREFIX || prefix == COMPOUNDING_WITHDRAWAL_PREFIX
}

#[inline]
fn has_compounding_credential(vid: &ValidatorIdentity, vi: usize) -> bool {
    vid.val_withdrawal_credentials[vi][0] == COMPOUNDING_WITHDRAWAL_PREFIX
}

#[inline]
fn get_beacon_proposer_index(sd: &SlotData) -> usize {
    sd.proposer_lookahead[(sd.slot % SLOTS_PER_EPOCH) as usize] as usize
}

fn switch_to_compounding_validator(
    vid: &mut ValidatorIdentity,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    vi: usize,
) {
    vid.val_withdrawal_credentials[vi][0] = COMPOUNDING_WITHDRAWAL_PREFIX;
    // Queue excess balance above MIN_ACTIVATION_BALANCE.
    let balance = sd.balances[vi];
    if balance > MIN_ACTIVATION_BALANCE {
        let excess = balance - MIN_ACTIVATION_BALANCE;
        sd.balances[vi] = MIN_ACTIVATION_BALANCE;
        pq.pending_deposits.push(PendingDeposit {
            pubkey: vid.val_pubkey[vi],
            withdrawal_credentials: vid.val_withdrawal_credentials[vi],
            amount: excess,
            signature: G2_POINT_AT_INFINITY,
            slot: 0, // GENESIS_SLOT
        });
    }
}

/// Apply a single deposit: for new validators, BLS-verify then add to the
/// registry with 0 balance; always queue a PendingDeposit for the amount.
/// Returns the skippable `SkipDepositBadSig` when BLS fails for a new
/// validator — per spec the deposit is dropped, the block continues.
#[allow(clippy::too_many_arguments)]
fn apply_deposit(
    vid: &mut ValidatorIdentity,
    epoch: &mut EpochData,
    sd: &mut SlotData,
    pq: &mut PendingQueues,
    pubkey: &[u8; 48],
    credentials: &B256,
    amount: u64,
    signature: &[u8; 96],
    zh: &[B256],
) -> Result<()> {
    let existing = find_validator_by_pubkey(vid, pubkey);
    if existing.is_none() {
        if !epoch_transition::is_valid_deposit_signature(pubkey, credentials, amount, signature, zh)
        {
            return Err(Error::SkipDepositBadSig { index: sd.eth1_deposit_index });
        }
        // Add to registry with 0 effective balance and 0 actual balance.
        let idx = vid.validator_cnt;
        vid.val_pubkey[idx] = *pubkey;
        vid.val_pubkey_decompressed[idx] = PublicKey::from_bytes(pubkey).unwrap_or_default();
        vid.val_withdrawal_credentials[idx] = *credentials;
        epoch.val_effective_balance[idx] = 0;
        epoch.set_val_slashed(idx, false);
        epoch.val_activation_eligibility_epoch[idx] = u64::MAX;
        epoch.val_activation_epoch[idx] = u64::MAX;
        epoch.val_exit_epoch[idx] = u64::MAX;
        epoch.val_withdrawable_epoch[idx] = u64::MAX;
        epoch.inactivity_scores[idx] = 0;
        sd.balances[idx] = 0;
        sd.previous_epoch_participation[idx] = 0;
        sd.current_epoch_participation[idx] = 0;
        vid.validator_cnt = idx + 1;
    }

    pq.pending_deposits.push(PendingDeposit {
        pubkey: *pubkey,
        withdrawal_credentials: *credentials,
        amount,
        signature: *signature,
        slot: 0, // GENESIS_SLOT — Eth1 bridge deposit.
    });
    Ok(())
}

// TODO(perf): O(n_validators) scan per call. Hit on every deposit-request,
// withdrawal-request, consolidation-request, and apply_deposit, plus
// rebuild_sync_committee_indices (512 × n). At MAX_VALIDATORS=2.75Mi sync
// rotation is ~1.5B comparisons. Replace with a per-VID-tier sorted
// Vec<(pubkey_hash, idx)> or HashMap that COWs with the VID tier.
// (~33 MB sorted vs ~165 MB HashMap.)
fn find_validator_by_pubkey(vid: &ValidatorIdentity, pubkey: &[u8; 48]) -> Option<usize> {
    vid.val_pubkey[..vid.validator_cnt].iter().position(|pk| pk == pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::box_zeroed;

    /// EF `sanity_blocks` doesn't exercise the eth1 majority threshold
    /// directly (its blocks vote at most a couple of times). Cover it here.
    #[test]
    fn eth1_data_vote_majority() {
        let mut sd: Box<SlotData> = box_zeroed();
        sd.slot = 32; // epoch 1

        // Build a body with eth1_data at [96..168).
        let mut body = vec![0u8; 396];
        let deposit_root = [0xAA; 32];
        body[96..128].copy_from_slice(&deposit_root);
        body[128..136].copy_from_slice(&42u64.to_le_bytes()); // deposit_count
        body[136..168].copy_from_slice(&[0xBB; 32]); // block_hash

        // slots_per_eth1_voting_period = 64 * 32 = 2048; need > 1024 votes.
        process_eth1_data(&mut sd, &body);
        assert_eq!(sd.eth1_votes.len(), 1);
        assert_ne!(sd.eth1_data.deposit_root, deposit_root);

        for _ in 0..1024 {
            sd.eth1_votes.push(Eth1Data {
                deposit_root,
                deposit_count: 42,
                block_hash: [0xBB; 32],
            });
        }
        process_eth1_data(&mut sd, &body);
        assert_eq!(sd.eth1_data.deposit_root, deposit_root);
    }

    /// Build a single-deposit body element (1240 B) with the given DepositData
    /// bytes and a zero-subtree proof for leaf index 0 (siblings = zh[0..33]).
    /// Returns (deposit_bytes, expected_root) where `expected_root` is what
    /// `state.eth1_data.deposit_root` must be for the proof to verify.
    fn build_deposit_at_index0(dd_bytes: &[u8; 184], zh: &[B256]) -> (Vec<u8>, B256) {
        let depth = (DEPOSIT_CONTRACT_TREE_DEPTH as u32) + 1;
        let mut bytes = vec![0u8; DEPOSIT_SIZE];
        // Proof: 33 siblings, sibling at level i is zh[i].
        for i in 0..depth as usize {
            bytes[i * 32..(i + 1) * 32].copy_from_slice(&zh[i]);
        }
        bytes[1056..1240].copy_from_slice(dd_bytes);

        // Expected root: start from the deposit-data leaf, climb the all-zero
        // siblings on the right.
        let leaf = ssz_hash::hash_tree_root_deposit_data(dd_bytes, zh);
        let mut value = leaf;
        for i in 0..depth as usize {
            let sib = zh[i];
            // index=0 → always left, sibling on the right.
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&value);
            buf[32..].copy_from_slice(&sib);
            value = ssz_hash::sha256(&buf);
        }
        (bytes, value)
    }

    fn make_dd() -> [u8; 184] {
        let mut dd = [0u8; 184];
        dd[0] = 0xAB; // pubkey
        dd[48] = 0x01; // withdrawal_credentials prefix
        dd[80..88].copy_from_slice(&32_000_000_000u64.to_le_bytes()); // amount
        dd[88] = 0xCD; // signature
        dd
    }

    #[test]
    fn process_deposits_accepts_valid_proof() {
        let zh = ssz_hash::compute_zero_hashes();
        let dd = make_dd();
        let (deposit, root) = build_deposit_at_index0(&dd, &zh);

        let mut vid: Box<ValidatorIdentity> = box_zeroed();
        let mut epoch: Box<EpochData> = box_zeroed();
        let mut sd: Box<SlotData> = box_zeroed();
        let mut pq = PendingQueues::new();
        sd.eth1_data.deposit_root = root;
        sd.eth1_deposit_index = 0;

        process_deposits(&mut vid, &mut epoch, &mut sd, &mut pq, &deposit, &zh)
            .expect("valid proof must accept");
        assert_eq!(sd.eth1_deposit_index, 1);
    }

    #[test]
    fn process_deposits_rejects_bad_proof() {
        let zh = ssz_hash::compute_zero_hashes();
        let dd = make_dd();
        let (mut deposit, root) = build_deposit_at_index0(&dd, &zh);

        // Flip a byte in the proof.
        deposit[0] ^= 0x01;

        let mut vid: Box<ValidatorIdentity> = box_zeroed();
        let mut epoch: Box<EpochData> = box_zeroed();
        let mut sd: Box<SlotData> = box_zeroed();
        let mut pq = PendingQueues::new();
        sd.eth1_data.deposit_root = root;
        sd.eth1_deposit_index = 0;

        let err =
            process_deposits(&mut vid, &mut epoch, &mut sd, &mut pq, &deposit, &zh).unwrap_err();
        assert!(err.is_fatal());
        assert!(matches!(err, Error::InvalidDepositProof { index: 0 }));
        assert_eq!(sd.eth1_deposit_index, 0, "index must not advance on rejection");
        assert!(pq.pending_deposits.is_empty());
    }

    #[test]
    fn process_deposits_rejects_wrong_root() {
        let zh = ssz_hash::compute_zero_hashes();
        let dd = make_dd();
        let (deposit, mut root) = build_deposit_at_index0(&dd, &zh);
        root[0] ^= 0xFF;

        let mut vid: Box<ValidatorIdentity> = box_zeroed();
        let mut epoch: Box<EpochData> = box_zeroed();
        let mut sd: Box<SlotData> = box_zeroed();
        let mut pq = PendingQueues::new();
        sd.eth1_data.deposit_root = root;
        sd.eth1_deposit_index = 0;

        let err =
            process_deposits(&mut vid, &mut epoch, &mut sd, &mut pq, &deposit, &zh).unwrap_err();
        assert!(matches!(err, Error::InvalidDepositProof { .. }));
    }

    #[test]
    fn process_deposits_rejects_wrong_index() {
        let zh = ssz_hash::compute_zero_hashes();
        let dd = make_dd();
        let (deposit, root) = build_deposit_at_index0(&dd, &zh);

        let mut vid: Box<ValidatorIdentity> = box_zeroed();
        let mut epoch: Box<EpochData> = box_zeroed();
        let mut sd: Box<SlotData> = box_zeroed();
        let mut pq = PendingQueues::new();
        sd.eth1_data.deposit_root = root;
        // Proof was built for index 0; claim index 1 instead → must fail.
        sd.eth1_deposit_index = 1;

        let err =
            process_deposits(&mut vid, &mut epoch, &mut sd, &mut pq, &deposit, &zh).unwrap_err();
        assert!(matches!(err, Error::InvalidDepositProof { index: 1 }));
    }
}
