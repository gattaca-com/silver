use core::cmp::{max, min};

use blst::min_pk::PublicKey;
use silver_beacon_state_data::{
    self as common, B256, BalancesWriteView, Current, EPOCHS_PER_SLASHINGS_VECTOR, Epoch,
    EpochGroup, EpochId, EpochView, Immutable, LongtailGroup, LongtailId, LongtailView,
    PENDING_CONSOLIDATIONS_LIMIT, PENDING_PARTIAL_WITHDRAWALS_LIMIT, ParticipationWriteView,
    PendingView, PendingWriteView, Previous, SLOTS_PER_EPOCH, SYNC_COMMITTEE_SIZE, Slot,
    SlotStateView, SlotStateWriteView, SpecConfig, StateId, StateReadView, StateWriterView,
    ValidatorsView, ValidatorsWriteView, append_validator,
};
use silver_common::{
    metrics::timed,
    ssz_view,
    ssz_view::{
        ATTESTATION_DATA_SIZE, AttestationDataView, AttestationView, BEACON_BLOCK_BODY_FIXED,
        BEACON_BLOCK_HEADER_SIZE, BLOCK_SYNC_AGGREGATE_SIZE, BeaconBlockBodyView,
        BeaconBlockHeaderView, CONSOLIDATION_REQUEST_SIZE, ConsolidationRequestView,
        DEPOSIT_CONTRACT_TREE_DEPTH, DEPOSIT_REQUEST_SIZE, DEPOSIT_SIZE, DepositDataView,
        DepositRequestView, DepositView, Eth1DataView, ExecutionPayloadView,
        PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SignedBeaconBlockView, SignedBlsToExecutionChangeView,
        SignedVoluntaryExitView, SyncAggregateView, WITHDRAWAL_REQUEST_SIZE, WITHDRAWAL_SIZE,
        WithdrawalRequestView, WithdrawalView,
    },
};

use crate::{
    bls::{self, SigBatch},
    epoch_transition::{self, EPOCHS_PER_ETH1_VOTING_PERIOD},
    error::{
        AttestationError, AttesterSlashingError, BlockError, BlsToExecutionChangeError, Error,
        ExecutionPayloadError, ProposerSlashingError, Result, SyncAggregateError,
        VoluntaryExitError, WithdrawalRecord, WithdrawalsError,
    },
    shuffling::{self, DOMAIN_BEACON_ATTESTER},
    ssz_hash::{self, hash_tree_root_block_header},
    validate,
};

const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;

const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 4096;
const FULL_EXIT_REQUEST_AMOUNT: u64 = 0;
const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
const UNSET_DEPOSIT_REQUESTS_START_INDEX: u64 = u64::MAX;
const EFFECTIVE_BALANCE_INCREMENT: u64 = 1_000_000_000;
const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;
// BLS G2 point at infinity (compressed): 0xc0 followed by 95 zero bytes.
const G2_POINT_AT_INFINITY: [u8; 96] = {
    let mut buf = [0u8; 96];
    buf[0] = 0xc0;
    buf
};

#[timed]
#[allow(clippy::too_many_arguments)]
pub fn apply_block(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochGroup,
    longtail: &mut LongtailGroup,
    parent: StateId,
    block_bytes: &[u8],
    block_slot: Slot,
    proposer_index: u32,
    parent_root: B256,
    body_root: B256,
    block_state_root: B256,
    shuffling: Option<&ShufflingRef<'_>>,
    active_scratch: &mut Vec<u32>,
    postponed_scratch: &mut Vec<common::PendingDeposit>,
    replace_u64_scratch: &mut Vec<(u32, u64)>,
    replace_u8_scratch: &mut Vec<(u32, u8)>,
    eff_scratch: &mut Vec<u64>,
    state_hash_scratch: &mut ssz_hash::StateHashScratch,
    attestation_votes: &mut Vec<(u32, B256, Epoch)>,
    sig_batch: &mut SigBatch,
) -> Result<(Option<EpochId>, Option<LongtailId>)> {
    let wrap = |kind: BlockError| Error::invalid_block(block_state_root, kind);

    check_slot_after_header(&view.slot.reader(), block_slot).map_err(wrap)?;
    let head_slot = view.slot.state().slot;
    check_proposer_lookahead(
        &epoch.view_opt(parent.epoch_idx),
        block_slot,
        head_slot,
        proposer_index,
    )
    .map_err(wrap)?;

    let (epoch_idx, longtail_idx) = if block_slot > head_slot {
        process_slots(
            cfg,
            view,
            epoch,
            longtail,
            parent,
            block_slot,
            active_scratch,
            postponed_scratch,
            replace_u64_scratch,
            replace_u8_scratch,
            eff_scratch,
            state_hash_scratch,
        )
    } else {
        (parent.epoch_idx, parent.longtail_idx)
    };

    let body = if block_bytes.len() > 184 { &block_bytes[184..] } else { &[] };
    // Resolve the boundary tiers AFTER process_slots (it may have rolled
    // them). process_block can't change them, so the hash reuses these.
    let epoch_view = epoch.view_opt(epoch_idx);
    let longtail_view = longtail.view_opt(longtail_idx);
    process_block_header(
        view,
        &epoch_view,
        block_slot,
        proposer_index as u64,
        parent_root,
        body_root,
    )
    .map_err(wrap)?;
    process_block_body(
        cfg,
        view,
        &epoch_view,
        &longtail_view,
        active_scratch,
        sig_batch,
        body,
        block_state_root,
        block_slot,
        proposer_index,
        shuffling,
        attestation_votes,
    )?;

    let rv = view.read(epoch_view, longtail_view);
    let actual = ssz_hash::hash_tree_root_state(&rv, state_hash_scratch);
    if actual != block_state_root {
        return Err(wrap(BlockError::PostStateRootMismatch {
            expected: block_state_root,
            got: actual,
        }));
    }
    Ok((epoch_idx, longtail_idx))
}

/// Test-only full-block apply: decompose, shuffle, STF, then check the
/// post-state root. Production path is `apply_block`.
#[timed]
#[allow(clippy::too_many_arguments)]
pub fn apply_signed_block_debug(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochGroup,
    longtail: &mut LongtailGroup,
    parent: StateId,
    block_bytes: &[u8],
) -> Result<(Option<EpochId>, Option<LongtailId>)> {
    if block_bytes.len() < 184 {
        return Err(Error::invalid_block([0; 32], BlockError::TooShort {
            len: block_bytes.len(),
            min: 184,
        }));
    }
    let (head_slot, head_block_header_slot) =
        (view.slot.state().slot, view.slot.state().latest_block_header.slot);
    let block_slot = SignedBeaconBlockView::slot(block_bytes);
    let proposer_index = SignedBeaconBlockView::proposer_index(block_bytes) as u32;
    let parent_root: B256 = *SignedBeaconBlockView::parent_root(block_bytes);
    let state_root: B256 = *SignedBeaconBlockView::state_root(block_bytes);
    let body = SignedBeaconBlockView::body(block_bytes);
    let body_root = ssz_hash::hash_tree_root_body(body);
    let wrap = |kind: BlockError| Error::invalid_block(state_root, kind);

    if block_slot <= head_block_header_slot {
        return Err(wrap(BlockError::SlotNotAfterHeader {
            slot: block_slot,
            latest: head_block_header_slot,
        }));
    }

    let mut active_scratch = Vec::new();
    let mut postponed_scratch: Vec<common::PendingDeposit> = Vec::new();
    let mut replace_u64_scratch: Vec<(u32, u64)> = Vec::new();
    let mut replace_u8_scratch: Vec<(u32, u8)> = Vec::new();
    let mut eff_scratch: Vec<u64> = Vec::new();
    let mut state_hash_scratch = ssz_hash::StateHashScratch::new();

    check_proposer_lookahead(
        &epoch.view_opt(parent.epoch_idx),
        block_slot,
        head_slot,
        proposer_index,
    )
    .map_err(wrap)?;

    let count = view.validators.count();
    if proposer_index as usize >= count {
        return Err(wrap(BlockError::ProposerOutOfRange { idx: proposer_index as u64, count }));
    }
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    if !verify_block_sig(
        view.imm,
        &view.validators.reader(),
        block_bytes,
        &body_root,
        block_epoch,
        proposer_index,
    ) {
        return Err(Error::InvalidBlockSig);
    }

    let (epoch_idx, longtail_idx) = if block_slot > head_slot {
        process_slots(
            cfg,
            view,
            epoch,
            longtail,
            parent,
            block_slot,
            &mut active_scratch,
            &mut postponed_scratch,
            &mut replace_u64_scratch,
            &mut replace_u8_scratch,
            &mut eff_scratch,
            &mut state_hash_scratch,
        )
    } else {
        (parent.epoch_idx, parent.longtail_idx)
    };
    // Resolve the boundary tiers AFTER process_slots (it may have rolled
    // them). process_block can't change them, so the hash reuses these.
    let epoch_view = epoch.view_opt(epoch_idx);
    let longtail_view = longtail.view_opt(longtail_idx);
    process_block_header(
        view,
        &epoch_view,
        block_slot,
        proposer_index as u64,
        parent_root,
        body_root,
    )
    .map_err(wrap)?;

    let mut curr = Vec::new();
    let mut prev = Vec::new();
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let rv = view.read(epoch_view, longtail_view);
    let sref = ShufflingRef::build(&rv, current_epoch, &mut curr, &mut prev);
    let mut votes_sink: Vec<(u32, B256, Epoch)> = Vec::new();
    let mut sig_batch = SigBatch::new();
    process_block_body(
        cfg,
        view,
        &epoch_view,
        &longtail_view,
        &mut active_scratch,
        &mut sig_batch,
        body,
        state_root,
        block_slot,
        proposer_index,
        Some(&sref),
        &mut votes_sink,
    )?;

    let rv = view.read(epoch_view, longtail_view);
    let actual = ssz_hash::hash_tree_root_state(&rv, &mut state_hash_scratch);
    if actual != state_root {
        return Err(wrap(BlockError::PostStateRootMismatch { expected: state_root, got: actual }));
    }
    Ok((epoch_idx, longtail_idx))
}

fn check_slot_after_header(
    slot: &SlotStateView,
    block_slot: Slot,
) -> std::result::Result<(), BlockError> {
    let latest = slot.state().latest_block_header.slot;
    if block_slot <= latest {
        Err(BlockError::SlotNotAfterHeader { slot: block_slot, latest })
    } else {
        Ok(())
    }
}

/// Proposer must match `proposer_lookahead` (Fulu, valid for current_epoch
/// and next_epoch — 64 slots from current_epoch start).
fn check_proposer_lookahead(
    epoch: &EpochView,
    block_slot: Slot,
    head_slot: Slot,
    proposer_index: u32,
) -> std::result::Result<(), BlockError> {
    let head_epoch = head_slot / SLOTS_PER_EPOCH;
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    if block_epoch != head_epoch && block_epoch != head_epoch + 1 {
        return Ok(());
    }
    let lookahead_idx = (block_slot - head_epoch * SLOTS_PER_EPOCH) as usize;
    let Some(expected) = epoch.proposer_at(lookahead_idx) else {
        return Ok(());
    };
    if (proposer_index as u64) != expected {
        return Err(BlockError::ProposerLookaheadMismatch { got: proposer_index as u64, expected });
    }
    Ok(())
}

fn verify_block_sig(
    imm: &Immutable,
    validators: &ValidatorsView,
    block_bytes: &[u8],
    body_root: &B256,
    block_epoch: Epoch,
    proposer_index: u32,
) -> bool {
    let (fork_version, gvr) = imm.fork_version_at(block_epoch);
    let pk = validators.pubkey_decompressed(proposer_index as usize);
    bls::verify_block_signature(block_bytes, pk, body_root, fork_version, &gvr)
}

/// Advance state from `view.slot`'s slot to `target_slot`, processing empty
/// slots. Handles epoch transitions at boundaries (spec: process_epoch runs
/// when `(state.slot + 1) % SLOTS_PER_EPOCH == 0`). At the first boundary the
/// fork's private epoch entry is rolled and the writer HELD for the rest of
/// the advance — one ring entry per advance, mutated through the held writer
/// at every later boundary; its commit at the end surfaces the id
/// (publish-last). Takes the parent bundle's boundary-tier ids (not resolved
/// views: a resolved view is a shared borrow of the group, and the boundary
/// roll needs `&mut` of that same group — ids are the only currency that can
/// cross a call that may still roll) and returns the updated pair for the
/// caller's `commit`.
#[allow(clippy::too_many_arguments)]
#[timed]
pub fn process_slots(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochGroup,
    longtail: &mut LongtailGroup,
    parent: StateId,
    target_slot: Slot,
    active_scratch: &mut Vec<u32>,
    postponed_scratch: &mut Vec<common::PendingDeposit>,
    replace_u64_scratch: &mut Vec<(u32, u64)>,
    replace_u8_scratch: &mut Vec<(u32, u8)>,
    eff_scratch: &mut Vec<u64>,
    state_hash_scratch: &mut ssz_hash::StateHashScratch,
) -> (Option<EpochId>, Option<LongtailId>) {
    let (epoch_idx, mut longtail_idx) = (parent.epoch_idx, parent.longtail_idx);
    // Pre-boundary slots: epoch tier read straight off the group.
    while view.slot.state().slot < target_slot {
        let epoch_view = epoch.view_opt(epoch_idx);
        process_slot(view, &epoch_view, longtail, longtail_idx, state_hash_scratch);
        if (view.slot.state().slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
            break;
        }
        view.slot.advance_slot();
    }
    if view.slot.state().slot >= target_slot {
        return (epoch_idx, longtail_idx);
    }

    // First boundary: roll this fork's private epoch entry, derived from the
    // inherited one (fresh off the base when no ancestor crossed a boundary).
    let mut epoch_w = match epoch_idx {
        Some(pe) => epoch.roll_from(pe),
        None => epoch.roll_fresh(),
    };

    // Boundary-onward slots: epoch tier read through the held writer.
    loop {
        epoch_transition::process_epoch(
            cfg,
            view,
            &mut epoch_w,
            longtail,
            &mut longtail_idx,
            active_scratch,
            postponed_scratch,
            replace_u64_scratch,
            replace_u8_scratch,
            eff_scratch,
            state_hash_scratch,
        );
        view.slot.advance_slot();
        while view.slot.state().slot < target_slot {
            process_slot(view, &epoch_w.reader(), longtail, longtail_idx, state_hash_scratch);
            if (view.slot.state().slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
                break;
            }
            view.slot.advance_slot();
        }
        if view.slot.state().slot >= target_slot {
            return (Some(epoch_w.commit()), longtail_idx);
        }
    }
}

pub fn process_slot(
    view: &mut StateWriterView,
    epoch: &EpochView,
    longtail: &LongtailGroup,
    longtail_idx: Option<LongtailId>,
    state_hash_scratch: &mut ssz_hash::StateHashScratch,
) {
    // Longtail resolved fresh each slot: a boundary `process_epoch` may roll
    // the fork a new entry mid-`process_slots` (the caller threads the
    // updated id). The epoch view comes from the caller (group resolution
    // before the first boundary, the held boundary writer's reader after).
    let rv = view.read(*epoch, longtail.view_opt(longtail_idx));
    let prev_state_root = ssz_hash::hash_tree_root_state(&rv, state_hash_scratch);
    let slot = &mut view.slot;
    slot.push_state_root(prev_state_root);

    slot.fill_latest_block_header_state_root(prev_state_root);
    let header = slot.state().latest_block_header;
    let block_root = hash_tree_root_block_header(&header);
    slot.push_block_root(block_root);
}

pub fn process_block_header(
    view: &mut StateWriterView,
    epoch: &EpochView,
    block_slot: Slot,
    proposer_index: u64,
    parent_root: B256,
    body_root: B256,
) -> Result<(), BlockError> {
    let current_slot = view.slot.state().slot;
    if block_slot != current_slot {
        return Err(BlockError::SlotStateMismatch { block: block_slot, state: current_slot });
    }
    let lbh = view.slot.state().latest_block_header;
    if block_slot <= lbh.slot {
        return Err(BlockError::SlotNotAfterHeader { slot: block_slot, latest: lbh.slot });
    }
    let count = view.validators.count();
    if proposer_index as usize >= count {
        return Err(BlockError::ProposerOutOfRange { idx: proposer_index, count });
    }

    let expected_proposer = epoch
        .proposer_at((block_slot % SLOTS_PER_EPOCH) as usize)
        .expect("slot-in-epoch is within the lookahead window");
    if proposer_index != expected_proposer {
        return Err(BlockError::ProposerLookaheadMismatch {
            got: proposer_index,
            expected: expected_proposer,
        });
    }
    if view.validators.is_slashed(proposer_index as usize) {
        return Err(BlockError::ProposerSlashed {
            idx: proposer_index,
            pubkey: *view.validators.pubkey(proposer_index as usize),
        });
    }

    let expected_parent = hash_tree_root_block_header(&lbh);
    if parent_root != expected_parent {
        return Err(BlockError::ParentRootMismatch { expected: expected_parent, got: parent_root });
    }

    view.slot.state_mut().latest_block_header = common::BeaconBlockHeader {
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
    pub curr_epoch: Epoch,
    pub curr_shuffled: &'a [u32],
    pub curr_committees_per_slot: usize,
    pub prev_epoch: Epoch,
    pub prev_shuffled: &'a [u32],
    pub prev_committees_per_slot: usize,
}

impl<'a> ShufflingRef<'a> {
    /// Populate `curr_buf`/`prev_buf` with the current+previous epoch's
    /// shuffled active-index lists, then bind them into a `ShufflingRef`.
    pub fn build(
        rv: &StateReadView,
        current_epoch: Epoch,
        curr_buf: &'a mut Vec<u32>,
        prev_buf: &'a mut Vec<u32>,
    ) -> Self {
        let (epoch, slot) = (&rv.epoch, &rv.slot);
        let previous_epoch = current_epoch.saturating_sub(1);
        let curr_seed =
            shuffling::get_seed_from_state(epoch, slot, current_epoch, DOMAIN_BEACON_ATTESTER);
        let prev_seed =
            shuffling::get_seed_from_state(epoch, slot, previous_epoch, DOMAIN_BEACON_ATTESTER);
        shuffling::get_active_validator_indices_into(&rv.validators, current_epoch, curr_buf);
        shuffling::get_active_validator_indices_into(&rv.validators, previous_epoch, prev_buf);
        shuffling::shuffle_list(curr_buf, &curr_seed);
        shuffling::shuffle_list(prev_buf, &prev_seed);
        let curr_committees_per_slot = shuffling::committees_per_slot(curr_buf.len());
        let prev_committees_per_slot = shuffling::committees_per_slot(prev_buf.len());
        Self {
            curr_epoch: current_epoch,
            curr_shuffled: curr_buf,
            curr_committees_per_slot,
            prev_epoch: previous_epoch,
            prev_shuffled: prev_buf,
            prev_committees_per_slot,
        }
    }
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

    /// In-bounds slice or `None` if the offsets don't bracket a valid range.
    /// Used by Pass-2 to skip ops whose section is malformed.
    #[inline]
    fn try_slice(&self, start: usize, end: usize) -> Option<&'a [u8]> {
        if start <= end && end <= self.body.len() { Some(&self.body[start..end]) } else { None }
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
#[timed]
#[allow(clippy::too_many_arguments)]
pub fn process_block_body(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &EpochView,
    longtail: &LongtailView,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    body: &[u8],
    state_root: B256,
    block_slot: Slot,
    proposer_index: u32,
    shuffling: Option<&ShufflingRef<'_>>,
    attestation_votes: &mut Vec<(u32, B256, Epoch)>,
) -> Result<()> {
    let wrap = |kind: BlockError| Error::invalid_block(state_root, kind);
    validate::validate_operation_counts(body).map_err(wrap)?;
    let offsets = BodyOffsets::new(body).ok_or_else(|| {
        wrap(BlockError::BodyTooShort { len: body.len(), min: BEACON_BLOCK_BODY_FIXED })
    })?;
    let count = view.validators.count();
    if (proposer_index as usize) >= count {
        return Err(wrap(BlockError::ProposerOutOfRange { idx: proposer_index as u64, count }));
    }

    sig_batch.clear();
    // Pass 1 is read-only: hand it the read-only sibling over the same fork.
    let rv = view.read(*epoch, *longtail);
    collect_sigs_block_body(
        &rv,
        active_scratch,
        sig_batch,
        &offsets,
        block_slot,
        proposer_index,
        shuffling,
    )?;
    if !sig_batch.verify_all() {
        return Err(Error::SigBatchFailed);
    }

    apply_block_body_pass2(
        cfg,
        view,
        *epoch,
        *longtail,
        active_scratch,
        &offsets,
        block_slot,
        proposer_index,
        shuffling,
        attestation_votes,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_block_body_pass2(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: EpochView,
    longtail: LongtailView,
    active_scratch: &mut Vec<u32>,
    offsets: &BodyOffsets<'_>,
    block_slot: Slot,
    proposer_index: u32,
    shuffling: Option<&ShufflingRef<'_>>,
    attestation_votes: &mut Vec<(u32, B256, Epoch)>,
) -> Result<()> {
    let body = offsets.body;
    let payload = offsets.payload();

    process_withdrawals(&mut *view, payload)?;
    process_execution_payload(&mut *view, cfg, payload, block_slot)?;
    process_randao(&mut view.slot, body);
    process_eth1_data(&mut view.slot, body);

    if let Some(section) =
        offsets.try_slice(offsets.proposer_slashings_off, offsets.attester_slashings_off)
    {
        process_proposer_slashings(&mut *view, epoch, cfg, section)?;
    }
    if let Some(section) =
        offsets.try_slice(offsets.attester_slashings_off, offsets.attestations_off)
    {
        process_attester_slashings(&mut *view, epoch, cfg, section, active_scratch)?;
    }
    if let Some(section) = offsets.try_slice(offsets.attestations_off, offsets.deposits_off) {
        process_attestations(
            &mut *view,
            epoch,
            section,
            block_slot,
            proposer_index,
            shuffling,
            attestation_votes,
            active_scratch,
        )?;
    }
    if let Some(section) = offsets.try_slice(offsets.deposits_off, offsets.voluntary_exits_off) {
        process_deposits(&mut *view, section)?;
    }
    if let Some(section) = offsets.try_slice(offsets.voluntary_exits_off, offsets.exec_off) {
        process_voluntary_exits(&mut *view, cfg, section)?;
    }
    if let Some(section) = offsets.try_slice(offsets.bls_changes_off, offsets.blob_off) {
        process_bls_to_execution_changes(&mut view.validators, section)?;
    }
    if offsets.exec_requests_off <= body.len() {
        process_execution_requests(&mut *view, cfg, &body[offsets.exec_requests_off..]);
    }
    process_sync_aggregate(&mut *view, longtail, &body[220..380], proposer_index)?;
    Ok(())
}

#[timed]
#[allow(clippy::too_many_arguments)]
fn collect_sigs_block_body(
    rv: &StateReadView,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    offsets: &BodyOffsets<'_>,
    block_slot: Slot,
    proposer_index: u32,
    shuffling: Option<&ShufflingRef<'_>>,
) -> Result<()> {
    let body = offsets.body;
    let imm = rv.imm;
    let validators = rv.validators;

    let proposer_pubkey = validators.pubkey_decompressed(proposer_index as usize);
    collect_sigs_randao(imm, body, block_slot, proposer_pubkey, sig_batch);

    if offsets.proposer_slashings_off <= offsets.attester_slashings_off &&
        offsets.attester_slashings_off <= body.len()
    {
        collect_sigs_proposer_slashings(
            imm,
            &validators,
            offsets.slice(offsets.proposer_slashings_off, offsets.attester_slashings_off),
            sig_batch,
        )?;
    }
    if offsets.attester_slashings_off <= offsets.attestations_off &&
        offsets.attestations_off <= body.len()
    {
        collect_sigs_attester_slashings(
            imm,
            &validators,
            offsets.slice(offsets.attester_slashings_off, offsets.attestations_off),
            active_scratch,
            sig_batch,
        )?;
    }
    if offsets.attestations_off <= offsets.deposits_off && offsets.deposits_off <= body.len() {
        collect_sigs_attestations(
            imm,
            &validators,
            offsets.slice(offsets.attestations_off, offsets.deposits_off),
            block_slot,
            shuffling,
            active_scratch,
            sig_batch,
        )?;
    }
    // deposits skipped — these are verified inline in `apply_deposit`.
    if offsets.voluntary_exits_off <= offsets.exec_off && offsets.exec_off <= body.len() {
        collect_sigs_voluntary_exits(
            imm,
            &validators,
            offsets.slice(offsets.voluntary_exits_off, offsets.exec_off),
            sig_batch,
        );
    }
    if offsets.bls_changes_off <= offsets.blob_off && offsets.blob_off <= body.len() {
        collect_sigs_bls_to_execution_changes(
            imm,
            &validators,
            offsets.slice(offsets.bls_changes_off, offsets.blob_off),
            sig_batch,
        )?;
    }
    collect_sigs_sync_aggregate(&rv, &body[220..380], block_slot, active_scratch, sig_batch);
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
    let (fork_version, gvr) = imm.fork_version_at(block_epoch);
    let mut epoch_chunk = [0u8; 32];
    epoch_chunk[..8].copy_from_slice(&block_epoch.to_le_bytes());
    let domain = bls::compute_domain(bls::DOMAIN_RANDAO, fork_version, &gvr);
    let signing_root = bls::compute_signing_root(&epoch_chunk, &domain);
    sig_batch.push_one(proposer_pubkey, reveal, signing_root);
}

/// Pass 2 — XOR reveal hash into the mix accumulator. BLS already verified
/// in pass 1; if it failed, we never reach here.
fn process_randao(slot: &mut SlotStateWriteView, body: &[u8]) {
    let reveal: &[u8; 96] = body[0..96].try_into().unwrap();
    let reveal_hash = ssz_hash::sha256(reveal);
    let mix = &mut slot.state_mut().randao_mix_current;
    for (b, &r) in mix.iter_mut().zip(reveal_hash.iter()) {
        *b ^= r;
    }
}

fn process_eth1_data(slot: &mut SlotStateWriteView, body: &[u8]) {
    // BeaconBlockBody.eth1_data at body[96..168].
    let eth1: &[u8; 72] = body[96..168].try_into().unwrap();
    let deposit_root: B256 = *Eth1DataView::deposit_root(eth1);
    let deposit_count = Eth1DataView::deposit_count(eth1);
    let block_hash: B256 = *Eth1DataView::block_hash(eth1);

    let vote = common::Eth1Data { deposit_root, deposit_count, block_hash };
    // One vote per slot, reset each voting period; the list never exceeds the
    // period length (`process_eth1_data_reset`).
    debug_assert!(
        slot.state().eth1_votes.len() < common::MAX_ETH1_VOTES,
        "eth1_votes exceeded MAX_ETH1_VOTES"
    );
    slot.state_mut().eth1_votes.push(vote);

    let mut count = 0usize;
    for v in slot.state().eth1_votes.as_slice() {
        if v.deposit_root == deposit_root &&
            v.deposit_count == deposit_count &&
            v.block_hash == block_hash
        {
            count += 1;
        }
    }
    let slots_per_eth1_voting_period = EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH;
    if count * 2 > slots_per_eth1_voting_period as usize {
        slot.state_mut().eth1_data = vote;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn collect_sigs_attestations(
    imm: &Immutable,
    validators: &ValidatorsView,
    attestation_data: &[u8],
    block_slot: Slot,
    shuffling: Option<&ShufflingRef<'_>>,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
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
            validators,
            att,
            current_epoch,
            shuffling,
            active_scratch,
            sig_batch,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn collect_sigs_single_attestation(
    imm: &Immutable,
    validators: &ValidatorsView,
    att: &[u8],
    current_epoch: Epoch,
    shuffling: Option<&ShufflingRef<'_>>,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttestationError> {
    let (fork_epoch, prev_v, curr_v, gvr) = imm.fork_descriptor();
    let data = AttestationView::data(att);
    let att_slot = AttestationDataView::slot(data);
    let target_epoch = AttestationDataView::target_epoch(data);
    let is_current = target_epoch == current_epoch;
    let shuffling = shuffling.ok_or(AttestationError::MissingShuffling)?;
    let (shuffled, committees_per_slot) = if is_current {
        (shuffling.curr_shuffled, shuffling.curr_committees_per_slot)
    } else {
        (shuffling.prev_shuffled, shuffling.prev_committees_per_slot)
    };
    if shuffled.is_empty() || committees_per_slot == 0 {
        return Err(AttestationError::EmptyShuffling);
    }
    let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(att));
    let agg_bits = AttestationView::aggregation_bits(att);
    if committee_bits == 0 {
        return Err(AttestationError::EmptyCommitteeBits);
    }

    active_scratch.clear();
    let mut agg_offset = 0usize;
    let count = validators.count();
    for ci in 0..committees_per_slot {
        if committee_bits & (1u64 << ci) == 0 {
            continue;
        }
        let committee =
            shuffling::get_beacon_committee(shuffled, att_slot, ci, committees_per_slot);
        for (j, &validator_idx) in committee.iter().enumerate() {
            let bit_pos = agg_offset + j;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx >= agg_bits.len() || agg_bits[byte_idx] & (1 << bit_idx) == 0 {
                continue;
            }
            let vi = validator_idx as usize;
            if vi >= count {
                return Err(AttestationError::ValidatorOutOfRange { vi, count });
            }
            active_scratch.push(validator_idx);
        }
        agg_offset += committee.len();
    }

    let fork_version = bls::fork_version_at_epoch(fork_epoch, prev_v, curr_v, target_epoch);
    let sig = AttestationView::signature(att);
    let object_root = ssz_hash::hash_attestation_data(data);
    let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fork_version, &gvr);
    let signing_root = bls::compute_signing_root(&object_root, &domain);
    sig_batch.push_aggregate(
        active_scratch.iter().map(|&vi| validators.pubkey_decompressed(vi as usize)),
        sig,
        signing_root,
    );
    Ok(())
}

/// Pass 2 — full data + state-dep validation, apply participation flags +
/// proposer rewards. BLS verified in pass 1.
#[timed]
#[allow(clippy::too_many_arguments)]
pub fn process_attestations(
    view: &mut StateWriterView,
    epoch: EpochView,
    attestation_data: &[u8],
    block_slot: Slot,
    proposer_index: u32,
    shuffling: Option<&ShufflingRef<'_>>,
    votes_sink: &mut Vec<(u32, B256, Epoch)>,
    active_scratch: &mut Vec<u32>,
) -> Result<(), AttestationError> {
    let slot = &view.slot;
    let validators = &view.validators;
    let balances = &mut view.balances;
    let previous_participation = &mut view.previous_participation;
    let current_participation = &mut view.current_participation;
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

    let total_active = total_active_balance(&validators.reader(), current_epoch);
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
            slot,
            validators,
            previous_participation,
            current_participation,
            epoch,
            att,
            current_epoch,
            previous_epoch,
            total_active,
            shuffling,
            votes_sink,
            active_scratch,
        )?;
        if reward > 0 && (proposer_index as usize) < validators.count() {
            const PROPOSER_WEIGHT: u64 = 8;
            const WEIGHT_DENOMINATOR: u64 = 64;
            let proposer_reward_denominator =
                (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
            let proposer_reward = reward / proposer_reward_denominator;
            let balance = balances.get(proposer_index as usize);
            balances.set(proposer_index, balance.saturating_add(proposer_reward));
        }
    }
    Ok(())
}

/// Pass 2 single-attestation worker — full data + state-dep validation +
/// participation flag updates. Returns the proposer reward numerator on
/// success.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub fn process_single_attestation(
    slot: &SlotStateWriteView,
    validators: &ValidatorsWriteView,
    previous_participation: &mut ParticipationWriteView<Previous>,
    current_participation: &mut ParticipationWriteView<Current>,
    epoch: EpochView,
    att: &[u8],
    current_epoch: Epoch,
    previous_epoch: Epoch,
    total_active: u64,
    shuffling: Option<&ShufflingRef<'_>>,
    votes_sink: &mut Vec<(u32, B256, Epoch)>,
    active_scratch: &mut Vec<u32>,
) -> Result<u64, AttestationError> {
    let current_slot = slot.state().slot;
    validate::validate_attestation_data(att, current_slot, current_epoch, previous_epoch)?;

    let parsed = ParsedAttestationData::from(att);
    let is_current =
        check_attestation_target_window(parsed.target_epoch, current_epoch, previous_epoch)?;
    check_attestation_source(epoch, is_current, parsed.source_epoch, parsed.source_root)?;

    let flag_weights = compute_attestation_flags(slot, &parsed, current_slot, is_current);

    collect_attestation_participants(
        &validators.reader(),
        att,
        shuffling,
        &parsed,
        is_current,
        active_scratch,
    )?;

    for &validator_idx in active_scratch.iter() {
        votes_sink.push((validator_idx, parsed.beacon_block_root, parsed.target_epoch));
    }

    if !flag_weights.iter().any(|&f| f) {
        return Ok(0);
    }
    Ok(apply_attestation_participation_flags(
        validators,
        previous_participation,
        current_participation,
        active_scratch,
        total_active,
        is_current,
        flag_weights,
    ))
}

struct ParsedAttestationData {
    att_slot: Slot,
    beacon_block_root: B256,
    source_epoch: Epoch,
    source_root: B256,
    target_epoch: Epoch,
    target_root: B256,
}

impl ParsedAttestationData {
    fn from(att: &[u8]) -> Self {
        let data = AttestationView::data(att);
        Self {
            att_slot: AttestationDataView::slot(data),
            beacon_block_root: *AttestationDataView::beacon_block_root(data),
            source_epoch: AttestationDataView::source_epoch(data),
            source_root: *AttestationDataView::source_root(data),
            target_epoch: AttestationDataView::target_epoch(data),
            target_root: *AttestationDataView::target_root(data),
        }
    }
}

fn check_attestation_target_window(
    target: Epoch,
    curr: Epoch,
    prev: Epoch,
) -> Result<bool, AttestationError> {
    if target == curr {
        Ok(true)
    } else if target == prev {
        Ok(false)
    } else {
        Err(AttestationError::TargetEpochOutOfWindow { target, prev, curr })
    }
}

fn check_attestation_source(
    epoch: EpochView,
    is_current: bool,
    source_epoch: Epoch,
    source_root: B256,
) -> Result<(), AttestationError> {
    let es = epoch.state();
    let justified =
        if is_current { es.current_justified_checkpoint } else { es.previous_justified_checkpoint };
    if source_epoch != justified.epoch || source_root != justified.root {
        return Err(AttestationError::SourceMismatch {
            expected_epoch: justified.epoch,
            expected_root: justified.root,
            got_epoch: source_epoch,
            got_root: source_root,
        });
    }
    Ok(())
}

fn compute_attestation_flags(
    slot: &SlotStateWriteView,
    parsed: &ParsedAttestationData,
    current_slot: Slot,
    _is_current: bool,
) -> [bool; 3] {
    let expected_target_root = slot.block_root_at_slot(parsed.target_epoch * SLOTS_PER_EPOCH);
    let is_matching_target = parsed.target_root == expected_target_root;
    let expected_head_root = slot.block_root_at_slot(parsed.att_slot);
    let is_matching_head = is_matching_target && parsed.beacon_block_root == expected_head_root;
    let inclusion_delay = current_slot.saturating_sub(parsed.att_slot);

    [inclusion_delay <= 5, is_matching_target, is_matching_head && inclusion_delay == 1]
}

fn collect_attestation_participants(
    validators: &ValidatorsView,
    att: &[u8],
    shuffling: Option<&ShufflingRef<'_>>,
    parsed: &ParsedAttestationData,
    is_current: bool,
    active_scratch: &mut Vec<u32>,
) -> Result<(), AttestationError> {
    let shuffling = shuffling.ok_or(AttestationError::MissingShuffling)?;
    let (shuffled, committees_per_slot) = if is_current {
        (shuffling.curr_shuffled, shuffling.curr_committees_per_slot)
    } else {
        (shuffling.prev_shuffled, shuffling.prev_committees_per_slot)
    };
    if shuffled.is_empty() || committees_per_slot == 0 {
        return Err(AttestationError::EmptyShuffling);
    }

    let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(att));
    let agg_bits = AttestationView::aggregation_bits(att);
    if committee_bits == 0 {
        return Err(AttestationError::EmptyCommitteeBits);
    }
    if committees_per_slot < 64 && (committee_bits >> committees_per_slot) != 0 {
        return Err(AttestationError::CommitteeBitsOverflow {
            committees_per_slot,
            bits: committee_bits,
        });
    }

    active_scratch.clear();
    let count = validators.count();
    let mut agg_offset = 0usize;
    for ci in 0..committees_per_slot {
        if committee_bits & (1u64 << ci) == 0 {
            continue;
        }
        let committee =
            shuffling::get_beacon_committee(shuffled, parsed.att_slot, ci, committees_per_slot);
        let before = active_scratch.len();
        for (j, &validator_idx) in committee.iter().enumerate() {
            let bit_pos = agg_offset + j;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx >= agg_bits.len() || agg_bits[byte_idx] & (1 << bit_idx) == 0 {
                continue;
            }
            let vi = validator_idx as usize;
            if vi >= count {
                return Err(AttestationError::ValidatorOutOfRange { vi, count });
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
    Ok(())
}

fn apply_attestation_participation_flags(
    validators: &ValidatorsWriteView,
    previous_participation: &mut ParticipationWriteView<Previous>,
    current_participation: &mut ParticipationWriteView<Current>,
    active_scratch: &[u32],
    total_active: u64,
    is_current: bool,
    flag_weights: [bool; 3],
) -> u64 {
    let sqrt_total = epoch_transition::integer_sqrt(total_active);
    let base_reward_per_increment = 1_000_000_000u64 * 64 / sqrt_total;

    const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14];
    let mut proposer_reward_numerator = 0u64;
    // Collect changed flags, then apply them in one sorted merge. A committee's
    // participants are distinct validator indices, so the batch is dup-free; a
    // per-validator `set_*_participation` would be O(|edits|) each (quadratic
    // over an epoch's accumulated participation edits).
    let mut updates: Vec<(u32, u8)> = Vec::with_capacity(active_scratch.len());
    for &vi in active_scratch {
        let prev_p = if is_current {
            current_participation.get(vi as usize)
        } else {
            previous_participation.get(vi as usize)
        };
        let mut p = prev_p;
        let effective_balance = validators.effective_balance(vi as usize);
        let base_reward = (effective_balance / 1_000_000_000) * base_reward_per_increment;
        for (fi, &weight) in PARTICIPATION_WEIGHTS.iter().enumerate() {
            let flag_bit = 1u8 << fi;
            if flag_weights[fi] && p & flag_bit == 0 {
                p |= flag_bit;
                proposer_reward_numerator += base_reward * weight;
            }
        }
        if p != prev_p {
            updates.push((vi, p));
        }
    }
    updates.sort_unstable_by_key(|(idx, _)| *idx);
    if is_current {
        current_participation.merge(&updates);
    } else {
        previous_participation.merge(&updates);
    }
    proposer_reward_numerator
}

/// Validate header sanity then cache the execution payload header.
/// No BLS sigs; everything happens in pass 2.
pub fn process_execution_payload(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    payload_bytes: &[u8],
    block_slot: Slot,
) -> Result<(), ExecutionPayloadError> {
    let imm = view.imm;
    let slot = &mut view.slot;
    if payload_bytes.len() < 528 {
        return Err(ExecutionPayloadError::TooShort { len: payload_bytes.len(), min: 528 });
    }
    validate::validate_execution_payload(
        cfg,
        &slot.reader(),
        imm.genesis_time,
        payload_bytes,
        block_slot,
    )?;

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

    slot.state_mut().latest_execution_payload_header = common::ExecutionPayloadHeader {
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
        transactions_root: ssz_hash::hash_transactions_from_payload(payload_bytes),
        withdrawals_root: ssz_hash::hash_withdrawals_from_payload(payload_bytes),
        blob_gas_used: ExecutionPayloadView::blob_gas_used(payload_bytes),
        excess_blob_gas: ExecutionPayloadView::excess_blob_gas(payload_bytes),
    };
    Ok(())
}

const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16384;
const MAX_PENDING_PARTIALS_PER_SWEEP: usize = 8;

/// Cursor and accumulators tracked across the two withdrawal phases.
struct WithdrawalsCursor {
    /// (validator_index, amount) selected in the partials phase, used by the
    /// sweep to discount already-debited balance.
    selected: [(u64, u64); MAX_PENDING_PARTIALS_PER_SWEEP],
    partials_emitted: usize,
    processed_partial_count: usize,
    expected_count: usize,
    withdrawal_index: u64,
    last_emitted_vi: u64,
}

impl WithdrawalsCursor {
    fn new(withdrawal_index: u64) -> Self {
        Self {
            selected: [(0, 0); MAX_PENDING_PARTIALS_PER_SWEEP],
            partials_emitted: 0,
            processed_partial_count: 0,
            expected_count: 0,
            withdrawal_index,
            last_emitted_vi: 0,
        }
    }
}

fn payload_record(withdrawals_data: &[u8], i: usize) -> WithdrawalRecord {
    let count = withdrawals_data.len() / WITHDRAWAL_SIZE;
    if i >= count {
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
}

/// Process withdrawals from the execution payload.
/// Withdrawal SSZ: index(8) + validator_index(8) + address(20) + amount(8) = 44
/// bytes.
pub fn process_withdrawals(
    view: &mut StateWriterView,
    payload_bytes: &[u8],
) -> Result<(), WithdrawalsError> {
    let slot = &mut view.slot;
    let validators = &view.validators;
    let balances = &mut view.balances;
    let pending = &mut view.pending;
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

    let payload_count = withdrawals_data.len() / WITHDRAWAL_SIZE;
    if payload_count > MAX_WITHDRAWALS_PER_PAYLOAD {
        return Err(WithdrawalsError::TooMany {
            count: payload_count,
            max: MAX_WITHDRAWALS_PER_PAYLOAD,
        });
    }

    let count = validators.count();
    let n_validators = count as u64;
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    let mut cursor = WithdrawalsCursor::new(slot.state().next_withdrawal_index);

    process_partial_withdrawals(
        validators,
        balances,
        pending,
        withdrawals_data,
        current_epoch,
        count,
        &mut cursor,
    )?;
    process_sweep_withdrawals(
        slot,
        validators,
        balances,
        withdrawals_data,
        current_epoch,
        count,
        n_validators,
        &mut cursor,
    )?;

    if cursor.expected_count != payload_count {
        return Err(WithdrawalsError::CountMismatch {
            expected: cursor.expected_count,
            actual: payload_count,
        });
    }

    apply_withdrawals(
        slot,
        balances,
        pending,
        withdrawals_data,
        payload_count,
        count,
        n_validators,
        &cursor,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_partial_withdrawals(
    validators: &ValidatorsWriteView,
    balances: &BalancesWriteView,
    pending: &PendingWriteView,
    withdrawals_data: &[u8],
    current_epoch: u64,
    count: usize,
    cursor: &mut WithdrawalsCursor,
) -> Result<(), WithdrawalsError> {
    let partial_limit = min(MAX_PENDING_PARTIALS_PER_SWEEP, MAX_WITHDRAWALS_PER_PAYLOAD - 1);
    let ppw_len = pending.pending_partial_withdrawals_len();

    for qi in 0..ppw_len {
        let pw = *pending.pending_partial_withdrawal(qi);
        if pw.withdrawable_epoch > current_epoch || cursor.partials_emitted >= partial_limit {
            break;
        }
        let vi = pw.index as u32;
        if (vi as usize) < count {
            let total_withdrawn =
                sum_selected_for(&cursor.selected[..cursor.partials_emitted], pw.index);
            let balance = balances.get(vi as usize).saturating_sub(total_withdrawn);
            let eligible = validators.exit_epoch(vi as usize) == u64::MAX &&
                validators.effective_balance(vi as usize) >= MIN_ACTIVATION_BALANCE &&
                balance > MIN_ACTIVATION_BALANCE;
            if eligible {
                let amount = min(balance - MIN_ACTIVATION_BALANCE, pw.amount);
                let creds = validators.credentials(vi as usize);
                let expected = WithdrawalRecord {
                    index: cursor.withdrawal_index,
                    validator_index: pw.index,
                    address: *creds.execution_address(),
                    amount,
                };
                let got = payload_record(withdrawals_data, cursor.expected_count);
                if got != expected {
                    return Err(WithdrawalsError::PartialMismatch {
                        payload_index: cursor.expected_count,
                        expected,
                        got,
                    });
                }
                cursor.selected[cursor.partials_emitted] = (pw.index, amount);
                cursor.partials_emitted += 1;
                cursor.expected_count += 1;
                cursor.withdrawal_index += 1;
                cursor.last_emitted_vi = pw.index;
            }
        }
        cursor.processed_partial_count += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_sweep_withdrawals(
    slot: &SlotStateWriteView,
    validators: &ValidatorsWriteView,
    balances: &BalancesWriteView,
    withdrawals_data: &[u8],
    current_epoch: u64,
    count: usize,
    n_validators: u64,
    cursor: &mut WithdrawalsCursor,
) -> Result<(), WithdrawalsError> {
    if n_validators == 0 {
        return Ok(());
    }
    let mut sweep_vi = slot.state().next_withdrawal_validator_index;
    let bound = min(n_validators, MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);

    for _ in 0..bound {
        let vi = sweep_vi as u32;
        if (vi as usize) < count {
            sweep_one_validator(
                validators,
                balances,
                withdrawals_data,
                sweep_vi,
                current_epoch,
                cursor,
            )?;
        }
        if cursor.expected_count >= MAX_WITHDRAWALS_PER_PAYLOAD {
            break;
        }
        sweep_vi = (sweep_vi + 1) % n_validators;
    }
    Ok(())
}

fn sweep_one_validator(
    validators: &ValidatorsWriteView,
    balances: &BalancesWriteView,
    withdrawals_data: &[u8],
    sweep_vi: u64,
    current_epoch: u64,
    cursor: &mut WithdrawalsCursor,
) -> Result<(), WithdrawalsError> {
    let vi = sweep_vi as u32;
    let creds = *validators.credentials(vi as usize);
    if !creds.has_execution_credential() {
        return Ok(());
    }

    let partial_drawn = sum_selected_for(&cursor.selected[..cursor.partials_emitted], sweep_vi);
    let balance = balances.get(vi as usize).saturating_sub(partial_drawn);
    let max_eb = creds.max_effective_balance();
    let address = *creds.execution_address();
    let wd_epoch = validators.withdrawable_epoch(vi as usize);
    let effective_balance = validators.effective_balance(vi as usize);

    let (expected_amount, kind) = if wd_epoch <= current_epoch && balance > 0 {
        (balance, SweepKind::Full)
    } else if effective_balance == max_eb && balance > max_eb {
        (balance - max_eb, SweepKind::Excess)
    } else {
        return Ok(());
    };

    let expected = WithdrawalRecord {
        index: cursor.withdrawal_index,
        validator_index: sweep_vi,
        address,
        amount: expected_amount,
    };
    let got = payload_record(withdrawals_data, cursor.expected_count);
    if got != expected {
        let pubkey = *validators.pubkey(vi as usize);
        return Err(match kind {
            SweepKind::Full => {
                WithdrawalsError::SweepMismatchFull { vi: sweep_vi, pubkey, expected, got }
            }
            SweepKind::Excess => {
                WithdrawalsError::SweepMismatchExcess { vi: sweep_vi, pubkey, expected, got }
            }
        });
    }
    cursor.expected_count += 1;
    cursor.withdrawal_index += 1;
    cursor.last_emitted_vi = sweep_vi;
    Ok(())
}

enum SweepKind {
    Full,
    Excess,
}

fn sum_selected_for(selected: &[(u64, u64)], vi: u64) -> u64 {
    let mut total = 0u64;
    for &(svi, samt) in selected {
        if svi == vi {
            total = total.saturating_add(samt);
        }
    }
    total
}

#[allow(clippy::too_many_arguments)]
fn apply_withdrawals(
    slot: &mut SlotStateWriteView,
    balances: &mut BalancesWriteView,
    pending: &mut PendingWriteView,
    withdrawals_data: &[u8],
    payload_count: usize,
    count: usize,
    n_validators: u64,
    cursor: &WithdrawalsCursor,
) {
    for i in 0..payload_count {
        let w: &[u8; WITHDRAWAL_SIZE] =
            withdrawals_data[i * WITHDRAWAL_SIZE..(i + 1) * WITHDRAWAL_SIZE].try_into().unwrap();
        let validator_index = WithdrawalView::validator_index(w) as u32;
        let amount = WithdrawalView::amount(w);
        debug_assert!((validator_index as usize) < count);
        let balance = balances.get(validator_index as usize);
        balances.set(validator_index, balance.saturating_sub(amount));
    }
    if cursor.expected_count > 0 {
        slot.state_mut().next_withdrawal_index = cursor.withdrawal_index;
    }
    if cursor.processed_partial_count > 0 {
        pending.drain_pending_partial_withdrawals(cursor.processed_partial_count);
    }
    if n_validators > 0 {
        if cursor.expected_count == MAX_WITHDRAWALS_PER_PAYLOAD {
            slot.state_mut().next_withdrawal_validator_index =
                (cursor.last_emitted_vi + 1) % n_validators;
        } else {
            let next_idx = slot.state().next_withdrawal_validator_index;
            slot.state_mut().next_withdrawal_validator_index =
                (next_idx + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP) % n_validators;
        }
    }
}

/// Pass 1 — resolve sync committee participants from
/// `sync_committee_indices` × bits, push aggregate sig (eth_aggregate
/// semantics — empty + G2-∞ ok).
pub fn collect_sigs_sync_aggregate(
    view: &StateReadView,
    sync_agg: &[u8],
    block_slot: Slot,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) {
    let imm = view.imm;
    let slot = &view.slot;
    let validators = &view.validators;
    let longtail = &view.longtail;
    if sync_agg.len() < BLOCK_SYNC_AGGREGATE_SIZE {
        return;
    }
    let sync_agg_fixed: &[u8; BLOCK_SYNC_AGGREGATE_SIZE] =
        sync_agg[..BLOCK_SYNC_AGGREGATE_SIZE].try_into().unwrap();
    let bits = SyncAggregateView::sync_committee_bits(sync_agg_fixed);
    let sig = SyncAggregateView::sync_committee_signature(sync_agg_fixed);

    let previous_slot = block_slot.saturating_sub(1);
    let previous_block_root = slot.block_root_at_slot(previous_slot);
    let previous_epoch = previous_slot / SLOTS_PER_EPOCH;
    let (fork_version, gvr) = imm.fork_version_at(previous_epoch);

    active_scratch.clear();
    let count = validators.count();
    let sync_indices = longtail.state().sync_committee_indices;
    for (i, &vi) in sync_indices.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if bits[byte_idx] & (1 << bit_idx) != 0 {
            if (vi as usize) >= count {
                sig_batch.poison();
                return;
            }
            active_scratch.push(vi);
        }
    }
    let domain = bls::compute_domain(bls::DOMAIN_SYNC_COMMITTEE, fork_version, &gvr);
    let signing_root = bls::compute_signing_root(&previous_block_root, &domain);
    sig_batch.push_eth_aggregate(
        active_scratch.len(),
        active_scratch.iter().map(|&vi| validators.pubkey_decompressed(vi as usize)),
        sig,
        signing_root,
    );
}

/// Pass 2 — apply sync_aggregate balance updates. BLS verified in pass 1.
#[timed]
pub fn process_sync_aggregate(
    view: &mut StateWriterView,
    longtail: LongtailView,
    sync_agg: &[u8],
    proposer_index: u32,
) -> Result<(), SyncAggregateError> {
    let slot = &view.slot;
    let validators = &view.validators;
    let balances = &mut view.balances;
    if sync_agg.len() < BLOCK_SYNC_AGGREGATE_SIZE {
        return Ok(());
    }
    let count = validators.count();
    if (proposer_index as usize) >= count {
        return Err(SyncAggregateError::ProposerOutOfRange { idx: proposer_index as u64, count });
    }
    let sync_agg_fixed: &[u8; BLOCK_SYNC_AGGREGATE_SIZE] =
        sync_agg[..BLOCK_SYNC_AGGREGATE_SIZE].try_into().unwrap();
    let bits = SyncAggregateView::sync_committee_bits(sync_agg_fixed);

    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    let total_active = total_active_balance(&validators.reader(), current_epoch);
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

    let sync_indices: [u32; SYNC_COMMITTEE_SIZE] = longtail.state().sync_committee_indices;

    let mut proposer_reward_sum = 0u64;
    #[allow(clippy::needless_range_loop)]
    for i in 0..SYNC_COMMITTEE_SIZE {
        let vi = sync_indices[i];
        if (vi as usize) >= count {
            continue;
        }
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let participated = bits[byte_idx] & (1 << bit_idx) != 0;
        let balance = balances.get(vi as usize);
        let new_bal = if participated {
            proposer_reward_sum += proposer_reward_per;
            balance.saturating_add(participant_reward)
        } else {
            balance.saturating_sub(participant_reward)
        };
        balances.set(vi, new_bal);
    }
    let bal_p = balances.get(proposer_index as usize);
    balances.set(proposer_index, bal_p.saturating_add(proposer_reward_sum));
    Ok(())
}

/// Pass 1 — push voluntary-exit sigs. Each exit's signing root is the
/// `(epoch, validator_index)` pair under `DOMAIN_VOLUNTARY_EXIT` pinned to
/// `CAPELLA_FORK_VERSION`. Returns false on out-of-range vi (early reject).
pub fn collect_sigs_voluntary_exits(
    imm: &Immutable,
    validators: &ValidatorsView,
    data: &[u8],
    sig_batch: &mut SigBatch,
) {
    let capella_fv = imm.capella_fork_version;
    let gvr = imm.genesis_validators_root;
    let count = data.len() / SIGNED_VOLUNTARY_EXIT_SIZE;
    let validator_count = validators.count();
    for i in 0..count {
        let exit: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] = data
            [i * SIGNED_VOLUNTARY_EXIT_SIZE..(i + 1) * SIGNED_VOLUNTARY_EXIT_SIZE]
            .try_into()
            .unwrap();
        let exit_epoch_msg = SignedVoluntaryExitView::epoch(exit);
        let vi_u = SignedVoluntaryExitView::validator_index(exit);
        let vi = vi_u as u32;
        if (vi as usize) >= validator_count {
            sig_batch.poison();
            return;
        }
        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch_msg, vi_u);
        let domain = bls::compute_domain(bls::DOMAIN_VOLUNTARY_EXIT, capella_fv, &gvr);
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(exit);
        let pk = validators.pubkey_decompressed(vi as usize);
        sig_batch.push_one(pk, sig, signing_root);
    }
}

/// Pass 2 — validate state-dependent preconditions (post-block-mutation
/// state evolution may change `is_slashable` / pending-balance), apply
/// `initiate_validator_exit` per accepted entry. BLS already verified.
pub fn process_voluntary_exits(
    view: &mut StateWriterView,
    cfg: &SpecConfig,
    data: &[u8],
) -> Result<(), VoluntaryExitError> {
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let pending = &view.pending;
    let count = data.len() / SIGNED_VOLUNTARY_EXIT_SIZE;
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let exit: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] = data
            [i * SIGNED_VOLUNTARY_EXIT_SIZE..(i + 1) * SIGNED_VOLUNTARY_EXIT_SIZE]
            .try_into()
            .unwrap();
        let exit_epoch_msg = SignedVoluntaryExitView::epoch(exit);
        let vi = SignedVoluntaryExitView::validator_index(exit) as u32;
        validate::validate_voluntary_exit(
            cfg,
            &validators.reader(),
            vi,
            exit_epoch_msg,
            current_epoch,
        )?;
        if get_pending_balance_to_withdraw(&pending.reader(), vi) != 0 {
            return Err(VoluntaryExitError::HasPendingBalance {
                vi: vi as usize,
                pubkey: *validators.pubkey(vi as usize),
            });
        }
        initiate_validator_exit(cfg, slot, validators, vi, current_epoch);
    }
    Ok(())
}

fn process_execution_requests(view: &mut StateWriterView, cfg: &SpecConfig, data: &[u8]) {
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
    let f0 = field(0);
    let f1 = field(1);
    let f2 = field(2);
    process_deposit_requests(&mut *view, f0);
    process_withdrawal_requests(&mut *view, cfg, f1);
    process_consolidation_requests(&mut *view, cfg, f2);
}

pub fn process_deposit_requests(view: &mut StateWriterView, data: &[u8]) {
    let slot = &mut view.slot;
    let pending = &mut view.pending;
    let count = data.len() / DEPOSIT_REQUEST_SIZE;
    let cur_slot = slot.state().slot;

    for i in 0..count {
        let d: &[u8; DEPOSIT_REQUEST_SIZE] =
            data[i * DEPOSIT_REQUEST_SIZE..(i + 1) * DEPOSIT_REQUEST_SIZE].try_into().unwrap();
        let pubkey = *DepositRequestView::pubkey(d);
        let credentials = common::Withdrawals(*DepositRequestView::withdrawal_credentials(d));
        let amount = DepositRequestView::amount(d);
        let signature = *DepositRequestView::signature(d);
        let index = DepositRequestView::index(d);

        if slot.state().deposit_requests_start_index == UNSET_DEPOSIT_REQUESTS_START_INDEX {
            slot.state_mut().deposit_requests_start_index = index;
        }

        pending.push_pending_deposit(common::PendingDeposit {
            pubkey,
            withdrawal_credentials: credentials,
            amount,
            signature,
            slot: cur_slot,
        });
    }
}

pub fn process_withdrawal_requests(view: &mut StateWriterView, cfg: &SpecConfig, data: &[u8]) {
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let balances = &view.balances;
    let pending = &mut view.pending;
    let count = data.len() / WITHDRAWAL_REQUEST_SIZE;
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;

    for i in 0..count {
        let r: &[u8; WITHDRAWAL_REQUEST_SIZE] = data
            [i * WITHDRAWAL_REQUEST_SIZE..(i + 1) * WITHDRAWAL_REQUEST_SIZE]
            .try_into()
            .unwrap();
        let source_address = WithdrawalRequestView::source_address(r);
        let validator_pubkey = WithdrawalRequestView::validator_pubkey(r);
        let amount = WithdrawalRequestView::amount(r);
        let is_full_exit = amount == FULL_EXIT_REQUEST_AMOUNT;

        let ppw_len = pending.pending_partial_withdrawals_len();
        if ppw_len >= PENDING_PARTIAL_WITHDRAWALS_LIMIT && !is_full_exit {
            continue;
        }

        let vi = match validators.find_by_pubkey(validator_pubkey) {
            Some(idx) => idx,
            None => continue,
        };

        let creds = *validators.credentials(vi as usize);
        if !creds.has_execution_credential() {
            continue;
        }
        if creds.execution_address() != source_address {
            continue;
        }
        if !is_active(&validators.reader(), vi, current_epoch) {
            continue;
        }
        if validators.exit_epoch(vi as usize) != u64::MAX {
            continue;
        }
        let act = validators.activation_epoch(vi as usize);
        if current_epoch < act + cfg.shard_committee_period {
            continue;
        }

        let pending_balance = get_pending_balance_to_withdraw(&pending.reader(), vi);

        if is_full_exit {
            if pending_balance == 0 {
                initiate_validator_exit(cfg, slot, validators, vi, current_epoch);
            }
            continue;
        }

        let effective_balance = validators.effective_balance(vi as usize);
        let balance = balances.get(vi as usize);
        let has_sufficient_eff = effective_balance >= MIN_ACTIVATION_BALANCE;
        let has_excess = balance > MIN_ACTIVATION_BALANCE + pending_balance;

        if creds.has_compounding_credential() && has_sufficient_eff && has_excess {
            let to_withdraw = min(balance - MIN_ACTIVATION_BALANCE - pending_balance, amount);
            let exit_queue_epoch = compute_exit_epoch_and_update_churn(
                cfg,
                slot,
                &validators.reader(),
                to_withdraw,
                current_epoch,
            );
            let withdrawable_epoch = exit_queue_epoch + cfg.min_validator_withdrawability_delay;
            pending.push_pending_partial_withdrawal(common::PendingPartialWithdrawal {
                index: vi as u64,
                amount: to_withdraw,
                withdrawable_epoch,
            });
        }
    }
}

pub fn process_consolidation_requests(view: &mut StateWriterView, cfg: &SpecConfig, data: &[u8]) {
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let balances = &mut view.balances;
    let pending = &mut view.pending;
    let count = data.len() / CONSOLIDATION_REQUEST_SIZE;
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;

    for i in 0..count {
        let r: &[u8; CONSOLIDATION_REQUEST_SIZE] = data
            [i * CONSOLIDATION_REQUEST_SIZE..(i + 1) * CONSOLIDATION_REQUEST_SIZE]
            .try_into()
            .unwrap();
        let source_address = ConsolidationRequestView::source_address(r);
        let source_pubkey = ConsolidationRequestView::source_pubkey(r);
        let target_pubkey = ConsolidationRequestView::target_pubkey(r);

        if source_pubkey == target_pubkey {
            if let Some(src) = validators.find_by_pubkey(source_pubkey) {
                let creds = *validators.credentials(src as usize);
                if creds.execution_address() == source_address &&
                    creds.has_eth1_credential() &&
                    is_active(&validators.reader(), src, current_epoch) &&
                    validators.exit_epoch(src as usize) == u64::MAX
                {
                    switch_to_compounding_validator(validators, balances, pending, src);
                }
            }
            continue;
        }

        // Full consolidation.
        let pc_len = pending.pending_consolidations_len();
        if pc_len >= PENDING_CONSOLIDATIONS_LIMIT {
            continue;
        }
        let churn_limit = get_consolidation_churn_limit(cfg, &validators.reader(), current_epoch);
        if churn_limit <= MIN_ACTIVATION_BALANCE {
            continue;
        }

        let source_idx = match validators.find_by_pubkey(source_pubkey) {
            Some(idx) => idx,
            None => continue,
        };
        let target_idx = match validators.find_by_pubkey(target_pubkey) {
            Some(idx) => idx,
            None => continue,
        };

        let source_creds = *validators.credentials(source_idx as usize);
        if !source_creds.has_execution_credential() {
            continue;
        }
        if source_creds.execution_address() != source_address {
            continue;
        }
        if !validators.credentials(target_idx as usize).has_compounding_credential() {
            continue;
        }
        if !is_active(&validators.reader(), source_idx, current_epoch) ||
            !is_active(&validators.reader(), target_idx, current_epoch)
        {
            continue;
        }
        if validators.exit_epoch(source_idx as usize) != u64::MAX ||
            validators.exit_epoch(target_idx as usize) != u64::MAX
        {
            continue;
        }
        let src_act = validators.activation_epoch(source_idx as usize);
        if current_epoch < src_act + cfg.shard_committee_period {
            continue;
        }
        if get_pending_balance_to_withdraw(&pending.reader(), source_idx) > 0 {
            continue;
        }

        let src_eff = validators.effective_balance(source_idx as usize);
        let exit_epoch = compute_consolidation_epoch_and_update_churn(
            cfg,
            slot,
            &validators.reader(),
            src_eff,
            current_epoch,
        );
        validators.set_exit_epoch(source_idx, exit_epoch);
        validators.set_withdrawable_epoch(
            source_idx,
            exit_epoch + cfg.min_validator_withdrawability_delay,
        );
        pending.push_pending_consolidation(common::PendingConsolidation {
            source_index: source_idx as u64,
            target_index: target_idx as u64,
        });
    }
}

/// Pass 1 — push both header sigs per slashing entry.
pub fn collect_sigs_proposer_slashings(
    imm: &Immutable,
    validators: &ValidatorsView,
    data: &[u8],
    sig_batch: &mut SigBatch,
) -> Result<(), ProposerSlashingError> {
    let (fork_epoch, prev_ver, cur_ver, gvr) = imm.fork_descriptor();
    let count = data.len() / PROPOSER_SLASHING_SIZE;
    let n = validators.count();
    for i in 0..count {
        let s: &[u8; PROPOSER_SLASHING_SIZE] =
            data[i * PROPOSER_SLASHING_SIZE..(i + 1) * PROPOSER_SLASHING_SIZE].try_into().unwrap();
        let vi = ProposerSlashingView::h1_proposer_index(s) as u32;
        if (vi as usize) >= n {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi: vi as usize, count: n });
        }
        let h1_slot = ProposerSlashingView::h1_slot(s);
        let h2_slot = ProposerSlashingView::h2_slot(s);
        let fv1 =
            bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, h1_slot / SLOTS_PER_EPOCH);
        let fv2 =
            bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, h2_slot / SLOTS_PER_EPOCH);
        let sr1 = signing_root_for_block_header(&s[0..208], fv1, &gvr);
        let sr2 = signing_root_for_block_header(&s[208..416], fv2, &gvr);
        let sig1 = ProposerSlashingView::h1_signature(s);
        let sig2 = ProposerSlashingView::h2_signature(s);
        let pk = validators.pubkey_decompressed(vi as usize);
        sig_batch.push_one(pk, sig1, sr1);
        sig_batch.push_one(pk, sig2, sr2);
    }
    Ok(())
}

/// Pass 2 — validate per-entry preconditions and slash. BLS already
/// verified. `is_slashable_validator` re-check picks up within-block
/// mutations (a same-vi double slashing rejects on the second entry
/// because the first one already set the slashed flag).
pub fn process_proposer_slashings(
    view: &mut StateWriterView,
    epoch: EpochView,
    cfg: &SpecConfig,
    data: &[u8],
) -> Result<(), ProposerSlashingError> {
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let balances = &mut view.balances;
    let count = data.len() / PROPOSER_SLASHING_SIZE;
    let n = validators.count();
    let proposer_index = get_beacon_proposer_index(slot, epoch);
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let s: &[u8; PROPOSER_SLASHING_SIZE] =
            data[i * PROPOSER_SLASHING_SIZE..(i + 1) * PROPOSER_SLASHING_SIZE].try_into().unwrap();
        validate::validate_proposer_slashing(s)?;
        let vi = ProposerSlashingView::h1_proposer_index(s) as u32;
        if (vi as usize) >= n {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi: vi as usize, count: n });
        }
        if !is_slashable_validator(&validators.reader(), vi, current_epoch) {
            return Err(ProposerSlashingError::NotSlashable {
                vi: vi as usize,
                pubkey: *validators.pubkey(vi as usize),
                epoch: current_epoch,
            });
        }
        slash_validator(cfg, slot, validators, balances, vi, proposer_index);
    }
    Ok(())
}

/// Compute signing root for a `BeaconBlockHeader` (208-byte SSZ): slot,
/// proposer_index, parent_root, state_root, body_root.
pub(crate) fn signing_root_for_block_header(
    header: &[u8],
    fork_version: [u8; 4],
    genesis_validators_root: &B256,
) -> B256 {
    let hb: &[u8; BEACON_BLOCK_HEADER_SIZE] =
        header[..BEACON_BLOCK_HEADER_SIZE].try_into().unwrap();
    let h = common::BeaconBlockHeader {
        slot: BeaconBlockHeaderView::slot(hb),
        proposer_index: BeaconBlockHeaderView::proposer_index(hb),
        parent_root: *BeaconBlockHeaderView::parent_root(hb),
        state_root: *BeaconBlockHeaderView::state_root(hb),
        body_root: *BeaconBlockHeaderView::body_root(hb),
    };
    let object_root = hash_tree_root_block_header(&h);
    let domain =
        bls::compute_domain(bls::DOMAIN_BEACON_PROPOSER, fork_version, genesis_validators_root);
    bls::compute_signing_root(&object_root, &domain)
}

/// Spec: process_deposit. Verify each Deposit's 33-level Merkle branch
/// against `state.eth1_data.deposit_root` at leaf index
/// `state.eth1_deposit_index` before queueing. A bad proof fails the block.
pub fn process_deposits(view: &mut StateWriterView, data: &[u8]) -> Result<()> {
    let count = data.len() / DEPOSIT_SIZE;

    for i in 0..count {
        let d: &[u8; DEPOSIT_SIZE] =
            data[i * DEPOSIT_SIZE..(i + 1) * DEPOSIT_SIZE].try_into().unwrap();
        let dd = DepositView::data(d);
        let proof = DepositView::proof(d);
        let leaf = ssz_hash::hash_tree_root_deposit_data(dd);
        let deposit_index = view.slot.state().eth1_deposit_index;
        let deposit_root = view.slot.state().eth1_data.deposit_root;
        if !ssz_hash::is_valid_merkle_branch(
            &leaf,
            proof,
            (DEPOSIT_CONTRACT_TREE_DEPTH as u32) + 1,
            deposit_index,
            &deposit_root,
        ) {
            return Err(Error::InvalidDepositProof { index: deposit_index });
        }

        let pubkey = DepositDataView::pubkey(dd);
        let credentials = common::Withdrawals(*DepositDataView::withdrawal_credentials(dd));
        let amount = DepositDataView::amount(dd);
        let signature = *DepositDataView::signature(dd);

        if let Err(e) = apply_deposit(view, pubkey, &credentials, amount, &signature) {
            if e.is_fatal() {
                return Err(e);
            }
        }
        view.slot.state_mut().eth1_deposit_index += 1;
    }
    Ok(())
}

/// Pass 1 — push bls_to_execution_change sigs. Signer is the validator's
/// BLS withdrawal key (the `from_bls_pubkey` in the message itself) — not
/// the signing key cached on `ValidatorsState` (`pubkey_decompressed`), so we
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
    validators: &ValidatorsView,
    data: &[u8],
    sig_batch: &mut SigBatch,
) -> Result<(), BlsToExecutionChangeError> {
    let genesis_fv = imm.genesis_fork_version;
    let gvr = imm.genesis_validators_root;
    let count = data.len() / SIGNED_BLS_CHANGE_SIZE;
    let validator_count = validators.count();
    for i in 0..count {
        let c: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            data[i * SIGNED_BLS_CHANGE_SIZE..(i + 1) * SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();
        let validator_index_u = SignedBlsToExecutionChangeView::validator_index(c);
        let from_bls_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(c);
        let to_execution_address = SignedBlsToExecutionChangeView::to_execution_address(c);
        let sig = SignedBlsToExecutionChangeView::signature(c);

        if (validator_index_u as usize) < validator_count {
            validate::validate_bls_to_execution_change(
                validators,
                validator_index_u as u32,
                from_bls_pubkey,
            )?;
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(
            validator_index_u,
            from_bls_pubkey,
            to_execution_address,
        );
        let domain = bls::compute_domain(bls::DOMAIN_BLS_TO_EXECUTION_CHANGE, genesis_fv, &gvr);
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
    validators: &mut ValidatorsWriteView,
    data: &[u8],
) -> Result<(), BlsToExecutionChangeError> {
    let count = data.len() / SIGNED_BLS_CHANGE_SIZE;
    for i in 0..count {
        let c: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            data[i * SIGNED_BLS_CHANGE_SIZE..(i + 1) * SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();
        let validator_index = SignedBlsToExecutionChangeView::validator_index(c) as u32;
        let from_bls_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(c);
        let to_execution_address = SignedBlsToExecutionChangeView::to_execution_address(c);

        validate::validate_bls_to_execution_change(
            &validators.reader(),
            validator_index,
            from_bls_pubkey,
        )?;
        let creds = common::Withdrawals::eth1(to_execution_address);
        validators.set_credentials(validator_index, creds);
    }
    Ok(())
}

/// Pass 1 — push both IndexedAttestation aggregate sigs per slashing entry.
pub fn collect_sigs_attester_slashings(
    imm: &Immutable,
    validators: &ValidatorsView,
    data: &[u8],
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttesterSlashingError> {
    let (fork_epoch, prev_ver, cur_ver, gvr) = imm.fork_descriptor();
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
            let target_epoch = ssz_view::IndexedAttestationView::target_epoch(ia);
            let fv = bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, target_epoch);
            active_scratch.clear();
            let n_idx = indices.len() / 8;
            let count = validators.count();
            for k in 0..n_idx {
                let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap());
                if vi as usize >= count {
                    return Err(AttesterSlashingError::ValidatorOutOfRange {
                        vi: vi as usize,
                        count,
                    });
                }
                active_scratch.push(vi as u32);
            }
            let data_chunk: &[u8; 128] = ssz_view::IndexedAttestationView::data(ia);
            let sig: &[u8; 96] = ssz_view::IndexedAttestationView::signature(ia);
            let object_root = ssz_hash::hash_attestation_data(data_chunk);
            let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &gvr);
            let signing_root = bls::compute_signing_root(&object_root, &domain);
            sig_batch.push_aggregate(
                active_scratch.iter().map(|&vi| validators.pubkey_decompressed(vi as usize)),
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
///
/// `scratch` is a u32 scratch that holds the slashable-intersection
/// indices between read-phase and mutate-phase. Caller-provided so the
/// allocation amortises; bounded by `MAX_ATTESTING_INDICES`.
pub fn process_attester_slashings(
    view: &mut StateWriterView,
    epoch: EpochView,
    cfg: &SpecConfig,
    data: &[u8],
    scratch: &mut Vec<u32>,
) -> Result<(), AttesterSlashingError> {
    if data.is_empty() {
        return Ok(());
    }
    let first_offset = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > data.len() {
        return Ok(());
    }
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let balances = &mut view.balances;
    let count = first_offset / 4;
    let proposer_index = get_beacon_proposer_index(slot, epoch);
    let n = validators.count();
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;

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
        // Collect slashable indices first to avoid holding `view` while
        // calling the mutating `slash_validator`.
        scratch.clear();
        {
            let v = validators.reader();
            for_each_sorted_intersection(i1, i2, |vi| {
                let vi32 = vi as u32;
                if vi < n && is_slashable_validator(&v, vi32, current_epoch) {
                    scratch.push(vi32);
                }
                false
            });
        }
        for &vi in scratch.iter() {
            // Re-check slashability after each prior slash mutation in the loop.
            if is_slashable_validator(&validators.reader(), vi, current_epoch) {
                slash_validator(cfg, slot, validators, balances, vi, proposer_index);
                slashed_any = true;
            }
        }
        if !slashed_any {
            return Err(AttesterSlashingError::NoSlashedIntersection);
        }
    }
    Ok(())
}

/// Gossip-side `AttesterSlashing` validator (single slashing, not the
/// block-body list form).
pub fn validate_attester_slashing_for_gossip(
    view: &StateReadView,
    slashing: &[u8],
    sig_batch: &mut SigBatch,
) -> bool {
    let (fork_epoch, prev_ver, cur_ver, gvr) = view.imm.fork_descriptor();
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
    if i1.len() / 8 > ssz_view::MAX_ATTESTING_INDICES ||
        i2.len() / 8 > ssz_view::MAX_ATTESTING_INDICES
    {
        return false;
    }
    if !indices_sorted_unique(i1) || !indices_sorted_unique(i2) {
        return false;
    }

    let current_epoch = view.slot.current_epoch();
    let count = view.validators.count();
    let validators = view.validators;
    let mut any_slashable = false;
    for_each_sorted_intersection(i1, i2, |vi| {
        let vi32 = vi as u32;
        if vi < count && is_slashable_validator(&validators, vi32, current_epoch) {
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
        let target_epoch = ssz_view::IndexedAttestationView::target_epoch(ia);
        let fv = bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, target_epoch);
        let n_idx = indices.len() / 8;
        for k in 0..n_idx {
            let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as usize;
            if vi >= count {
                return false;
            }
        }
        let data_chunk: &[u8; 128] = ssz_view::IndexedAttestationView::data(ia);
        let sig: &[u8; 96] = ssz_view::IndexedAttestationView::signature(ia);
        let object_root = ssz_hash::hash_attestation_data(data_chunk);
        let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &gvr);
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        sig_batch.push_aggregate(
            (0..n_idx).map(|k| {
                let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as u32;
                view.validators.pubkey_decompressed(vi as usize)
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
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &mut ValidatorsWriteView,
    balances: &mut BalancesWriteView,
    vi: u32,
    proposer_index: u32,
) {
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    let effective_balance = validators.effective_balance(vi as usize);

    initiate_validator_exit(cfg, slot, validators, vi, current_epoch);
    validators.set_slashed(vi, true);
    let prev_wd = validators.withdrawable_epoch(vi as usize);
    let new_wd = max(prev_wd, current_epoch + EPOCHS_PER_SLASHINGS_VECTOR as u64);
    validators.set_withdrawable_epoch(vi, new_wd);

    // Per-block accumulator for the in-progress epoch (flushed at the boundary
    // by process_slashings_reset into `epoch.slashings`).
    let acc = slot.state_mut().current_epoch_slashings.saturating_add(effective_balance);
    slot.state_mut().current_epoch_slashings = acc;

    let penalty = effective_balance / cfg.min_slashing_penalty_quotient;
    let bal_vi = balances.get(vi as usize);
    balances.set(vi, bal_vi.saturating_sub(penalty));

    // Spec: increase_balance(proposer, proposer_reward); increase_balance(
    // whistleblower, whistleblower_reward - proposer_reward). With no
    // explicit whistleblower (block-included slashings), whistleblower_index
    // defaults to proposer_index, so the proposer receives the full
    // whistleblower_reward.
    let whistleblower_reward = effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT;
    let bal_pi = balances.get(proposer_index as usize);
    balances.set(proposer_index, bal_pi.saturating_add(whistleblower_reward));
}

fn initiate_validator_exit(
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &mut ValidatorsWriteView,
    vi: u32,
    current_epoch: Epoch,
) {
    if validators.exit_epoch(vi as usize) != u64::MAX {
        return;
    }
    let effective_balance = validators.effective_balance(vi as usize);
    let exit_epoch = compute_exit_epoch_and_update_churn(
        cfg,
        slot,
        &validators.reader(),
        effective_balance,
        current_epoch,
    );
    validators.set_exit_epoch(vi, exit_epoch);
    validators.set_withdrawable_epoch(vi, exit_epoch + cfg.min_validator_withdrawability_delay);
}

fn compute_exit_epoch_and_update_churn(
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &ValidatorsView,
    exit_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + cfg.max_seed_lookahead;
    let prev_earliest = slot.state().earliest_exit_epoch;
    let mut earliest = max(prev_earliest, activation_exit_epoch);
    let per_epoch_churn = get_activation_exit_churn_limit(cfg, validators, current_epoch);

    let mut balance_to_consume = if prev_earliest < earliest {
        per_epoch_churn
    } else {
        slot.state().exit_balance_to_consume
    };

    if exit_balance > balance_to_consume {
        let to_process = exit_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    slot.state_mut().exit_balance_to_consume = balance_to_consume - exit_balance;
    slot.state_mut().earliest_exit_epoch = earliest;
    earliest
}

fn compute_consolidation_epoch_and_update_churn(
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &ValidatorsView,
    consolidation_balance: u64,
    current_epoch: Epoch,
) -> Epoch {
    let activation_exit_epoch = current_epoch + 1 + cfg.max_seed_lookahead;
    let prev_earliest = slot.state().earliest_consolidation_epoch;
    let mut earliest = max(prev_earliest, activation_exit_epoch);
    let per_epoch_churn = get_consolidation_churn_limit(cfg, validators, current_epoch);

    let mut balance_to_consume = if prev_earliest < earliest {
        per_epoch_churn
    } else {
        slot.state().consolidation_balance_to_consume
    };

    if consolidation_balance > balance_to_consume {
        let to_process = consolidation_balance - balance_to_consume;
        let additional = (to_process - 1) / per_epoch_churn + 1;
        earliest += additional;
        balance_to_consume += additional * per_epoch_churn;
    }

    slot.state_mut().consolidation_balance_to_consume = balance_to_consume - consolidation_balance;
    slot.state_mut().earliest_consolidation_epoch = earliest;
    earliest
}

fn get_balance_churn_limit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    current_epoch: Epoch,
) -> u64 {
    let total = total_active_balance(validators, current_epoch);
    let churn = max(cfg.min_per_epoch_churn_limit, total / cfg.churn_limit_quotient);
    churn - churn % EFFECTIVE_BALANCE_INCREMENT
}

fn get_activation_exit_churn_limit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    current_epoch: Epoch,
) -> u64 {
    min(
        cfg.max_per_epoch_activation_exit_churn_limit,
        get_balance_churn_limit(cfg, validators, current_epoch),
    )
}

fn get_consolidation_churn_limit(
    cfg: &SpecConfig,
    validators: &ValidatorsView,
    current_epoch: Epoch,
) -> u64 {
    get_balance_churn_limit(cfg, validators, current_epoch) -
        get_activation_exit_churn_limit(cfg, validators, current_epoch)
}

/// O(N + |edits|): single sweep over activation/exit/effective_balance columns.
fn total_active_balance(validators: &ValidatorsView, current_epoch: Epoch) -> u64 {
    let n = validators.count();
    let mut act = validators.iter_activation_epochs();
    let mut exit = validators.iter_exit_epochs();
    let mut effective_balance = validators.iter_effective_balances();
    let mut total: u64 = 0;
    for _ in 0..n {
        let a = act.next().unwrap();
        let x = exit.next().unwrap();
        let b = effective_balance.next().unwrap();
        if a <= current_epoch && current_epoch < x {
            total += b;
        }
    }
    total.max(EFFECTIVE_BALANCE_INCREMENT)
}

pub(crate) fn get_pending_balance_to_withdraw(pending: &PendingView, vi: u32) -> u64 {
    let n = pending.pending_partial_withdrawals_len();
    let mut total = 0u64;
    for i in 0..n {
        let pw = pending.pending_partial_withdrawal(i);
        if pw.index == vi as u64 {
            total += pw.amount;
        }
    }
    total
}

#[inline]
fn is_active(validators: &ValidatorsView, vi: u32, e: Epoch) -> bool {
    validators.activation_epoch(vi as usize) <= e && e < validators.exit_epoch(vi as usize)
}

#[inline]
pub(crate) fn is_slashable_validator(validators: &ValidatorsView, vi: u32, e: Epoch) -> bool {
    !validators.is_slashed(vi as usize) &&
        validators.activation_epoch(vi as usize) <= e &&
        e < validators.withdrawable_epoch(vi as usize)
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
        let curr = read(i);
        if curr <= prev {
            return false;
        }
        prev = curr;
    }
    true
}

#[inline]
fn get_beacon_proposer_index(slot: &SlotStateWriteView, epoch: EpochView) -> u32 {
    let s = slot.state().slot;
    epoch
        .proposer_at((s % SLOTS_PER_EPOCH) as usize)
        .expect("slot-in-epoch is within the lookahead window") as u32
}

fn switch_to_compounding_validator(
    validators: &mut ValidatorsWriteView,
    balances: &mut BalancesWriteView,
    pending: &mut PendingWriteView,
    vi: u32,
) {
    let mut bytes = validators.credentials(vi as usize).0;
    bytes[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
    let creds = common::Withdrawals(bytes);
    validators.set_credentials(vi, creds);

    let balance = balances.get(vi as usize);
    if balance > MIN_ACTIVATION_BALANCE {
        let excess = balance - MIN_ACTIVATION_BALANCE;
        balances.set(vi, MIN_ACTIVATION_BALANCE);
        let pubkey = *validators.pubkey(vi as usize);
        pending.push_pending_deposit(common::PendingDeposit {
            pubkey,
            withdrawal_credentials: creds,
            amount: excess,
            signature: G2_POINT_AT_INFINITY,
            slot: 0, // GENESIS_SLOT
        });
    }
}

/// Apply a single deposit: for new validators, BLS-verify then
/// `append_validator`. Always queue a `PendingDeposit` for the amount. Spec
/// defaults for new validator columns (FAR_FUTURE_EPOCH for epoch fields, 0 for
/// counters, false for slashed) come from the view layer's `appended_default` —
/// no explicit edits required. Returns `SkipDepositBadSig` when BLS fails for
/// a new validator (per spec: drop deposit, continue block).
fn apply_deposit(
    view: &mut StateWriterView,
    pubkey: &[u8; 48],
    credentials: &common::Withdrawals,
    amount: u64,
    signature: &[u8; 96],
) -> Result<()> {
    let existing = view.validators.find_by_pubkey(pubkey);
    if existing.is_none() {
        if !epoch_transition::is_valid_deposit_signature(pubkey, credentials, amount, signature) {
            return Err(Error::SkipDepositBadSig { index: view.slot.state().eth1_deposit_index });
        }
        let pubkey_decompressed = PublicKey::from_bytes(pubkey).unwrap_or_default();
        append_validator(view, *pubkey, pubkey_decompressed, *credentials);
    }

    view.pending.push_pending_deposit(common::PendingDeposit {
        pubkey: *pubkey,
        withdrawal_credentials: *credentials,
        amount,
        signature: *signature,
        slot: 0, // GENESIS_SLOT — Eth1 bridge deposit.
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BalancesGroup, BeaconState, CurrentParticipationGroup, EpochGroup, EpochStateFinalized,
        FinalizedValidators, InactivityScoresGroup, LongtailGroup, LongtailState, PendingGroup,
        PendingQueues, PreviousParticipationGroup, SlotStateFinalized, SlotStateGroup, StateId,
        ValidatorsGroup,
    };

    use super::*;

    /// `BeaconState` + its working bundle; `view()` rolls a fresh fork off
    /// the bundle like production `apply_block_view` (not reusable here: it
    /// asserts a non-empty validator set). Cross-view persistence needs
    /// `commit` + `state_id` writeback.
    struct TestState {
        bs: BeaconState,
        state_id: StateId,
    }

    impl TestState {
        fn view(&mut self) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
            let sid = self.state_id;
            let bs = &mut self.bs;
            let view = StateWriterView::new(
                &bs.immutable,
                bs.balances.roll_from(sid.balances_idx),
                bs.pending.roll_from(sid.pending_idx),
                bs.previous_participation.roll_from(sid.previous_participation_idx),
                bs.current_participation.roll_from(sid.current_participation_idx),
                bs.inactivity.roll_from(sid.inactivity_idx),
                bs.slot_states.roll_from(sid.slot_idx),
                bs.validators.roll_from(sid.validators_idx),
            );
            (view, &mut bs.epoch, &mut bs.longtail)
        }
    }

    fn fresh_state() -> TestState {
        let validators = ValidatorsGroup::new(FinalizedValidators::with_validators(&[]));
        let cap = validators.base().capacity();
        let n = validators.base().validator_count();
        // Sibling lists stay lockstep with the registry: n zero entries.
        let zero_flags = vec![0u8; n];
        let zero_scores = vec![0u8; n * 8];
        let mut bs = BeaconState {
            immutable: Immutable::default(),
            validators,
            balances: BalancesGroup::new(cap, n, &[]).unwrap(),
            pending: PendingGroup::new(PendingQueues::default()),
            previous_participation: PreviousParticipationGroup::new(cap, n, &zero_flags).unwrap(),
            current_participation: CurrentParticipationGroup::new(cap, n, &zero_flags).unwrap(),
            inactivity: InactivityScoresGroup::new(cap, n, &zero_scores).unwrap(),
            // Slot tier anchored at the empty base's slot (0).
            slot_states: SlotStateGroup::new(SlotStateFinalized::default()),
            epoch: EpochGroup::new(EpochStateFinalized::default()),
            longtail: LongtailGroup::new(LongtailState::default()),
        };
        let state_id = bs.roll_fresh();
        TestState { bs, state_id }
    }

    /// EF `sanity_blocks` doesn't exercise the eth1 majority threshold
    /// directly (its blocks vote at most a couple of times). Cover it here.
    #[test]
    fn eth1_data_vote_majority() {
        let mut st = fresh_state();
        let (mut view, _, _) = st.view();
        view.slot.state_mut().slot = 32;

        // Build a body with eth1_data at [96..168).
        let mut body = vec![0u8; 396];
        let deposit_root = [0xAA; 32];
        body[96..128].copy_from_slice(&deposit_root);
        body[128..136].copy_from_slice(&42u64.to_le_bytes());
        body[136..168].copy_from_slice(&[0xBB; 32]);

        // slots_per_eth1_voting_period = 64 * 32 = 2048; need > 1024 votes.
        process_eth1_data(&mut view.slot, &body);
        assert_eq!(view.slot.state().eth1_votes.len(), 1);
        assert_ne!(view.slot.state().eth1_data.deposit_root, deposit_root);

        for _ in 0..1024 {
            view.slot.state_mut().eth1_votes.push(common::Eth1Data {
                deposit_root,
                deposit_count: 42,
                block_hash: [0xBB; 32],
            });
        }
        process_eth1_data(&mut view.slot, &body);
        assert_eq!(view.slot.state().eth1_data.deposit_root, deposit_root);
    }

    /// Build a single-deposit body element (1240 B) with a zero-subtree proof
    /// for leaf index 0 (siblings = zh[0..33]). Returns (deposit_bytes,
    /// expected_root) where `expected_root` is what
    /// `state.eth1_data.deposit_root` must be for the proof to verify.
    fn build_deposit_at_index0(dd_bytes: &[u8; 184]) -> (Vec<u8>, B256) {
        let depth = (DEPOSIT_CONTRACT_TREE_DEPTH as u32) + 1;
        let mut bytes = vec![0u8; DEPOSIT_SIZE];
        for i in 0..depth as usize {
            bytes[i * 32..(i + 1) * 32].copy_from_slice(&ssz_hash::ZERO_HASHES[i]);
        }
        bytes[1056..1240].copy_from_slice(dd_bytes);

        // Expected root: start from the deposit-data leaf, climb the all-zero
        // siblings on the right.
        let leaf = ssz_hash::hash_tree_root_deposit_data(dd_bytes);
        let mut value = leaf;
        for i in 0..depth as usize {
            let sib = ssz_hash::ZERO_HASHES[i];
            // index=0 → always left, sibling on the right.
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&value);
            buf[32..].copy_from_slice(&sib);
            value = ssz_hash::sha256(&buf);
        }
        (bytes, value)
    }

    fn deposit_into(view: &mut StateWriterView, deposit: &[u8]) -> Result<()> {
        process_deposits(view, deposit)
    }

    fn make_dd() -> [u8; 184] {
        let mut dd = [0u8; 184];
        dd[0] = 0xAB;
        dd[48] = 0x01;
        dd[80..88].copy_from_slice(&32_000_000_000u64.to_le_bytes());
        dd[88] = 0xCD;
        dd
    }

    #[test]
    fn process_deposits_accepts_valid_proof() {
        let dd = make_dd();
        let (deposit, root) = build_deposit_at_index0(&dd);

        let mut st = fresh_state();
        let (mut view, _, _) = st.view();
        view.slot.state_mut().eth1_data =
            common::Eth1Data { deposit_root: root, ..Default::default() };
        // eth1_deposit_index defaults to 0.

        deposit_into(&mut view, &deposit).expect("valid proof must accept");
        assert_eq!(view.slot.state().eth1_deposit_index, 1);
    }

    #[test]
    fn process_deposits_rejects_bad_proof() {
        let dd = make_dd();
        let (mut deposit, root) = build_deposit_at_index0(&dd);

        deposit[0] ^= 0x01;

        let mut st = fresh_state();
        let (mut view, _, _) = st.view();
        view.slot.state_mut().eth1_data =
            common::Eth1Data { deposit_root: root, ..Default::default() };

        let err = deposit_into(&mut view, &deposit).unwrap_err();
        assert!(err.is_fatal());
        assert!(matches!(err, Error::InvalidDepositProof { index: 0 }));
        assert_eq!(view.slot.state().eth1_deposit_index, 0, "index must not advance on rejection");
    }

    #[test]
    fn process_deposits_rejects_wrong_root() {
        let dd = make_dd();
        let (deposit, mut root) = build_deposit_at_index0(&dd);
        root[0] ^= 0xFF;

        let mut st = fresh_state();
        let (mut view, _, _) = st.view();
        view.slot.state_mut().eth1_data =
            common::Eth1Data { deposit_root: root, ..Default::default() };

        let err = deposit_into(&mut view, &deposit).unwrap_err();
        assert!(matches!(err, Error::InvalidDepositProof { .. }));
    }

    #[test]
    fn process_deposits_rejects_wrong_index() {
        let dd = make_dd();
        let (deposit, root) = build_deposit_at_index0(&dd);

        let mut st = fresh_state();
        let (mut view, _, _) = st.view();
        view.slot.state_mut().eth1_data =
            common::Eth1Data { deposit_root: root, ..Default::default() };
        // Proof was built for index 0; claim index 1 instead → must fail.
        view.slot.state_mut().eth1_deposit_index += 1;

        let err = deposit_into(&mut view, &deposit).unwrap_err();
        assert!(matches!(err, Error::InvalidDepositProof { index: 1 }));
    }
}
