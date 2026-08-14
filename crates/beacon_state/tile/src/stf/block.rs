use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BlockBodyError, BodyFork, BodyOffsets, Epoch, EpochGroup, EpochId,
    EpochView, EpochWriteView, Eth1Data, Eth1WriteView, Immutable, LongtailGroup, LongtailId,
    LongtailView, SLOTS_PER_EPOCH, Slot, SlotStateView, SlotStateWriteView, SpecConfig, StateId,
    StateReadView, StateWriterView, ValidatorsView,
};
use silver_common::ssz_view::{
    BEACON_BLOCK_BODY_FIXED, Eth1DataView, SIGNED_BEACON_BLOCK_MIN, SignedBeaconBlockView,
};

use crate::{
    bls::{self, SigBatch},
    error::{BlockError, Error, Result},
    merkle,
    ssz_hash::{self, hash_tree_root_block_header},
    stf::{
        AttestationVote, EPOCHS_PER_ETH1_VOTING_PERIOD, ShufflingRef, StfScratch,
        collect_sigs_attestations, collect_sigs_attester_slashings,
        collect_sigs_bls_to_execution_changes, collect_sigs_execution_payload_bid,
        collect_sigs_proposer_slashings, collect_sigs_sync_aggregate, collect_sigs_voluntary_exits,
        gloas::collect_sigs_payload_attestations, process_attestations, process_attester_slashings,
        process_bls_to_execution_changes, process_deposits, process_epoch,
        process_execution_payload, process_execution_payload_bid, process_execution_requests,
        process_parent_execution_payload, process_payload_attestations, process_proposer_slashings,
        process_sync_aggregate, process_voluntary_exits, process_withdrawals_fulu,
        process_withdrawals_gloas, upgrade_to_gloas,
    },
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
    header: &BeaconBlockHeader,
    shuffling: Option<&ShufflingRef<'_>>,
    scratch: &mut StfScratch,
    attestation_votes: &mut Vec<AttestationVote>,
    slashed_sink: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> Result<(Option<EpochId>, Option<LongtailId>)> {
    let block_slot = header.slot;
    let proposer_index = header.proposer_index as u32;
    let block_state_root = header.state_root;
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
        process_slots(cfg, view, epoch, longtail, parent, block_slot, scratch)
    } else {
        (parent.epoch_idx, parent.longtail_idx)
    };

    let body = if block_bytes.len() > SIGNED_BEACON_BLOCK_MIN {
        SignedBeaconBlockView::body(block_bytes)
    } else {
        &[]
    };
    // Resolve the boundary tiers AFTER process_slots (it may have rolled
    // them). process_block can't change them, so the hash reuses these.
    let epoch_view = epoch.view_opt(epoch_idx);
    let longtail_view = longtail.view_opt(longtail_idx);
    process_block_header(
        view,
        &epoch_view,
        block_slot,
        header.proposer_index,
        header.parent_root,
        header.body_root,
    )
    .map_err(wrap)?;
    process_block_body(
        cfg,
        view,
        &epoch_view,
        &longtail_view,
        &mut scratch.active,
        sig_batch,
        body,
        block_state_root,
        block_slot,
        proposer_index,
        shuffling,
        attestation_votes,
        slashed_sink,
    )?;

    let rv = view.read(epoch_view, longtail_view);
    let actual = ssz_hash::hash_tree_root_state(&rv, &mut scratch.state_hash);
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
pub fn apply_signed_block_debug(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochGroup,
    longtail: &mut LongtailGroup,
    parent: StateId,
    block_bytes: &[u8],
) -> Result<(Option<EpochId>, Option<LongtailId>)> {
    if block_bytes.len() < SIGNED_BEACON_BLOCK_MIN {
        return Err(Error::invalid_block([0; 32], BlockError::TooShort {
            len: block_bytes.len(),
            min: SIGNED_BEACON_BLOCK_MIN,
        }));
    }
    let (head_slot, head_block_header_slot) =
        (view.slot.state().slot, view.slot.state().latest_block_header.slot);
    let block_slot = SignedBeaconBlockView::slot(block_bytes);
    let proposer_index = SignedBeaconBlockView::proposer_index(block_bytes) as u32;
    let parent_root: B256 = *SignedBeaconBlockView::parent_root(block_bytes);
    let state_root: B256 = *SignedBeaconBlockView::state_root(block_bytes);
    let body = SignedBeaconBlockView::body(block_bytes);
    let wrap = |kind: BlockError| Error::invalid_block(state_root, kind);

    if block_slot <= head_block_header_slot {
        return Err(wrap(BlockError::SlotNotAfterHeader {
            slot: block_slot,
            latest: head_block_header_slot,
        }));
    }

    let mut scratch = StfScratch::new(0);

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
    let (epoch_idx, longtail_idx) = if block_slot > head_slot {
        process_slots(cfg, view, epoch, longtail, parent, block_slot, &mut scratch)
    } else {
        (parent.epoch_idx, parent.longtail_idx)
    };
    // Resolve the boundary tiers AFTER process_slots (it may have rolled
    // them). process_block can't change them, so the hash reuses these.
    let epoch_view = epoch.view_opt(epoch_idx);
    let longtail_view = longtail.view_opt(longtail_idx);

    // body_root + proposer-sig read the block's fork from the post-`process_slots`
    // epoch view, so a block at the fork boundary uses the upgraded fork (Gloas
    // body layout / signing version), not the parent's.
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    let body_root =
        ssz_hash::hash_tree_root_body(body, epoch_view.is_gloas(view.imm.gloas_fork_version));
    if !verify_block_sig(
        view.imm,
        &epoch_view,
        &view.validators.reader(),
        block_bytes,
        &body_root,
        block_epoch,
        proposer_index,
    ) {
        return Err(Error::InvalidBlockSig);
    }

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
    let mut votes_sink: Vec<AttestationVote> = Vec::new();
    let mut slashed_sink: Vec<u32> = Vec::new();
    let mut sig_batch = SigBatch::new();
    process_block_body(
        cfg,
        view,
        &epoch_view,
        &longtail_view,
        &mut scratch.active,
        &mut sig_batch,
        body,
        state_root,
        block_slot,
        proposer_index,
        Some(&sref),
        &mut votes_sink,
        &mut slashed_sink,
    )?;

    let rv = view.read(epoch_view, longtail_view);
    let actual = ssz_hash::hash_tree_root_state(&rv, &mut scratch.state_hash);
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
    epoch: &EpochView,
    validators: &ValidatorsView,
    block_bytes: &[u8],
    body_root: &B256,
    block_epoch: Epoch,
    proposer_index: u32,
) -> bool {
    let fork_version = epoch.fork_version_at(block_epoch);
    let pk = validators.pubkey_decompressed(proposer_index as usize);
    bls::verify_block_signature(
        block_bytes,
        pk,
        body_root,
        fork_version,
        &imm.genesis_validators_root,
    )
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
#[timed]
pub fn process_slots(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochGroup,
    longtail: &mut LongtailGroup,
    parent: StateId,
    target_slot: Slot,
    scratch: &mut StfScratch,
) -> (Option<EpochId>, Option<LongtailId>) {
    let (epoch_idx, mut longtail_idx) = (parent.epoch_idx, parent.longtail_idx);
    // Pre-boundary slots: epoch tier read straight off the group.
    while view.slot.state().slot < target_slot {
        let epoch_view = epoch.view_opt(epoch_idx);
        process_slot(view, &epoch_view, longtail, longtail_idx, &mut scratch.state_hash);
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
    let mut epoch_w = epoch.roll_inheriting(epoch_idx);

    // Boundary-onward slots: epoch tier read through the held writer.
    loop {
        process_epoch(cfg, view, &mut epoch_w, longtail, &mut longtail_idx, scratch);
        view.slot.advance_slot();

        maybe_upgrade_to_gloas(cfg, view, &mut epoch_w);
        while view.slot.state().slot < target_slot {
            process_slot(view, &epoch_w.reader(), longtail, longtail_idx, &mut scratch.state_hash);
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

fn maybe_upgrade_to_gloas(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: &mut EpochWriteView,
) {
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    if cfg.is_gloas_activation_epoch(current_epoch) &&
        !epoch.reader().is_gloas(view.imm.gloas_fork_version)
    {
        upgrade_to_gloas(view, epoch);
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

    if epoch.is_gloas(view.imm.gloas_fork_version) {
        view.slot.unset_next_payload_availability();
    }
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

    view.slot.state_mut().latest_block_header = BeaconBlockHeader {
        slot: block_slot,
        proposer_index,
        parent_root,
        state_root: [0u8; 32],
        body_root,
    };

    Ok(())
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
    attestation_votes: &mut Vec<AttestationVote>,
    slashed_sink: &mut Vec<u32>,
) -> Result<()> {
    let wrap = |kind: BlockError| Error::invalid_block(state_root, kind);
    let is_gloas = epoch.is_gloas(view.imm.gloas_fork_version);
    let fork = if is_gloas { BodyFork::Gloas } else { BodyFork::Fulu };
    let offsets = BodyOffsets::new(body, fork).ok_or_else(|| {
        wrap(BlockBodyError::BodyTooShort { len: body.len(), min: BEACON_BLOCK_BODY_FIXED }.into())
    })?;

    let count = view.validators.count();
    if (proposer_index as usize) >= count {
        return Err(wrap(BlockError::ProposerOutOfRange { idx: proposer_index as u64, count }));
    }
    offsets.validate().map_err(|e| wrap(e.into()))?;

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

    apply_block_body(
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
        slashed_sink,
        is_gloas,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_block_body(
    cfg: &SpecConfig,
    view: &mut StateWriterView,
    epoch: EpochView,
    longtail: LongtailView,
    active_scratch: &mut Vec<u32>,
    offsets: &BodyOffsets<'_>,
    block_slot: Slot,
    proposer_index: u32,
    shuffling: Option<&ShufflingRef<'_>>,
    attestation_votes: &mut Vec<AttestationVote>,
    slashed_sink: &mut Vec<u32>,
    is_gloas: bool,
) -> Result<()> {
    let body = offsets.body();
    let payload = offsets.payload();

    if is_gloas {
        process_parent_execution_payload(&mut *view, &epoch, cfg, body)?;
        process_withdrawals_gloas(&mut *view);
        if let Some(bid) = offsets.signed_bid() {
            process_execution_payload_bid(&mut *view, &epoch, cfg, bid)?;
        }
    } else {
        process_withdrawals_fulu(&mut *view, payload)?;
        process_execution_payload(&mut *view, cfg, payload, block_slot)?;
    }

    process_randao(&mut view.slot, body);
    process_eth1_data(&mut view.slot, &mut view.eth1, body);

    if let Some(section) = offsets.proposer_slashings() {
        process_proposer_slashings(&mut *view, epoch, cfg, section)?;
    }
    if let Some(section) = offsets.attester_slashings() {
        process_attester_slashings(&mut *view, epoch, cfg, section, active_scratch, slashed_sink)?;
    }
    if let Some(section) = offsets.attestations() {
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

    if !is_gloas && let Some(section) = offsets.deposits() {
        process_deposits(&mut *view, section)?;
    }

    if let Some(section) = offsets.voluntary_exits() {
        process_voluntary_exits(&mut *view, cfg, section)?;
    }
    if let Some(section) = offsets.bls_changes() {
        process_bls_to_execution_changes(&mut view.validators, section)?;
    }

    if is_gloas {
        if let Some(section) = offsets.payload_attestations() {
            process_payload_attestations(&*view, section)?;
        }
    } else {
        process_execution_requests(&mut *view, cfg, offsets.execution_requests());
    }

    process_sync_aggregate(&mut *view, longtail, offsets.sync_aggregate(), proposer_index)?;

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
    let body = offsets.body();
    let imm = rv.imm;
    let validators = rv.validators;

    let proposer_pubkey = validators.pubkey_decompressed(proposer_index as usize);
    collect_sigs_randao(imm, &rv.epoch, body, block_slot, proposer_pubkey, sig_batch);

    if let Some(section) = offsets.proposer_slashings() {
        collect_sigs_proposer_slashings(imm, &rv.epoch, &validators, section, sig_batch)?;
    }
    if let Some(section) = offsets.attester_slashings() {
        collect_sigs_attester_slashings(
            imm,
            &rv.epoch,
            &validators,
            section,
            active_scratch,
            sig_batch,
        )?;
    }
    if let Some(section) = offsets.attestations() {
        collect_sigs_attestations(
            imm,
            &rv.epoch,
            &validators,
            section,
            block_slot,
            shuffling,
            sig_batch,
        )?;
    }

    if let Some(section) = offsets.voluntary_exits() {
        collect_sigs_voluntary_exits(imm, &validators, section, sig_batch);
    }
    if let Some(section) = offsets.bls_changes() {
        collect_sigs_bls_to_execution_changes(imm, &validators, section, sig_batch)?;
    }

    if rv.is_gloas() {
        let current_epoch = block_slot / SLOTS_PER_EPOCH;
        if let Some(bid) = offsets.signed_bid() {
            collect_sigs_execution_payload_bid(
                imm,
                &rv.epoch,
                &rv.builders,
                bid,
                current_epoch,
                sig_batch,
            )?;
        }
        if let Some(section) = offsets.payload_attestations() {
            collect_sigs_payload_attestations(
                imm,
                &validators,
                &rv.epoch,
                block_slot,
                section,
                sig_batch,
            )?;
        }
    }

    collect_sigs_sync_aggregate(
        rv,
        offsets.sync_aggregate(),
        block_slot,
        active_scratch,
        sig_batch,
    );
    Ok(())
}

#[timed]
pub fn collect_sigs_randao(
    imm: &Immutable,
    epoch: &EpochView,
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
    let fork_version = epoch.fork_version_at(block_epoch);
    let mut epoch_chunk = [0u8; 32];
    epoch_chunk[..8].copy_from_slice(&block_epoch.to_le_bytes());
    let domain =
        bls::compute_domain(bls::DOMAIN_RANDAO, fork_version, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&epoch_chunk, &domain);
    sig_batch.push_one(proposer_pubkey, reveal, signing_root);
}

/// Pass 2 — XOR reveal hash into the mix accumulator. BLS already verified
/// in pass 1; if it failed, we never reach here.
fn process_randao(slot: &mut SlotStateWriteView, body: &[u8]) {
    let reveal: &[u8; 96] = body[0..96].try_into().unwrap();
    let reveal_hash = merkle::sha256(reveal);
    let mix = &mut slot.state_mut().randao_mix_current;
    for (b, &r) in mix.iter_mut().zip(reveal_hash.iter()) {
        *b ^= r;
    }
}

fn process_eth1_data(slot: &mut SlotStateWriteView, eth1: &mut Eth1WriteView, body: &[u8]) {
    // BeaconBlockBody.eth1_data at body[96..168].
    let data: &[u8; 72] = body[96..168].try_into().unwrap();
    let deposit_root: B256 = *Eth1DataView::deposit_root(data);
    let deposit_count = Eth1DataView::deposit_count(data);
    let block_hash: B256 = *Eth1DataView::block_hash(data);

    let vote = Eth1Data { deposit_root, deposit_count, block_hash };
    // One vote per slot, reset each voting period (`process_eth1_data_reset`);
    // `push` enforces the spec cap.
    eth1.push(vote);

    let count = eth1
        .iter()
        .filter(|v| {
            v.deposit_root == deposit_root &&
                v.deposit_count == deposit_count &&
                v.block_hash == block_hash
        })
        .count();
    let slots_per_eth1_voting_period = EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH;
    if count * 2 > slots_per_eth1_voting_period as usize {
        slot.state_mut().eth1_data = vote;
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{EpochStateFinalized, Eth1Data};

    use super::*;
    use crate::test_state::TestState;

    fn fresh_state() -> TestState {
        // Empty registry; slot tier anchored at the empty base's slot (0).
        TestState::new(EpochStateFinalized::default(), &[])
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
        process_eth1_data(&mut view.slot, &mut view.eth1, &body);
        assert_eq!(view.eth1.len(), 1);
        assert_ne!(view.slot.state().eth1_data.deposit_root, deposit_root);

        for _ in 0..1024 {
            view.eth1.push(Eth1Data { deposit_root, deposit_count: 42, block_hash: [0xBB; 32] });
        }
        process_eth1_data(&mut view.slot, &mut view.eth1, &body);
        assert_eq!(view.slot.state().eth1_data.deposit_root, deposit_root);
    }
}
