use blst::min_pk::PublicKey;
use flux_profiler::timed;
#[cfg(feature = "ef_tests")]
use silver_beacon_state_data::ValidatorsView;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BodyFork, BodyOffsets, Epoch, EpochView, EpochWriteView, Eth1Data,
    Eth1WriteView, ForkWriter, Immutable, LongtailGroup, LongtailId, SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT, Slot, SlotStateView, SlotStateWriteView, SpecConfig, StateReadView,
    StateWriterView,
};
use silver_common::ssz_view::{BeaconBlockBodyGloasView, Eth1DataView};
#[cfg(feature = "ef_tests")]
use silver_common::ssz_view::{SIGNED_BEACON_BLOCK_MIN, SignedBeaconBlockView};

use crate::{
    bls::{self, SigBatch},
    error::{BlockError, Error, Result},
    merkle,
    ssz_hash::{self, PayloadRoots, hash_tree_root_block_header},
    stf::{
        BlockVotes, EPOCHS_PER_ETH1_VOTING_PERIOD, ShufflingRef, StfScratch,
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

#[derive(Clone, Copy)]
pub enum BlockFork {
    Fulu { payload_roots: PayloadRoots },
    Gloas,
}

impl BlockFork {
    pub fn is_gloas(self) -> bool {
        matches!(self, Self::Gloas)
    }

    fn body_fork(self) -> BodyFork {
        match self {
            Self::Fulu { .. } => BodyFork::Fulu,
            Self::Gloas => BodyFork::Gloas,
        }
    }
}

pub struct BlockInput<'a> {
    pub header: &'a BeaconBlockHeader,
    pub body: &'a [u8],
    pub fork: BlockFork,
    pub shuffling: &'a ShufflingRef<'a>,
}

impl<'a> BlockInput<'a> {
    pub fn proposer_index(&self) -> u32 {
        self.header.proposer_index as u32
    }

    pub fn invalid(&self, kind: BlockError) -> Error {
        Error::invalid_block(self.header.state_root, kind)
    }

    fn offsets(&self) -> Result<BodyOffsets<'a>> {
        BodyOffsets::validated(self.body, self.fork.body_fork()).map_err(|e| self.invalid(e.into()))
    }
}

pub fn hash_body(offsets: &BodyOffsets<'_>) -> (B256, BlockFork) {
    match offsets.fork() {
        BodyFork::Gloas => {
            (BeaconBlockBodyGloasView::hash_tree_root(offsets.body()), BlockFork::Gloas)
        }
        BodyFork::Fulu => {
            let (root, payload_roots) = ssz_hash::hash_tree_root_body_fulu_with_roots(offsets);
            (root, BlockFork::Fulu { payload_roots })
        }
    }
}

#[timed]
pub fn apply_block(
    cfg: &SpecConfig,
    fork: &mut ForkWriter,
    input: &BlockInput<'_>,
    scratch: &mut StfScratch,
    sig_batch: &mut SigBatch,
    out: &mut BlockVotes,
) -> Result<()> {
    let block_slot = input.header.slot;
    check_slot_after_header(&fork.view.slot.reader(), block_slot).map_err(|e| input.invalid(e))?;
    let head_slot = fork.view.slot.state().slot;
    check_proposer_lookahead(&fork.epoch_view(), block_slot, head_slot, input.proposer_index())
        .map_err(|e| input.invalid(e))?;

    if block_slot > head_slot {
        process_slots(cfg, fork, block_slot, scratch);
    }

    // process_slots may have rolled the epoch tier.
    let epoch_view = fork.epoch.view_opt(fork.epoch_idx);
    process_block_header(&mut fork.view, &epoch_view, input.header)
        .map_err(|e| input.invalid(e))?;
    process_block_body(cfg, fork, input, scratch, sig_batch, out)?;

    let actual = ssz_hash::hash_tree_root_state(&fork.read());
    let expected = input.header.state_root;
    if actual != expected {
        return Err(input.invalid(BlockError::PostStateRootMismatch { expected, got: actual }));
    }
    Ok(())
}

/// Full-block apply for the EF spec suites: verifies the proposer signature
/// and builds the shuffling itself. Production path is `apply_block`.
#[cfg(feature = "ef_tests")]
#[timed]
pub fn apply_signed_block_debug(
    cfg: &SpecConfig,
    fork: &mut ForkWriter,
    block_bytes: &[u8],
) -> Result<()> {
    if block_bytes.len() < SIGNED_BEACON_BLOCK_MIN {
        return Err(Error::invalid_block([0; 32], BlockError::TooShort {
            len: block_bytes.len(),
            min: SIGNED_BEACON_BLOCK_MIN,
        }));
    }
    let (head_slot, head_block_header_slot) =
        (fork.view.slot.state().slot, fork.view.slot.state().latest_block_header.slot);
    let block_slot = SignedBeaconBlockView::slot(block_bytes);
    let proposer_index = SignedBeaconBlockView::proposer_index(block_bytes) as u32;
    let parent_root: B256 = *SignedBeaconBlockView::parent_root(block_bytes);
    let state_root: B256 = *SignedBeaconBlockView::state_root(block_bytes);
    let body = SignedBeaconBlockView::body(block_bytes);
    let wrap = |kind: BlockError| Error::invalid_block(state_root, kind);
    let mut sig_batch = SigBatch::new();
    let mut votes = BlockVotes::default();

    if block_slot <= head_block_header_slot {
        return Err(wrap(BlockError::SlotNotAfterHeader {
            slot: block_slot,
            latest: head_block_header_slot,
        }));
    }

    let mut scratch = StfScratch::new(0);

    check_proposer_lookahead(&fork.epoch_view(), block_slot, head_slot, proposer_index)
        .map_err(wrap)?;

    let count = fork.view.validators.count();
    if proposer_index as usize >= count {
        return Err(wrap(BlockError::ProposerOutOfRange { idx: proposer_index as u64, count }));
    }
    if block_slot > head_slot {
        process_slots(cfg, fork, block_slot, &mut scratch);
    }
    // Resolve the boundary tiers AFTER process_slots (it may have rolled
    // them). process_block can't change them, so the hash reuses these.
    let ForkWriter { view, epoch, longtail, epoch_idx, longtail_idx, .. } = fork;
    let epoch_view = epoch.view_opt(*epoch_idx);
    let longtail_view = longtail.view_opt(*longtail_idx);

    // body_root + proposer-sig read the block's fork from the post-`process_slots`
    // epoch view, so a block at the fork boundary uses the upgraded fork (Gloas
    // body layout / signing version), not the parent's.
    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    let body_fork = if epoch_view.is_gloas(view.imm.gloas_fork_version) {
        BodyFork::Gloas
    } else {
        BodyFork::Fulu
    };
    let offsets = BodyOffsets::validated(body, body_fork).map_err(|e| wrap(e.into()))?;
    let (body_root, block_fork) = hash_body(&offsets);
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

    let header = BeaconBlockHeader {
        slot: block_slot,
        proposer_index: proposer_index as u64,
        parent_root,
        state_root,
        body_root,
    };
    process_block_header(view, &epoch_view, &header).map_err(wrap)?;

    let mut curr = Vec::new();
    let mut prev = Vec::new();
    let current_epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    let rv = view.read(epoch_view, longtail_view);
    let sref = ShufflingRef::build(&rv, current_epoch, &mut curr, &mut prev);
    let input = BlockInput { header: &header, body, fork: block_fork, shuffling: &sref };
    process_block_body(cfg, fork, &input, &mut scratch, &mut sig_batch, &mut votes)?;

    let actual = ssz_hash::hash_tree_root_state(&fork.read());
    if actual != state_root {
        return Err(wrap(BlockError::PostStateRootMismatch { expected: state_root, got: actual }));
    }
    Ok(())
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

#[cfg(feature = "ef_tests")]
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
    let domain = bls::compute_domain(
        bls::DOMAIN_BEACON_PROPOSER,
        fork_version,
        &imm.genesis_validators_root,
    );
    bls::verify_block_signature(block_bytes, pk, body_root, &domain)
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
    fork: &mut ForkWriter,
    target_slot: Slot,
    scratch: &mut StfScratch,
) {
    let ForkWriter { view, epoch, longtail, epoch_idx, longtail_idx, .. } = fork;
    // Pre-boundary slots: epoch tier read straight off the group.
    while view.slot.state().slot < target_slot {
        let epoch_view = epoch.view_opt(*epoch_idx);
        process_slot(view, &epoch_view, longtail, *longtail_idx);
        if (view.slot.state().slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
            break;
        }
        view.slot.advance_slot();
    }
    if view.slot.state().slot >= target_slot {
        return;
    }

    // First boundary: roll this fork's private epoch entry, derived from the
    // inherited one (fresh off the base when no ancestor crossed a boundary).
    let mut epoch_w = epoch.roll_inheriting(*epoch_idx);

    // Boundary-onward slots: epoch tier read through the held writer.
    loop {
        process_epoch(cfg, view, &mut epoch_w, longtail, longtail_idx, scratch);
        view.slot.advance_slot();

        maybe_upgrade_to_gloas(cfg, view, &mut epoch_w);
        while view.slot.state().slot < target_slot {
            process_slot(view, &epoch_w.reader(), longtail, *longtail_idx);
            if (view.slot.state().slot + 1).is_multiple_of(SLOTS_PER_EPOCH) {
                break;
            }
            view.slot.advance_slot();
        }
        if view.slot.state().slot >= target_slot {
            *epoch_idx = Some(epoch_w.commit());
            return;
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
        tracing::info!(epoch = current_epoch, "state upgraded to gloas");
        upgrade_to_gloas(view, epoch);
    }
}

pub fn process_slot(
    view: &mut StateWriterView,
    epoch: &EpochView,
    longtail: &LongtailGroup,
    longtail_idx: Option<LongtailId>,
) {
    // Longtail resolved fresh each slot: a boundary `process_epoch` may roll
    // the fork a new entry mid-`process_slots` (the caller threads the
    // updated id). The epoch view comes from the caller (group resolution
    // before the first boundary, the held boundary writer's reader after).
    let rv = view.read(*epoch, longtail.view_opt(longtail_idx));
    let prev_state_root = ssz_hash::hash_tree_root_state(&rv);
    let bucket = (view.slot.state().slot % SLOTS_PER_HISTORICAL_ROOT as u64) as u32;
    view.state_roots.set(bucket, prev_state_root);

    view.slot.fill_latest_block_header_state_root(prev_state_root);
    let header = view.slot.state().latest_block_header;
    view.block_roots.set(bucket, hash_tree_root_block_header(&header));

    if epoch.is_gloas(view.imm.gloas_fork_version) {
        view.slot.unset_next_payload_availability();
    }
}

/// `header.state_root` is ignored: `latest_block_header` stores it zeroed.
pub fn process_block_header(
    view: &mut StateWriterView,
    epoch: &EpochView,
    header: &BeaconBlockHeader,
) -> Result<(), BlockError> {
    let BeaconBlockHeader { slot: block_slot, proposer_index, parent_root, body_root, .. } =
        *header;
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
pub fn process_block_body(
    cfg: &SpecConfig,
    fork: &mut ForkWriter,
    input: &BlockInput<'_>,
    scratch: &mut StfScratch,
    sig_batch: &mut SigBatch,
    out: &mut BlockVotes,
) -> Result<()> {
    debug_assert_eq!(
        input.fork.is_gloas(),
        fork.epoch_view().is_gloas(fork.view.imm.gloas_fork_version),
        "body parsed for one fork, state on another",
    );
    let offsets = input.offsets()?;

    let proposer_index = input.proposer_index();
    let count = fork.view.validators.count();
    if (proposer_index as usize) >= count {
        let idx = proposer_index as u64;
        return Err(input.invalid(BlockError::ProposerOutOfRange { idx, count }));
    }

    sig_batch.clear();
    // Pass 1 is read-only: hand it the read-only sibling over the same fork.
    collect_sigs_block_body(&fork.read(), &mut scratch.active, sig_batch, &offsets, input)?;
    if !sig_batch.verify_all() {
        return Err(Error::SigBatchFailed);
    }

    apply_block_body(cfg, fork, &offsets, input, scratch, out)
}

fn apply_block_body(
    cfg: &SpecConfig,
    fork: &mut ForkWriter,
    offsets: &BodyOffsets<'_>,
    input: &BlockInput<'_>,
    scratch: &mut StfScratch,
    out: &mut BlockVotes,
) -> Result<()> {
    let ForkWriter { view, epoch, longtail, epoch_idx, longtail_idx, .. } = fork;
    let epoch = epoch.view_opt(*epoch_idx);
    let longtail = longtail.view_opt(*longtail_idx);
    let is_gloas = input.fork.is_gloas();
    let block_slot = input.header.slot;
    let proposer_index = input.proposer_index();
    let body = offsets.body();

    let parent_slot = match input.fork {
        BlockFork::Gloas => {
            process_parent_execution_payload(&mut *view, &epoch, cfg, body)?;
            process_withdrawals_gloas(&mut *view);
            match offsets.signed_bid() {
                Some(bid) => Some(process_execution_payload_bid(&mut *view, &epoch, cfg, bid)?),
                None => None,
            }
        }
        BlockFork::Fulu { payload_roots } => {
            let payload = offsets.payload();
            process_withdrawals_fulu(&mut *view, payload)?;
            process_execution_payload(&mut *view, cfg, payload, block_slot, payload_roots)?;
            None
        }
    };

    process_randao(view, body, block_slot / SLOTS_PER_EPOCH);
    process_eth1_data(&mut view.slot, &mut view.eth1, body);

    if let Some(section) = offsets.proposer_slashings() {
        process_proposer_slashings(&mut *view, epoch, cfg, section)?;
    }
    if let Some(section) = offsets.attester_slashings() {
        process_attester_slashings(&mut *view, epoch, cfg, section, &mut out.slashed)?;
    }
    if let Some(section) = offsets.attestations() {
        process_attestations(
            &mut *view,
            epoch,
            section,
            block_slot,
            parent_slot,
            proposer_index,
            input.shuffling,
            &mut out.votes,
            scratch,
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
fn collect_sigs_block_body(
    rv: &StateReadView,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
    offsets: &BodyOffsets<'_>,
    input: &BlockInput<'_>,
) -> Result<()> {
    let block_slot = input.header.slot;
    let proposer_index = input.proposer_index();
    let shuffling = input.shuffling;
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

    if input.fork.is_gloas() {
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

/// Pass 2 — XOR the reveal's hash into the current epoch's mix. BLS already
/// verified in pass 1; if it failed, we never reach here.
fn process_randao(view: &mut StateWriterView, body: &[u8], block_epoch: Epoch) {
    let reveal: &[u8; 96] = body[0..96].try_into().unwrap();
    view.randao_mixes.mix_in_reveal(block_epoch, &merkle::sha256(reveal));
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
