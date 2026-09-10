use flux::spine::SpineProducers;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BodyFork, BodyOffsets, Checkpoint, Epoch, SLOTS_PER_EPOCH, Slot,
    StateId, StateReadView,
};
use silver_common::{
    BeaconStateEvent, BlockSource, BlockStage, EngineFcuReq, EngineNewPayloadReq, EngineReq,
    SyncNeed, SyncUpdate, TCacheRead, TRandomAccess, hex32,
    ssz_view::{self, BeaconBlockBodyFuluView, BeaconBlockBodyGloasView, SignedBeaconBlockView},
};

use super::{
    BeaconStateTile, Feedback, MAXIMUM_GOSSIP_CLOCK_DISPARITY, ParsedBlock, Producers,
    gossip::EnvelopeCheck, held_blocks::WaitingBlock,
};
use crate::{
    bls,
    error::PrecheckError,
    fork_choice::{BlockImport, ExecutionStatus, ForkChoiceNode, PayloadStatus},
    ssz_hash, stf,
};

struct AppliedBlock {
    id: StateId,
    justified: Checkpoint,
    finalized: Checkpoint,
    unrealized: (Checkpoint, Checkpoint),
    execution_block_hash: B256,
    bid_block_hash: B256,
    votes: stf::BlockVotes,
}

/// A block whose post-state is committed but not yet in fork choice.
pub(super) struct StagedBlock {
    pub(super) parsed: ParsedBlock,
    applied: AppliedBlock,
}

impl StagedBlock {
    pub(super) fn state_id_mut(&mut self) -> &mut StateId {
        &mut self.applied.id
    }

    #[cfg(test)]
    pub(super) fn with_state_id(parsed: ParsedBlock, id: StateId) -> Self {
        let applied = AppliedBlock {
            id,
            justified: Checkpoint::default(),
            finalized: Checkpoint::default(),
            unrealized: Default::default(),
            execution_block_hash: [0u8; 32],
            bid_block_hash: [0u8; 32],
            votes: stf::BlockVotes::default(),
        };
        Self { parsed, applied }
    }
}

impl BeaconStateTile {
    pub fn try_apply_block(&mut self, data: &[u8]) -> Feedback {
        match self.parse_and_verify_block(data, false) {
            Ok(parsed) => self.stage_and_import(parsed, data),
            Err(err) => err.feedback(),
        }
    }

    /// The timer spans the post-publication work too, so it is not the
    /// tick-to-attestable latency.
    #[timed]
    pub(super) fn apply_block(
        &mut self,
        data: &[u8],
        read: TCacheRead,
        source: BlockSource,
        pre_verified: bool,
        producers: &mut Producers,
        mut send_gossip: impl FnMut(&mut Producers),
    ) -> Feedback {
        if let Err(e) = Self::check_block_size(data) {
            tracing::warn!(?source, "{e}");
            return e.feedback();
        }

        let block_slot = SignedBeaconBlockView::slot(data);
        let parsed = match self.parse_and_verify_block(data, pre_verified) {
            Ok(parsed) => {
                if parsed.relay_eligible {
                    send_gossip(producers);
                }
                parsed
            }
            Err(e) => {
                let f = e.feedback();
                if let Feedback::AlreadyKnown(block_root) = f {
                    self.emit_block_received(
                        data,
                        block_root,
                        BlockStage::AlreadyKnown,
                        source,
                        producers,
                    );
                    Self::emit_persist_block(read, source, block_slot, block_root, producers);
                }
                return f;
            }
        };

        let waits_for_columns = self.waits_for_columns(&parsed);
        if waits_for_columns && self.held.staged_len() >= self.pending_bounds.max_dc {
            tracing::warn!(
                block = hex32(&parsed.block_root),
                "too many blocks awaiting data availability; dropped"
            );
            return Feedback::Ignore;
        }

        producers.produce(EngineReq::NewPayload(EngineNewPayloadReq {
            data: read,
            block_root: parsed.block_root,
            slot: block_slot,
            block_source: source,
        }));

        let f = if waits_for_columns {
            match self.stage_block(parsed, data) {
                Ok(staged) => {
                    Feedback::AwaitData(self.held.stage(WaitingBlock { staged, read, source }))
                }
                Err(f) => f,
            }
        } else {
            self.stage_and_import(parsed, data)
        };
        match f {
            Feedback::Accept(Some(block_root)) => {
                self.announce_imported(data, block_root, read, source, producers);
            }
            Feedback::AwaitData(block_root) => {
                self.emit_block_received(
                    data,
                    block_root,
                    BlockStage::AwaitData,
                    source,
                    producers,
                );
            }
            Feedback::Reject(Some(block_root)) => {
                producers.produce(BeaconStateEvent::BlockRejected { block_root, source });
            }
            _ => {}
        }
        tracing::info!(
            ?source,
            head_slot = self.head_state_slot(),
            block_slot,
            wall_slot = self.ticker.current_slot(),
            time_into_slot = ?self.ticker.slot_time_elapsed(),
            "applied block: {:?}",
            f
        );
        f
    }

    /// Everything the rest of the node learns from an import, in the order it
    /// needs it: the stage, the bytes to persist, the FCU, then the next
    /// epoch's shuffling warmed off the new head.
    pub(super) fn announce_imported(
        &mut self,
        data: &[u8],
        block_root: B256,
        read: TCacheRead,
        source: BlockSource,
        producers: &mut Producers,
    ) {
        let block_slot = SignedBeaconBlockView::slot(data);
        self.emit_block_received(data, block_root, BlockStage::Applied, source, producers);
        Self::emit_persist_block(read, source, block_slot, block_root, producers);

        let (head_root, head, safe, fin) = self.fork_choice.fcu_execution_hashes();
        producers.produce(EngineReq::Fcu(EngineFcuReq {
            block_root: head_root,
            head_block_hash: head,
            safe_block_hash: safe,
            finalized_block_hash: fin,
        }));

        self.precompute_next_epoch_shuffling(block_slot / SLOTS_PER_EPOCH);
    }

    /// Warm epoch `block_epoch + 1`'s attester shuffling and committee
    /// aggregates on the head post-state: its inputs (the `E-1` randao mix,
    /// the active set) are fixed once `block_epoch` begins, so the boundary
    /// block's inline `ensure_window` becomes a cache hit and every block's
    /// `collect_sigs` gets the aggregate-subtract path.
    pub(super) fn precompute_next_epoch_shuffling(&mut self, block_epoch: Epoch) {
        let view = self.state.read_view(self.last_applied);
        self.shuffling_cache.ensure_window(&view, block_epoch + 1);
        self.shuffling_cache.try_cache_committee_aggs(&view, block_epoch + 1);
    }

    fn emit_persist_block(
        read: TCacheRead,
        source: BlockSource,
        slot: u64,
        block_root: B256,
        producers: &mut Producers,
    ) {
        producers.produce(BeaconStateEvent::PersistBlock { ssz: read, source, slot, block_root });
    }

    pub(super) fn da_required(&self) -> bool {
        !matches!(self.sync_target, SyncUpdate::SyncingFinalized { .. })
    }

    fn waits_for_columns(&self, parsed: &ParsedBlock) -> bool {
        self.da_required() && parsed.has_data_columns && !self.held.is_available(&parsed.block_root)
    }

    pub(super) fn replay_block(&mut self, read: TCacheRead) {
        let acquired = self.replay_consumer.acquire(read);
        let Some((data, _)) = acquired.buffer().ok() else {
            return;
        };

        if !SignedBeaconBlockView::check_size(data) {
            tracing::error!(len = data.len(), "replayed on-disk block malformed");
            return;
        }

        let block_slot = SignedBeaconBlockView::slot(data);
        let feedback = match self.parse_and_verify_block(data, false) {
            Ok(parsed) => self.stage_and_import(parsed, data),
            Err(err) => err.feedback(),
        };

        match feedback {
            Feedback::Reject(block_root) => tracing::error!(
                block_slot,
                block_root = ?block_root.map(|r| hex32(&r)),
                "replayed block rejected",
            ),
            _ => tracing::info!(
                head_slot = self.head_state_slot(),
                block_slot,
                "replayed block: {:?}",
                feedback
            ),
        }

        if matches!(feedback, Feedback::Accept(_)) {
            self.precompute_next_epoch_shuffling(block_slot / SLOTS_PER_EPOCH);
        }
    }

    pub(super) fn replay_envelope(&mut self, read: TCacheRead) {
        let acquired = self.replay_consumer.acquire(read);
        let Some((data, _)) = acquired.buffer().ok() else {
            return;
        };

        match self.validate_execution_payload_envelope(data) {
            EnvelopeCheck::Ready { block_root, .. } => {
                self.fork_choice.mark_payload_verified(&block_root);
                self.recompute_head();
            }
            EnvelopeCheck::AwaitBlock(block_root) => tracing::error!(
                block = hex32(&block_root),
                "replayed envelope precedes its block; replay is misordered"
            ),
            EnvelopeCheck::Ignore => {
                tracing::warn!("replayed on-disk envelope rejected")
            }
        }
    }

    #[timed]
    pub(super) fn parse_and_verify_block(
        &mut self,
        data: &[u8],
        pre_verified: bool,
    ) -> Result<ParsedBlock, PrecheckError> {
        let parsed = match self.precheck_block(data) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(head_slot = self.head_state_slot(), "{err}");
                return Err(err);
            }
        };

        if !pre_verified && !self.verify_block_signature(data, &parsed) {
            tracing::warn!(
                head_slot = self.head_state_slot(),
                block_root = ?hex32(&parsed.block_root),
                "block BLS proposer signature invalid"
            );
            return Err(PrecheckError::InvalidSignature { block_root: parsed.block_root });
        }

        Ok(parsed)
    }

    #[timed]
    fn stage_and_import(&mut self, parsed: ParsedBlock, data: &[u8]) -> Feedback {
        let staged = match self.stage_block(parsed, data) {
            Ok(staged) => staged,
            Err(feedback) => return feedback,
        };
        let block_root = staged.parsed.block_root;
        self.import_staged(staged, data);

        Feedback::Accept(Some(block_root))
    }

    #[timed]
    fn stage_block(&mut self, parsed: ParsedBlock, data: &[u8]) -> Result<StagedBlock, Feedback> {
        match self.apply_stf_and_commit(&parsed, data) {
            Ok(applied) => Ok(StagedBlock { parsed, applied }),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    block_slot = %parsed.header.slot,
                    head_slot = self.head_state_slot(),
                    "block rejected"
                );
                self.held.reject(parsed.block_root, parsed.header.slot);
                Err(Feedback::Reject(Some(parsed.block_root)))
            }
        }
    }

    pub(super) fn handle_data_columns_available(
        &mut self,
        block_root: B256,
        slot: Slot,
        producers: &mut Producers,
    ) {
        let Some(waiting) = self.held.mark_available(block_root, slot) else {
            tracing::debug!(block = hex32(&block_root), slot, "DataColumnsAvailable received");
            return;
        };
        let WaitingBlock { staged, read, source } = waiting;

        let acquired = self.block_consumer(source).acquire(read);
        let Ok((data, _)) = acquired.buffer() else {
            tracing::error!(
                block = hex32(&block_root),
                slot,
                "block lapped in the tcache before its data columns arrived; re-requesting"
            );
            producers.produce(SyncNeed::missing_block(block_root, slot));
            self.stf_scratch.votes.recycle(staged.applied.votes);
            return;
        };

        self.import_staged(staged, data);
        self.announce_imported(data, block_root, read, source, producers);
        self.on_accept(Some(block_root), producers);
    }

    fn block_consumer(&mut self, source: BlockSource) -> &mut TRandomAccess {
        match source {
            BlockSource::Gossip => &mut self.gossip_consumer,
            BlockSource::Rpc => &mut self.rpc_consumer,
        }
    }

    /// Run the per-block STF against a COW child of the parent post-state and
    /// commit it. Holds the `&mut self.state` borrow for the whole transition
    /// (ending at `commit`), then returns the committed `StateId`, the post-
    /// state `(justified, finalized)` checkpoints, and the execution block
    /// hash.
    #[timed]
    fn apply_stf_and_commit(
        &mut self,
        parsed: &ParsedBlock,
        data: &[u8],
    ) -> crate::Result<AppliedBlock> {
        let block_epoch = parsed.header.slot / SLOTS_PER_EPOCH;

        // Per-block attester shuffling against the parent post-state (active
        // set + seed for an epoch are fixed at its prior boundary). The child
        // is a COW copy of the parent pre-STF, so shuffle inputs read identical
        // off `parent_state_id` — done before the held-writer view takes the
        // `&mut self.state` borrow. Reuse the `(epoch, mix)`-keyed cache so
        // consecutive same-epoch blocks skip the O(rounds·n) shuffle.
        let sref = {
            let view = self.state.read_view(parsed.parent_state_id);
            self.shuffling_cache.ensure_window(&view, block_epoch);
            self.shuffling_cache.build_ref(&view, block_epoch)
        };

        // COW: an unpublished child off the parent post-state. The view HOLDS
        // every rolled per-slot writer for the whole transition (the boundary
        // epoch/longtail writers are rolled inside `process_epoch` and their
        // committed ids returned); `commit` assembles the child bundle for
        // publish-last.
        let parent = parsed.parent_state_id;
        let (mut view, epoch, longtail) = self.state.apply_block_view(parent);
        let mut votes = self.stf_scratch.votes.take();
        let transition = stf::apply_block(
            &self.spec,
            &mut view,
            epoch,
            longtail,
            parent,
            data,
            &parsed.header,
            Some(&sref),
            &mut self.stf_scratch,
            &mut votes,
            &mut self.sig_batch,
        );
        let (epoch_idx, longtail_idx) = match transition {
            Ok(committed) => committed,
            Err(e) => {
                self.stf_scratch.votes.recycle(votes);
                return Err(e);
            }
        };

        // Snapshot checkpoints while the view is live, then `commit` it so the
        // `&mut self.state` borrow ends before the fork-choice / publish work.
        let es = epoch.view_opt(epoch_idx).state();
        let checkpoints = (es.current_justified_checkpoint, es.finalized_checkpoint);
        // Spec `compute_pulled_up_tip`: the j/f this post-state would realize at
        // its epoch boundary, read-only on the live view.
        let unrealized =
            stf::unrealized_checkpoints(&view, es, parsed.header.slot / SLOTS_PER_EPOCH);
        let execution_block_hash = view.slot.state().latest_execution_payload_header.block_hash;
        let bid_block_hash = view.slot.state().latest_execution_payload_bid.block_hash;

        Ok(AppliedBlock {
            id: view.commit(epoch_idx, longtail_idx),
            justified: checkpoints.0,
            finalized: checkpoints.1,
            unrealized,
            execution_block_hash,
            bid_block_hash,
            votes,
        })
    }

    /// Fork-choice import and head publish; the tick-to-attestable window
    /// ends when this returns.
    #[timed]
    pub(super) fn import_staged(&mut self, staged: StagedBlock, block_data: &[u8]) {
        let StagedBlock { parsed, applied } = staged;
        let AppliedBlock {
            id: new_id,
            justified,
            finalized,
            unrealized,
            execution_block_hash,
            bid_block_hash,
            votes,
        } = applied;

        let is_gloas = parsed.is_gloas;
        let (parent_payload_status, bid_block_hash, payload_verified) = if is_gloas {
            (parsed.parent_payload_status, bid_block_hash, false)
        } else {
            (PayloadStatus::Full, execution_block_hash, true)
        };

        // Fold block-included attestations into the LMD vote tracker.
        let n = self.head_validator_count();
        for vote in &votes.votes {
            self.fork_choice.record_vote(vote, n);
        }

        self.fork_choice.on_block(BlockImport {
            slot: parsed.header.slot,
            block_root: parsed.block_root,
            parent_root: parsed.header.parent_root,
            execution_block_hash,
            justified,
            finalized,
            unrealized_justified: unrealized.0,
            unrealized_finalized: unrealized.1,
            state_id: new_id,
            bid_block_hash,
            parent_payload_status,
            payload_verified,
            is_gloas,
        });

        // Block-included attester slashings: mark the slashed validators
        // equivocating (spec `on_attester_slashing`), removing any live LMD
        // weight on the next recompute.
        for &idx in &votes.slashed {
            self.fork_choice.mark_equivocating(idx as usize);
        }
        self.stf_scratch.votes.recycle(votes);

        // Proposer boost: the FIRST current-slot block that arrived before the
        // attesting deadline (first 1/3) gets a transient weight bonus, expired
        // at the next slot boundary by the fork-choice tick. Set before
        // `recompute_head` so `apply_score_changes` folds it in. First-block
        // guard per spec `update_proposer_boost_root`.
        let before_deadline = self.ticker.is_before_attesting_interval(is_gloas);

        if parsed.header.slot == self.ticker.current_slot() &&
            before_deadline &&
            self.fork_choice.proposer_boost_root == [0u8; 32]
        {
            self.refresh_justified_balances();
            self.fork_choice.set_proposer_boost(parsed.block_root);
        }

        self.held.discard_available(&parsed.block_root);

        // Adopt the new block as head before recompute so `lift_checkpoints`
        // reads ITS post-state checkpoints — an epoch-boundary block's justified
        // advance lands this import, not one recompute later.
        self.last_applied = new_id;
        self.last_applied_block_root = parsed.block_root;

        if is_gloas {
            self.notify_ptc_from_block(block_data);
        }

        self.recompute_head();
        self.state.publish_state_id(new_id);

        self.maybe_finalize();
    }

    fn check_block_size(data: &[u8]) -> Result<(), PrecheckError> {
        if SignedBeaconBlockView::check_size(data) {
            return Ok(());
        }
        Err(PrecheckError::SizeMismatch {
            expected_min: ssz_view::SIGNED_BEACON_BLOCK_MIN,
            expected_max: ssz_view::SIGNED_BEACON_BLOCK_MAX,
            got: data.len(),
        })
    }

    fn precheck_block(&self, data: &[u8]) -> Result<ParsedBlock, PrecheckError> {
        Self::check_block_size(data)?;

        let block_slot = SignedBeaconBlockView::slot(data);
        let block_epoch = block_slot / SLOTS_PER_EPOCH;
        let proposer_index = SignedBeaconBlockView::proposer_index(data);
        let parent_root = *SignedBeaconBlockView::parent_root(data);
        let state_root = *SignedBeaconBlockView::state_root(data);

        let body = SignedBeaconBlockView::body(data);

        let is_gloas = self.spec.is_gloas_at(block_epoch);

        let canonical = if is_gloas {
            BeaconBlockBodyGloasView::check_canonical(body)
        } else {
            BeaconBlockBodyFuluView::check_canonical(body)
        };
        if !canonical {
            return Err(PrecheckError::NonCanonicalBody { block_slot, body_len: body.len() });
        }

        let body_root = ssz_hash::hash_tree_root_body(body, is_gloas);

        let block_header = BeaconBlockHeader {
            slot: block_slot,
            proposer_index,
            parent_root,
            state_root,
            body_root,
        };

        let block_root = ssz_hash::hash_tree_root_block_header(&block_header);
        if self.fork_choice.find_node_idx(&block_root).is_some() {
            return Err(PrecheckError::AlreadyKnown { block_root });
        }
        if self.held.is_staged(&block_root) {
            return Err(PrecheckError::AwaitingData { block_root });
        }
        if self.held.is_rejected(&block_root) {
            return Err(PrecheckError::Rejected { block_root });
        }

        let finalized_slot = self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH;
        if block_slot <= finalized_slot {
            return Err(PrecheckError::PreFinalized { block_slot, finalized_slot });
        }

        if self.held.is_rejected(&parent_root) {
            return Err(PrecheckError::ParentInvalid { parent_root, block_root });
        }
        let Some(parent_idx) = self.fork_choice.find_node_idx(&parent_root) else {
            let last_applied_slot = self.head_state_slot();
            return Err(PrecheckError::ParentMissing {
                parent_root,
                block_root,
                last_applied_slot,
                block_slot,
            });
        };

        let parent_node = self.fork_choice.node(parent_idx);
        // EL declared the parent invalid — descendants are invalid by
        // definition. Reject before the COW/EL round-trip.
        if parent_node.execution_status == ExecutionStatus::Invalid {
            return Err(PrecheckError::ParentInvalid { parent_root, block_root });
        }

        let parent_state_id = parent_node.state_id;
        let parent_payload_status = if is_gloas {
            Self::gloas_parent_payload_status(body, parent_node, parent_root, block_root)?
        } else {
            PayloadStatus::Full
        };

        // Immutable read view of the parent post-state.
        let rv = self.state.read_view(parent_state_id);
        let parent_slot = rv.slot.slot_number();

        // A block must strictly extend its parent's slot.
        if block_slot <= parent_slot {
            return Err(PrecheckError::PastSlot { block_slot, parent_slot });
        }

        if block_slot > self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return Err(PrecheckError::FutureSlot {
                block_slot,
                wall_slot: self.ticker.current_slot(),
            });
        }

        let parent_epoch = parent_slot / SLOTS_PER_EPOCH;
        // Fulu proposer selection via `proposer_lookahead`, fixed at the
        // parent's prior epoch boundary and covering only its current + next
        // epoch.
        let lookahead_idx = (block_slot - parent_epoch * SLOTS_PER_EPOCH) as usize;
        let relay_eligible = match rv.epoch.proposer_at(lookahead_idx) {
            Some(expected) if proposer_index != expected => {
                return Err(PrecheckError::ProposerLookaheadMismatch {
                    expected,
                    got: proposer_index,
                    block_root,
                });
            }
            Some(_) => true,
            None => {
                tracing::debug!(
                    block_slot,
                    parent_slot,
                    "proposer lookahead does not reach this block — not relayed"
                );
                false
            }
        };

        let validator_count = rv.validators.count();
        if proposer_index as usize >= validator_count {
            return Err(PrecheckError::ProposerIndexTooBig {
                got: proposer_index,
                validator_count,
                block_root,
            });
        }

        if !is_gloas {
            self.precheck_fulu_payload(body, block_slot, block_epoch, &rv, block_root)?;
        }

        let has_data_columns = SignedBeaconBlockView::has_data_columns(data, is_gloas);

        Ok(ParsedBlock {
            header: block_header,
            block_root,
            has_data_columns,
            parent_state_id,
            is_gloas,
            parent_payload_status,
            relay_eligible,
        })
    }

    /// The Fulu gossip rules require the execution timestamp and the active
    /// blob limit before propagation. The STF re-checks both, but that runs
    /// after the relay has already gone out.
    fn precheck_fulu_payload(
        &self,
        body: &[u8],
        block_slot: Slot,
        block_epoch: Epoch,
        rv: &StateReadView<'_>,
        block_root: B256,
    ) -> Result<(), PrecheckError> {
        let Some(offsets) = BodyOffsets::new(body, BodyFork::Fulu) else {
            return Err(PrecheckError::NonCanonicalBody { block_slot, body_len: body.len() });
        };
        let payload = offsets.payload();
        if payload.len() < ssz_view::EXECUTION_PAYLOAD_FIXED {
            return Err(PrecheckError::NonCanonicalBody { block_slot, body_len: body.len() });
        }
        let expected = rv.imm.genesis_time + block_slot * self.spec.seconds_per_slot();
        let got = ssz_view::ExecutionPayloadView::timestamp(payload);
        if got != expected {
            return Err(PrecheckError::PayloadTimestamp { expected, got, block_root });
        }

        let max = self.spec.blob_params_at(block_epoch).max_blobs_per_block as usize;
        let got = offsets.blob_commitments_fulu().len() / ssz_view::BYTES_PER_KZG_COMMITMENT;
        if got > max {
            return Err(PrecheckError::TooManyCommitments { got, max, block_root });
        }

        Ok(())
    }

    fn verify_block_signature(&self, data: &[u8], parsed: &ParsedBlock) -> bool {
        let block_epoch = parsed.header.slot / SLOTS_PER_EPOCH;
        let rv = self.state.read_view(parsed.parent_state_id);
        let fork_version = self.spec.fork_version_at(block_epoch);
        let proposer_pubkey =
            rv.validators.pubkey_decompressed(parsed.header.proposer_index as usize);
        let domain = bls::compute_domain(
            bls::DOMAIN_BEACON_PROPOSER,
            fork_version,
            &rv.imm.genesis_validators_root,
        );
        bls::verify_block_signature(data, proposer_pubkey, &parsed.header.body_root, &domain)
    }

    fn gloas_parent_payload_status(
        body: &[u8],
        parent_node: &ForkChoiceNode,
        parent_root: B256,
        block_root: B256,
    ) -> Result<PayloadStatus, PrecheckError> {
        let bid_off =
            ssz_view::BeaconBlockBodyGloasView::signed_execution_payload_bid_offset(body) as usize;
        let bid_end =
            ssz_view::BeaconBlockBodyGloasView::payload_attestations_offset(body) as usize;
        let full = body
            .get(bid_off..bid_end)
            .filter(|bid| ssz_view::SignedExecutionPayloadBidView::check_size(bid))
            .map(ssz_view::SignedExecutionPayloadBidView::message)
            .is_some_and(|msg| {
                *ssz_view::ExecutionPayloadBidView::parent_block_hash(msg) ==
                    parent_node.payload.bid_block_hash
            });

        if full && !parent_node.payload.verified {
            return Err(PrecheckError::UnverifiedParentPayload { parent_root, block_root });
        }
        if full { Ok(PayloadStatus::Full) } else { Ok(PayloadStatus::Empty) }
    }
}
