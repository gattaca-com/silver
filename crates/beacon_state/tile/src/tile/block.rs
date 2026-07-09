use flux::spine::SpineProducers;
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BeaconBlockHeader, Checkpoint, SLOTS_PER_EPOCH, StateId};
use silver_common::{
    BeaconStateEvent, BlockSource, EngineFcuReq, EngineNewPayloadReq, EngineReq, TRead, hex32,
    ssz_view::{self, SignedBeaconBlockView},
};

use super::{BeaconStateTile, Feedback, ParsedBlock, Producers};
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
}

impl BeaconStateTile {
    pub fn try_apply_block(&mut self, data: &[u8]) -> Feedback {
        self.apply_block_impl(data, false, false, |_block_root| {})
    }

    /// Post-import emission: PersistBlock (for storage) + Status (head and
    /// possibly finalized just moved). Called after `handle_block` returns
    /// `GossipFeedback::Accept` from gossip or RPC range/root response paths.
    #[timed]
    pub(super) fn apply_block(
        &mut self,
        data: &[u8],
        data_tcache: TRead,
        source: BlockSource,
        pre_verified: bool,
        producers: &mut Producers,
    ) -> Feedback {
        let block_slot = SignedBeaconBlockView::slot(data);
        if block_slot < (self.head_finalized_checkpoint().epoch * SLOTS_PER_EPOCH) {
            // Pre-finalization block - either backfill or irrelevant.
            return Feedback::Ignore;
        }
        let f = self.apply_block_impl(data, true, pre_verified, |root| {
            producers.produce(EngineReq::NewPayload(EngineNewPayloadReq {
                data: *data_tcache,
                block_root: root,
                block_source: source,
            }));
        });

        if let Feedback::Reject(Some(block_root)) = f {
            producers.produce(BeaconStateEvent::BlockRejected { block_root, source });
        }
        tracing::info!(
            ?source,
            head_slot = self.head_state_slot(),
            block_slot,
            "applied block: {:?}",
            f
        );
        if !matches!(f, Feedback::Accept(_)) {
            return f;
        }

        producers.produce(BeaconStateEvent::PersistBlock { ssz: *data_tcache, source });

        let (head_root, head, safe, fin) = self.fork_choice.fcu_execution_hashes();
        producers.produce(EngineReq::Fcu(EngineFcuReq {
            block_root: head_root,
            head_block_hash: head,
            safe_block_hash: safe,
            finalized_block_hash: fin,
        }));

        f
    }

    pub(super) fn replay_block(&mut self, data: &[u8]) {
        if !SignedBeaconBlockView::check_size(data) {
            tracing::error!(len = data.len(), "replayed on-disk block malformed");
            return;
        }

        let block_slot = SignedBeaconBlockView::slot(data);
        let feedback = self.apply_block_impl(data, false, false, |_block_root| {});
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
    }

    #[timed]
    pub(super) fn apply_block_impl<F: FnMut([u8; 32])>(
        &mut self,
        data: &[u8],
        gate_da: bool,
        pre_verified: bool,
        mut notify_el: F,
    ) -> Feedback {
        let parsed = match self.precheck_block(data) {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(head_slot = self.head_state_slot(), "{err}");
                return err.feedback();
            }
        };

        if !pre_verified && !self.verify_block_signature(data, &parsed) {
            tracing::warn!(
                head_slot = self.head_state_slot(),
                block_root = ?hex32(&parsed.block_root),
                "block BLS proposer signature invalid"
            );
            return Feedback::Reject(Some(parsed.block_root));
        }

        // Data availability is only required above the finalized boundary.
        if gate_da &&
            parsed.header.slot > self.da_boundary() &&
            parsed.has_data_columns &&
            !self.dc_available.contains_key(&parsed.block_root)
        {
            return Feedback::AwaitData(parsed.block_root);
        }

        // Fire as early as possible so the EL round-trip overlaps with the
        // state transition — mirrors Lighthouse's async payload notification.
        // After the DA gate, so a block parked on AwaitData doesn't re-send
        // newPayload on every retry.
        notify_el(parsed.block_root);

        let applied = match self.apply_stf_and_commit(&parsed, data) {
            Ok(committed) => committed,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    block_slot = %parsed.header.slot,
                    head_slot = self.head_state_slot(),
                    "block rejected"
                );
                return Feedback::Reject(Some(parsed.block_root));
            }
        };

        self.publish_applied_block(&parsed, data, applied);
        Feedback::Accept(Some(parsed.block_root))
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
        self.shuffling_cache.ensure_window(
            &self.state,
            parsed.parent_state_id,
            block_epoch,
            &mut self.stf_scratch.active,
        );
        let sref = self.shuffling_cache.build_ref(&self.state, parsed.parent_state_id, block_epoch);

        // COW: an unpublished child off the parent post-state. The view HOLDS
        // every rolled per-slot writer for the whole transition (the boundary
        // epoch/longtail writers are rolled inside `process_epoch` and their
        // committed ids returned); `commit` assembles the child bundle for
        // publish-last.
        let parent = parsed.parent_state_id;
        let (mut view, epoch, longtail) = self.state.apply_block_view(parent);
        self.attestation_votes_scratch.clear();
        self.slashed_indices_scratch.clear();
        let (epoch_idx, longtail_idx) = stf::apply_block(
            &self.spec,
            &mut view,
            epoch,
            longtail,
            parent,
            data,
            &parsed.header,
            Some(&sref),
            &mut self.stf_scratch,
            &mut self.attestation_votes_scratch,
            &mut self.slashed_indices_scratch,
            &mut self.sig_batch,
        )?;

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
        })
    }

    #[timed]
    fn publish_applied_block(
        &mut self,
        parsed: &ParsedBlock,
        block_data: &[u8],
        applied: AppliedBlock,
    ) {
        let AppliedBlock {
            id: new_id,
            justified,
            finalized,
            unrealized,
            execution_block_hash,
            bid_block_hash,
        } = applied;

        let is_gloas = parsed.is_gloas;
        let (parent_payload_status, bid_block_hash, payload_verified) = if is_gloas {
            (parsed.parent_payload_status, bid_block_hash, false)
        } else {
            (PayloadStatus::Full, execution_block_hash, true)
        };

        // Fold block-included attestations into the LMD vote tracker.
        let n = self.head_validator_count();
        for i in 0..self.attestation_votes_scratch.len() {
            let v = self.attestation_votes_scratch[i];
            self.fork_choice.record_vote(&v, n);
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
        for i in 0..self.slashed_indices_scratch.len() {
            let idx = self.slashed_indices_scratch[i] as usize;
            self.fork_choice.mark_equivocating(idx);
        }

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

        self.dc_available.remove(&parsed.block_root);

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

    fn precheck_block(&self, data: &[u8]) -> Result<ParsedBlock, PrecheckError> {
        if !SignedBeaconBlockView::check_size(data) {
            return Err(PrecheckError::SizeMismatch {
                expected_min: ssz_view::SIGNED_BEACON_BLOCK_MIN,
                expected_max: ssz_view::SIGNED_BEACON_BLOCK_MAX,
                got: data.len(),
            });
        }
        let block_slot = SignedBeaconBlockView::slot(data);
        let block_epoch = block_slot / SLOTS_PER_EPOCH;
        let finalized_epoch = self.fork_choice.finalized_checkpoint.epoch;
        if block_epoch < finalized_epoch {
            return Err(PrecheckError::PreFinalized { block_epoch, finalized_epoch });
        }

        let proposer_index = SignedBeaconBlockView::proposer_index(data);
        let parent_root = *SignedBeaconBlockView::parent_root(data);
        let state_root = *SignedBeaconBlockView::state_root(data);

        let body = SignedBeaconBlockView::body(data);

        let is_gloas = self.spec.is_gloas_at(block_epoch);
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

        // Spec gossip rule: IGNORE blocks whose slot exceeds wall slot.
        let wall_slot_plus_one = self.ticker.current_slot() + 1;
        if block_slot > wall_slot_plus_one {
            return Err(PrecheckError::FutureSlot { block_slot, wall_slot_plus_one });
        }

        let parent_epoch = parent_slot / SLOTS_PER_EPOCH;
        // Fulu proposer selection via `proposer_lookahead` (current + next
        // epoch, 64 slots), fixed at the parent's prior epoch boundary — read
        // it from the parent post-state.
        if block_epoch == parent_epoch || block_epoch == parent_epoch + 1 {
            let lookahead_idx = (block_slot - parent_epoch * SLOTS_PER_EPOCH) as usize;
            if let Some(expected) = rv.epoch.proposer_at(lookahead_idx) &&
                proposer_index != expected
            {
                return Err(PrecheckError::ProposerLookaheadMismatch {
                    expected,
                    got: proposer_index,
                    block_root,
                });
            }
        }

        let validator_count = rv.validators.count();
        if proposer_index as usize >= validator_count {
            return Err(PrecheckError::ProposerIndexTooBig {
                got: proposer_index,
                validator_count,
                block_root,
            });
        }

        let has_data_columns = SignedBeaconBlockView::has_data_columns(data, is_gloas);

        Ok(ParsedBlock {
            header: block_header,
            block_root,
            has_data_columns,
            parent_state_id,
            is_gloas,
            parent_payload_status,
        })
    }

    fn verify_block_signature(&self, data: &[u8], parsed: &ParsedBlock) -> bool {
        let block_epoch = parsed.header.slot / SLOTS_PER_EPOCH;
        let rv = self.state.read_view(parsed.parent_state_id);
        let fork_version = self.spec.fork_version_at(block_epoch);
        let proposer_pubkey =
            rv.validators.pubkey_decompressed(parsed.header.proposer_index as usize);
        bls::verify_block_signature(
            data,
            proposer_pubkey,
            &parsed.header.body_root,
            fork_version,
            &rv.imm.genesis_validators_root,
        )
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
