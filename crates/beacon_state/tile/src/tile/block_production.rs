use std::io::Write;

use flux::spine::SpineProducers;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BodyOffsets, ExecutionAddress, SLOTS_PER_EPOCH, Slot, StateId,
};
use silver_common::{
    BeaconApiResponse, EngineGetPayloadReq, EngineGetPayloadResp, EnginePreparePayloadReq,
    EnginePreparePayloadResp, EngineReq, PayloadFrame, ProduceBlockFailure, ProducedBlock,
    TCacheProducer, TCacheRead, TRead,
    ssz_view::{BEACON_BLOCK_BODY_FIXED, BLOCK_SYNC_AGGREGATE_SIZE},
};
use silver_ssz::block_body::{BeaconBlockBodyFulu, EMPTY_SYNC_AGGREGATE};

use super::{BeaconStateTile, Producers, block::AppliedBlock};
use crate::{
    ssz_hash,
    stf::{self, BlockFork, BlockInput, ExpectedWithdrawals, get_expected_withdrawals},
};

/// Offsets of `block`, `kzg_proofs` and `blobs`.
const BLOCK_CONTENTS_FIXED: usize = 3 * 4;
/// `slot`, `proposer_index`, `parent_root`, `state_root` and the body offset.
const BEACON_BLOCK_FIXED: usize = 8 + 8 + 32 + 32 + 4;

/// Requests with equal proposals are served one block.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Proposal {
    pub(super) slot: Slot,
    pub(super) parent_root: B256,
    pub(super) randao_reveal: [u8; 96],
    pub(super) graffiti: [u8; 32],
}

impl Proposal {
    fn builds_on(&self, slot: Slot, parent_root: B256) -> bool {
        self.slot == slot && self.parent_root == parent_root
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadStage {
    Preparing,
    Prepared { payload_id: [u8; 8] },
    Fetching { payload_id: [u8; 8] },
}

/// The EL building a payload for `slot` on `parent_root`. `id` tags both
/// engine requests, so any fetch answer carries this payload.
struct Payload {
    id: u64,
    slot: Slot,
    parent_root: B256,
    stage: PayloadStage,
}

impl Payload {
    fn fetch(&mut self, payload_id: [u8; 8], producers: &mut Producers) {
        producers.produce(EngineReq::GetPayload(EngineGetPayloadReq { id: self.id, payload_id }));
        self.stage = PayloadStage::Fetching { payload_id };
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Operations<'a> {
    pub(super) proposer_slashings: &'a [u8],
    pub(super) attester_slashings: &'a [u8],
    pub(super) attestations: &'a [u8],
    pub(super) voluntary_exits: &'a [u8],
    pub(super) sync_aggregate: &'a [u8; BLOCK_SYNC_AGGREGATE_SIZE],
    pub(super) bls_to_execution_changes: &'a [u8],
}

impl Operations<'static> {
    pub(super) const NONE: Self = Self {
        proposer_slashings: &[],
        attester_slashings: &[],
        attestations: &[],
        voluntary_exits: &[],
        sync_aggregate: &EMPTY_SYNC_AGGREGATE,
        bls_to_execution_changes: &[],
    };
}

/// The post-state is committed, so the import of the signed block skips its
/// state transition.
struct BuiltBlock {
    proposal: Proposal,
    block: ProducedBlock,
    payload: Option<TRead>,
    body_root: B256,
    block_fork: BlockFork,
    block_root: B256,
    post_state: Option<AppliedBlock>,
}

#[derive(Default)]
pub(super) struct BlockProduction {
    payloads: Vec<Payload>,
    pending: Vec<(u64, Proposal)>,
    built: Option<BuiltBlock>,
    next_payload_id: u64,
}

impl BlockProduction {
    fn payload(&mut self, slot: Slot, parent_root: B256) -> Option<&mut Payload> {
        self.payloads.iter_mut().find(|p| p.slot == slot && p.parent_root == parent_root)
    }

    #[cfg(test)]
    pub(super) fn payload_id(&mut self, slot: Slot, parent_root: B256) -> Option<[u8; 8]> {
        match self.payload(slot, parent_root)?.stage {
            PayloadStage::Prepared { payload_id } | PayloadStage::Fetching { payload_id } => {
                Some(payload_id)
            }
            PayloadStage::Preparing => None,
        }
    }

    fn begin_preparation(&mut self, slot: Slot, parent_root: B256) -> u64 {
        debug_assert!(self.payload(slot, parent_root).is_none(), "one payload per parent");
        let id = self.next_payload_id;
        self.next_payload_id += 1;
        self.payloads.push(Payload { id, slot, parent_root, stage: PayloadStage::Preparing });
        id
    }

    fn take_pending(&mut self, slot: Slot, parent_root: B256) -> Vec<(u64, Proposal)> {
        self.pending.extract_if(.., |(_, proposal)| proposal.builds_on(slot, parent_root)).collect()
    }

    fn built_for(&self, proposal: &Proposal) -> Option<ProducedBlock> {
        self.built.as_ref().filter(|built| built.proposal == *proposal).map(|built| built.block)
    }

    fn latest_prepared_slot(&self) -> Option<Slot> {
        self.payloads.iter().map(|payload| payload.slot).max()
    }

    pub(super) fn prune_before(&mut self, slot: Slot, producers: &mut Producers) {
        self.payloads.retain(|payload| payload.slot >= slot);
        if let Some(built) = self.built.as_mut().filter(|built| built.proposal.slot < slot) {
            built.payload = None;
        }
        for (request_id, _) in self.pending.extract_if(.., |(_, p)| p.slot < slot) {
            answer(producers, request_id, Err(ProduceBlockFailure::PayloadUnavailable));
        }
    }

    pub(super) fn take_produced_state(&mut self, block_root: &B256) -> Option<AppliedBlock> {
        self.built.as_mut().filter(|built| built.block_root == *block_root)?.post_state.take()
    }

    pub(super) fn drop_outdated(&mut self, parent_known: impl Fn(&B256) -> bool) {
        self.built.take_if(|built| !parent_known(&built.proposal.parent_root));
    }

    pub(super) fn state_ids_mut(&mut self) -> impl Iterator<Item = &mut StateId> {
        self.built
            .iter_mut()
            .flat_map(|built| built.post_state.iter_mut())
            .map(|post_state| post_state.state_id_mut())
    }
}

impl BeaconStateTile {
    fn proposer_on_head(&self, slot: Slot) -> Option<u64> {
        let head = self.state.read_view(self.last_applied);
        let head_epoch_start = head.slot.state().slot / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH;
        let proposer = head.epoch.proposer_at(slot.checked_sub(head_epoch_start)? as usize);
        if proposer.is_none() {
            silver_log::error!(slot, "proposer lookahead does not reach the slot");
        }
        proposer
    }

    /// Starts the EL building a payload for `slot` on the head, when a
    /// registered validator proposes it and none is built or being built.
    #[timed]
    pub(super) fn prepare_payload(
        &mut self,
        slot: Slot,
        fallback_fee_recipient: Option<ExecutionAddress>,
        producers: &mut Producers,
    ) -> Result<(), ProduceBlockFailure> {
        if self.spec.is_gloas_at_slot(slot) {
            return Err(ProduceBlockFailure::SlotNotProposable);
        }
        let (head_root, head_block_hash, safe_block_hash, finalized_block_hash) =
            self.fork_choice.fcu_execution_hashes();
        if head_root != self.head_block_root() {
            silver_log::warn!(slot, "head state does not follow fork choice; payload not prepared");
            return Err(ProduceBlockFailure::Internal);
        }
        if self.block_production.payload(slot, head_root).is_some() {
            return Ok(());
        }

        let proposer = self.proposer_on_head(slot).ok_or(ProduceBlockFailure::Internal)?;
        let fee_recipient = self
            .proposer_preparations
            .fee_recipient(proposer)
            .or(fallback_fee_recipient)
            .ok_or(ProduceBlockFailure::NoFeeRecipient)?;
        let genesis_time = self.state.read_view(self.last_applied).imm.genesis_time;

        let state_id = self.epoch_start_state(self.last_applied, slot);
        // Never committed: the ring slots it rolls are freed with the tail.
        let fork = self.state.apply_block_view(state_id);
        let prev_randao = fork.view.randao_mixes.at_epoch(slot / SLOTS_PER_EPOCH);
        let ExpectedWithdrawals { withdrawals, .. } = get_expected_withdrawals(&fork.view);

        let id = self.block_production.begin_preparation(slot, head_root);
        producers.produce(EngineReq::PreparePayload(EnginePreparePayloadReq {
            id,
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
            attrs_timestamp: genesis_time + slot * self.spec.seconds_per_slot(),
            attrs_prev_randao: prev_randao,
            attrs_fee_recipient: fee_recipient,
            attrs_parent_beacon_block_root: head_root,
            attrs_withdrawals: withdrawals,
        }));

        silver_log::info!(slot, proposer, "payload preparation requested");
        Ok(())
    }

    pub(super) fn prepare_payload_on_new_head(&mut self, producers: &mut Producers) {
        let Some(slot) = self.block_production.latest_prepared_slot() else {
            return;
        };
        if slot > self.ticker.current_slot() {
            let _ = self.prepare_payload(slot, self.default_fee_recipient, producers);
        }
    }

    #[timed]
    pub(super) fn produce_block(
        &mut self,
        request_id: u64,
        proposal: Proposal,
        producers: &mut Producers,
    ) {
        if let Some(block) = self.block_production.built_for(&proposal) {
            return answer(producers, request_id, Ok(block));
        }
        match self.start_proposal(&proposal, producers) {
            Ok(()) => self.block_production.pending.push((request_id, proposal)),
            Err(failure) => answer(producers, request_id, Err(failure)),
        }
    }

    /// The reveal is checked after the EL is asked, so it builds meanwhile.
    fn start_proposal(
        &mut self,
        proposal: &Proposal,
        producers: &mut Producers,
    ) -> Result<(), ProduceBlockFailure> {
        let slot = proposal.slot;
        if slot <= self.last_applied_block_slot() || slot > self.ticker.current_slot() + 1 {
            return Err(ProduceBlockFailure::SlotNotProposable);
        }
        match self.block_production.payload(slot, proposal.parent_root) {
            Some(payload) => {
                if let PayloadStage::Prepared { payload_id } = payload.stage {
                    payload.fetch(payload_id, producers);
                }
            }
            None => self.prepare_payload(slot, self.default_fee_recipient, producers)?,
        }

        let (parent, proposer) = self.proposal_parent(proposal)?;
        if !self.randao_reveal_verifies(parent, proposer, proposal) {
            return Err(ProduceBlockFailure::InvalidRandaoReveal);
        }
        Ok(())
    }

    /// Resolved on every use: a finalization while the EL builds re-bases
    /// the parent's `StateId`. The head is preferred as it is already rolled
    /// to the current slot.
    #[timed]
    fn proposal_parent(
        &mut self,
        proposal: &Proposal,
    ) -> Result<(StateId, u64), ProduceBlockFailure> {
        let from = if self.head_block_root() == proposal.parent_root {
            self.last_applied
        } else {
            let node = self.fork_choice.find_node_idx(&proposal.parent_root).ok_or_else(|| {
                silver_log::warn!(slot = proposal.slot, "proposal parent left fork choice");
                ProduceBlockFailure::Internal
            })?;
            self.fork_choice.node(node).state_id
        };
        let parent = self.epoch_start_state(from, proposal.slot);
        let proposer = self
            .state
            .read_view(parent)
            .epoch
            .proposer_at((proposal.slot % SLOTS_PER_EPOCH) as usize)
            .ok_or(ProduceBlockFailure::Internal)?;
        Ok((parent, proposer))
    }

    #[timed]
    fn randao_reveal_verifies(
        &mut self,
        parent: StateId,
        proposer: u64,
        proposal: &Proposal,
    ) -> bool {
        let view = self.state.read_view(parent);
        let signing_root = stf::randao_signing_root(view.imm, &view.epoch, proposal.slot);
        let pubkey = view.validators.pubkey_decompressed(proposer as usize);
        self.sig_batch.clear();
        self.sig_batch.push_one(pubkey, &proposal.randao_reveal, signing_root);
        self.sig_batch.verify_all()
    }

    #[timed]
    pub(super) fn on_payload_prepared(
        &mut self,
        response: EnginePreparePayloadResp,
        producers: &mut Producers,
    ) {
        let production = &mut self.block_production;
        let Some(at) = production
            .payloads
            .iter()
            .position(|p| p.id == response.id && p.stage == PayloadStage::Preparing)
        else {
            return;
        };
        let payload = &mut production.payloads[at];
        let (slot, parent_root) = (payload.slot, payload.parent_root);
        // Refused: the next request prepares again.
        let Some(payload_id) = response.payload_id else {
            production.payloads.swap_remove(at);
            for (request_id, _) in production.take_pending(slot, parent_root) {
                answer(producers, request_id, Err(ProduceBlockFailure::PayloadUnavailable));
            }
            return;
        };
        if production.pending.iter().any(|(_, proposal)| proposal.builds_on(slot, parent_root)) {
            payload.fetch(payload_id, producers);
        } else {
            payload.stage = PayloadStage::Prepared { payload_id };
        }
    }

    /// Serves every request waiting on the payload. The payload goes back to
    /// prepared, so a later request fetches the EL's latest build.
    #[timed]
    pub(super) fn on_payload(&mut self, response: EngineGetPayloadResp, producers: &mut Producers) {
        let Some(payload) = self.block_production.payloads.iter_mut().find(|p| p.id == response.id)
        else {
            return;
        };
        let PayloadStage::Fetching { payload_id } = payload.stage else {
            return;
        };
        payload.stage = PayloadStage::Prepared { payload_id };
        let (slot, parent_root) = (payload.slot, payload.parent_root);

        for (request_id, proposal) in self.block_production.take_pending(slot, parent_root) {
            let block = match response.data {
                Some(data) => self.block_for(proposal, data, Operations::NONE),
                None => Err(ProduceBlockFailure::PayloadUnavailable),
            };
            answer(producers, request_id, block);
        }
    }

    /// The built block's `(body_root, fork)` when `body` is its body. Comparing
    /// the bytes is cheaper than hashing the payload again.
    #[timed]
    pub(super) fn built_body_hash(&mut self, slot: Slot, body: &[u8]) -> Option<(B256, BlockFork)> {
        let built = self.block_production.built.as_ref().filter(|b| b.proposal.slot == slot)?;
        let contents = self.events_producer.read_buffer(built.block.header).ok()?;
        let frame = PayloadFrame::parse(built.payload.as_ref()?.buffer().ok()?.0)?;

        let (before_payload, bls_changes) = contents.split_at(built.block.payload_at as usize);
        let body_head = &before_payload[BLOCK_CONTENTS_FIXED + BEACON_BLOCK_FIXED..];
        let body_tail =
            &frame.after_payload[..frame.commitments.len() + frame.execution_requests.len()];
        let mut rest = body;
        for part in [body_head, frame.execution_payload, bls_changes, body_tail] {
            rest = rest.strip_prefix(part)?;
        }
        rest.is_empty().then_some((built.body_root, built.block_fork))
    }

    #[timed]
    pub(super) fn block_for(
        &mut self,
        proposal: Proposal,
        payload: TCacheRead,
        operations: Operations<'_>,
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        if let Some(block) = self.block_production.built_for(&proposal) {
            return Ok(block);
        }
        let built = match self.build_block(proposal, payload, operations) {
            Err(ProduceBlockFailure::Invalid) if operations != Operations::NONE => {
                silver_log::warn!(
                    slot = proposal.slot,
                    "packed operations fail the block; built without them"
                );
                self.build_block(proposal, payload, Operations::NONE)
            }
            built => built,
        }?;
        let block = built.block;
        self.block_production.built = Some(built);
        Ok(block)
    }

    #[timed]
    fn build_block(
        &mut self,
        proposal: Proposal,
        payload: TCacheRead,
        operations: Operations<'_>,
    ) -> Result<BuiltBlock, ProduceBlockFailure> {
        let slot = proposal.slot;
        let acquired = self.reader.acquire(payload);
        let Ok((frame, _)) = acquired.buffer() else {
            silver_log::error!(slot, "payload overwritten before the block was assembled");
            return Err(ProduceBlockFailure::Internal);
        };
        let Some(frame) = PayloadFrame::parse(frame) else {
            silver_log::error!(slot, "payload frame is misframed");
            return Err(ProduceBlockFailure::Internal);
        };
        let max_blobs = self.spec.blob_params_at(slot / SLOTS_PER_EPOCH).max_blobs_per_block;
        if frame.blob_count as u64 > max_blobs {
            silver_log::warn!(
                slot,
                blobs = frame.blob_count,
                max_blobs,
                "EL built over the blob limit"
            );
            return Err(ProduceBlockFailure::Invalid);
        }

        let (parent, proposer_index) = self.proposal_parent(&proposal)?;
        let eth1_data = self.state.read_view(parent).slot.state().eth1_data.to_ssz();
        let body = BeaconBlockBodyFulu {
            randao_reveal: &proposal.randao_reveal,
            eth1_data: &eth1_data,
            graffiti: &proposal.graffiti,
            proposer_slashings: operations.proposer_slashings,
            attester_slashings: operations.attester_slashings,
            attestations: operations.attestations,
            deposits: &[],
            voluntary_exits: operations.voluntary_exits,
            sync_aggregate: operations.sync_aggregate,
            execution_payload: frame.execution_payload,
            bls_to_execution_changes: operations.bls_to_execution_changes,
            blob_kzg_commitments: frame.commitments,
            execution_requests: frame.execution_requests,
        };
        let mut body_fixed = [0; BEACON_BLOCK_BODY_FIXED];
        let offsets = body.write_fixed(&mut body_fixed).map_err(|e| {
            silver_log::warn!(?e, slot, "assembled body is not canonical");
            ProduceBlockFailure::Invalid
        })?;
        offsets.validate().map_err(|e| {
            silver_log::warn!(?e, slot, "assembled body is over its limits");
            ProduceBlockFailure::Invalid
        })?;
        let (body_root, block_fork) = stf::hash_body(&offsets);
        let mut header = BeaconBlockHeader {
            slot,
            proposer_index,
            parent_root: proposal.parent_root,
            state_root: [0; 32],
            body_root,
        };
        let (block_root, post_state) = self.seal(&mut header, parent, offsets, block_fork)?;
        let (contents, payload_at) =
            self.write_contents(&header, &body, offsets.fixed(), frame.cell_proofs.len())?;

        silver_log::info!(slot, blobs = frame.blob_count, "block assembled");
        Ok(BuiltBlock {
            proposal,
            block: ProducedBlock {
                header: contents,
                payload_at,
                payload: acquired.to_read(),
                execution_payload_value: frame.block_value,
            },
            payload: Some(acquired),
            body_root,
            block_fork,
            block_root,
            post_state: Some(post_state),
        })
    }

    /// Fills `state_root`, and commits the post-state.
    #[timed]
    fn seal(
        &mut self,
        header: &mut BeaconBlockHeader,
        parent: StateId,
        body: BodyOffsets<'_>,
        block_fork: BlockFork,
    ) -> Result<(B256, AppliedBlock), ProduceBlockFailure> {
        let slot = header.slot;
        let epoch = slot / SLOTS_PER_EPOCH;
        let shuffling = {
            let view = self.state.read_view(parent);
            self.shuffling_cache.ensure_window(&view, epoch);
            self.shuffling_cache.build_ref(&view, epoch)
        };
        let mut fork = self.state.apply_block_view(parent);
        let mut votes = self.stf_scratch.votes.take();
        let input = BlockInput {
            header: &*header,
            block_root: [0; 32],
            body,
            fork: block_fork,
            shuffling: &shuffling,
        };
        let state_root = stf::post_state_root_unchecked(
            &self.spec,
            &mut fork,
            &input,
            &mut self.stf_scratch,
            &mut votes,
        );
        header.state_root = match state_root {
            Ok(state_root) => state_root,
            Err(e) => {
                self.stf_scratch.votes.recycle(votes);
                silver_log::warn!(?e, slot, "assembled block fails the state transition");
                return Err(ProduceBlockFailure::Invalid);
            }
        };

        // The root commits to the state root, so the transition ran without it.
        let block_root = ssz_hash::hash_tree_root_block_header(header);
        fork.view.slot.state_mut().latest_block_root = block_root;
        Ok((block_root, AppliedBlock::commit(fork, header, block_fork, votes)))
    }

    /// SSZ `BlockContents` without the payload frame's parts. Returns where
    /// the frame's payload goes; its `after_payload` goes at the end.
    #[timed]
    fn write_contents(
        &mut self,
        header: &BeaconBlockHeader,
        body: &BeaconBlockBodyFulu<'_>,
        body_fixed: &[u8],
        cell_proofs_len: usize,
    ) -> Result<(TCacheRead, u32), ProduceBlockFailure> {
        let proofs_at = BLOCK_CONTENTS_FIXED + BEACON_BLOCK_FIXED + body.ssz_len();
        let [block_offset, proofs_offset, blobs_offset] =
            [BLOCK_CONTENTS_FIXED, proofs_at, proofs_at + cell_proofs_len]
                .map(|at| (at as u32).to_le_bytes());
        let [
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            _,
            bls_changes,
            ..,
        ] = body.variable_fields();
        let before_payload: [&[u8]; 14] = [
            &block_offset,
            &proofs_offset,
            &blobs_offset,
            &header.slot.to_le_bytes(),
            &header.proposer_index.to_le_bytes(),
            &header.parent_root,
            &header.state_root,
            &(BEACON_BLOCK_FIXED as u32).to_le_bytes(),
            body_fixed,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
        ];
        let payload_at = before_payload.iter().map(|part| part.len()).sum::<usize>();
        let len = payload_at + bls_changes.len();

        let contents = self.events_producer.write_with(len, |mut out| {
            for part in before_payload.into_iter().chain([bls_changes]) {
                out.write_all(part).expect("sized to its parts");
            }
        });
        let Some(contents) = contents else {
            silver_log::error!(
                slot = header.slot,
                len,
                "beacon_state tcache full; block not served"
            );
            return Err(ProduceBlockFailure::Internal);
        };
        Ok((contents, payload_at as u32))
    }
}

fn answer(
    producers: &mut Producers,
    request_id: u64,
    block: Result<ProducedBlock, ProduceBlockFailure>,
) {
    producers.produce(BeaconApiResponse::ProducedBlock { request_id, block });
}
