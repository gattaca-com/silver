use flux::spine::SpineProducers;
use silver_beacon_state_data::{
    B256, BeaconBlockHeader, BodyFork, BodyOffsets, Eth1Data, SLOTS_PER_EPOCH, Slot, StateId,
};
use silver_common::{
    BeaconApiResponse, EngineGetPayloadReq, EngineGetPayloadResp, EnginePreparePayloadResp,
    EngineReq, MAX_BLOBS_PER_BLOCK, PayloadFrame, ProduceBlockFailure, ProducedBlock,
    TCacheProducer, TCacheRead,
};
use silver_ssz::block_body::{BeaconBlockBodyFulu, EMPTY_SYNC_AGGREGATE};

use super::{BeaconStateTile, Producers};
use crate::stf::{self, BlockInput};

/// Offsets of `block`, `kzg_proofs` and `blobs`.
const BLOCK_CONTENTS_FIXED: usize = 3 * 4;
/// `slot`, `proposer_index`, `parent_root`, `state_root` and the body offset.
const BEACON_BLOCK_FIXED: usize = 8 + 8 + 32 + 32 + 4;

#[derive(Clone, Copy)]
pub(super) struct BlockRequest {
    pub(super) request_id: u64,
    pub(super) slot: Slot,
    pub(super) randao_reveal: [u8; 96],
    pub(super) graffiti: [u8; 32],
}

/// What makes two requests for one slot ask for the same block.
#[derive(Clone, Copy, PartialEq, Eq)]
struct BlockInputs {
    parent_root: B256,
    randao_reveal: [u8; 96],
    graffiti: [u8; 32],
}

/// Fixed when the build starts, so a head that moves meanwhile does not
/// change the block under assembly.
#[derive(Clone, Copy)]
struct BuildContext {
    parent_state: StateId,
    proposer_index: u64,
}

#[derive(Clone, Copy)]
enum Stage {
    Idle,
    Preparing { id: u64, context: BuildContext },
    Fetching { id: u64, context: BuildContext },
    Built(ProducedBlock),
}

/// The block for `slot`: every request with the same inputs gets the same
/// one, built once.
pub(super) struct BlockProduction {
    slot: Slot,
    inputs: BlockInputs,
    stage: Stage,
    waiters: Vec<u64>,
    next_payload_request: u64,
}

impl Default for BlockProduction {
    fn default() -> Self {
        Self {
            slot: 0,
            inputs: BlockInputs { parent_root: [0; 32], randao_reveal: [0; 96], graffiti: [0; 32] },
            stage: Stage::Idle,
            waiters: Vec::new(),
            next_payload_request: 0,
        }
    }
}

impl BlockProduction {
    fn track(&mut self, slot: Slot, inputs: BlockInputs, producers: &mut Producers) {
        self.finish(Err(ProduceBlockFailure::Superseded), producers);
        self.slot = slot;
        self.inputs = inputs;
    }

    /// A failure leaves the slot idle, so a retry builds again.
    fn finish(
        &mut self,
        block: Result<ProducedBlock, ProduceBlockFailure>,
        producers: &mut Producers,
    ) {
        for request_id in self.waiters.drain(..) {
            answer(producers, request_id, block);
        }
        self.stage = match block {
            Ok(block) => Stage::Built(block),
            Err(_) => Stage::Idle,
        };
    }
}

impl BeaconStateTile {
    pub(super) fn produce_block(&mut self, request: BlockRequest, producers: &mut Producers) {
        let BlockRequest { request_id, slot, randao_reveal, graffiti } = request;
        let inputs = BlockInputs { parent_root: self.head_block_root(), randao_reveal, graffiti };
        let production = &mut self.block_production;
        if slot < production.slot {
            return answer(producers, request_id, Err(ProduceBlockFailure::SlotNotProposable));
        }
        if slot != production.slot || inputs != production.inputs {
            production.track(slot, inputs, producers);
        }
        production.waiters.push(request_id);
        match production.stage {
            Stage::Built(block) => return production.finish(Ok(block), producers),
            Stage::Preparing { .. } | Stage::Fetching { .. } => return,
            Stage::Idle => {}
        }

        let stage = self.start_build(slot, producers);
        let production = &mut self.block_production;
        match stage {
            Ok(stage) => production.stage = stage,
            Err(failure) => production.finish(Err(failure), producers),
        }
    }

    fn start_build(
        &mut self,
        slot: Slot,
        producers: &mut Producers,
    ) -> Result<Stage, ProduceBlockFailure> {
        if slot <= self.last_applied_block_slot() || slot > self.ticker.current_slot() + 1 {
            return Err(ProduceBlockFailure::SlotNotProposable);
        }
        let proposer_index = self.proposer_on_head(slot).ok_or(ProduceBlockFailure::Internal)?;
        let context = BuildContext { parent_state: self.last_applied, proposer_index };

        // A head that moved after the preparation tick left no payload to fetch.
        let parent_root = self.block_production.inputs.parent_root;
        Ok(match self.payload_preparations.payload_id(slot, parent_root) {
            Some(payload_id) => {
                Stage::Fetching { id: self.request_payload(payload_id, producers), context }
            }
            None => Stage::Preparing { id: self.prepare_payload(slot, producers)?, context },
        })
    }

    fn request_payload(&mut self, payload_id: [u8; 8], producers: &mut Producers) -> u64 {
        let id = self.block_production.next_payload_request;
        self.block_production.next_payload_request += 1;
        producers.produce(EngineReq::GetPayload(EngineGetPayloadReq { id, payload_id }));
        id
    }

    pub(super) fn on_payload_prepared(
        &mut self,
        response: EnginePreparePayloadResp,
        producers: &mut Producers,
    ) {
        self.payload_preparations.on_response(response);
        let Stage::Preparing { id, context } = self.block_production.stage else {
            return;
        };
        if id != response.id {
            return;
        }
        let Some(payload_id) = response.payload_id else {
            return self
                .block_production
                .finish(Err(ProduceBlockFailure::PayloadUnavailable), producers);
        };
        let id = self.request_payload(payload_id, producers);
        self.block_production.stage = Stage::Fetching { id, context };
    }

    pub(super) fn on_payload(&mut self, response: EngineGetPayloadResp, producers: &mut Producers) {
        let Stage::Fetching { id, context } = self.block_production.stage else {
            return;
        };
        if id != response.id {
            return;
        }
        let block = match response.data {
            Some(data) => self.assemble_block(context, data),
            None => Err(ProduceBlockFailure::PayloadUnavailable),
        };
        self.block_production.finish(block, producers);
    }

    fn assemble_block(
        &mut self,
        context: BuildContext,
        data: TCacheRead,
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        let BlockProduction { slot, inputs, .. } = self.block_production;
        let acquired = self.reader.acquire(data);
        let Ok((frame, _)) = acquired.buffer() else {
            tracing::error!(slot, "payload overwritten before the block was assembled");
            return Err(ProduceBlockFailure::Internal);
        };
        let Some(frame) = PayloadFrame::parse(frame) else {
            tracing::error!(slot, "payload frame is misframed");
            return Err(ProduceBlockFailure::Internal);
        };
        if frame.blob_count > MAX_BLOBS_PER_BLOCK {
            tracing::warn!(slot, blobs = frame.blob_count, "EL returned an unusable blobs bundle");
            return Err(ProduceBlockFailure::Invalid);
        }

        let parent = self.epoch_start_state(context.parent_state, slot);
        let eth1_data = encode_eth1_data(&self.state.read_view(parent).slot.state().eth1_data);
        let body = BeaconBlockBodyFulu {
            randao_reveal: &inputs.randao_reveal,
            eth1_data: &eth1_data,
            graffiti: &inputs.graffiti,
            proposer_slashings: &[],
            attester_slashings: &[],
            attestations: &[],
            deposits: &[],
            voluntary_exits: &[],
            sync_aggregate: &EMPTY_SYNC_AGGREGATE,
            execution_payload: frame.execution_payload,
            bls_to_execution_changes: &[],
            blob_kzg_commitments: frame.commitments,
            execution_requests: frame.execution_requests,
        };
        let header = BeaconBlockHeader {
            slot,
            proposer_index: context.proposer_index,
            parent_root: inputs.parent_root,
            state_root: [0; 32],
            body_root: [0; 32],
        };
        let contents = self.write_block_contents(header, parent, &body, &frame);
        tracing::info!(slot, blobs = frame.blob_count, ok = contents.is_ok(), "block assembled");
        Ok(ProducedBlock { contents: contents?, execution_payload_value: frame.block_value })
    }

    /// Lays the block contents out in their tcache slot and seals the header
    /// over the body in place, so the payload is copied once.
    fn write_block_contents(
        &mut self,
        mut header: BeaconBlockHeader,
        parent: StateId,
        body: &BeaconBlockBodyFulu<'_>,
        frame: &PayloadFrame<'_>,
    ) -> Result<TCacheRead, ProduceBlockFailure> {
        let block_len = BEACON_BLOCK_FIXED + body.ssz_len();
        let proofs_at = BLOCK_CONTENTS_FIXED + block_len;
        let blobs_at = proofs_at + frame.cell_proofs.len();
        let len = blobs_at + frame.blobs.len();

        let Some(mut reservation) = self.events_producer.reserve(len, true) else {
            tracing::error!(slot = header.slot, len, "beacon_state tcache full; block not served");
            return Err(ProduceBlockFailure::Internal);
        };
        let Ok(buffer) = reservation.buffer() else {
            tracing::error!(slot = header.slot, "block contents reservation is unwritable");
            return Err(ProduceBlockFailure::Internal);
        };
        let (fixed, rest) = buffer[..len].split_at_mut(BLOCK_CONTENTS_FIXED);
        for (offset, at) in
            fixed.chunks_exact_mut(4).zip([BLOCK_CONTENTS_FIXED, proofs_at, blobs_at])
        {
            offset.copy_from_slice(&(at as u32).to_le_bytes());
        }
        let (block, rest) = rest.split_at_mut(block_len);
        let (proofs, blobs) = rest.split_at_mut(frame.cell_proofs.len());
        proofs.copy_from_slice(frame.cell_proofs);
        blobs.copy_from_slice(frame.blobs);

        let (block_fixed, body_ssz) = block.split_at_mut(BEACON_BLOCK_FIXED);
        body.encode(body_ssz);
        self.seal_header(&mut header, parent, body_ssz)?;
        block_fixed[..8].copy_from_slice(&header.slot.to_le_bytes());
        block_fixed[8..16].copy_from_slice(&header.proposer_index.to_le_bytes());
        block_fixed[16..48].copy_from_slice(&header.parent_root);
        block_fixed[48..80].copy_from_slice(&header.state_root);
        block_fixed[80..].copy_from_slice(&(BEACON_BLOCK_FIXED as u32).to_le_bytes());

        reservation.increment_offset(len);
        Ok(reservation.read())
    }

    /// Fills `body_root` and `state_root`; the state transition runs on a
    /// fork that is never committed.
    fn seal_header(
        &mut self,
        header: &mut BeaconBlockHeader,
        parent: StateId,
        body: &[u8],
    ) -> Result<(), ProduceBlockFailure> {
        let slot = header.slot;
        let offsets = BodyOffsets::validated(body, BodyFork::Fulu).map_err(|e| {
            tracing::warn!(?e, slot, "assembled body is not canonical");
            ProduceBlockFailure::Invalid
        })?;
        let (body_root, fork) = stf::hash_body(&offsets);
        header.body_root = body_root;

        let epoch = slot / SLOTS_PER_EPOCH;
        let shuffling = {
            let view = self.state.read_view(parent);
            self.shuffling_cache.ensure_window(&view, epoch);
            self.shuffling_cache.build_ref(&view, epoch)
        };
        // Never committed: the ring slots it rolls are freed with the tail.
        let mut fork_writer = self.state.apply_block_view(parent);
        let mut votes = self.stf_scratch.votes.take();
        let input =
            BlockInput { header: &*header, block_root: [0; 32], body, fork, shuffling: &shuffling };
        let state_root = stf::post_state_root(
            &self.spec,
            &mut fork_writer,
            &input,
            &mut self.stf_scratch,
            &mut self.sig_batch,
            &mut votes,
        );
        self.stf_scratch.votes.recycle(votes);
        header.state_root = state_root.map_err(|e| {
            tracing::warn!(?e, slot, "assembled block fails the state transition");
            ProduceBlockFailure::Invalid
        })?;
        Ok(())
    }
}

fn encode_eth1_data(eth1_data: &Eth1Data) -> [u8; 72] {
    let mut out = [0; 72];
    out[..32].copy_from_slice(&eth1_data.deposit_root);
    out[32..40].copy_from_slice(&eth1_data.deposit_count.to_le_bytes());
    out[40..].copy_from_slice(&eth1_data.block_hash);
    out
}

fn answer(
    producers: &mut Producers,
    request_id: u64,
    block: Result<ProducedBlock, ProduceBlockFailure>,
) {
    producers.produce(BeaconApiResponse::ProducedBlock { request_id, block });
}
