use std::{
    io::Write,
    mem,
    time::{Duration, Instant},
};

use flux::spine::SpineProducers;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, BUILDER_INDEX_SELF_BUILD, BeaconBlockHeader, BodyFork, BodyOffsets, ExecutionAddress,
    ExecutionPayloadBid, SLOTS_PER_EPOCH, Slot, StateId,
};
use silver_common::{
    BeaconApiResponse, BidPolicy, BuilderBid, BuilderBidsRequest, BuilderBidsResponse,
    EngineGetPayloadReq, EngineGetPayloadResp, EnginePreparePayloadReq, EnginePreparePayloadResp,
    EngineReq, PayloadFrame, ProduceBlockFailure, ProducedBlock, ProducedEnvelope,
    SidecarBidRequest, SidecarBidResponse, TCacheProducer, TCacheRead, TRead,
    ssz_hash_gloas::{
        EMPTY_EXECUTION_REQUESTS, EMPTY_EXECUTION_REQUESTS_ROOT, ExecutionRequestsView,
    },
    ssz_view::{
        BEACON_BLOCK_BODY_FIXED, BLOCK_SYNC_AGGREGATE_SIZE, BuilderBidFuluView,
        ExecutionPayloadEnvelopeView, ExecutionPayloadView, SignedBuilderBidFuluView,
        SignedExecutionPayloadBidView,
    },
    wei_saturating,
};
use silver_slashing::Selection;
use silver_ssz::block_body::{BeaconBlockBodyFulu, BeaconBlockBodyGloas, EMPTY_SYNC_AGGREGATE};

use super::{
    BeaconStateTile, Feedback, Producers,
    bid_pool::BidBranch,
    block::AppliedBlock,
    payload_attributes::{PayloadBasis, PayloadContext},
};
use crate::{
    bls::G2_POINT_AT_INFINITY,
    ssz_hash,
    stf::{self, BlockFork, BlockInput, decode_bid, get_expected_withdrawals},
};

mod attestation_rewards;
mod bid_weight;
mod local_payloads;

use attestation_rewards::AttestationRewards;
use bid_weight::BidWeight;
use local_payloads::LocalPayloads;

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
    pub(super) bid_policy: BidPolicy,
    pub(super) builder_config_hash: Option<B256>,
}

impl Proposal {
    fn builds_on(&self, slot: Slot, parent_root: B256) -> bool {
        self.slot == slot && self.parent_root == parent_root
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadStage {
    /// Not asked of the EL, or refused by it.
    Idle,
    Preparing,
    Prepared {
        payload_id: [u8; 8],
    },
    Fetching {
        payload_id: [u8; 8],
    },
}

/// The one block being built, for `slot` on `parent_root`: the EL's payload
/// and the sidecar's bid. `engine_id` tags the EL's requests, so a stale
/// answer finds nothing.
struct BlockBuild {
    slot: Slot,
    parent_root: B256,
    engine_id: u64,
    stage: PayloadStage,
    context: Option<PayloadContext>,
    local: Option<Result<TRead, ProduceBlockFailure>>,
    payload_deadline: Option<Instant>,
    parent_hash: B256,
    bid: SidecarBid,
}

enum SidecarBid {
    NotAsked,
    Awaiting,
    Answered(Option<TRead>),
}

impl BlockBuild {
    fn builds_on(&self, slot: Slot, parent_root: B256) -> bool {
        self.slot == slot && self.parent_root == parent_root
    }

    fn fetch(&mut self, payload_id: [u8; 8], producers: &mut Producers) {
        let id = self.engine_id;
        producers.produce(EngineReq::GetPayload(EngineGetPayloadReq {
            id,
            payload_id,
            is_gloas: self.context.expect("payload prepared before fetch").is_gloas,
        }));
        self.stage = PayloadStage::Fetching { payload_id };
    }

    fn is_complete(&self) -> bool {
        self.local.is_some() && !matches!(self.bid, SidecarBid::Awaiting)
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
    /// Gloas only.
    pub(super) payload_attestations: &'a [u8],
}

impl Operations<'static> {
    pub(super) const NONE: Self = Self {
        proposer_slashings: &[],
        attester_slashings: &[],
        attestations: &[],
        voluntary_exits: &[],
        sync_aggregate: &EMPTY_SYNC_AGGREGATE,
        bls_to_execution_changes: &[],
        payload_attestations: &[],
    };
}

pub(super) struct PackedOperations {
    slashings: Selection,
    attestations: Vec<u8>,
    voluntary_exits: Vec<u8>,
    sync_aggregate: [u8; BLOCK_SYNC_AGGREGATE_SIZE],
    bls_to_execution_changes: Vec<u8>,
    payload_attestations: Vec<u8>,
}

impl Default for PackedOperations {
    fn default() -> Self {
        Self {
            slashings: Selection::default(),
            attestations: Vec::new(),
            voluntary_exits: Vec::new(),
            sync_aggregate: EMPTY_SYNC_AGGREGATE,
            bls_to_execution_changes: Vec::new(),
            payload_attestations: Vec::new(),
        }
    }
}

impl PackedOperations {
    fn clear(&mut self) {
        self.slashings.clear();
        self.attestations.clear();
        self.voluntary_exits.clear();
        self.sync_aggregate = EMPTY_SYNC_AGGREGATE;
        self.bls_to_execution_changes.clear();
        self.payload_attestations.clear();
    }

    fn operations(&self) -> Operations<'_> {
        Operations {
            proposer_slashings: self.slashings.proposer_slashings(),
            attester_slashings: self.slashings.attester_slashings(),
            attestations: &self.attestations,
            voluntary_exits: &self.voluntary_exits,
            sync_aggregate: &self.sync_aggregate,
            bls_to_execution_changes: &self.bls_to_execution_changes,
            payload_attestations: &self.payload_attestations,
        }
    }
}

struct BidCommitment {
    /// SSZ `SignedExecutionPayloadBid`.
    signed_bid: Vec<u8>,
    /// Little-endian wei, including unweighted execution payments.
    value: [u8; 32],
    weight: BidWeight,
    local: Option<TCacheRead>,
    /// The parent payload's requests when building on it, else empty.
    parent_requests: Box<[u8]>,
    builds_on_full_parent: bool,
    builder_entry: Option<u32>,
}

/// A builder-API bid that passed its checks and its entry's terms.
struct WeighedBid<'a> {
    /// `builder_boost_factor` times the counted payment.
    weight: BidWeight,
    value: u128,
    entry: u32,
    signed_bid: &'a [u8],
}

/// The committed post-state lets import skip the signed block's state
/// transition.
struct BuiltBlock {
    proposal: Proposal,
    block: ProducedBlock,
    payload: Option<TRead>,
    body_root: B256,
    block_fork: BlockFork,
    block_root: B256,
    post_state: Option<AppliedBlock>,
    execution_parent: Option<(B256, bool)>,
}

struct PendingGloas {
    request_id: u64,
    proposal: Proposal,
    bids: SidecarBid,
    deadline: Instant,
}

pub(super) struct BlockProduction {
    building: Option<BlockBuild>,
    pending: Vec<(u64, Proposal)>,
    pending_gloas: Vec<PendingGloas>,
    built: Option<BuiltBlock>,
    local_payloads: LocalPayloads,
    next_engine_id: u64,
    packed: PackedOperations,
    payload_timeout: Duration,
}

/// What the EL said of the payload it built.
#[derive(Clone, Copy)]
struct LocalPayload {
    value: [u8; 32],
    should_override_builder: bool,
}

impl BlockProduction {
    pub(super) fn new(payload_timeout: Duration) -> Self {
        Self {
            building: None,
            pending: Vec::new(),
            pending_gloas: Vec::new(),
            built: None,
            local_payloads: LocalPayloads::default(),
            next_engine_id: 0,
            packed: PackedOperations::default(),
            payload_timeout,
        }
    }

    fn building_on(&mut self, slot: Slot, parent_root: B256) -> Option<&mut BlockBuild> {
        self.building.as_mut().filter(|build| build.builds_on(slot, parent_root))
    }

    #[cfg(test)]
    pub(super) fn payload_id(&mut self, slot: Slot, parent_root: B256) -> Option<[u8; 8]> {
        match self.building_on(slot, parent_root)?.stage {
            PayloadStage::Prepared { payload_id } | PayloadStage::Fetching { payload_id } => {
                Some(payload_id)
            }
            PayloadStage::Idle | PayloadStage::Preparing => None,
        }
    }

    #[cfg(test)]
    pub(super) fn awaits_local_payload(&mut self, slot: Slot, parent_root: B256) -> bool {
        self.building_on(slot, parent_root).is_some_and(|build| build.local.is_none())
    }

    /// The build for `slot` on `parent_root`, replacing another one. Requests
    /// still waiting on the replaced build fail: its parent has been
    /// overtaken.
    fn build(
        &mut self,
        slot: Slot,
        parent_root: B256,
        producers: &mut Producers,
    ) -> &mut BlockBuild {
        if self.building_on(slot, parent_root).is_none() {
            for (request_id, _) in
                self.pending.extract_if(.., |(_, proposal)| !proposal.builds_on(slot, parent_root))
            {
                answer(producers, request_id, Err(ProduceBlockFailure::PayloadUnavailable));
            }
            for pending in self
                .pending_gloas
                .extract_if(.., |pending| !pending.proposal.builds_on(slot, parent_root))
            {
                answer(producers, pending.request_id, Err(ProduceBlockFailure::PayloadUnavailable));
            }
            self.building = Some(BlockBuild {
                slot,
                parent_root,
                engine_id: 0,
                stage: PayloadStage::Idle,
                context: None,
                local: None,
                payload_deadline: None,
                parent_hash: [0; 32],
                bid: SidecarBid::NotAsked,
            });
        }
        self.building.as_mut().expect("built above")
    }

    fn begin_preparation(
        &mut self,
        slot: Slot,
        parent_root: B256,
        context: PayloadContext,
        producers: &mut Producers,
    ) -> u64 {
        let id = self.next_engine_id;
        self.next_engine_id += 1;
        let waiting =
            self.pending.iter().any(|(_, proposal)| proposal.builds_on(slot, parent_root)) ||
                self.pending_gloas
                    .iter()
                    .any(|pending| pending.proposal.builds_on(slot, parent_root));
        self.built.take_if(|built| built.proposal.builds_on(slot, parent_root) && context.is_gloas);
        let build = self.build(slot, parent_root, producers);
        build.engine_id = id;
        build.stage = PayloadStage::Preparing;
        build.context = Some(context);
        build.local = None;
        if !waiting {
            build.payload_deadline = None;
        }
        self.local_payloads.retain_branch(slot, parent_root, context.head_block_hash);
        id
    }

    fn take_pending(&mut self, slot: Slot, parent_root: B256) -> Vec<(u64, Proposal)> {
        self.pending.extract_if(.., |(_, proposal)| proposal.builds_on(slot, parent_root)).collect()
    }

    fn built_for(&self, proposal: &Proposal) -> Option<ProducedBlock> {
        self.built.as_ref().filter(|built| built.proposal == *proposal).map(|built| built.block)
    }

    pub(super) fn prepared_slot(&self) -> Option<Slot> {
        self.building.as_ref().filter(|build| build.stage != PayloadStage::Idle).map(|b| b.slot)
    }

    pub(super) fn prune_before(&mut self, slot: Slot, producers: &mut Producers) {
        self.building.take_if(|build| build.slot < slot);
        if let Some(built) = self.built.as_mut().filter(|built| built.proposal.slot < slot) {
            built.payload = None;
        }
        for (request_id, _) in self.pending.extract_if(.., |(_, p)| p.slot < slot) {
            answer(producers, request_id, Err(ProduceBlockFailure::PayloadUnavailable));
        }
        self.local_payloads.prune_before(slot);
        for pending in self.pending_gloas.extract_if(.., |pending| pending.proposal.slot < slot) {
            answer(producers, pending.request_id, Err(ProduceBlockFailure::PayloadUnavailable));
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
    pub(super) fn local_payload_envelope(
        &mut self,
        slot: Slot,
        block_root: &B256,
    ) -> Option<ProducedEnvelope> {
        if slot != self.ticker.current_slot() {
            return None;
        }
        let envelope = self.block_production.local_payloads.get(slot, block_root)?;
        let parent_root = *ExecutionPayloadEnvelopeView::parent_beacon_block_root(&envelope.header);
        let head = self.head_block_root();
        if head != *block_root {
            if head != parent_root {
                return None;
            }
            let (parent_hash, _) = self.execution_parent(slot, parent_root).ok()?;
            let payload = self.reader.acquire(envelope.payload);
            let frame = PayloadFrame::parse(payload.buffer().ok()?.0)?;
            if *ExecutionPayloadView::parent_hash(frame.execution_payload) != parent_hash {
                return None;
            }
        }
        Some(envelope)
    }

    fn cached_block(&mut self, proposal: &Proposal) -> Option<ProducedBlock> {
        let block = self.block_production.built_for(proposal)?;
        let built = self.block_production.built.as_ref()?;
        if let Some(parent) = built.execution_parent &&
            (self.execution_parent(proposal.slot, proposal.parent_root).ok() != Some(parent) ||
                proposal.parent_root != self.head_block_root())
        {
            self.block_production.built = None;
            return None;
        }
        if self.events_producer.read_buffer(block.header).is_err() {
            self.block_production.built = None;
            return None;
        }
        if block.envelope_header.is_some() &&
            self.block_production.local_payloads.get(proposal.slot, &built.block_root).is_none()
        {
            return None;
        }
        Some(block)
    }

    pub(super) fn proposer_on_head(&self, slot: Slot) -> Option<u64> {
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
        let basis = self.payload_basis(slot, fallback_fee_recipient.unwrap_or_default())?;
        if !basis.local_proposer && fallback_fee_recipient.is_none() {
            return Err(ProduceBlockFailure::NoFeeRecipient);
        }
        self.prepare_payload_on(basis, producers)
    }

    pub(super) fn prepare_payload_on(
        &mut self,
        basis: PayloadBasis,
        producers: &mut Producers,
    ) -> Result<(), ProduceBlockFailure> {
        let slot = basis.slot;
        if let Some(build) = self.block_production.building_on(slot, basis.head_root) {
            if build.stage != PayloadStage::Idle && build.context == Some(basis.context) {
                return Ok(());
            }
            build.stage = PayloadStage::Idle;
            build.context = None;
            build.local = None;
        }
        let inputs = self.payload_inputs(&basis)?;

        let (head_root, context) = (basis.head_root, basis.context);
        let id = self.block_production.begin_preparation(slot, head_root, context, producers);
        producers.produce(EngineReq::PreparePayload(EnginePreparePayloadReq {
            id,
            head_block_hash: context.head_block_hash,
            safe_block_hash: basis.safe_block_hash,
            finalized_block_hash: basis.finalized_block_hash,
            attrs_timestamp: basis.timestamp,
            attrs_prev_randao: inputs.prev_randao,
            attrs_fee_recipient: context.fee_recipient,
            attrs_parent_beacon_block_root: head_root,
            attrs_withdrawals: inputs.withdrawals,
            is_gloas: context.is_gloas,
            attrs_slot_number: slot,
            attrs_target_gas_limit: context.target_gas_limit,
        }));
        silver_log::info!(slot, proposer = basis.proposer, "payload preparation requested");

        self.publish_payload_attributes(&basis, &inputs, producers);
        Ok(())
    }

    pub(super) fn refresh_payload_preparation(&mut self, producers: &mut Producers) {
        let Some(slot) = self.block_production.prepared_slot() else {
            return;
        };
        if slot >= self.ticker.current_slot() {
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
        if let Err(failure) = self.check_slot_proposable(proposal.slot) {
            return answer(producers, request_id, Err(failure));
        }
        if let Some(block) = self.cached_block(&proposal) {
            return answer(producers, request_id, Ok(block));
        }
        if self.spec.is_gloas_at_slot(proposal.slot) {
            return self.start_gloas_proposal(request_id, proposal, producers);
        }
        let local = self.start_local_payload(&proposal, producers);

        // Checked after the EL is asked, so it builds in the meantime.
        let (parent, proposer) = match self.verified_parent(&proposal) {
            Ok(verified) => verified,
            Err(failure) => return answer(producers, request_id, Err(failure)),
        };
        let asked = self.ask_sidecar_bid(&proposal, parent, proposer, producers);
        let payload_deadline = Instant::now() + self.block_production.payload_timeout;
        let build = self.block_production.build(proposal.slot, proposal.parent_root, producers);
        match local {
            Ok(()) => {
                build.local = None;
                build.payload_deadline = Some(payload_deadline);
            }
            Err(failure) if asked => build.local = Some(Err(failure)),
            Err(failure) => return answer(producers, request_id, Err(failure)),
        }
        self.block_production.pending.push((request_id, proposal));
        self.serve_complete(producers);
    }

    fn start_gloas_proposal(
        &mut self,
        request_id: u64,
        proposal: Proposal,
        producers: &mut Producers,
    ) {
        let local = self.start_local_payload(&proposal, producers);
        let (parent, proposer) = match self.verified_parent(&proposal) {
            Ok(parent) => parent,
            Err(failure) => return answer(producers, request_id, Err(failure)),
        };
        let (branch, _) = match self.bid_branch(&proposal) {
            Ok(branch) => branch,
            Err(failure) => return answer(producers, request_id, Err(failure)),
        };
        let deadline = Instant::now() + self.block_production.payload_timeout;
        let build = self.block_production.build(proposal.slot, proposal.parent_root, producers);
        match local {
            Ok(()) => {
                build.payload_deadline.get_or_insert(deadline);
            }
            Err(failure) => build.local = Some(Err(failure)),
        }
        let bids = if proposal.builder_config_hash.is_some() {
            let view = self.state.read_view(parent);
            producers.produce(BuilderBidsRequest {
                request_id,
                slot: proposal.slot,
                parent_hash: branch.parent_hash,
                parent_root: proposal.parent_root,
                proposer_pubkey: *view.validators.pubkey(proposer as usize),
            });
            SidecarBid::Awaiting
        } else {
            SidecarBid::NotAsked
        };
        self.block_production.pending_gloas.push(PendingGloas {
            request_id,
            proposal,
            bids,
            deadline,
        });
        self.serve_complete(producers);
    }

    pub(super) fn on_builder_bids(
        &mut self,
        response: BuilderBidsResponse,
        producers: &mut Producers,
    ) {
        let Some(pending) = self.block_production.pending_gloas.iter_mut().find(|pending| {
            pending.request_id == response.request_id &&
                matches!(pending.bids, SidecarBid::Awaiting)
        }) else {
            return;
        };
        pending.bids = SidecarBid::Answered(response.bids.map(|bids| self.reader.acquire(bids)));
        self.serve_complete(producers);
    }

    /// Asks the PBS client for a bid on the proposal's parent payload, unless
    /// the request weights the bid at zero. Returns whether a bid is coming.
    fn ask_sidecar_bid(
        &mut self,
        proposal: &Proposal,
        parent: StateId,
        proposer: u64,
        producers: &mut Producers,
    ) -> bool {
        if proposal.bid_policy.builder_boost_factor == 0 {
            return false;
        }
        let build = self.block_production.build(proposal.slot, proposal.parent_root, producers);
        if !matches!(build.bid, SidecarBid::NotAsked) {
            return true;
        }
        // Never committed, as in `prepare_payload`.
        let fork = self.state.apply_block_view(parent);
        let parent_header = &fork.view.slot.state().latest_execution_payload_header;
        let request = SidecarBidRequest {
            slot: proposal.slot,
            parent_hash: parent_header.block_hash,
            prev_randao: fork.view.randao_mixes.at_epoch(proposal.slot / SLOTS_PER_EPOCH),
            withdrawals_root: get_expected_withdrawals(&fork.view).root(),
            block_number: parent_header.block_number + 1,
            parent_gas_limit: parent_header.gas_limit,
            proposer_pubkey: *fork.view.validators.pubkey(proposer as usize),
        };
        let build = self.block_production.build(proposal.slot, proposal.parent_root, producers);
        build.parent_hash = request.parent_hash;
        build.bid = SidecarBid::Awaiting;
        producers.produce(request);
        true
    }

    pub(super) fn start_local_payload(
        &mut self,
        proposal: &Proposal,
        producers: &mut Producers,
    ) -> Result<(), ProduceBlockFailure> {
        if self.spec.is_gloas_at_slot(proposal.slot) {
            if proposal.parent_root != self.head_block_root() {
                return Err(ProduceBlockFailure::PayloadUnavailable);
            }
            let fee_recipient = self
                .fork_choice
                .shuffling_dependent_root(&proposal.parent_root, proposal.slot / SLOTS_PER_EPOCH)
                .and_then(|root| self.seen_proposer_preferences.get(proposal.slot, &root))
                .map(|prefs| prefs.fee_recipient)
                .or(self.default_fee_recipient);
            self.prepare_payload(proposal.slot, fee_recipient, producers)?;
        }
        match self.block_production.building_on(proposal.slot, proposal.parent_root) {
            Some(build) if build.stage != PayloadStage::Idle => {
                if let PayloadStage::Prepared { payload_id } = build.stage &&
                    (build.local.is_none() || !self.spec.is_gloas_at_slot(proposal.slot))
                {
                    build.fetch(payload_id, producers);
                }
                Ok(())
            }
            _ => self.prepare_payload(proposal.slot, self.default_fee_recipient, producers),
        }
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
        let Some(build) = production.building.as_mut().filter(|build| {
            build.engine_id == response.id && build.stage == PayloadStage::Preparing
        }) else {
            return;
        };
        // Refused: the next request prepares again.
        let Some(payload_id) = response.payload_id else {
            build.stage = PayloadStage::Idle;
            build.local = Some(Err(ProduceBlockFailure::PayloadUnavailable));
            self.serve_complete(producers);
            return;
        };
        if production.pending.is_empty() && production.pending_gloas.is_empty() {
            build.stage = PayloadStage::Prepared { payload_id };
        } else {
            build.fetch(payload_id, producers);
        }
    }

    /// The payload goes back to prepared, so a later request fetches the
    /// EL's latest build.
    #[timed]
    pub(super) fn on_payload(&mut self, response: EngineGetPayloadResp, producers: &mut Producers) {
        let Some(build) =
            self.block_production.building.as_mut().filter(|b| b.engine_id == response.id)
        else {
            return;
        };
        let PayloadStage::Fetching { payload_id } = build.stage else {
            return;
        };
        build.stage = PayloadStage::Prepared { payload_id };
        build.local = Some(
            response
                .data
                .map(|data| self.reader.acquire(data))
                .ok_or(ProduceBlockFailure::PayloadUnavailable),
        );
        self.serve_complete(producers);
    }

    /// Builds without the EL's payload once it is later than the timeout.
    pub(super) fn expire_payload_waits(&mut self, producers: &mut Producers) {
        let now = Instant::now();
        if let Some(build) = self.block_production.building.as_mut().filter(|build| {
            build.local.is_none() && build.payload_deadline.is_some_and(|deadline| deadline <= now)
        }) {
            silver_log::warn!(slot = build.slot, "the EL's payload is late; built without it");
            build.stage = PayloadStage::Idle;
            build.local = Some(Err(ProduceBlockFailure::PayloadUnavailable));
        }
        for pending in &mut self.block_production.pending_gloas {
            if pending.deadline <= now && matches!(pending.bids, SidecarBid::Awaiting) {
                silver_log::warn!(
                    slot = pending.proposal.slot,
                    "builder bids are late; used available candidates"
                );
                pending.bids = SidecarBid::Answered(None);
            }
        }
        self.serve_complete(producers);
    }

    pub(super) fn on_sidecar_bid(&mut self, answer: SidecarBidResponse, producers: &mut Producers) {
        let Some(build) = self.block_production.building.as_mut().filter(|build| {
            build.slot == answer.slot &&
                build.parent_hash == answer.parent_hash &&
                matches!(build.bid, SidecarBid::Awaiting)
        }) else {
            return;
        };
        build.bid = SidecarBid::Answered(answer.signed_bid.map(|bid| self.reader.acquire(bid)));
        self.serve_complete(producers);
    }

    fn serve_complete(&mut self, producers: &mut Producers) {
        let Some(mut build) = self.block_production.building.take_if(|build| build.is_complete())
        else {
            return;
        };
        for (request_id, proposal) in
            self.block_production.take_pending(build.slot, build.parent_root)
        {
            let block = self.build_from(proposal, &mut build);
            answer(producers, request_id, block);
        }
        let pending: Vec<_> = self
            .block_production
            .pending_gloas
            .extract_if(.., |pending| {
                pending.proposal.builds_on(build.slot, build.parent_root) &&
                    !matches!(pending.bids, SidecarBid::Awaiting)
            })
            .collect();
        for pending in pending {
            let bids = match &pending.bids {
                SidecarBid::Answered(Some(read)) => read.buffer().ok().map(|(frame, _)| frame),
                _ => None,
            }
            .unwrap_or_default();
            let branch = self.execution_parent(build.slot, build.parent_root);
            let local = build.local.as_ref().and_then(|result| result.as_ref().ok()).filter(|_| {
                build.context.is_some_and(|context| {
                    branch == Ok((context.head_block_hash, context.full_parent))
                })
            });
            let block = self.produce_gloas_block(pending.proposal, bids, local.map(TRead::to_read));
            answer(producers, pending.request_id, block);
        }
        self.block_production.building = Some(build);
    }

    /// The bid when it wins and passes the state transition, else the local
    /// payload. A bid the transition refuses is dropped.
    fn build_from(
        &mut self,
        proposal: Proposal,
        build: &mut BlockBuild,
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        let local = build.local.as_ref().expect("served once complete");
        let local_terms = local.as_ref().ok().and_then(local_payload);
        let signed_bid = match &build.bid {
            SidecarBid::Answered(Some(read)) => read.buffer().ok().map(|(bytes, _)| bytes),
            SidecarBid::NotAsked | SidecarBid::Awaiting | SidecarBid::Answered(None) => None,
        };
        let on_bid = signed_bid
            .filter(|signed_bid| self.sidecar_bid_wins(&proposal, signed_bid, local_terms))
            .map(|signed_bid| self.produce_on_sidecar_bid(proposal, signed_bid));
        let refused = match on_bid {
            Some(Ok(block)) => return Ok(block),
            Some(Err(failure)) => Some(failure),
            None => None,
        };
        if refused == Some(ProduceBlockFailure::Invalid) {
            silver_log::warn!(slot = proposal.slot, "sidecar bid fails the block; dropped");
            build.bid = SidecarBid::Answered(None);
        }

        let local = build.local.as_ref().expect("served once complete");
        match (local, refused) {
            (Ok(payload), _) => {
                let mut packed = mem::take(&mut self.block_production.packed);
                self.pack_operations(&proposal, false, &mut packed);
                let block = self.block_for(proposal, payload.to_read(), packed.operations());
                self.block_production.packed = packed;
                block
            }
            (Err(_), Some(failure)) => Err(failure),
            (Err(failure), None) => Err(*failure),
        }
    }

    fn sidecar_bid_wins(
        &self,
        proposal: &Proposal,
        signed_bid: &[u8],
        local: Option<LocalPayload>,
    ) -> bool {
        let bid = SignedBuilderBidFuluView::message(signed_bid);
        let bid_wei = wei_saturating(BuilderBidFuluView::value(bid));
        let bid_gwei = u64::try_from(bid_wei / 1_000_000_000).unwrap_or(u64::MAX);
        let wins = proposal.bid_policy.admits(bid_gwei) &&
            match local {
                None => true,
                Some(local) if local.should_override_builder => false,
                Some(local) => {
                    let boost = u128::from(proposal.bid_policy.builder_boost_factor);
                    bid_wei.saturating_mul(boost) / 100 > wei_saturating(&local.value)
                }
            };
        silver_log::info!(
            slot = proposal.slot,
            bid_wei,
            local_wei = local.map(|local| wei_saturating(&local.value)),
            should_override_builder = local.is_some_and(|local| local.should_override_builder),
            boost = proposal.bid_policy.builder_boost_factor,
            wins,
            "sidecar bid against the local payload"
        );
        wins
    }

    pub(super) fn produce_on_sidecar_bid(
        &mut self,
        proposal: Proposal,
        signed_bid: &[u8],
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        self.build_packed(proposal, false, |tile, operations| {
            tile.build_blinded_block(proposal, signed_bid, operations)
        })
    }

    #[timed]
    fn pack_operations(
        &mut self,
        proposal: &Proposal,
        builds_on_full_parent: bool,
        packed: &mut PackedOperations,
    ) {
        let Ok((parent, _)) = self.proposal_parent(proposal) else {
            return packed.clear();
        };
        let pre_state = self.state.read_view(parent);
        self.slashing_pool.select(&pre_state, &mut packed.slashings);
        let gloas = self.spec.is_gloas_at_slot(proposal.slot);
        let epoch = proposal.slot / SLOTS_PER_EPOCH;
        match self.shuffling_cache.for_block(&pre_state, epoch) {
            Some(shuffling) => {
                let rewards = AttestationRewards::new(
                    &pre_state,
                    shuffling,
                    proposal.parent_root,
                    proposal.slot,
                    builds_on_full_parent,
                );
                self.attestation_pool.pack(
                    |data, committee_index, weights| rewards.weigh(data, committee_index, weights),
                    &mut packed.attestations,
                );
            }
            None => {
                silver_log::warn!(
                    slot = proposal.slot,
                    "no shuffling for the proposal; packed no attestations"
                );
                packed.attestations.clear();
            }
        }
        self.sync_contribution_pool.write_sync_aggregate(
            proposal.slot - 1,
            proposal.parent_root,
            &mut packed.sync_aggregate,
        );
        packed.voluntary_exits.clear();
        let slashed = packed.slashings.offenders();
        self.exit_pool.select(&self.spec, &pre_state, slashed, &mut packed.voluntary_exits);
        packed.bls_to_execution_changes.clear();
        self.bls_change_pool.select(&pre_state, &mut packed.bls_to_execution_changes);
        packed.payload_attestations.clear();
        if gloas {
            self.payload_attestation_pool.select(
                &proposal.parent_root,
                proposal.slot,
                &mut packed.payload_attestations,
            );
        }
    }

    /// The built block's `(body_root, fork)` when `body` is its body. Comparing
    /// the bytes is cheaper than hashing the payload again.
    #[timed]
    pub(super) fn built_body_hash(&mut self, slot: Slot, body: &[u8]) -> Option<(B256, BlockFork)> {
        let built = self.block_production.built.as_ref().filter(|b| b.proposal.slot == slot)?;
        let contents = self.events_producer.read_buffer(built.block.header).ok()?;
        if built.block_fork.is_gloas() {
            let built_body = contents.get(BEACON_BLOCK_FIXED..)?;
            return (built_body == body).then_some((built.body_root, built.block_fork));
        }
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
        self.build_with_fallbacks(proposal, operations, |tile, operations| {
            tile.build_block(proposal, payload, operations)
        })
    }

    /// On Gloas, retries without exits first: the parent payload's withdrawal
    /// requests apply before the body and can fail an exit the pool checked
    /// on the parent state. Then retries without any packed operation.
    fn build_with_fallbacks(
        &mut self,
        proposal: Proposal,
        operations: Operations<'_>,
        mut build: impl FnMut(&mut Self, Operations<'_>) -> Result<BuiltBlock, ProduceBlockFailure>,
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        if let Some(block) = self.cached_block(&proposal) {
            return Ok(block);
        }

        let without_exits = Operations { voluntary_exits: &[], ..operations };
        let retry_without_exits =
            self.spec.is_gloas_at_slot(proposal.slot) && without_exits != operations;
        let last_tried = if retry_without_exits { without_exits } else { operations };
        let built = build(self, operations)
            .or_else(|failure| match failure {
                ProduceBlockFailure::Invalid if retry_without_exits => {
                    silver_log::warn!(
                        slot = proposal.slot,
                        "packed exits fail the block; built without them"
                    );
                    build(self, without_exits)
                }
                failure => Err(failure),
            })
            .or_else(|failure| match failure {
                ProduceBlockFailure::Invalid if last_tried != Operations::NONE => {
                    silver_log::warn!(
                        slot = proposal.slot,
                        "packed operations fail the block; built without them"
                    );
                    build(self, Operations::NONE)
                }
                failure => Err(failure),
            })?;

        let block = built.block;
        self.block_production.built = Some(built);
        Ok(block)
    }

    #[timed]
    fn produce_gloas_block(
        &mut self,
        proposal: Proposal,
        builder_bids: &[u8],
        local: Option<TCacheRead>,
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        self.check_slot_proposable(proposal.slot)?;
        if proposal.parent_root != self.head_block_root() {
            return Err(ProduceBlockFailure::PayloadUnavailable);
        }
        let (parent, _) = self.verified_parent(&proposal)?;
        let external = self.bid_commitment(&proposal, parent, builder_bids);
        let local = local.and_then(|payload| match self.local_commitment(&proposal, payload) {
            Ok(local) => Some(local),
            Err(failure) => {
                silver_log::warn!(slot = proposal.slot, ?failure, "local payload refused");
                None
            }
        });
        let local_wins = local.as_ref().is_some_and(|(bid, override_builder)| {
            *override_builder ||
                external.as_ref().is_none_or(|external| bid.weight >= external.weight)
        });
        let local = local.map(|(bid, _)| bid);
        let candidates = if local_wins { [local, external] } else { [external, local] };
        for commitment in candidates.into_iter().flatten() {
            match self.build_committed(proposal, &commitment) {
                Ok(block) => return Ok(block),
                Err(error) => {
                    silver_log::warn!(
                        slot = proposal.slot,
                        ?error,
                        "candidate failed block construction"
                    );
                }
            }
        }
        silver_log::info!(slot = proposal.slot, "no bid or local payload built; returning empty");
        let empty = self.empty_commitment(&proposal, parent)?;
        self.build_committed(proposal, &empty)
    }

    fn build_committed(
        &mut self,
        proposal: Proposal,
        commitment: &BidCommitment,
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        self.build_packed(proposal, commitment.builds_on_full_parent, |tile, operations| {
            tile.build_gloas_block(proposal, commitment, operations)
        })
    }

    fn check_slot_proposable(&self, slot: Slot) -> Result<(), ProduceBlockFailure> {
        if slot <= self.last_applied_block_slot() || slot > self.ticker.current_slot() + 1 {
            return Err(ProduceBlockFailure::SlotNotProposable);
        }
        Ok(())
    }

    fn verified_parent(
        &mut self,
        proposal: &Proposal,
    ) -> Result<(StateId, u64), ProduceBlockFailure> {
        let (parent, proposer) = self.proposal_parent(proposal)?;
        if !self.randao_reveal_verifies(parent, proposer, proposal) {
            return Err(ProduceBlockFailure::InvalidRandaoReveal);
        }
        Ok((parent, proposer))
    }

    fn build_packed(
        &mut self,
        proposal: Proposal,
        builds_on_full_parent: bool,
        build: impl FnMut(&mut Self, Operations<'_>) -> Result<BuiltBlock, ProduceBlockFailure>,
    ) -> Result<ProducedBlock, ProduceBlockFailure> {
        let mut packed = mem::take(&mut self.block_production.packed);
        self.pack_operations(&proposal, builds_on_full_parent, &mut packed);
        let block = self.build_with_fallbacks(proposal, packed.operations(), build);
        self.block_production.packed = packed;
        block
    }

    /// The branch fork choice builds the proposal on, and whether it builds
    /// on the parent's payload.
    fn bid_branch(&self, proposal: &Proposal) -> Result<(BidBranch, bool), ProduceBlockFailure> {
        let (parent_hash, full) = self.execution_parent(proposal.slot, proposal.parent_root)?;
        let branch =
            BidBranch { slot: proposal.slot, parent_root: proposal.parent_root, parent_hash };
        Ok((branch, full))
    }

    pub(super) fn execution_parent(
        &self,
        slot: Slot,
        parent_root: B256,
    ) -> Result<(B256, bool), ProduceBlockFailure> {
        let node = self.fork_choice.find_node_idx(&parent_root).ok_or_else(|| {
            silver_log::warn!(slot, "proposal parent left fork choice");
            ProduceBlockFailure::Internal
        })?;
        let full = self.fork_choice.should_build_on_full(node, slot);
        let node = self.fork_choice.node(node);
        let parent_hash = if full {
            node.payload.bid_block_hash
        } else {
            self.state.read_view(node.state_id).slot.state().latest_block_hash
        };
        Ok((parent_hash, full))
    }

    /// The heavier of the p2p pool's best bid on the branch, weighted by the
    /// request's policy, and the best of `builder_bids`, weighted by their
    /// entries' terms. A tie goes to the p2p bid.
    fn bid_commitment(
        &mut self,
        proposal: &Proposal,
        parent: StateId,
        builder_bids: &[u8],
    ) -> Option<BidCommitment> {
        let (branch, full) = self.bid_branch(proposal).ok()?;
        let mut builder: Option<WeighedBid<'_>> = None;
        for bid in BuilderBid::iter(builder_bids) {
            if let Some(bid) = self.weigh_builder_bid(&branch, bid) &&
                builder.as_ref().is_none_or(|best| bid.weight > best.weight)
            {
                builder = Some(bid);
            }
        }
        let p2p = self.payload_bids_pool.best(&branch).filter(|(bid, _)| {
            let admitted = bid.value >= proposal.bid_policy.min_bid;
            if !admitted {
                silver_log::info!(
                    slot = proposal.slot,
                    value = bid.value,
                    min_bid = proposal.bid_policy.min_bid,
                    boost = proposal.bid_policy.builder_boost_factor,
                    "best p2p bid is not admitted"
                );
            }
            admitted
        });
        let p2p_weight = p2p.map(|(bid, _)| {
            BidWeight::external(u128::from(bid.value), proposal.bid_policy.builder_boost_factor)
        });
        let builder = builder.filter(|bid| p2p_weight.is_none_or(|weight| bid.weight > weight));
        let (signed_bid, value, weight, builder_entry) = match (builder, p2p) {
            (Some(bid), _) => (bid.signed_bid.to_vec(), bid.value, bid.weight, Some(bid.entry)),
            (None, Some((bid, signature))) => {
                let mut signed_bid = Vec::new();
                bid.write_signed_ssz(signature, &mut signed_bid);
                (signed_bid, u128::from(bid.value), p2p_weight.expect("pooled bid"), None)
            }
            (None, None) => {
                silver_log::info!(slot = proposal.slot, full, "no admitted bid on the branch");
                return None;
            }
        };
        let parent_requests = self.parent_requests(full, &proposal.parent_root);
        let parent_state = self.state.read_view(parent);
        Some(BidCommitment {
            signed_bid,
            value: wei_from_gwei(value),
            weight,
            local: None,
            parent_requests,
            builds_on_full_parent: branch.parent_hash ==
                parent_state.slot.state().latest_execution_payload_bid.block_hash,
            builder_entry,
        })
    }

    /// `bid` when it is on `branch`, passes the checks a gossiped bid does,
    /// and its entry admits it.
    fn weigh_builder_bid<'a>(
        &mut self,
        branch: &BidBranch,
        bid: BuilderBid<'a>,
    ) -> Option<WeighedBid<'a>> {
        let (slot, entry) = (branch.slot, bid.entry);
        let Ok(decoded) = decode_bid(bid.signed_bid) else {
            silver_log::warn!(slot, entry, "builder bid is misframed");
            return None;
        };
        if BidBranch::from(&decoded) != *branch {
            silver_log::warn!(slot, entry, "builder bid is for another branch");
            return None;
        }
        let counted = bid.terms.counted(decoded.value, decoded.execution_payment);
        if counted < u128::from(bid.terms.min_bid) {
            silver_log::info!(
                slot,
                entry,
                counted,
                min_bid = bid.terms.min_bid,
                boost = bid.terms.builder_boost_factor,
                "builder bid is not admitted"
            );
            return None;
        }
        let signature = SignedExecutionPayloadBidView::signature(bid.signed_bid);
        if let Err(feedback) = self.check_bid_on_parent(&decoded, signature, |key| bid.accepts(key))
        {
            let reason = match feedback {
                Feedback::Reject { reason, .. } => reason,
                _ => "ignored",
            };
            silver_log::warn!(slot, entry, reason, "builder bid refused");
            return None;
        }
        let weight = BidWeight::external(counted, bid.terms.builder_boost_factor);
        silver_log::info!(
            slot,
            entry,
            value = decoded.value,
            execution_payment = decoded.execution_payment,
            ?weight,
            "builder bid verified"
        );
        let value = u128::from(decoded.value) + u128::from(decoded.execution_payment);
        Some(WeighedBid { weight, value, entry, signed_bid: bid.signed_bid })
    }

    fn local_commitment(
        &mut self,
        proposal: &Proposal,
        payload: TCacheRead,
    ) -> Result<(BidCommitment, bool), ProduceBlockFailure> {
        let acquired = self.reader.acquire(payload);
        let (bytes, _) = acquired.buffer().map_err(|_| ProduceBlockFailure::Internal)?;
        let frame = PayloadFrame::parse(bytes).ok_or(ProduceBlockFailure::Invalid)?;
        let execution = frame.execution_payload;
        let (branch, full) = self.bid_branch(proposal)?;
        if !ExecutionPayloadView::check_canonical_gloas(execution) ||
            !ExecutionRequestsView::check_canonical(frame.execution_requests) ||
            ExecutionRequestsView::check_counts(frame.execution_requests).is_err()
        {
            return Err(ProduceBlockFailure::Invalid);
        }
        let genesis_time = self.state.read_view(self.last_applied).imm.genesis_time;
        if ExecutionPayloadView::slot_number(execution) != proposal.slot ||
            *ExecutionPayloadView::parent_hash(execution) != branch.parent_hash ||
            ExecutionPayloadView::timestamp(execution) !=
                genesis_time + proposal.slot * self.spec.seconds_per_slot()
        {
            return Err(ProduceBlockFailure::Invalid);
        }
        let bid = ExecutionPayloadBid {
            parent_block_hash: branch.parent_hash,
            parent_block_root: proposal.parent_root,
            block_hash: *ExecutionPayloadView::block_hash(execution),
            prev_randao: *ExecutionPayloadView::prev_randao(execution),
            fee_recipient: *ExecutionPayloadView::fee_recipient(execution),
            gas_limit: ExecutionPayloadView::gas_limit(execution),
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: proposal.slot,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: frame
                .commitments
                .chunks_exact(48)
                .map(|commitment| commitment.try_into().expect("48 bytes"))
                .collect(),
            execution_requests_root: ExecutionRequestsView::hash_tree_root(
                frame.execution_requests,
            ),
        };
        let commitment = self.self_build_commitment(&bid, full, frame.block_value, Some(payload));
        Ok((commitment, frame.should_override_builder))
    }

    /// A self-built bid whose payload is never revealed, so the slot's
    /// payload is empty. Its `block_hash` is zero, which no parent has.
    fn empty_commitment(
        &self,
        proposal: &Proposal,
        parent: StateId,
    ) -> Result<BidCommitment, ProduceBlockFailure> {
        let (branch, full) = self.bid_branch(proposal)?;
        let bid = ExecutionPayloadBid {
            parent_block_hash: branch.parent_hash,
            parent_block_root: proposal.parent_root,
            block_hash: [0; 32],
            prev_randao: self
                .state
                .read_view(parent)
                .randao_mixes
                .at_epoch(proposal.slot / SLOTS_PER_EPOCH),
            fee_recipient: [0; 20],
            gas_limit: 0,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: proposal.slot,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: Default::default(),
            execution_requests_root: *EMPTY_EXECUTION_REQUESTS_ROOT,
        };
        Ok(self.self_build_commitment(&bid, full, [0; 32], None))
    }

    fn self_build_commitment(
        &self,
        bid: &ExecutionPayloadBid,
        builds_on_full_parent: bool,
        value: [u8; 32],
        local: Option<TCacheRead>,
    ) -> BidCommitment {
        let mut signed_bid = Vec::new();
        bid.write_signed_ssz(&G2_POINT_AT_INFINITY, &mut signed_bid);
        BidCommitment {
            signed_bid,
            value,
            weight: BidWeight::local(&value),
            local,
            parent_requests: self.parent_requests(builds_on_full_parent, &bid.parent_block_root),
            builds_on_full_parent,
            builder_entry: None,
        }
    }

    fn parent_requests(&self, builds_on_full_parent: bool, parent_root: &B256) -> Box<[u8]> {
        let requests = if builds_on_full_parent {
            self.payload_execution_requests.get(parent_root)
        } else {
            &EMPTY_EXECUTION_REQUESTS
        };
        requests.into()
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
                payload: Some(acquired.to_read()),
                envelope_header: None,
                execution_payload_value: frame.block_value,
                consensus_block_value: wei_from_gwei(post_state.proposer_reward().into()),
                builder_entry: None,
            },
            payload: Some(acquired),
            body_root,
            block_fork,
            block_root,
            post_state: Some(post_state),
            execution_parent: None,
        })
    }

    #[timed]
    fn build_gloas_block(
        &mut self,
        proposal: Proposal,
        commitment: &BidCommitment,
        operations: Operations<'_>,
    ) -> Result<BuiltBlock, ProduceBlockFailure> {
        let slot = proposal.slot;
        let (parent, proposer_index) = self.proposal_parent(&proposal)?;
        let eth1_data = self.state.read_view(parent).slot.state().eth1_data.to_ssz();
        let body = BeaconBlockBodyGloas {
            randao_reveal: &proposal.randao_reveal,
            eth1_data: &eth1_data,
            graffiti: &proposal.graffiti,
            proposer_slashings: operations.proposer_slashings,
            attester_slashings: operations.attester_slashings,
            attestations: operations.attestations,
            deposits: &[],
            voluntary_exits: operations.voluntary_exits,
            sync_aggregate: operations.sync_aggregate,
            bls_to_execution_changes: operations.bls_to_execution_changes,
            signed_execution_payload_bid: &commitment.signed_bid,
            payload_attestations: operations.payload_attestations,
            parent_execution_requests: &commitment.parent_requests,
        };
        // No payload to splice around, so the body is encoded whole.
        let mut encoded = vec![0; body.ssz_len()];
        body.encode(&mut encoded);
        let offsets = BodyOffsets::validated(&encoded, BodyFork::Gloas).map_err(|e| {
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
        let (block_root, mut post_state) = self.seal(&mut header, parent, offsets, block_fork)?;
        let execution_parent = self.execution_parent(slot, proposal.parent_root)?;
        let payload = commitment.local.map(|payload| self.reader.acquire(payload));
        let envelope_header = if let Some(payload) = &payload {
            let (bytes, _) = payload.buffer().map_err(|_| ProduceBlockFailure::Internal)?;
            let frame = PayloadFrame::parse(bytes).ok_or(ProduceBlockFailure::Invalid)?;
            let view = self.state.read_view(*post_state.state_id_mut());
            if !stf::payload_withdrawals_match_expected(&view, frame.execution_payload) {
                silver_log::warn!(slot, "local payload withdrawals differ from the proposed state");
                return Err(ProduceBlockFailure::Invalid);
            }
            let header = frame.self_build_envelope_header(block_root, proposal.parent_root);
            let branch = BidBranch {
                slot,
                parent_root: proposal.parent_root,
                parent_hash: execution_parent.0,
            };
            self.block_production.local_payloads.insert(
                branch,
                block_root,
                header,
                payload.clone(),
            );
            Some(header)
        } else {
            None
        };
        let block = self.write_block(&header, &[&encoded])?;

        silver_log::info!(
            slot,
            execution_value = wei_saturating(&commitment.value),
            builder_entry = commitment.builder_entry,
            "block assembled on a bid"
        );
        Ok(BuiltBlock {
            proposal,
            block: ProducedBlock {
                header: block,
                payload_at: (BEACON_BLOCK_FIXED + encoded.len()) as u32,
                payload: payload.as_ref().map(TRead::to_read),
                envelope_header,
                execution_payload_value: commitment.value,
                consensus_block_value: wei_from_gwei(post_state.proposer_reward().into()),
                builder_entry: commitment.builder_entry,
            },
            payload,
            body_root,
            block_fork,
            block_root,
            post_state: Some(post_state),
            execution_parent: Some(execution_parent),
        })
    }

    #[timed]
    fn build_blinded_block(
        &mut self,
        proposal: Proposal,
        signed_bid: &[u8],
        operations: Operations<'_>,
    ) -> Result<BuiltBlock, ProduceBlockFailure> {
        let slot = proposal.slot;
        let bid = SignedBuilderBidFuluView::message(signed_bid);
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
            execution_payload: BuilderBidFuluView::header(bid),
            bls_to_execution_changes: operations.bls_to_execution_changes,
            blob_kzg_commitments: BuilderBidFuluView::blob_kzg_commitments(bid),
            execution_requests: BuilderBidFuluView::execution_requests(bid),
        };
        let mut body_fixed = [0; BEACON_BLOCK_BODY_FIXED];
        let offsets = body.write_fixed_blinded(&mut body_fixed).map_err(|e| {
            silver_log::warn!(?e, slot, "assembled blinded body is not canonical");
            ProduceBlockFailure::Invalid
        })?;
        offsets.validate().map_err(|e| {
            silver_log::warn!(?e, slot, "assembled blinded body is over its limits");
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
        let mut body_parts: [&[u8]; 10] = [&[]; 10];
        body_parts[0] = offsets.fixed();
        body_parts[1..].copy_from_slice(&body.variable_fields());
        let block = self.write_block(&header, &body_parts)?;

        silver_log::info!(slot, "blinded block assembled on a sidecar bid");
        Ok(BuiltBlock {
            proposal,
            block: ProducedBlock {
                header: block,
                payload_at: (BEACON_BLOCK_FIXED + body.ssz_len()) as u32,
                payload: None,
                envelope_header: None,
                execution_payload_value: *BuilderBidFuluView::value(bid),
                consensus_block_value: wei_from_gwei(post_state.proposer_reward().into()),
                builder_entry: None,
            },
            payload: None,
            body_root,
            block_fork,
            block_root,
            post_state: Some(post_state),
            execution_parent: None,
        })
    }

    /// SSZ `BeaconBlock` with its body in `body` parts.
    fn write_block(
        &mut self,
        header: &BeaconBlockHeader,
        body: &[&[u8]],
    ) -> Result<TCacheRead, ProduceBlockFailure> {
        let len = BEACON_BLOCK_FIXED + body.iter().map(|part| part.len()).sum::<usize>();
        let block = self.events_producer.write_with(len, |mut out| {
            for part in [
                &header.slot.to_le_bytes()[..],
                &header.proposer_index.to_le_bytes(),
                &header.parent_root,
                &header.state_root,
                &(BEACON_BLOCK_FIXED as u32).to_le_bytes(),
            ]
            .into_iter()
            .chain(body.iter().copied())
            {
                out.write_all(part).expect("sized to its parts");
            }
        });
        block.ok_or_else(|| {
            silver_log::error!(
                slot = header.slot,
                len,
                "beacon_state tcache full; block not served"
            );
            ProduceBlockFailure::Internal
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
            self.shuffling_cache.for_block(&view, epoch).ok_or_else(|| {
                silver_log::error!(
                    epoch,
                    state_epoch = view.slot.current_epoch(),
                    "production shuffling unavailable from the parent state"
                );
                ProduceBlockFailure::Internal
            })?
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

fn local_payload(payload: &TRead) -> Option<LocalPayload> {
    let frame = PayloadFrame::parse(payload.buffer().ok()?.0)?;
    Some(LocalPayload {
        value: frame.block_value,
        should_override_builder: frame.should_override_builder,
    })
}

fn wei_from_gwei(gwei: u128) -> [u8; 32] {
    let mut wei = [0; 32];
    wei[..16].copy_from_slice(&(gwei * 1_000_000_000).to_le_bytes());
    wei
}

fn answer(
    producers: &mut Producers,
    request_id: u64,
    block: Result<ProducedBlock, ProduceBlockFailure>,
) {
    producers.produce(BeaconApiResponse::ProducedBlock { request_id, block });
}
