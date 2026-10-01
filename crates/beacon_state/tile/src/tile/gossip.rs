use std::fmt::{self, Display};

use flux::spine::SpineProducers;
use silver_beacon_state_data::{
    B256, Epoch, MIN_SEED_LOOKAHEAD, ParsedAggregateAndProof, SLOTS_PER_EPOCH,
    SYNC_SUBCOMMITTEE_MASK_WORDS, SYNC_SUBCOMMITTEE_SIZE, Slot, StateId, StateReadView,
    SyncSubcommittee, gloas::PTC_SIZE,
};
use silver_common::{
    BeaconStateEvent, BlockSource, EngineNewPayloadEnvelopeReq, EngineReq, GossipTopic,
    LOCAL_GOSSIP_STREAM_ID, LocalGossipFailure, MAX_BLOBS_PER_BLOCK, NewGossipMsg, PeerEvent,
    SyncNeed, TCacheRead, TRead, compute_subnet_for_attestation, hex32,
    metrics::timed,
    ssz_view::{
        AttestationDataView, AttesterSlashingView, ExecutionPayloadEnvelopeView as Envelope,
        PAYLOAD_ATTESTATION_MESSAGE_SIZE, PROPOSER_SLASHING_SIZE, PayloadAttestationDataView,
        PayloadAttestationMessageView, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
        SIGNED_CONTRIBUTION_AND_PROOF_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE,
        SYNC_COMMITTEE_MSG_SIZE, SignedBlsToExecutionChangeView,
        SignedExecutionPayloadEnvelopeView as SignedPayload, SignedSyncCommitteeProofView,
        SignedVoluntaryExitView, SingleAttestationView, SyncCommitteeView,
    },
};
use silver_ssz::ssz_view::SignedExecutionPayloadBidView;

use super::{
    BeaconStateTile, Feedback, MAXIMUM_GOSSIP_CLOCK_DISPARITY, Producers, UNSPECIFIED_REJECT,
    attestation_pool::InsertOutcome, fork_data_roots::ForkDataRoots, held_blocks::BlockSourceMsg,
    seen_aggregates::Coverage,
};
use crate::{
    bls::{self, CheckedSignature, PublicKey, VerifiedSingleAttestation},
    counters::BeaconStateCounters,
    error::ExecutionPayloadBidError as BidError,
    fork_choice::ExecutionStatus,
    merkle, ssz_hash,
    stf::{
        self, BuilderLedger, decode_bid, validate_bid_builder,
        verify_execution_payload_bid_signature,
    },
    validate,
};

pub(super) const VOTE_BATCH_CAP: usize = 1024;

pub(super) const PTC_MASK_WORDS: usize = PTC_SIZE.div_ceil(64);

pub(super) struct PreparedAttestation {
    buf: [u8; SINGLE_ATT_SIZE],
    committee_position: usize,
    committee_len: usize,
    pubkey: PublicKey,
    signing_root: B256,
    data_root: B256,
    signature: CheckedSignature,
    attester: u32,
    target: stf::VoteTarget,
}

pub(super) struct PreparedSyncMessage {
    slot: Slot,
    subnet: u64,
    validator: u64,
    block_root: B256,
    positions: [u64; SYNC_SUBCOMMITTEE_MASK_WORDS],
    pubkey: PublicKey,
    signing_root: B256,
    signature: CheckedSignature,
}

pub(crate) struct PreparedPtc {
    pub block_root: B256,
    pub slot: Slot,
    pub validator: u64,
    pub ptc_positions: [u64; PTC_MASK_WORDS],
    pub present: bool,
    pub da: bool,
    pub pubkey: PublicKey,
    pub signing_root: B256,
    pub signature: CheckedSignature,
}

#[allow(clippy::large_enum_variant)]
pub(super) enum PreparedVote {
    Attestation(PreparedAttestation),
    SyncMessage(PreparedSyncMessage),
    Ptc(PreparedPtc),
}

impl PreparedVote {
    fn sig_parts(&self) -> (&PublicKey, CheckedSignature, &B256) {
        match self {
            Self::Attestation(p) => (&p.pubkey, p.signature, &p.signing_root),
            Self::SyncMessage(p) => (&p.pubkey, p.signature, &p.signing_root),
            Self::Ptc(p) => (&p.pubkey, p.signature, &p.signing_root),
        }
    }

    /// Only attestations keep their bytes past preparation.
    fn message(&self) -> &[u8] {
        match self {
            Self::Attestation(p) => &p.buf,
            Self::SyncMessage(_) | Self::Ptc(_) => &[],
        }
    }

    fn is_seen(&self, tile: &BeaconStateTile) -> bool {
        match self {
            Self::Attestation(p) => {
                tile.seen_attesters.contains(p.target.target_epoch, p.attester as usize)
            }
            Self::SyncMessage(p) => {
                tile.seen_sync_msgs[p.subnet as usize].contains(p.slot, p.validator as usize)
            }
            Self::Ptc(p) => tile.seen_ptc.contains(p.slot, p.validator as usize),
        }
    }

    fn dedup_key(&self) -> (u8, u64, u64, u64) {
        match self {
            Self::Attestation(p) => (0, p.attester as u64, p.target.target_epoch, 0),
            Self::SyncMessage(p) => (1, p.validator, p.slot, p.subnet),
            Self::Ptc(p) => (2, p.validator, p.slot, 0),
        }
    }
}

pub(super) enum EnvelopeCheck {
    Ready { block_root: B256, state_id: StateId },
    AwaitBlock(B256),
    Ignore,
    Reject,
}

pub(super) struct BatchedVote {
    pub vote: NewGossipMsg,
    pub pin: TRead,
}

impl BeaconStateTile {
    #[timed]
    pub(super) fn handle_attestation(&mut self, data: &[u8], subnet: u64) -> Feedback {
        let prepared = match self.prepare_attestation(data, subnet) {
            Ok(prepared) => prepared,
            Err(feedback) => return feedback,
        };
        if !bls::verify_one_checked(&prepared.pubkey, &prepared.signature, &prepared.signing_root) {
            return self.reject("attestation bad signature");
        }
        self.commit_attestation(&prepared);
        Feedback::Accept
    }

    /// Everything up to (but excluding) the pairing: structural checks,
    /// dedup, committee membership, roots, signature parse + subgroup
    /// check. The pairing runs
    /// either singly (`handle_attestation`) or batched
    /// (`flush_attestations`).
    fn prepare_attestation(
        &mut self,
        data: &[u8],
        subnet: u64,
    ) -> Result<PreparedAttestation, Feedback> {
        // Exact size: trailing bytes parse fine here (fixed-size prefix) but
        // strict-SSZ peers reject the relayed message — their P4 lands on us,
        // not the originator.
        if data.len() != SINGLE_ATT_SIZE {
            return Err(self.reject("attestation size"));
        }
        let buf: &[u8; SINGLE_ATT_SIZE] = data[..SINGLE_ATT_SIZE].try_into().unwrap();
        let attester_index = SingleAttestationView::attester_index(buf) as usize;
        let block_root = *SingleAttestationView::beacon_block_root(buf);
        let target_epoch = SingleAttestationView::target_epoch(buf);
        let att_slot = SingleAttestationView::slot(buf);
        let committee_index = SingleAttestationView::committee_index(buf) as usize;

        if !self.attestation_slot_is_open(att_slot) {
            return Err(self.slot_window_miss(att_slot));
        }

        self.seen_attesters.rotate_to(self.seen_window_epoch());
        if self.seen_attesters.contains(target_epoch, attester_index) {
            return Err(Feedback::AlreadySeen);
        }

        // Pre-Gloas single attestations encode the committee in
        // `committee_index`, so `AttestationData.index` must be 0. Gloas widens
        // it to a payload-status bit (`index == 1` ⇒ payload present).
        let data_index = SingleAttestationView::data_index(buf);
        let is_gloas = self.spec.is_gloas_at(target_epoch);
        if !validate::attestation_index_ok(is_gloas, data_index) {
            return Err(self.reject("attestation data index"));
        }
        self.validate_attestation_target(SingleAttestationView::data(buf))?;
        let payload_present = if is_gloas {
            self.gloas_payload_present(&block_root, att_slot, data_index)?
        } else {
            false
        };

        let canon_id = self.canonical_state_id();
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        // Validate committee membership against the canonical head.
        let view = self.state.read_view(canon_id);
        self.shuffling_cache.ensure_window(&view, att_epoch);
        let Some(shuffling) = self.shuffling_cache.lookup(&view, att_epoch) else {
            return Err(Feedback::Ignore);
        };
        if committee_index >= shuffling.committees_per_slot {
            return Err(self.reject("attestation committee index out of range"));
        }
        if subnet !=
            compute_subnet_for_attestation(
                shuffling.committees_per_slot as u64,
                att_slot,
                committee_index as u64,
            )
        {
            return Err(self.reject("attestation wrong subnet"));
        }
        let committee = shuffling.committee(att_slot, committee_index);
        let Some(committee_position) = committee.iter().position(|&v| v == attester_index as u32)
        else {
            return Err(self.reject("attester not in committee"));
        };
        let committee_len = committee.len();
        if attester_index >= view.validators.count() {
            return Err(self.reject("attester index out of range"));
        }
        let fork_version = view.epoch.fork_version_at(target_epoch);
        let domain = bls::domain_from_fork_data(
            bls::DOMAIN_BEACON_ATTESTER,
            &self.fork_data_roots.root(fork_version, &view.imm.genesis_validators_root),
        );
        let (data_root, signing_root) =
            self.attestation_root_memo.roots(SingleAttestationView::data(buf).as_bytes(), &domain);
        let Some(signature) = CheckedSignature::parse(SingleAttestationView::signature(buf)) else {
            return Err(self.reject("attestation signature malformed"));
        };

        Ok(PreparedAttestation {
            buf: *buf,
            committee_position,
            committee_len,
            pubkey: *view.validators.pubkey_decompressed(attester_index),
            signing_root,
            data_root,
            signature,
            attester: attester_index as u32,
            target: stf::VoteTarget {
                block_root,
                target_epoch,
                attestation_slot: att_slot,
                payload_present,
            },
        })
    }

    fn commit_attestation(&mut self, p: &PreparedAttestation) {
        let verified =
            VerifiedSingleAttestation { data_root: p.data_root, signature: *p.signature.as_sig() };
        let outcome = self.attestation_pool.insert_verified(
            &p.buf,
            p.committee_position,
            p.committee_len,
            &verified,
        );
        debug_assert!(outcome != InsertOutcome::Inconsistent);
        if outcome == InsertOutcome::Full {
            BeaconStateCounters::AttestationPoolFull.inc();
            silver_log::debug!(
                slot = p.target.attestation_slot,
                committee = SingleAttestationView::committee_index(&p.buf),
                "attestation pool full"
            );
        }

        let n = self.head_validator_count();
        let slot = self.ticker.current_slot();
        self.fork_choice.record_or_defer_votes(
            p.target,
            std::slice::from_ref(&p.attester),
            n,
            slot,
        );

        self.seen_attesters.mark(p.target.target_epoch, p.attester as usize);
    }

    pub(super) fn defer_vote(&mut self, vote: NewGossipMsg, producers: &mut Producers) {
        let pin = self.reader.acquire(vote.ssz);
        self.vote_batch.push(BatchedVote { vote, pin });
        if self.vote_batch.len() >= VOTE_BATCH_CAP {
            self.flush_votes(producers);
        }
    }

    pub(super) fn flush_votes(&mut self, producers: &mut Producers) {
        if !self.vote_batch.is_empty() {
            self.verify_and_commit_votes(producers);
        }
    }

    /// Apply the deferred votes (attestations, sync committee messages, PTC
    /// attestations): sequential cheap validation in arrival order, then one
    /// multi-pairing verify for the survivors. A failed batch falls back to
    /// per-message verification so only the culprits are rejected.
    #[timed]
    fn verify_and_commit_votes(&mut self, producers: &mut Producers) {
        debug_assert!(!self.vote_batch.is_empty());
        BeaconStateCounters::VoteBatchSize.set(self.vote_batch.len() as u64);

        self.sig_batch.clear();
        debug_assert!(self.vote_pending.is_empty());

        // Drain from the back after one in-place reversal: this preserves
        // arrival order without O(n) front-removes or another allocation.
        self.vote_batch.reverse();
        while let Some(BatchedVote { vote, pin }) = self.vote_batch.pop() {
            let Some(data) = pin.buffer().ok().map(|(d, _)| d) else {
                Self::local_verdict(&vote, Feedback::Ignore, producers);
                continue;
            };
            let prepared = match vote.topic {
                GossipTopic::BeaconAttestation(subnet) => {
                    self.prepare_attestation(data, subnet).map(PreparedVote::Attestation)
                }
                GossipTopic::SyncCommittee(subnet) => {
                    self.prepare_sync_message(data, subnet).map(PreparedVote::SyncMessage)
                }
                GossipTopic::PayloadAttestationMessage => {
                    self.prepare_ptc(data).map(PreparedVote::Ptc)
                }
                _ => continue,
            };
            match prepared {
                Ok(p) => {
                    // Pair only the first candidate for each dedup key, but
                    // retain later candidates. If that representative makes
                    // the batch fail, fallback verification can still find a
                    // later valid candidate for the same key. A sync message
                    // on several subnets carries one signature, paired once.
                    let key = p.dedup_key();
                    let (pk, sig, root) = p.sig_parts();
                    let paired = self.vote_pending.iter().any(|(_, q)| q.dedup_key() == key) ||
                        matches!(p, PreparedVote::SyncMessage(_)) &&
                            self.sig_batch.contains(pk, sig, root);
                    if !paired {
                        self.sig_batch.push_parsed(pk, sig, *root);
                    }
                    self.vote_pending.push((vote, p));
                }
                Err(Feedback::Reject(_)) => self.reject_gossip(&vote, data, producers),
                Err(feedback @ Feedback::RequestEnvelope { block_root, att_slot }) => {
                    producers.produce(SyncNeed::missing_envelope(block_root, att_slot));
                    Self::local_verdict(&vote, feedback, producers);
                }
                Err(feedback) => Self::local_verdict(&vote, feedback, producers),
            }
        }

        let batch_ok = self.sig_batch.verify_all();
        if !batch_ok && !self.vote_pending.is_empty() {
            BeaconStateCounters::VoteBatchFallback.inc();
        }

        let mut accepted = false;
        let mut committed_ptc = false;
        self.vote_pending.reverse();
        while let Some((m, p)) = self.vote_pending.pop() {
            // Deduplicate only against votes whose signatures have already
            // verified and been committed. An invalid earlier arrival with
            // the same key must not suppress a later valid vote.
            if p.is_seen(self) {
                Self::local_verdict(&m, Feedback::AlreadySeen, producers);
                continue;
            }
            let (pk, sig, root) = p.sig_parts();
            let valid = batch_ok || bls::verify_one_checked(pk, &sig, root);
            if valid {
                match &p {
                    PreparedVote::Attestation(p) => self.commit_attestation(p),
                    PreparedVote::SyncMessage(p) => self.commit_sync_message(p),
                    PreparedVote::Ptc(p) => {
                        self.commit_ptc(p);
                        committed_ptc = true;
                    }
                }
                Self::relay_gossip(&m, producers);
                accepted = true;
            } else {
                self.reject_reason.set("vote bad signature");
                self.reject_gossip(&m, p.message(), producers);
            }
        }

        // PTC votes all dirty the same fork-choice structure; fold the whole
        // flush in one head recomputation rather than once per message.
        if committed_ptc {
            self.recompute_head();
        }

        if accepted {
            self.publish_status(producers);
        }
    }

    pub(super) fn prepare_sync_message(
        &mut self,
        data: &[u8],
        subnet: u64,
    ) -> Result<PreparedSyncMessage, Feedback> {
        if data.len() != SYNC_COMMITTEE_MSG_SIZE {
            return Err(self.reject("sync message size"));
        }
        let buf: &[u8; SYNC_COMMITTEE_MSG_SIZE] =
            data[..SYNC_COMMITTEE_MSG_SIZE].try_into().unwrap();
        let slot = SyncCommitteeView::slot(buf);
        let validator = SyncCommitteeView::validator_index(buf);

        if subnet >= silver_common::SYNC_COMMITTEE_SUBNETS as u64 {
            return Err(self.reject("sync message subnet out of range"));
        }
        if !self.ticker.is_current_slot_with_disparity(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return Err(self.slot_window_miss(slot));
        }

        let seen = &mut self.seen_sync_msgs[subnet as usize];
        seen.rotate_to(self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY));
        if seen.contains(slot, validator as usize) {
            return Err(Feedback::AlreadySeen);
        }

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        if validator as usize >= view.validators.count() {
            return Err(self.reject("sync message validator out of range"));
        }

        let committee = SyncSubcommittee::of(&view, subnet as usize);
        let positions = committee.positions(validator as usize, &view.validators);
        if positions.iter().all(|&word| word == 0) {
            return Err(self.reject("sync message validator not in subcommittee"));
        }

        let block_root = *SyncCommitteeView::beacon_block_root(buf);
        let fork_version = view.epoch.fork_version_at(slot / SLOTS_PER_EPOCH);
        let domain = bls::domain_from_fork_data(
            bls::DOMAIN_SYNC_COMMITTEE,
            &self.fork_data_roots.root(fork_version, &view.imm.genesis_validators_root),
        );
        let signing_root = bls::compute_signing_root(&block_root, &domain);
        let Some(signature) = CheckedSignature::parse(SyncCommitteeView::signature(buf)) else {
            return Err(self.reject("sync message signature malformed"));
        };

        Ok(PreparedSyncMessage {
            slot,
            subnet,
            validator,
            block_root,
            positions,
            pubkey: *view.validators.pubkey_decompressed(validator as usize),
            signing_root,
            signature,
        })
    }

    fn commit_sync_message(&mut self, p: &PreparedSyncMessage) {
        let outcome = self.sync_contribution_pool.insert_verified(
            p.slot,
            p.subnet,
            p.block_root,
            &p.positions,
            p.signature.as_sig(),
        );
        debug_assert!(outcome != InsertOutcome::Inconsistent);
        if outcome == InsertOutcome::Full {
            BeaconStateCounters::SyncContributionPoolFull.inc();
            silver_log::debug!(
                slot = p.slot,
                subcommittee = p.subnet,
                block = hex32(&p.block_root),
                "sync contribution pool full"
            );
        }
        self.seen_sync_msgs[p.subnet as usize].mark(p.slot, p.validator as usize);
    }

    #[timed]
    pub(super) fn handle_sync_contribution(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_CONTRIBUTION_AND_PROOF_SIZE {
            return self.reject("contribution size");
        }
        let buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE] =
            data[..SIGNED_CONTRIBUTION_AND_PROOF_SIZE].try_into().unwrap();
        let slot = SignedSyncCommitteeProofView::slot(buf);
        let subcommittee = SignedSyncCommitteeProofView::subcommittee_index(buf);
        let aggregator = SignedSyncCommitteeProofView::aggregator_index(buf);
        let block_root = *SignedSyncCommitteeProofView::beacon_block_root(buf);
        let bits = SignedSyncCommitteeProofView::aggregation_bits(buf);

        if subcommittee >= silver_common::SYNC_COMMITTEE_SUBNETS as u64 {
            return self.reject("contribution subcommittee out of range");
        }
        if !self.ticker.is_current_slot_with_disparity(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            return self.slot_window_miss(slot);
        }

        let seen = &mut self.seen_contribution_aggregators[subcommittee as usize];
        seen.rotate_to(self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY));
        if seen.contains(slot, aggregator as usize) {
            return Feedback::AlreadySeen;
        }
        let coverage = self.seen_aggregates.coverage(slot, subcommittee, block_root, bits);
        if coverage == Coverage::BySuperset {
            return Feedback::AlreadySeen;
        }

        if !is_sync_aggregator(SignedSyncCommitteeProofView::selection_proof(buf)) {
            return self.reject("contribution aggregator not selected");
        }

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        let count = view.validators.count();
        if aggregator as usize >= count {
            return self.reject("contribution aggregator out of range");
        }
        let committee = SyncSubcommittee::of(&view, subcommittee as usize);
        if !committee.contains(aggregator as usize, &view.validators) {
            return self.reject("contribution aggregator not in subcommittee");
        }

        let fv = view.epoch.fork_version_at(slot / SLOTS_PER_EPOCH);
        let fork_data_root = self.fork_data_roots.root(fv, &view.imm.genesis_validators_root);
        let domain = |ty| bls::domain_from_fork_data(ty, &fork_data_root);

        let sr_sp = bls::compute_signing_root(
            &ssz_hash::hash_tree_root_sync_selection_data(slot, subcommittee),
            &domain(bls::DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF),
        );
        let contribution_root = ssz_hash::hash_tree_root_sync_contribution(
            slot,
            &block_root,
            subcommittee,
            bits,
            SignedSyncCommitteeProofView::contribution_signature(buf),
        );
        let cap_root = ssz_hash::hash_tree_root_contribution_and_proof(
            aggregator,
            &contribution_root,
            SignedSyncCommitteeProofView::selection_proof(buf),
        );
        let sr_outer =
            bls::compute_signing_root(&cap_root, &domain(bls::DOMAIN_CONTRIBUTION_AND_PROOF));
        let sr_agg = bls::compute_signing_root(&block_root, &domain(bls::DOMAIN_SYNC_COMMITTEE));

        let mut participants = 0usize;
        let mut unknown = false;
        self.sig_batch.clear();
        let aggregator_pk = view.validators.pubkey_decompressed(aggregator as usize);
        self.sig_batch.push_one(
            aggregator_pk,
            SignedSyncCommitteeProofView::selection_proof(buf),
            sr_sp,
        );
        self.sig_batch.push_one(
            aggregator_pk,
            SignedSyncCommitteeProofView::signature(buf),
            sr_outer,
        );
        self.sig_batch.push_aggregate(
            (0..SYNC_SUBCOMMITTEE_SIZE).filter_map(|i| {
                if bits[i / 8] & (1 << (i % 8)) == 0 {
                    return None;
                }
                participants += 1;
                let Some(vi) = committee.validator_at(i, &view.validators) else {
                    unknown = true;
                    return None;
                };
                Some(view.validators.pubkey_decompressed(vi))
            }),
            SignedSyncCommitteeProofView::contribution_signature(buf),
            sr_agg,
        );
        if unknown || participants == 0 || !self.sig_batch.verify_all() {
            return self.reject("contribution bad signature");
        }

        self.seen_aggregates.record(slot, subcommittee, block_root, bits);
        self.seen_contribution_aggregators[subcommittee as usize].mark(slot, aggregator as usize);
        // Not pooled: aggregators build contributions from messages alone.
        // TODO: Proposing will want them, to fill the sync aggregate with messages
        // the mesh never delivered here.
        Feedback::Accept
    }

    #[timed]
    fn handle_execution_payload_bid(&mut self, signed_bid: &[u8]) -> Feedback {
        let Ok(bid) = decode_bid(signed_bid) else {
            return self.reject("bid malformed");
        };
        let signature = SignedExecutionPayloadBidView::signature(signed_bid);

        if !self.payload_bids_pool.is_candidate(&bid) {
            return Feedback::Ignore;
        }
        let is_current =
            |slot| self.ticker.is_current_slot_with_disparity(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY);
        let current_or_next = is_current(bid.slot) || (bid.slot > 0 && is_current(bid.slot - 1));
        if !current_or_next {
            return Feedback::Ignore;
        }
        // In-protocol bids pay only through `value`; the pool also ranks
        // out-of-protocol bids, so this belongs to gossip, not the pool.
        if bid.execution_payment != 0 {
            return self.reject("bid has execution payment");
        }
        if bid.block_hash == bid.parent_block_hash {
            return self.reject("bid block hash equals parent");
        }
        let bid_epoch = bid.slot / SLOTS_PER_EPOCH;
        let max_blobs = self.spec.blob_params_at(bid_epoch).max_blobs_per_block as usize;
        if bid.blob_kzg_commitments.len() > max_blobs {
            return self.reject("bid too many blob commitments");
        }

        let Some(idx) = self.fork_choice.find_node_idx(&bid.parent_block_root) else {
            return Feedback::Ignore;
        };
        let node = self.fork_choice.node(idx);
        if bid.slot <= node.slot {
            return self.reject("bid slot not after parent");
        }
        let (parent_state, parent_payload) = (node.state_id, node.payload);
        {
            let parent = self.state.read_view(parent_state);

            // Full: the bid builds on the parent's own payload, which must be
            // verified. Empty: on the payload the parent itself built on.
            let full = bid.parent_block_hash == parent_payload.bid_block_hash;
            if full && !parent_payload.verified {
                return Feedback::Ignore;
            }
            if !full && bid.parent_block_hash != parent.slot.state().latest_block_hash {
                return Feedback::Ignore;
            }

            let parent_epoch = parent.slot.state().slot / SLOTS_PER_EPOCH;
            if bid_epoch > parent_epoch + MIN_SEED_LOOKAHEAD {
                return Feedback::Ignore;
            }
            if bid.prev_randao != parent.randao_mixes.at_epoch(parent_epoch) {
                return self.reject("bid prev_randao mismatch");
            }
        }

        // The spec checks the builder on `process_slots(parent, bid.slot)`.
        // Only epoch processing moves what those checks read (finalization,
        // pending payments); `process_slot` touches none of it. So the
        // epoch-start state of the bid's epoch is exact, and it is the cached
        // one the slot tick reuses rather than a fork-choice advance.
        let at_bid = self.epoch_start_state(parent_state, bid.slot);
        let view = self.state.read_view(at_bid);

        let finalized_epoch = view.epoch.state().finalized_checkpoint.epoch;
        match validate_bid_builder(&BuilderLedger::of_reader(&view), finalized_epoch, &bid) {
            Ok(()) => {}
            Err(e @ BidError::InsufficientBalance { .. }) => {
                silver_log::debug!(?e, "execution payload bid ignored");
                return Feedback::Ignore;
            }
            Err(e) => {
                silver_log::debug!(?e, "invalid execution payload bid");
                return self.reject("bid invalid");
            }
        }
        // Last of the checks: a pairing costs more than all of them together.
        if let Err(e) = verify_execution_payload_bid_signature(
            view.imm,
            &view.epoch,
            &view.builders,
            &bid,
            signature,
        ) {
            silver_log::debug!(?e, "execution payload bid signature rejected");
            return self.reject("bid bad signature");
        }

        self.payload_bids_pool.add(bid, *signature);
        Feedback::Accept
    }

    /// EF `fork_choice` vector path only: production gossip reaches the same
    /// work through `handle_attestation` / `handle_aggregate_and_proof`, which
    /// have already resolved the committee by the time votes are recorded.
    #[cfg(feature = "ef_tests")]
    pub(super) fn apply_attestation(&mut self, att: &[u8]) -> Feedback {
        use silver_common::ssz_view::AttestationView;

        let data = AttestationView::data(att);
        if let Err(f) = self.validate_attestation_target(data) {
            return f;
        }

        let canon_id = self.canonical_state_id();
        let att_epoch = data.slot() / SLOTS_PER_EPOCH;
        let n = self.head_validator_count();
        {
            let view = self.state.read_view(canon_id);
            self.shuffling_cache.ensure_window(&view, att_epoch);
            let Some(shuffling) = self.shuffling_cache.lookup(&view, att_epoch) else {
                return Feedback::Ignore;
            };
            if stf::AttestedCommittees::new(att, &shuffling)
                .and_then(|c| c.attesters_into(n, &mut self.stf_scratch.active))
                .is_err()
            {
                return self.reject("attestation committees invalid");
            }
        }

        self.record_attester_votes(data, n);
        Feedback::Accept
    }

    fn record_attester_votes(&mut self, data: AttestationDataView<'_>, validator_count: usize) {
        let target = stf::VoteTarget {
            block_root: *data.beacon_block_root(),
            target_epoch: data.target_epoch(),
            attestation_slot: data.slot(),
            payload_present: data.index() == 1,
        };
        self.fork_choice.record_or_defer_votes(
            target,
            &self.stf_scratch.active,
            validator_count,
            self.ticker.current_slot(),
        );
    }

    #[timed]
    pub(super) fn handle_aggregate_and_proof(&mut self, data: &[u8]) -> Feedback {
        let Some(parsed) = ParsedAggregateAndProof::try_from(data) else {
            return self.reject("aggregate malformed");
        };

        // Gossip-rule checks (no state access). Pre-Gloas requires index 0;
        // Gloas widens it to the payload-status bit (`index < 2`).
        let is_gloas = self.spec.is_gloas_at(parsed.att_epoch);
        let index_ok = validate::attestation_index_ok(is_gloas, parsed.agg_data_index);
        if !index_ok || parsed.agg_data.target_epoch() != parsed.att_epoch {
            return self.reject("aggregate data index");
        }
        if !self.attestation_slot_is_open(parsed.agg_slot) {
            return self.slot_window_miss(parsed.agg_slot);
        }

        self.seen_aggregators.rotate_to(self.seen_window_epoch());
        if self.seen_aggregators.contains(parsed.att_epoch, parsed.aggregator_index) {
            return Feedback::AlreadySeen;
        }

        if parsed.committee_bits.count_ones() != 1 {
            return self.reject("aggregate committee bits");
        }
        let committee_index = parsed.committee_bits.trailing_zeros() as usize;

        let data_root = self.attestation_root_memo.data_root(parsed.agg_data.as_bytes());
        let coverage = self.seen_aggregates.coverage(
            parsed.agg_slot,
            committee_index as u64,
            data_root,
            parsed.aggregation_bits,
        );
        if coverage == Coverage::BySuperset {
            return Feedback::AlreadySeen;
        }

        if let Err(f) = self.validate_attestation_target(parsed.agg_data) {
            return f;
        }
        if is_gloas {
            if let Err(f) = self.gloas_payload_present(
                parsed.agg_data.beacon_block_root(),
                parsed.agg_slot,
                parsed.agg_data_index,
            ) {
                return f;
            }
        }

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        self.shuffling_cache.ensure_window(&view, parsed.att_epoch);
        let count = view.validators.count();
        if parsed.aggregator_index >= count {
            return self.reject("aggregator index out of range");
        }

        let Some(shuffling) = self.shuffling_cache.lookup(&view, parsed.att_epoch) else {
            return Feedback::Ignore;
        };
        if committee_index >= shuffling.committees_per_slot {
            return self.reject("aggregate committee index out of range");
        }
        let committee = shuffling.committee(parsed.agg_slot, committee_index);
        if !committee.contains(&(parsed.aggregator_index as u32)) {
            return self.reject("aggregator not in committee");
        }
        let committee_len = committee.len();

        let Ok(committees) = stf::AttestedCommittees::new(parsed.aggregate_bytes, &shuffling)
        else {
            return self.reject("aggregate committees invalid");
        };
        if committees.attesters_into(count, &mut self.stf_scratch.active).is_err() ||
            self.stf_scratch.active.is_empty()
        {
            return self.reject("aggregate has no attesters");
        }

        if !is_aggregator(committee_len, parsed.selection_proof) {
            return self.reject("aggregator not selected");
        }

        if !Self::verify_aggregate_and_proof_sigs(
            &view,
            &parsed,
            &committees,
            data_root,
            &mut self.fork_data_roots,
            &mut self.sig_batch,
        ) {
            return self.reject("aggregate bad signature");
        }

        // A union-covered aggregate's votes are all already folded; it still
        // relays — union coverage must never gate forwarding.
        if coverage != Coverage::ByUnion {
            self.record_attester_votes(parsed.agg_data, count);
        }
        self.seen_aggregates.record(
            parsed.agg_slot,
            committee_index as u64,
            data_root,
            parsed.aggregation_bits,
        );
        self.seen_aggregators.mark(parsed.att_epoch, parsed.aggregator_index);
        Feedback::Accept
    }

    pub(super) fn validate_execution_payload_envelope(&self, ssz: &[u8]) -> EnvelopeCheck {
        if !SignedPayload::check_size(ssz) || !Envelope::check_size(SignedPayload::message(ssz)) {
            return EnvelopeCheck::Reject;
        }
        let block_root = *Envelope::beacon_block_root(SignedPayload::message(ssz));
        let Some(idx) = self.fork_choice.find_node_idx(&block_root) else {
            return EnvelopeCheck::AwaitBlock(block_root);
        };
        let node = self.fork_choice.node(idx);
        if node.slot < self.fork_choice.finalized_checkpoint.epoch * SLOTS_PER_EPOCH {
            return EnvelopeCheck::Ignore;
        }
        let state_id = node.state_id;
        let rv = self.state.read_view(state_id);
        if let Err(e) = stf::verify_execution_payload_envelope(&rv, &self.spec, ssz) {
            silver_log::info!(error = %e, "execution_payload_envelope rejected");
            return EnvelopeCheck::Reject;
        }
        EnvelopeCheck::Ready { block_root, state_id }
    }

    fn emit_envelope_available(
        acquired: &TRead,
        source: BlockSource,
        slot: u64,
        block_root: B256,
        producers: &mut Producers,
    ) {
        producers.produce(BeaconStateEvent::EnvelopeAvailable {
            ssz: acquired.to_read(),
            source,
            slot,
            block_root,
        });
    }

    #[timed]
    pub(super) fn handle_execution_payload_envelope(
        &mut self,
        acquired: TRead,
        ssz: &[u8],
        source: BlockSource,
        producers: &mut Producers,
    ) -> Feedback {
        let (block_root, state_id) = match self.validate_execution_payload_envelope(ssz) {
            EnvelopeCheck::Ready { block_root, state_id } => (block_root, state_id),
            EnvelopeCheck::AwaitBlock(block_root) => {
                self.buffer_pending_envelope(block_root, acquired);
                return Feedback::Ignore;
            }
            EnvelopeCheck::Ignore => return Feedback::Ignore,
            EnvelopeCheck::Reject => return self.reject("envelope invalid"),
        };

        let rv = self.state.read_view(state_id);
        let slot = rv.slot.slot_number();
        if !stf::envelope_withdrawals_match_expected(&rv, ssz) {
            silver_log::error!(
                block = hex32(&block_root),
                "envelope withdrawals are not the expected ones"
            );
            return Feedback::Accept;
        }
        let slot_state = rv.slot;

        if self.fork_choice.is_payload_verified(&block_root) {
            Self::emit_envelope_available(&acquired, source, slot, block_root, producers);
            return Feedback::AlreadySeen;
        }

        // Versioned hashes come from the committed bid's KZG commitments — the
        // envelope does not carry them.
        let mut versioned_hashes = [[0u8; 32]; MAX_BLOBS_PER_BLOCK];
        let hash_count = match slot_state.bid_versioned_hashes_len(&mut versioned_hashes) {
            Some(n) => n as u8,
            None => return self.reject("envelope bid versioned hashes"),
        };

        self.fork_choice.mark_payload_verified(&block_root);
        producers.produce(EngineReq::NewPayloadEnvelope(EngineNewPayloadEnvelopeReq {
            data: acquired.to_read(),
            block_root,
            block_source: source,
            hash_count,
            versioned_hashes,
        }));

        Self::emit_envelope_available(&acquired, source, slot, block_root, producers);

        self.drain_awaiting_payload(block_root, producers);
        self.recompute_head();

        Feedback::Accept
    }

    fn buffer_pending_envelope(&mut self, block_root: B256, acquired: TRead) {
        let has_room = self.pending_envelopes.len() < self.pending_bounds.max_dc ||
            self.pending_envelopes.contains_key(&block_root);
        if !has_room {
            silver_log::warn!(
                block = hex32(&block_root),
                cap = self.pending_bounds.max_dc,
                "pending-envelope buffer full; envelope dropped"
            );
            return;
        }
        self.pending_envelopes.insert(block_root, acquired);
    }

    pub(super) fn drain_pending_envelope(
        &mut self,
        block_root: B256,
        slot: Slot,
        producers: &mut Producers,
    ) {
        let Some(acquired) = self.pending_envelopes.remove(&block_root) else {
            return;
        };

        let Some((ssz, _)) = acquired.buffer().ok() else {
            silver_log::warn!(
                block = hex32(&block_root),
                slot,
                "parked envelope lapped; refetching"
            );
            producers.produce(SyncNeed::missing_envelope(block_root, slot));
            return;
        };

        self.handle_execution_payload_envelope(
            acquired.clone(),
            ssz,
            BlockSource::Gossip,
            producers,
        );
    }

    fn gloas_payload_present(
        &mut self,
        block_root: &B256,
        att_slot: Slot,
        data_index: u64,
    ) -> Result<bool, Feedback> {
        if data_index != 1 {
            return Ok(false);
        }
        let Some(idx) = self.fork_choice.find_node_idx(block_root) else {
            return Err(Feedback::Ignore);
        };
        if self.fork_choice.node(idx).slot == att_slot {
            return Err(self.reject("payload present for same-slot block"));
        }
        if !self.fork_choice.is_payload_verified(block_root) {
            return Err(Feedback::RequestEnvelope { block_root: *block_root, att_slot });
        }
        // Spec `verify_attestation_payload_status`: the EL's verdict on the
        // attested payload decides, an outstanding one defers the vote.
        match self.fork_choice.node(idx).execution_status {
            ExecutionStatus::Valid => Ok(true),
            ExecutionStatus::Optimistic => Err(Feedback::Ignore),
            ExecutionStatus::Invalid => Err(self.reject("attested payload invalid")),
        }
    }

    /// Spec `is_future_slot` and Deneb's `is_current_or_previous_epoch`
    /// (EIP-7045 widened the window from 32 slots to the whole previous
    /// epoch), both with clock disparity.
    pub(super) fn slot_window_miss(&self, slot: Slot) -> Feedback {
        if self.ticker.is_future_slot(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) {
            Feedback::Future
        } else {
            Feedback::TooOld
        }
    }

    fn attestation_slot_is_open(&self, slot: Slot) -> bool {
        let epoch_open = |epoch: Epoch| {
            self.ticker.is_within_slot_range(
                epoch * SLOTS_PER_EPOCH,
                SLOTS_PER_EPOCH - 1,
                MAXIMUM_GOSSIP_CLOCK_DISPARITY,
            )
        };
        let epoch = slot / SLOTS_PER_EPOCH;
        !self.ticker.is_future_slot(slot, MAXIMUM_GOSSIP_CLOCK_DISPARITY) &&
            (epoch_open(epoch) || epoch_open(epoch + 1))
    }

    /// The epoch the per-epoch seen-caches rotate to: the newest one a vote can
    /// legitimately carry right now, so an early next-epoch vote has a lane.
    fn seen_window_epoch(&self) -> Epoch {
        self.ticker.latest_slot_with_disparity(MAXIMUM_GOSSIP_CLOCK_DISPARITY) / SLOTS_PER_EPOCH
    }

    fn validate_attestation_target(&self, data: AttestationDataView<'_>) -> Result<(), Feedback> {
        let att_slot = data.slot();
        let target_epoch = data.target_epoch();
        if target_epoch != att_slot / SLOTS_PER_EPOCH {
            return Err(self.reject("attestation target epoch mismatch"));
        }
        let Some(idx) = self.fork_choice.find_node_idx(data.beacon_block_root()) else {
            BeaconStateCounters::AttestationUnknownRoot.inc();
            return Err(Feedback::Ignore);
        };
        match self.fork_choice.checkpoint_block_of(idx, target_epoch * SLOTS_PER_EPOCH) {
            Some(r) if r == *data.target_root() => {}
            Some(_) => return Err(self.reject("attestation target root mismatch")),
            None => return Err(Feedback::Ignore),
        }
        if self.fork_choice.node(idx).slot <= att_slot {
            Ok(())
        } else {
            Err(self.reject("attestation block newer than slot"))
        }
    }

    fn verify_aggregate_and_proof_sigs(
        view: &StateReadView,
        parsed: &ParsedAggregateAndProof<'_>,
        committees: &stf::AttestedCommittees<'_>,
        data_root: B256,
        fork_data_roots: &mut ForkDataRoots,
        sig_batch: &mut bls::SigBatch,
    ) -> bool {
        let fv = view.epoch.fork_version_at(parsed.agg_data.target_epoch());
        let fork_data_root = fork_data_roots.root(fv, &view.imm.genesis_validators_root);
        let domain = |ty| bls::domain_from_fork_data(ty, &fork_data_root);

        // (1) selection_proof — signer = aggregator, msg = htr(uint64(slot)).
        let slot_root = merkle::uint64_chunk(parsed.agg_slot);
        let sr_sp = bls::compute_signing_root(&slot_root, &domain(bls::DOMAIN_SELECTION_PROOF));

        // (2) outer AggregateAndProof signature.
        let agg_proof_root = ssz_hash::hash_tree_root_aggregate_and_proof(
            parsed.aggregator_index as u64,
            parsed.aggregate_bytes,
            data_root,
            parsed.selection_proof,
            fv == view.imm.gloas_fork_version,
        );
        let sr_aap =
            bls::compute_signing_root(&agg_proof_root, &domain(bls::DOMAIN_AGGREGATE_AND_PROOF));

        // (3) inner aggregate signature over AttestationData.
        let sr_att = bls::compute_signing_root(&data_root, &domain(bls::DOMAIN_BEACON_ATTESTER));

        sig_batch.clear();
        let aggregator_pk = view.validators.pubkey_decompressed(parsed.aggregator_index);
        sig_batch.push_one(aggregator_pk, parsed.selection_proof, sr_sp);
        sig_batch.push_one(aggregator_pk, parsed.outer_sig, sr_aap);
        committees.push_aggregate_sig(&view.validators, parsed.agg_sig, sr_att, sig_batch);
        sig_batch.verify_all()
    }

    #[timed]
    pub(super) fn handle_voluntary_exit(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_VOLUNTARY_EXIT_SIZE {
            return self.reject("exit size");
        }
        let buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] =
            data[..SIGNED_VOLUNTARY_EXIT_SIZE].try_into().unwrap();
        let exit_epoch = SignedVoluntaryExitView::epoch(buf);
        let vi_u = SignedVoluntaryExitView::validator_index(buf);
        let vi = vi_u as usize;

        if self.seen_exits.contains(vi) {
            return Feedback::AlreadySeen;
        }
        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        if vi >= view.validators.count() {
            return self.reject("exit validator out of range");
        }
        let current_epoch = view.slot.current_epoch();
        if let Err(e) = validate::validate_voluntary_exit(
            &self.spec,
            &view.validators,
            vi_u as u32,
            exit_epoch,
            current_epoch,
        ) {
            silver_log::debug!(error = %e, "voluntary_exit gossip rejected");
            return self.reject("exit invalid");
        }
        if stf::get_pending_balance_to_withdraw(&view.pending, vi_u as u32) != 0 {
            return self.reject("exit with pending withdrawal");
        }

        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch, vi_u);
        let imm = view.imm;
        let domain = bls::compute_domain(
            bls::DOMAIN_VOLUNTARY_EXIT,
            imm.capella_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(buf);
        if !bls::verify_one(view.validators.pubkey_decompressed(vi), sig, &signing_root) {
            return self.reject("exit bad signature");
        }
        self.seen_exits.mark(vi);
        Feedback::Accept
    }

    pub(super) fn handle_proposer_slashing(&mut self, data: &[u8]) -> Feedback {
        if data.len() != PROPOSER_SLASHING_SIZE {
            return self.reject("proposer slashing size");
        }
        let buf: &[u8; PROPOSER_SLASHING_SIZE] = data[..PROPOSER_SLASHING_SIZE].try_into().unwrap();
        if let Err(e) = validate::validate_proposer_slashing(buf) {
            silver_log::debug!(error = %e, "proposer_slashing gossip rejected");
            return self.reject("proposer slashing invalid");
        }

        let proposer_index = ProposerSlashingView::h1_proposer_index(buf) as usize;
        if self.seen_proposer_slashings.contains(proposer_index) {
            return Feedback::AlreadySeen;
        }
        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        let current_epoch = view.slot.current_epoch();
        if proposer_index >= view.validators.count() {
            return self.reject("proposer slashing index out of range");
        }
        if !view.validators.is_slashable(proposer_index, current_epoch) {
            return self.reject("proposer not slashable");
        }

        let h1_epoch = ProposerSlashingView::h1_slot(buf) / SLOTS_PER_EPOCH;
        let fv = view.epoch.fork_version_at(h1_epoch);
        let domain =
            bls::compute_domain(bls::DOMAIN_BEACON_PROPOSER, fv, &view.imm.genesis_validators_root);
        let sr1 = stf::signing_root_for_block_header(&buf[0..208], &domain);
        let sr2 = stf::signing_root_for_block_header(&buf[208..416], &domain);
        let sig1 = ProposerSlashingView::h1_signature(buf);
        let sig2 = ProposerSlashingView::h2_signature(buf);
        let pubkey = view.validators.pubkey_decompressed(proposer_index);

        self.sig_batch.clear();
        self.sig_batch.push_one(pubkey, sig1, sr1);
        self.sig_batch.push_one(pubkey, sig2, sr2);
        if !self.sig_batch.verify_all() {
            return self.reject("proposer slashing bad signature");
        }
        self.seen_proposer_slashings.mark(proposer_index);
        let admission = self.slashing_pool.insert_proposer_slashing(buf, &view);
        silver_log::info!(proposer_index, ?admission, "proposer slashing pooled");
        Feedback::Accept
    }

    pub(super) fn handle_attester_slashing(&mut self, data: &[u8]) -> Feedback {
        if !AttesterSlashingView::check_size(data) {
            return self.reject("attester slashing size");
        }
        let canon_id = self.canonical_state_id();
        let slashed = &mut self.stf_scratch.active;
        let feedback = {
            let view = self.state.read_view(canon_id);
            // Spec order: no validator left to slash is an IGNORE before any
            // validity REJECT.
            let seen = |vi| self.seen_attester_slashed.contains(vi);
            match stf::attester_slashing_names_unseen(data, seen) {
                None => {
                    self.reject_reason.set("attester slashing invalid");
                    Feedback::Reject(None)
                }
                Some(false) => Feedback::Ignore,
                Some(true) => {
                    let valid = stf::validate_attester_slashing_for_gossip(
                        &view,
                        data,
                        slashed,
                        &mut self.sig_batch,
                    );
                    if valid {
                        Feedback::Accept
                    } else {
                        self.reject_reason.set("attester slashing bad signature");
                        Feedback::Reject(None)
                    }
                }
            }
        };
        // Mark the equivocators (spec `on_attester_slashing`) so fork choice
        // excludes them. Idempotent; removes any live LMD weight next recompute.
        if feedback == Feedback::Accept {
            for &idx in slashed.iter() {
                self.fork_choice.mark_equivocating(idx as usize);
                self.seen_attester_slashed.mark(idx as usize);
            }
            let view = self.state.read_view(canon_id);
            let admission = self.slashing_pool.insert_attester_slashing(data, slashed, &view);
            silver_log::info!(offenders = slashed.len(), ?admission, "attester slashing pooled");
        }
        feedback
    }

    #[timed]
    pub(super) fn handle_bls_to_execution_change(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_BLS_CHANGE_SIZE {
            return self.reject("bls change size");
        }
        let buf: &[u8; SIGNED_BLS_CHANGE_SIZE] = data[..SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);

        let vi_u = SignedBlsToExecutionChangeView::validator_index(buf);
        let vi = vi_u as usize;
        if self.seen_bls_changes.contains(vi) {
            return Feedback::AlreadySeen;
        }
        if vi >= view.validators.count() {
            return self.reject("bls change validator out of range");
        }
        let from_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(buf);
        let to_address = SignedBlsToExecutionChangeView::to_execution_address(buf);
        if let Err(e) =
            validate::validate_bls_to_execution_change(&view.validators, vi_u as u32, from_pubkey)
        {
            silver_log::debug!(error = %e, "bls_to_execution_change gossip rejected");
            return self.reject("bls change invalid");
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(vi_u, from_pubkey, to_address);
        let imm = view.imm;
        let domain = bls::compute_domain(
            bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            imm.genesis_fork_version,
            &imm.genesis_validators_root,
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedBlsToExecutionChangeView::signature(buf);
        // Signer is the message's `from_bls_pubkey`, not a cached key.
        if !bls::verify_one_compressed(from_pubkey, sig, &signing_root) {
            return self.reject("bls change bad signature");
        }
        self.seen_bls_changes.mark(vi);
        Feedback::Accept
    }

    /// False when the ring lapped `read` before it could be handled.
    pub(super) fn handle_gossip(
        &mut self,
        read: TCacheRead,
        m: NewGossipMsg,
        mut do_relay: bool,
        pre_verified: bool,
        producers: &mut Producers,
    ) -> bool {
        let acquired = self.reader.acquire(read);
        let Some(data) = acquired.buffer().ok().map(|(d, _)| d) else { return false };

        let feedback = match m.topic {
            GossipTopic::BeaconBlock if self.sync_target.is_syncing() => {
                match self.parse_and_verify_block(data, pre_verified) {
                    Ok(parsed) if do_relay && parsed.relay_eligible => {
                        Self::relay_gossip(&m, producers)
                    }
                    Err(err) if matches!(err.feedback(), Feedback::Reject(_)) => {
                        producers.produce(PeerEvent::P2pGossipInvalidMsg {
                            p2p_peer: m.stream_id.peer(),
                            topic: m.topic,
                            hash: m.msg_hash,
                        })
                    }
                    _ => {}
                }
                return true;
            }
            GossipTopic::BeaconBlock => {
                let feedback = self.apply_block(
                    data,
                    &acquired,
                    BlockSource::Gossip,
                    pre_verified,
                    producers,
                    |p| {
                        if do_relay {
                            Self::relay_gossip(&m, p);
                        }
                    },
                );
                do_relay = false; // relayed on callback.
                feedback
            }
            GossipTopic::BeaconAttestation(subnet) => self.handle_attestation(data, subnet),
            GossipTopic::BeaconAggregateAndProof => self.handle_aggregate_and_proof(data),
            GossipTopic::VoluntaryExit => self.handle_voluntary_exit(data),
            GossipTopic::ProposerSlashing => self.handle_proposer_slashing(data),
            GossipTopic::AttesterSlashing => self.handle_attester_slashing(data),
            GossipTopic::BlsToExecutionChange => self.handle_bls_to_execution_change(data),
            GossipTopic::ExecutionPayload => self.handle_execution_payload_envelope(
                acquired.clone(),
                data,
                BlockSource::Gossip,
                producers,
            ),
            GossipTopic::SyncCommitteeContributionAndProof => self.handle_sync_contribution(data),
            GossipTopic::ExecutionPayloadBid => self.handle_execution_payload_bid(data),
            _ => return true,
        };
        match feedback {
            Feedback::Reject(_) => self.reject_gossip(&m, data, producers),
            Feedback::Accept => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }
                self.publish_status(producers);
            }
            Feedback::RequestParent { .. } => self.park_block(
                feedback,
                BlockSourceMsg::Gossip(m, acquired.clone()),
                data,
                producers,
            ),
            Feedback::AwaitParentPayload { .. } => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }
                self.park_block(
                    feedback,
                    BlockSourceMsg::Gossip(m, acquired.clone()),
                    data,
                    producers,
                );
            }
            Feedback::RequestEnvelope { block_root, att_slot } => {
                producers.produce(SyncNeed::missing_envelope(block_root, att_slot));
                Self::local_verdict(&m, feedback, producers);
            }
            Feedback::Ignore | Feedback::AlreadySeen | Feedback::TooOld | Feedback::Future => {
                Self::local_verdict(&m, feedback, producers)
            }
            Feedback::BlockImported(_) | Feedback::AwaitData(_) | Feedback::BlockKnown(_) => {}
        }
        true
    }

    fn relay_gossip(m: &NewGossipMsg, producers: &mut Producers) {
        producers.produce(PeerEvent::SendGossip {
            originator_stream_id: m.stream_id,
            topic: m.topic,
            domain: m.domain,
            ssz_cache: m.ssz_cache,
            msg_hash: m.msg_hash,
            recv_ts: m.recv_ts,
            protobuf: m.protobuf,
            ssz: m.ssz,
        });
        Self::local_verdict(m, Feedback::Accept, producers);
    }

    pub(super) fn reject(&self, reason: &'static str) -> Feedback {
        self.reject_reason.set(reason);
        Feedback::Reject(None)
    }

    fn reject_gossip(&self, m: &NewGossipMsg, data: &[u8], producers: &mut Producers) {
        let reason = self.reject_reason.replace(UNSPECIFIED_REJECT);
        if m.stream_id == LOCAL_GOSSIP_STREAM_ID {
            return Self::local_verdict(m, Feedback::Reject(None), producers);
        }
        silver_log::warn!(
            p2p_peer = m.stream_id.peer(),
            topic = ?m.topic,
            reason,
            message = %GossipFields { topic: m.topic, data },
            head_slot = self.head_state_slot(),
            wall_slot = self.ticker.current_slot(),
            time_into_slot = ?self.ticker.slot_time_elapsed(),
            justified_epoch = self.fork_choice.justified_checkpoint.epoch,
            finalized_epoch = self.fork_choice.finalized_checkpoint.epoch,
            "gossip rejected"
        );
        producers.produce(PeerEvent::P2pGossipInvalidMsg {
            p2p_peer: m.stream_id.peer(),
            topic: m.topic,
            hash: m.msg_hash,
        });
    }

    /// Network gossip ignores are deliberately silent. A local API request,
    /// however, needs a terminal verdict so Control can complete it.
    pub(super) fn local_verdict(m: &NewGossipMsg, feedback: Feedback, producers: &mut Producers) {
        if m.stream_id != LOCAL_GOSSIP_STREAM_ID {
            return;
        }
        let result = match feedback {
            Feedback::Accept => Ok(()),
            Feedback::Reject(_) => Err(LocalGossipFailure::Invalid),
            // Already on the network is published, as fallback validator
            // clients that submit to several nodes rely on.
            Feedback::AlreadySeen => Ok(()),
            Feedback::TooOld => Err(LocalGossipFailure::TooOld),
            Feedback::Future => Err(LocalGossipFailure::Future),
            _ => Err(LocalGossipFailure::Unverifiable),
        };
        producers.produce(BeaconStateEvent::LocalGossipVerdict { hash: m.msg_hash, result });
    }
}

pub(super) fn is_aggregator(committee_len: usize, selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let h = merkle::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}

pub(super) fn is_sync_aggregator(selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;
    let modulo = (SYNC_SUBCOMMITTEE_SIZE as u64 / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE).max(1);
    let h = merkle::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}

/// EF `gossip_validation` entry points for the batched vote topics: one
/// message at a time, verified alone and committed, as the batch path does for
/// each survivor.
#[cfg(feature = "ef_tests")]
impl BeaconStateTile {
    pub fn ef_gossip_sync_committee_message(&mut self, ssz: &[u8], subnet: u64) -> Feedback {
        let prepared = match self.prepare_sync_message(ssz, subnet) {
            Ok(p) => PreparedVote::SyncMessage(p),
            Err(feedback) => return feedback,
        };
        self.ef_verify_and_commit(prepared)
    }

    pub fn ef_gossip_payload_attestation(&mut self, ssz: &[u8]) -> Feedback {
        let prepared = match self.prepare_ptc(ssz) {
            Ok(p) => PreparedVote::Ptc(p),
            Err(feedback) => return feedback,
        };
        self.ef_verify_and_commit(prepared)
    }

    fn ef_verify_and_commit(&mut self, prepared: PreparedVote) -> Feedback {
        let (pk, sig, root) = prepared.sig_parts();
        if !bls::verify_one_checked(pk, &sig, root) {
            return self.reject("vote bad signature");
        }
        match &prepared {
            PreparedVote::Attestation(p) => self.commit_attestation(p),
            PreparedVote::SyncMessage(p) => self.commit_sync_message(p),
            PreparedVote::Ptc(p) => self.commit_ptc(p),
        }
        self.recompute_head();
        Feedback::Accept
    }
}

/// A rejected message's identifying fields, decoded only when logged.
struct GossipFields<'a> {
    topic: GossipTopic,
    data: &'a [u8],
}

impl Display for GossipFields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.data;
        match self.topic {
            GossipTopic::BeaconAttestation(_) if data.len() == SINGLE_ATT_SIZE => {
                let buf = data[..SINGLE_ATT_SIZE].try_into().unwrap();
                let d = SingleAttestationView::data(buf);
                write!(
                    f,
                    "slot={} committee={} attester={} index={} block_root={} source_epoch={} \
                     target={}/{}",
                    d.slot(),
                    SingleAttestationView::committee_index(buf),
                    SingleAttestationView::attester_index(buf),
                    d.index(),
                    hex32(d.beacon_block_root()),
                    d.source_epoch(),
                    d.target_epoch(),
                    hex32(d.target_root()),
                )
            }
            GossipTopic::BeaconAggregateAndProof => match ParsedAggregateAndProof::try_from(data) {
                Some(p) => write!(
                    f,
                    "slot={} aggregator={} committee_bits={:#x} index={} block_root={} \
                     source_epoch={} target={}/{}",
                    p.agg_slot,
                    p.aggregator_index,
                    p.committee_bits,
                    p.agg_data_index,
                    hex32(p.agg_data.beacon_block_root()),
                    p.agg_data.source_epoch(),
                    p.agg_data.target_epoch(),
                    hex32(p.agg_data.target_root()),
                ),
                None => write!(f, "len={}", data.len()),
            },
            GossipTopic::SyncCommittee(_) if data.len() == SYNC_COMMITTEE_MSG_SIZE => {
                let buf = data[..SYNC_COMMITTEE_MSG_SIZE].try_into().unwrap();
                write!(
                    f,
                    "slot={} validator={} block_root={}",
                    SyncCommitteeView::slot(buf),
                    SyncCommitteeView::validator_index(buf),
                    hex32(SyncCommitteeView::beacon_block_root(buf)),
                )
            }
            GossipTopic::PayloadAttestationMessage
                if data.len() == PAYLOAD_ATTESTATION_MESSAGE_SIZE =>
            {
                let buf = data[..PAYLOAD_ATTESTATION_MESSAGE_SIZE].try_into().unwrap();
                let d = PayloadAttestationMessageView::data(buf);
                write!(
                    f,
                    "slot={} validator={} block_root={} present={} blob_data_available={}",
                    PayloadAttestationDataView::slot(d),
                    PayloadAttestationMessageView::validator_index(buf),
                    hex32(PayloadAttestationDataView::beacon_block_root(d)),
                    PayloadAttestationDataView::payload_present(d),
                    PayloadAttestationDataView::blob_data_available(d),
                )
            }
            _ => write!(f, "len={}", data.len()),
        }
    }
}
