use flux::spine::SpineProducers;
use silver_beacon_state_data::{
    B256, ParsedAggregateAndProof, SLOTS_PER_EPOCH, Slot, StateId, StateReadView,
};
use silver_common::{
    ATTESTATION_SUBNETS, BeaconStateEvent, BlockSource, EngineNewPayloadEnvelopeReq, EngineReq,
    GossipTopic, MAX_BLOBS_PER_BLOCK, NewGossipMsg, PeerEvent, TCacheRead, TRead,
    metrics::timed,
    ssz_view::{
        AttestationDataView, AttesterSlashingView, ExecutionPayloadEnvelopeView as Envelope,
        PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, SignedBlsToExecutionChangeView,
        SignedExecutionPayloadEnvelopeView as SignedPayload, SignedVoluntaryExitView,
        SingleAttestationView,
    },
};

use super::{
    ATTESTATION_PROPAGATION_SLOT_RANGE, BY_ROOT_REQUEST_ID, BeaconStateTile, Feedback, Producers,
    attestation_pool::InsertOutcome,
    orphan_pool::{PendingBlock, has_room},
    seen_aggregates::Coverage,
};
use crate::{bls, counters::BeaconStateCounters, merkle, ssz_hash, stf, validate};

pub(super) enum EnvelopeCheck {
    Ready { block_root: B256, state_id: StateId },
    AwaitBlock(B256),
    Ignore,
}

impl BeaconStateTile {
    #[timed]
    pub(super) fn handle_attestation(&mut self, data: &[u8], subnet: u64) -> Feedback {
        if data.len() < SINGLE_ATT_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; SINGLE_ATT_SIZE] = data[..SINGLE_ATT_SIZE].try_into().unwrap();
        let attester_index = SingleAttestationView::attester_index(buf) as usize;
        let block_root = *SingleAttestationView::beacon_block_root(buf);
        let target_epoch = SingleAttestationView::target_epoch(buf);
        let att_slot = SingleAttestationView::slot(buf);
        let committee_index = SingleAttestationView::committee_index(buf) as usize;

        let wall = self.ticker.current_slot();
        if att_slot > wall || att_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall {
            return Feedback::Ignore;
        }

        self.seen_attesters.rotate_to(wall / SLOTS_PER_EPOCH);
        if self.seen_attesters.contains(target_epoch, attester_index) {
            return Feedback::Ignore;
        }

        // Pre-Gloas single attestations encode the committee in
        // `committee_index`, so `AttestationData.index` must be 0. Gloas widens
        // it to a payload-status bit (`index == 1` ⇒ payload present).
        let data_index = SingleAttestationView::data_index(buf);
        let is_gloas = self.spec.is_gloas_at(target_epoch);
        if !validate::attestation_index_ok(is_gloas, data_index) {
            return Feedback::Reject(None);
        }
        if let Err(f) = self.validate_attestation_target(SingleAttestationView::data(buf)) {
            return f;
        }
        let payload_present = if is_gloas {
            match self.gloas_payload_present(&block_root, att_slot, data_index) {
                Ok(present) => present,
                Err(f) => return f,
            }
        } else {
            false
        };

        let canon_id = self.canonical_state_id();
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        // Validate committee membership + signature against the canonical head.
        let view = self.state.read_view(canon_id);
        self.shuffling_cache.ensure_window(&view, att_epoch);
        let Some(shuffling) = self.shuffling_cache.lookup(&view, att_epoch) else {
            return Feedback::Ignore;
        };
        if committee_index >= shuffling.committees_per_slot {
            return Feedback::Reject(None);
        }
        if subnet !=
            compute_subnet_for_attestation(
                shuffling.committees_per_slot,
                att_slot,
                committee_index,
            )
        {
            return Feedback::Reject(None);
        }
        let committee = shuffling.committee(att_slot, committee_index);
        let Some(committee_position) = committee.iter().position(|&v| v == attester_index as u32)
        else {
            return Feedback::Reject(None);
        };
        let committee_len = committee.len();
        if attester_index >= view.validators.count() {
            return Feedback::Reject(None);
        }
        let fork_version = view.epoch.fork_version_at(target_epoch);
        let domain = bls::domain_from_fork_data(
            bls::DOMAIN_BEACON_ATTESTER,
            &view.imm.fork_data_root(fork_version),
        );
        let Some(verified) = bls::verify_single_attestation(
            buf,
            view.validators.pubkey_decompressed(attester_index),
            &domain,
        ) else {
            return Feedback::Reject(None);
        };

        let outcome = self.attestation_pool.insert_verified(
            buf,
            committee_position,
            committee_len,
            &verified,
        );
        debug_assert!(outcome != InsertOutcome::Inconsistent);
        if outcome == InsertOutcome::Full {
            BeaconStateCounters::AttestationPoolFull.inc();
            tracing::debug!(slot = att_slot, committee = committee_index, "attestation pool full");
        }

        let vote = stf::AttestationVote {
            validator: attester_index as u32,
            block_root,
            target_epoch,
            attestation_slot: att_slot,
            payload_present,
        };
        let n = self.head_validator_count();
        self.record_or_defer_vote(vote, n);

        self.seen_attesters.mark(target_epoch, attester_index);

        Feedback::Accept(None)
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
                return Feedback::Reject(None);
            }
        }

        self.record_attester_votes(data, n);
        Feedback::Accept(None)
    }

    fn record_attester_votes(&mut self, data: AttestationDataView<'_>, validator_count: usize) {
        let block_root = *data.beacon_block_root();
        let target_epoch = data.target_epoch();
        let attestation_slot = data.slot();
        let payload_present = data.index() == 1;
        for i in 0..self.stf_scratch.active.len() {
            let vote = stf::AttestationVote {
                validator: self.stf_scratch.active[i],
                block_root,
                target_epoch,
                attestation_slot,
                payload_present,
            };
            self.record_or_defer_vote(vote, validator_count);
        }
    }

    #[timed]
    pub(super) fn handle_aggregate_and_proof(&mut self, data: &[u8]) -> Feedback {
        let Some(parsed) = ParsedAggregateAndProof::try_from(data) else {
            return Feedback::Reject(None);
        };

        // Gossip-rule checks (no state access). Pre-Gloas requires index 0;
        // Gloas widens it to the payload-status bit (`index < 2`).
        let is_gloas = self.spec.is_gloas_at(parsed.att_epoch);
        let index_ok = validate::attestation_index_ok(is_gloas, parsed.agg_data_index);
        if !index_ok || parsed.agg_data.target_epoch() != parsed.att_epoch {
            return Feedback::Reject(None);
        }
        let wall = self.ticker.current_slot();
        if parsed.agg_slot > wall ||
            parsed.agg_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall
        {
            return Feedback::Ignore;
        }

        self.seen_aggregators.rotate_to(wall / SLOTS_PER_EPOCH);
        if self.seen_aggregators.contains(parsed.att_epoch, parsed.aggregator_index) {
            return Feedback::Ignore;
        }

        if parsed.committee_bits.count_ones() != 1 {
            return Feedback::Reject(None);
        }
        let committee_index = parsed.committee_bits.trailing_zeros() as usize;

        let data_root = ssz_hash::hash_attestation_data(parsed.agg_data.as_bytes());
        let coverage = self.seen_aggregates.coverage(
            parsed.agg_slot,
            committee_index as u64,
            data_root,
            parsed.aggregation_bits,
        );
        if coverage == Coverage::BySuperset {
            return Feedback::Ignore;
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
            return Feedback::Ignore;
        }

        let Some(shuffling) = self.shuffling_cache.lookup(&view, parsed.att_epoch) else {
            return Feedback::Ignore;
        };
        if committee_index >= shuffling.committees_per_slot {
            return Feedback::Reject(None);
        }
        let committee = shuffling.committee(parsed.agg_slot, committee_index);
        if !committee.contains(&(parsed.aggregator_index as u32)) {
            return Feedback::Reject(None);
        }
        let committee_len = committee.len();

        let Ok(committees) = stf::AttestedCommittees::new(parsed.aggregate_bytes, &shuffling)
        else {
            return Feedback::Reject(None);
        };
        if committees.attesters_into(count, &mut self.stf_scratch.active).is_err() ||
            self.stf_scratch.active.is_empty()
        {
            return Feedback::Reject(None);
        }

        if !is_aggregator(committee_len, parsed.selection_proof) {
            return Feedback::Reject(None);
        }

        if !Self::verify_aggregate_and_proof_sigs(
            &view,
            &parsed,
            &committees,
            data_root,
            &mut self.sig_batch,
        ) {
            return Feedback::Reject(None);
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
        Feedback::Accept(None)
    }

    pub(super) fn validate_execution_payload_envelope(&self, ssz: &[u8]) -> EnvelopeCheck {
        if !SignedPayload::check_size(ssz) {
            return EnvelopeCheck::Ignore;
        }
        let msg = SignedPayload::message(ssz);
        let block_root = *Envelope::beacon_block_root(msg);
        let Some(idx) = self.fork_choice.find_node_idx(&block_root) else {
            return EnvelopeCheck::AwaitBlock(block_root);
        };
        let state_id = self.fork_choice.node(idx).state_id;
        let rv = self.state.read_view(state_id);
        if let Err(e) = stf::verify_execution_payload_envelope(&rv, &self.spec, ssz) {
            tracing::debug!(error = %e, "execution_payload_envelope rejected");
            return EnvelopeCheck::Ignore;
        }
        EnvelopeCheck::Ready { block_root, state_id }
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
        };

        if self.fork_choice.is_payload_verified(&block_root) {
            return Feedback::Ignore;
        }

        // Versioned hashes come from the committed bid's KZG commitments — the
        // envelope does not carry them.
        let mut versioned_hashes = [[0u8; 32]; MAX_BLOBS_PER_BLOCK];
        let hash_count = match self
            .state
            .read_view(state_id)
            .slot
            .bid_versioned_hashes_len(&mut versioned_hashes)
        {
            Some(n) => n as u8,
            None => return Feedback::Reject(None),
        };

        self.fork_choice.mark_payload_verified(&block_root);
        self.envelope_requested.remove(&block_root);
        producers.produce(EngineReq::NewPayloadEnvelope(EngineNewPayloadEnvelopeReq {
            data: acquired.read,
            block_root,
            block_source: source,
            hash_count,
            versioned_hashes,
        }));

        producers.produce(BeaconStateEvent::PersistEnvelope { ssz: acquired.read, source });

        self.drain_awaiting_payload(block_root, producers);
        self.recompute_head();

        Feedback::Accept(Some(block_root))
    }

    fn buffer_pending_envelope(&mut self, block_root: B256, acquired: TRead) {
        if !has_room(&self.pending_envelopes, self.pending_bounds.max_dc, &block_root) {
            return;
        }
        self.pending_envelopes.insert(block_root, acquired);
    }

    pub(super) fn drain_pending_envelope(&mut self, block_root: B256, producers: &mut Producers) {
        let Some(acquired) = self.pending_envelopes.remove(&block_root) else {
            return;
        };

        let Some((ssz, _)) = acquired.buffer().ok() else {
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
            return Err(Feedback::Reject(None));
        }
        if !self.fork_choice.is_payload_verified(block_root) {
            let now_ms = self.ticker.millis_since_genesis();
            let rerequest_ms = self.pending_bounds.envelope_rerequest_ms;
            let due = self
                .envelope_requested
                .get(block_root)
                .is_none_or(|&at_ms| now_ms.saturating_sub(at_ms) >= rerequest_ms);
            if due {
                self.envelope_request_queue.push(*block_root);
            }
            return Err(Feedback::Ignore);
        }
        Ok(true)
    }

    fn drain_envelope_requests(&mut self, producers: &mut Producers) {
        if self.envelope_request_queue.is_empty() {
            return;
        }
        let now_ms = self.ticker.millis_since_genesis();
        let mut queue = std::mem::take(&mut self.envelope_request_queue);
        for block_root in queue.drain(..) {
            self.envelope_requested.insert(block_root, now_ms);
            producers.produce(PeerEvent::SendEnvelopesByRootRequest {
                request_id: BY_ROOT_REQUEST_ID,
                p2p_peer: None,
                block_root,
            });
        }
        self.envelope_request_queue = queue;
    }

    fn validate_attestation_target(&self, data: AttestationDataView<'_>) -> Result<(), Feedback> {
        let att_slot = data.slot();
        let target_epoch = data.target_epoch();
        if target_epoch != att_slot / SLOTS_PER_EPOCH {
            return Err(Feedback::Reject(None));
        }
        let Some(idx) = self.fork_choice.find_node_idx(data.beacon_block_root()) else {
            return Err(Feedback::Ignore);
        };
        match self.fork_choice.checkpoint_block_of(idx, target_epoch * SLOTS_PER_EPOCH) {
            Some(r) if r == *data.target_root() => {}
            Some(_) => return Err(Feedback::Reject(None)),
            None => return Err(Feedback::Ignore),
        }
        if self.fork_choice.node(idx).slot <= att_slot {
            Ok(())
        } else {
            Err(Feedback::Reject(None))
        }
    }

    fn record_or_defer_vote(&mut self, vote: stf::AttestationVote, validator_count: usize) {
        if vote.attestation_slot == self.ticker.current_slot() {
            self.fork_choice.defer_vote(vote);
        } else {
            self.fork_choice.record_vote(&vote, validator_count);
        }
    }

    fn verify_aggregate_and_proof_sigs(
        view: &StateReadView,
        parsed: &ParsedAggregateAndProof<'_>,
        committees: &stf::AttestedCommittees<'_>,
        data_root: B256,
        sig_batch: &mut bls::SigBatch,
    ) -> bool {
        let fv = view.epoch.fork_version_at(parsed.agg_data.target_epoch());
        let fork_data_root = view.imm.fork_data_root(fv);
        let domain = |ty| bls::domain_from_fork_data(ty, &fork_data_root);

        // (1) selection_proof — signer = aggregator, msg = htr(uint64(slot)).
        let slot_root = merkle::uint64_chunk(parsed.agg_slot);
        let sr_sp = bls::compute_signing_root(&slot_root, &domain(bls::DOMAIN_SELECTION_PROOF));

        // (2) outer AggregateAndProof signature.
        let agg_proof_root = ssz_hash::hash_tree_root_aggregate_and_proof(
            parsed.aggregator_index as u64,
            parsed.aggregate_bytes,
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
            return Feedback::Reject(None);
        }
        let buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] =
            data[..SIGNED_VOLUNTARY_EXIT_SIZE].try_into().unwrap();
        let exit_epoch = SignedVoluntaryExitView::epoch(buf);
        let vi_u = SignedVoluntaryExitView::validator_index(buf);
        let vi = vi_u as usize;

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        // Out-of-range index: state may be stale, defer.
        if vi >= view.validators.count() {
            return Feedback::Ignore;
        }
        let current_epoch = view.slot.current_epoch();
        if let Err(e) = validate::validate_voluntary_exit(
            &self.spec,
            &view.validators,
            vi_u as u32,
            exit_epoch,
            current_epoch,
        ) {
            tracing::debug!(error = %e, "voluntary_exit gossip rejected");
            return Feedback::Reject(None);
        }
        if stf::get_pending_balance_to_withdraw(&view.pending, vi_u as u32) != 0 {
            return Feedback::Reject(None);
        }

        let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch, vi_u);
        let imm = view.imm;
        let domain = bls::domain_from_fork_data(
            bls::DOMAIN_VOLUNTARY_EXIT,
            &imm.fork_data_root(imm.capella_fork_version),
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedVoluntaryExitView::signature(buf);
        if !bls::verify_one(view.validators.pubkey_decompressed(vi), sig, &signing_root) {
            return Feedback::Reject(None);
        }
        Feedback::Accept(None)
    }

    pub(super) fn handle_proposer_slashing(&mut self, data: &[u8]) -> Feedback {
        if data.len() != PROPOSER_SLASHING_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; PROPOSER_SLASHING_SIZE] = data[..PROPOSER_SLASHING_SIZE].try_into().unwrap();
        if let Err(e) = validate::validate_proposer_slashing(buf) {
            tracing::debug!(error = %e, "proposer_slashing gossip rejected");
            return Feedback::Reject(None);
        }

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);
        let current_epoch = view.slot.current_epoch();
        let proposer_index = ProposerSlashingView::h1_proposer_index(buf) as usize;
        if proposer_index >= view.validators.count() {
            return Feedback::Ignore;
        }
        if !stf::is_slashable_validator(&view.validators, proposer_index as u32, current_epoch) {
            return Feedback::Reject(None);
        }

        let h1_epoch = ProposerSlashingView::h1_slot(buf) / SLOTS_PER_EPOCH;
        let fv = view.epoch.fork_version_at(h1_epoch);
        let domain =
            bls::domain_from_fork_data(bls::DOMAIN_BEACON_PROPOSER, &view.imm.fork_data_root(fv));
        let sr1 = stf::signing_root_for_block_header(&buf[0..208], &domain);
        let sr2 = stf::signing_root_for_block_header(&buf[208..416], &domain);
        let sig1 = ProposerSlashingView::h1_signature(buf);
        let sig2 = ProposerSlashingView::h2_signature(buf);
        let pubkey = view.validators.pubkey_decompressed(proposer_index);

        self.sig_batch.clear();
        self.sig_batch.push_one(pubkey, sig1, sr1);
        self.sig_batch.push_one(pubkey, sig2, sr2);
        if !self.sig_batch.verify_all() {
            return Feedback::Reject(None);
        }
        Feedback::Accept(None)
    }

    pub(super) fn handle_attester_slashing(&mut self, data: &[u8]) -> Feedback {
        if !AttesterSlashingView::check_size(data) {
            return Feedback::Reject(None);
        }
        let canon_id = self.canonical_state_id();
        let ok = {
            let view = self.state.read_view(canon_id);
            stf::validate_attester_slashing_for_gossip(
                &view,
                data,
                &mut self.slashed_indices_scratch,
                &mut self.sig_batch,
            )
        };
        if !ok {
            return Feedback::Reject(None);
        }
        // Mark the equivocators (spec `on_attester_slashing`) so fork choice
        // excludes them. Idempotent; removes any live LMD weight next recompute.
        for i in 0..self.slashed_indices_scratch.len() {
            let idx = self.slashed_indices_scratch[i] as usize;
            self.fork_choice.mark_equivocating(idx);
        }
        Feedback::Accept(None)
    }

    #[timed]
    pub(super) fn handle_bls_to_execution_change(&mut self, data: &[u8]) -> Feedback {
        if data.len() != SIGNED_BLS_CHANGE_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; SIGNED_BLS_CHANGE_SIZE] = data[..SIGNED_BLS_CHANGE_SIZE].try_into().unwrap();

        let canon_id = self.canonical_state_id();
        let view = self.state.read_view(canon_id);

        let vi_u = SignedBlsToExecutionChangeView::validator_index(buf);
        let vi = vi_u as usize;
        if vi >= view.validators.count() {
            return Feedback::Ignore;
        }
        let from_pubkey = SignedBlsToExecutionChangeView::from_bls_pubkey(buf);
        let to_address = SignedBlsToExecutionChangeView::to_execution_address(buf);
        if let Err(e) =
            validate::validate_bls_to_execution_change(&view.validators, vi_u as u32, from_pubkey)
        {
            tracing::debug!(error = %e, "bls_to_execution_change gossip rejected");
            return Feedback::Reject(None);
        }

        let object_root = ssz_hash::hash_tree_root_bls_change(vi_u, from_pubkey, to_address);
        let imm = view.imm;
        let domain = bls::domain_from_fork_data(
            bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            &imm.fork_data_root(imm.genesis_fork_version),
        );
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        let sig = SignedBlsToExecutionChangeView::signature(buf);
        // Signer is the message's `from_bls_pubkey`, not a cached key.
        if !bls::verify_one_compressed(from_pubkey, sig, &signing_root) {
            return Feedback::Reject(None);
        }
        Feedback::Accept(None)
    }

    pub(super) fn handle_gossip(
        &mut self,
        read: TCacheRead,
        m: NewGossipMsg,
        do_relay: bool,
        pre_verified: bool,
        producers: &mut Producers,
    ) {
        let acquired = self.gossip_consumer.acquire(read);
        let Some(data) = acquired.buffer().ok().map(|(d, _)| d) else { return };

        let feedback = match m.topic {
            GossipTopic::BeaconBlock => {
                self.apply_block(data, read, BlockSource::Gossip, pre_verified, producers)
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
            GossipTopic::PayloadAttestationMessage => self.handle_payload_attestation(data),
            _ => {
                self.drain_envelope_requests(producers);
                return;
            }
        };
        match feedback {
            Feedback::Reject(_) => producers.produce(PeerEvent::P2pGossipInvalidMsg {
                p2p_peer: m.stream_id.peer(),
                topic: m.topic,
                hash: m.msg_hash,
            }),
            Feedback::Accept(block_root) => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }
                self.on_accept(block_root, producers);
            }
            Feedback::RequestParent { .. } => {
                self.park_block(feedback, PendingBlock::Gossip(m), data, producers)
            }
            Feedback::AwaitData(_) | Feedback::AwaitParentPayload { .. } => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }
                self.park_block(feedback, PendingBlock::Gossip(m), data, producers);
            }
            Feedback::Ignore => {}
        }
        self.drain_envelope_requests(producers);
    }

    fn relay_gossip(m: &NewGossipMsg, producers: &mut Producers) {
        producers.produce(PeerEvent::SendGossip {
            originator_stream_id: m.stream_id,
            topic: m.topic,
            msg_hash: m.msg_hash,
            recv_ts: m.recv_ts,
            protobuf: m.protobuf,
        });
    }
}

pub(super) fn is_aggregator(committee_len: usize, selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let h = merkle::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}

pub(super) fn compute_subnet_for_attestation(
    committees_per_slot: usize,
    slot: Slot,
    committee_index: usize,
) -> u64 {
    let committees_since_epoch_start = committees_per_slot as u64 * (slot % SLOTS_PER_EPOCH);
    (committees_since_epoch_start + committee_index as u64) % ATTESTATION_SUBNETS as u64
}
