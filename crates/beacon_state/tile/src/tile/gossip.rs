use flux::spine::SpineProducers;
use silver_beacon_state_data::{ParsedAggregateAndProof, SLOTS_PER_EPOCH, StateReadView};
use silver_common::{
    BlockSource, GossipTopic, NewGossipMsg, PeerEvent,
    ssz_view::{
        AttesterSlashingView, PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, SignedBeaconBlockView,
        SignedBlsToExecutionChangeView, SignedVoluntaryExitView, SingleAttestationView,
    },
};

use super::{
    ATTESTATION_PROPAGATION_SLOT_RANGE, BeaconStateTile, Feedback, Producers,
    orphan_pool::PendingBlock,
};
use crate::{bls, shuffling, ssz_hash, stf, validate};

impl BeaconStateTile {
    pub(super) fn handle_attestation(&mut self, data: &[u8]) -> Feedback {
        if data.len() < SINGLE_ATT_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; SINGLE_ATT_SIZE] = data[..SINGLE_ATT_SIZE].try_into().unwrap();
        let attester_index = SingleAttestationView::attester_index(buf) as usize;
        let block_root = *SingleAttestationView::beacon_block_root(buf);
        let target_epoch = SingleAttestationView::target_epoch(buf);
        let att_slot = SingleAttestationView::slot(buf);
        let committee_index = SingleAttestationView::committee_index(buf) as usize;
        let target_root = *SingleAttestationView::target_root(buf);

        let wall = self.ticker.current_slot();
        if att_slot > wall || att_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall {
            return Feedback::Ignore;
        }

        // Fulu single attestations encode the committee in `committee_index`;
        // `AttestationData.index` must be 0.
        if SingleAttestationView::data_index(buf) != 0 {
            return Feedback::Reject(None);
        }
        if target_epoch != att_slot / SLOTS_PER_EPOCH {
            return Feedback::Reject(None);
        }
        match self.fork_choice.get_checkpoint_block(&block_root, target_epoch * SLOTS_PER_EPOCH) {
            Some(r) if r == target_root => {}
            Some(_) => return Feedback::Reject(None),
            None => return Feedback::Ignore,
        }
        if let Some(idx) = self.fork_choice.find_node_idx(&block_root) &&
            self.fork_choice.node(idx).slot > att_slot
        {
            return Feedback::Reject(None);
        }

        let canon_id = self.canonical_state_id();
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        self.shuffling_cache.ensure_window(
            &self.state,
            canon_id,
            att_epoch,
            &mut self.stf_scratch.active,
        );

        // Validate committee membership + signature against the canonical head.
        let view = self.state.read_view(canon_id);
        let shuffled = match self.shuffling_cache.lookup(&view, att_epoch) {
            Some(s) => s,
            None => return Feedback::Ignore,
        };
        let committees_per_slot = shuffling::committees_per_slot(shuffled.len());
        if committee_index >= committees_per_slot {
            return Feedback::Reject(None);
        }
        let committee = shuffling::get_beacon_committee(
            shuffled,
            att_slot,
            committee_index,
            committees_per_slot,
        );
        if !committee.contains(&(attester_index as u32)) {
            return Feedback::Reject(None);
        }
        if attester_index >= view.validators.count() {
            return Feedback::Reject(None);
        }
        let (fork_version, gvr) = view.imm.fork_version_at(target_epoch);
        let ok = bls::verify_single_attestation(
            buf,
            view.validators.pubkey_decompressed(attester_index),
            fork_version,
            &gvr,
        );
        if !ok {
            return Feedback::Reject(None);
        }

        // Spec `validate_on_attestation`: a current-slot vote is not eligible
        // until the next slot. Defer it; older slots apply immediately.
        if att_slot == self.ticker.current_slot() {
            self.fork_choice.defer_vote(attester_index as u32, block_root, target_epoch);
        } else {
            let n = self.head_validator_count();
            self.fork_choice.record_vote(attester_index, block_root, target_epoch, n);
        }
        Feedback::Accept(None)
    }

    /// Spec `on_attestation` core for an aggregated `Attestation` (the inner
    /// part of a `SignedAggregateAndProof`): validate the LMD/FFG target and
    /// ancestry, derive the attesting indices via committee shuffling, and
    /// record their votes (deferring current-slot votes per the slot+1 rule).
    pub(super) fn apply_attestation(&mut self, att: &[u8]) -> Feedback {
        use silver_common::ssz_view::{AttestationDataView, AttestationView};
        let data = AttestationView::data(att);
        let att_slot = AttestationDataView::slot(data);
        let target_epoch = AttestationDataView::target_epoch(data);
        let target_root = *AttestationDataView::target_root(data);
        let beacon_block_root = *AttestationDataView::beacon_block_root(data);

        if target_epoch != att_slot / SLOTS_PER_EPOCH {
            return Feedback::Reject(None);
        }
        match self
            .fork_choice
            .get_checkpoint_block(&beacon_block_root, target_epoch * SLOTS_PER_EPOCH)
        {
            Some(r) if r == target_root => {}
            Some(_) => return Feedback::Reject(None),
            None => return Feedback::Ignore,
        }
        match self.fork_choice.find_node_idx(&beacon_block_root) {
            Some(idx) if self.fork_choice.node(idx).slot <= att_slot => {}
            _ => return Feedback::Ignore,
        }

        let canon_id = self.canonical_state_id();
        let att_epoch = att_slot / SLOTS_PER_EPOCH;
        self.shuffling_cache.ensure_window(
            &self.state,
            canon_id,
            att_epoch,
            &mut self.stf_scratch.active,
        );
        let n = self.head_validator_count();
        {
            let view = self.state.read_view(canon_id);
            let Some(shuffled) = self.shuffling_cache.lookup(&view, att_epoch) else {
                return Feedback::Ignore;
            };
            let cps = shuffling::committees_per_slot(shuffled.len());
            if stf::attesting_indices_from_shuffled(
                att,
                shuffled,
                cps,
                n,
                &mut self.stf_scratch.active,
            )
            .is_err()
            {
                return Feedback::Reject(None);
            }
        }

        let defer = att_slot == self.ticker.current_slot();
        for i in 0..self.stf_scratch.active.len() {
            let vi = self.stf_scratch.active[i];
            if defer {
                self.fork_choice.defer_vote(vi, beacon_block_root, target_epoch);
            } else {
                self.fork_choice.record_vote(vi as usize, beacon_block_root, target_epoch, n);
            }
        }
        Feedback::Accept(None)
    }

    pub(super) fn handle_aggregate_and_proof(&mut self, data: &[u8]) -> Feedback {
        let Some(parsed) = ParsedAggregateAndProof::try_from(data) else {
            return Feedback::Reject(None);
        };

        // Gossip-rule checks (no state access).
        if parsed.agg_data_index != 0 || parsed.target_epoch != parsed.att_epoch {
            return Feedback::Reject(None);
        }
        let wall = self.ticker.current_slot();
        if parsed.agg_slot > wall ||
            parsed.agg_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall
        {
            return Feedback::Ignore;
        }
        if parsed.committee_bits.count_ones() != 1 {
            return Feedback::Reject(None);
        }
        let committee_index = parsed.committee_bits.trailing_zeros() as usize;

        // Fork-choice: block known + target.root ancestor at target-epoch start.
        match self
            .fork_choice
            .get_checkpoint_block(&parsed.beacon_block_root, parsed.target_epoch * SLOTS_PER_EPOCH)
        {
            Some(r) if r == parsed.target_root => {}
            Some(_) => return Feedback::Reject(None),
            None => return Feedback::Ignore,
        }

        let canon_id = self.canonical_state_id();
        self.shuffling_cache.ensure_window(
            &self.state,
            canon_id,
            parsed.att_epoch,
            &mut self.stf_scratch.active,
        );

        let view = self.state.read_view(canon_id);
        let count = view.validators.count();
        if parsed.aggregator_index >= count {
            return Feedback::Ignore;
        }

        let shuffled = match self.shuffling_cache.lookup(&view, parsed.att_epoch) {
            Some(s) => s,
            None => return Feedback::Ignore,
        };
        let committees_per_slot = shuffling::committees_per_slot(shuffled.len());
        if committee_index >= committees_per_slot {
            return Feedback::Reject(None);
        }
        let committee = shuffling::get_beacon_committee(
            shuffled,
            parsed.agg_slot,
            committee_index,
            committees_per_slot,
        );
        if !committee.contains(&(parsed.aggregator_index as u32)) {
            return Feedback::Reject(None);
        }
        let committee_len = committee.len();

        self.stf_scratch.active.clear();
        for (j, &vi32) in committee.iter().enumerate() {
            let byte_idx = j / 8;
            let bit_idx = j % 8;
            if byte_idx >= parsed.aggregation_bits.len() ||
                parsed.aggregation_bits[byte_idx] & (1 << bit_idx) == 0
            {
                continue;
            }
            if vi32 as usize >= count {
                return Feedback::Reject(None);
            }
            self.stf_scratch.active.push(vi32);
        }
        if self.stf_scratch.active.is_empty() {
            return Feedback::Reject(None);
        }

        if !is_aggregator(committee_len, parsed.selection_proof) {
            return Feedback::Reject(None);
        }

        if !Self::verify_aggregate_and_proof_sigs(
            &view,
            &parsed,
            &self.stf_scratch.active,
            &mut self.sig_batch,
        ) {
            return Feedback::Reject(None);
        }

        // Record the votes (validates target/ancestry + slot+1 deferral, derives
        // the committee again). The inner attestation is the aggregate field.
        self.apply_attestation(parsed.aggregate_bytes)
    }

    fn verify_aggregate_and_proof_sigs(
        view: &StateReadView,
        parsed: &ParsedAggregateAndProof<'_>,
        active_scratch: &[u32],
        sig_batch: &mut bls::SigBatch,
    ) -> bool {
        let (fv, gvr) = view.imm.fork_version_at(parsed.target_epoch);

        // (1) selection_proof — signer = aggregator, msg = htr(uint64(slot)).
        let slot_root = ssz_hash::uint64_chunk(parsed.agg_slot);
        let domain_sp = bls::compute_domain(bls::DOMAIN_SELECTION_PROOF, fv, &gvr);
        let sr_sp = bls::compute_signing_root(&slot_root, &domain_sp);

        // (2) outer AggregateAndProof signature.
        let agg_proof_root = ssz_hash::hash_tree_root_aggregate_and_proof(
            parsed.aggregator_index as u64,
            parsed.aggregate_bytes,
            parsed.selection_proof,
        );
        let domain_aap = bls::compute_domain(bls::DOMAIN_AGGREGATE_AND_PROOF, fv, &gvr);
        let sr_aap = bls::compute_signing_root(&agg_proof_root, &domain_aap);

        // (3) inner aggregate signature over AttestationData.
        let data_root = ssz_hash::hash_attestation_data(parsed.agg_data);
        let domain_att = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &gvr);
        let sr_att = bls::compute_signing_root(&data_root, &domain_att);

        sig_batch.clear();
        let aggregator_pk = view.validators.pubkey_decompressed(parsed.aggregator_index);
        sig_batch.push_one(aggregator_pk, parsed.selection_proof, sr_sp);
        sig_batch.push_one(aggregator_pk, parsed.outer_sig, sr_aap);
        sig_batch.push_aggregate(
            active_scratch.iter().map(|&vi| view.validators.pubkey_decompressed(vi as usize)),
            parsed.agg_sig,
            sr_att,
        );
        sig_batch.verify_all()
    }

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
        let domain = bls::compute_domain(
            bls::DOMAIN_VOLUNTARY_EXIT,
            imm.capella_fork_version,
            &imm.genesis_validators_root,
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
        let h2_epoch = ProposerSlashingView::h2_slot(buf) / SLOTS_PER_EPOCH;
        let (fv1, gvr) = view.imm.fork_version_at(h1_epoch);
        let (fv2, _) = view.imm.fork_version_at(h2_epoch);
        let sr1 = stf::signing_root_for_block_header(&buf[0..208], fv1, &gvr);
        let sr2 = stf::signing_root_for_block_header(&buf[208..416], fv2, &gvr);
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
        let domain = bls::compute_domain(
            bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
            imm.genesis_fork_version,
            &imm.genesis_validators_root,
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
        m: NewGossipMsg,
        data: &[u8],
        do_relay: bool,
        pre_verified: bool,
        producers: &mut Producers,
    ) {
        let feedback = match m.topic {
            GossipTopic::BeaconBlock => {
                let acquired = self.gossip_consumer.acquire(m.ssz);
                Some(self.apply_block(data, acquired, BlockSource::Gossip, pre_verified, producers))
            }
            GossipTopic::BeaconAttestation(_) => Some(self.handle_attestation(data)),
            GossipTopic::BeaconAggregateAndProof => Some(self.handle_aggregate_and_proof(data)),
            GossipTopic::VoluntaryExit => Some(self.handle_voluntary_exit(data)),
            GossipTopic::ProposerSlashing => Some(self.handle_proposer_slashing(data)),
            GossipTopic::AttesterSlashing => Some(self.handle_attester_slashing(data)),
            GossipTopic::BlsToExecutionChange => Some(self.handle_bls_to_execution_change(data)),
            _ => None,
        };
        match feedback {
            Some(Feedback::Reject(_)) => producers.produce(PeerEvent::P2pGossipInvalidMsg {
                p2p_peer: m.stream_id.peer(),
                topic: m.topic,
                hash: m.msg_hash,
            }),
            Some(Feedback::Accept(block_root)) => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }

                // Try to apply any pending blocks for which this one was the parent.
                if let Some(root) = block_root {
                    self.apply_pending_blocks(root, producers);
                }
                producers.produce(self.status_event());
            }
            Some(Feedback::RequestParent { parent_root, block_root }) => {
                let peer = m.stream_id.peer();
                let block_slot = SignedBeaconBlockView::slot(data);
                self.buffer_orphan(
                    parent_root,
                    block_root,
                    PendingBlock::Gossip(m),
                    block_slot,
                    peer,
                    producers,
                );
            }
            Some(Feedback::AwaitData(block_root)) => {
                if do_relay {
                    Self::relay_gossip(&m, producers);
                }
                self.buffer_awaiting_columns(block_root, PendingBlock::Gossip(m));
            }
            Some(Feedback::Ignore) | None => {}
        }
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
    let h = ssz_hash::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}
