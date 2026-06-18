use silver_beacon_state_data::{ParsedAggregateAndProof, SLOTS_PER_EPOCH, StateReadView};
use silver_common::ssz_view::{
    AttesterSlashingView, PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
    SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, SignedBlsToExecutionChangeView,
    SignedVoluntaryExitView, SingleAttestationView,
};

use super::{ATTESTATION_PROPAGATION_SLOT_RANGE, BeaconStateTile, Feedback};
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

        let wall = self.ticker.current_slot();
        if att_slot > wall || att_slot.saturating_add(ATTESTATION_PROPAGATION_SLOT_RANGE) < wall {
            return Feedback::Ignore;
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

        self.on_attestation(attester_index, block_root, target_epoch);
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

        for i in 0..self.stf_scratch.active.len() {
            let vi = self.stf_scratch.active[i] as usize;
            self.on_attestation(vi, parsed.beacon_block_root, parsed.target_epoch);
        }
        Feedback::Accept(None)
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
        let view = self.state.read_view(canon_id);
        if stf::validate_attester_slashing_for_gossip(&view, data, &mut self.sig_batch) {
            Feedback::Accept(None)
        } else {
            Feedback::Reject(None)
        }
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
}

pub(super) fn is_aggregator(committee_len: usize, selection_proof: &[u8; 96]) -> bool {
    const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let h = ssz_hash::sha256(selection_proof);
    u64::from_le_bytes(h[0..8].try_into().unwrap()) % modulo == 0
}
