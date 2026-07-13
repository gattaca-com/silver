use flux_profiler::timed;
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, StateId};
use silver_common::{
    PayloadValidationStatus,
    ssz_view::{
        BeaconBlockBodyGloasView as BlockBodyGloas, PAYLOAD_ATTESTATION_SIZE,
        PayloadAttestationDataView as PayloadAttestationData,
        PayloadAttestationMessageView as PayloadAttestationMessage,
        PayloadAttestationView as PayloadAttestation, SignedBeaconBlockView,
    },
};
use silver_ssz::ssz_view::PAYLOAD_ATTESTATION_MESSAGE_SIZE;

use super::BeaconStateTile;
use crate::{stf, tile::Feedback};

impl BeaconStateTile {
    /// Rebuild fork choice's justified-balance snapshot when its justified
    /// checkpoint has moved.
    #[timed]
    pub(super) fn refresh_justified_balances(&mut self) {
        if !self.fork_choice.justified_balances_stale() {
            return;
        }

        let jc = self.fork_choice.justified_checkpoint;
        // Justified is lifted only to resident roots; fall back to the head if
        // somehow absent (boot before the anchor node is wired).
        let sid = match self.fork_choice.find_node_idx(&jc.root) {
            Some(idx) => self.fork_choice.node(idx).state_id,
            None => self.last_applied,
        };
        let validators = self.state.read_view(sid).validators;
        self.fork_choice.set_justified_balances(jc, validators);
    }

    #[timed]
    pub(super) fn recompute_head(&mut self) {
        self.fork_choice.set_current_slot(self.ticker.current_slot());
        // Lift first: an epoch-boundary block's post-state may advance the
        // justified checkpoint, and `lift_checkpoints` reads the head post-state
        // (`last_applied`). Lifting before the refresh lets
        // `refresh_justified_balances` rebuild the snapshot for the *new*
        // checkpoint and fold weight against the new balances in this same pass.
        self.lift_checkpoints();
        self.refresh_justified_balances();
        self.fork_choice.recompute_head();
    }

    /// Monotonically lift fork-choice justified/finalized from the head post-
    /// state, but only to roots present in our node list — during sync the
    /// post-state often names checkpoints from blocks we never imported.
    pub(super) fn lift_checkpoints(&mut self) {
        let (j, f) = self.head_checkpoints();
        self.fork_choice.lift_justified(j);
        self.fork_choice.lift_finalized(f);
    }

    /// Spec `on_tick_per_slot` epoch-boundary pull-up: lift store
    /// justified/finalized from the head node's *unrealized* checkpoints
    /// (monotone, resident-only). For the canonical head this largely
    /// duplicates the realized `lift_checkpoints` after the eager
    /// `on_slot_start` advance; the value is consistency when the head node
    /// itself hasn't crossed the boundary yet.
    fn lift_unrealized_checkpoints(&mut self) {
        let head = self.fork_choice.find_head();
        let Some(idx) = self.fork_choice.find_node_idx(&head) else {
            return;
        };
        let n = self.fork_choice.node(idx);
        let (uj, uf) = (n.checkpoints.unrealized_justified, n.checkpoints.unrealized_finalized);
        self.fork_choice.lift_justified(uj);
        self.fork_choice.lift_finalized(uf);
    }

    /// Spec `on_tick`, fork-choice only: expire proposer boost, make the
    /// previous slot's deferred votes eligible, refold the head, and at an
    /// epoch boundary pull up unrealized checkpoints.
    #[timed]
    pub(super) fn fork_choice_tick(&mut self) {
        let prev_epoch = self.fork_choice.current_epoch();
        let new_epoch = self.ticker.current_slot() / SLOTS_PER_EPOCH;
        self.fork_choice.expire_proposer_boost();
        let n = self.head_validator_count();
        self.fork_choice.drain_pending_votes(n);
        self.recompute_head();
        if new_epoch > prev_epoch {
            self.lift_unrealized_checkpoints();
        }
    }

    /// Index bundle of fork-choice's canonical tip. For gossip-object
    /// validation per spec ("the head state").
    pub(super) fn canonical_state_id(&self) -> StateId {
        let head_root = self.fork_choice.find_head();
        let idx = self
            .fork_choice
            .find_node_idx(&head_root)
            .expect("find_head returns a node-resident root");
        self.fork_choice.node(idx).state_id
    }

    /// EL payload verdict, from either newPayload or an FCU response.
    pub(super) fn on_payload_verdict(
        &mut self,
        block_root: &B256,
        latest_valid_hash: &B256,
        status: PayloadValidationStatus,
    ) {
        match status {
            PayloadValidationStatus::Valid => {
                self.fork_choice.on_payload_valid(block_root);
            }
            PayloadValidationStatus::Invalid => {
                self.fork_choice.on_payload_invalid(block_root, latest_valid_hash);
                self.recompute_head();
            }
            // Optimistic: EL still syncing; verdict arrives on a later FCU.
            PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted => {}
        }
    }

    pub(super) fn handle_payload_attestation(&mut self, ssz: &[u8]) -> Feedback {
        if ssz.len() < PAYLOAD_ATTESTATION_MESSAGE_SIZE {
            return Feedback::Reject(None);
        }
        let buf: &[u8; PAYLOAD_ATTESTATION_MESSAGE_SIZE] =
            ssz[..PAYLOAD_ATTESTATION_MESSAGE_SIZE].try_into().unwrap();

        let validator_index = PayloadAttestationMessage::validator_index(buf);
        let data = PayloadAttestationMessage::data(buf);
        let block_root = *PayloadAttestationData::beacon_block_root(data);
        let slot = PayloadAttestationData::slot(data);
        let present = PayloadAttestationData::payload_present(data);
        let da = PayloadAttestationData::blob_data_available(data);

        let Some(idx) = self.fork_choice.find_node_idx(&block_root) else {
            return Feedback::Ignore;
        };
        let state_id = self.fork_choice.node(idx).state_id;

        let ptc_idx = {
            let rv = self.state.read_view(state_id);
            let state_epoch = rv.slot.slot_number() / SLOTS_PER_EPOCH;
            let Some(ptc) = stf::get_ptc(&rv.epoch, state_epoch, slot) else {
                return Feedback::Ignore;
            };
            match ptc.iter().position(|&v| v == validator_index) {
                Some(p) => p,
                None => return Feedback::Ignore,
            }
        };

        self.fork_choice.record_ptc_vote(&block_root, ptc_idx, present, da);
        self.recompute_head();

        Feedback::Accept(Some(block_root))
    }

    pub(super) fn notify_ptc_from_block(&mut self, block_data: &[u8]) {
        let body = SignedBeaconBlockView::body(block_data);
        let start = BlockBodyGloas::payload_attestations_offset(body) as usize;
        let end = BlockBodyGloas::parent_execution_requests_offset(body) as usize;
        let Some(section) = body.get(start..end) else {
            return;
        };

        for pa in section.chunks_exact(PAYLOAD_ATTESTATION_SIZE) {
            let Ok(pa) = <&[u8; PAYLOAD_ATTESTATION_SIZE]>::try_from(pa) else {
                continue;
            };
            let data = PayloadAttestation::data(pa);
            let block_root = *PayloadAttestationData::beacon_block_root(data);
            let present = PayloadAttestationData::payload_present(data);
            let da = PayloadAttestationData::blob_data_available(data);

            let bits = PayloadAttestation::aggregation_bits(pa);
            for i in 0..bits.len() * 8 {
                if bits[i / 8] >> (i % 8) & 1 == 1 {
                    self.fork_choice.record_ptc_vote(&block_root, i, present, da);
                }
            }
        }
    }
}
