use flux::spine::SpineProducers;
use silver_beacon_state_data::{Slot, StateReadView};
use silver_common::{
    BeaconStateEvent, BlockSource, GossipTopic, TCacheProducer, TProducer,
    ssz_view::{
        ProposerSlashingView, SINGLE_ATT_SIZE, SignedBeaconBlockView, SingleAttestationView,
    },
};
use silver_slashing::{Observation, Offence, SignedHeader};

use super::{
    BeaconStateTile, Feedback, Producers, block::ParsedBlock, seen_validators::SeenIndices,
};
use crate::{bls, error::PrecheckError, ssz_hash};

impl BeaconStateTile {
    /// Closed gossip keys cannot add evidence, so they skip hashing and BLS.
    /// They still decode the body, as the spec rejects malformed payloads at
    /// any key. Pulled blocks still run the full validation path, as sync
    /// may need either block.
    pub(super) fn admit_block(
        &mut self,
        data: &[u8],
        source: BlockSource,
    ) -> Result<ParsedBlock, Feedback> {
        if !SignedBeaconBlockView::check_size(data) {
            return Err(Feedback::Reject(None));
        }
        if source == BlockSource::Gossip {
            let slot = SignedBeaconBlockView::slot(data);
            let proposer_index = SignedBeaconBlockView::proposer_index(data);
            if self.detection.proposals.is_closed(slot, proposer_index, |index| {
                let head = self.state.read_view(self.canonical_state_id());
                slashable(&head, &self.seen_proposer_slashings, index)
            }) {
                if let Err(error) = self.decode_body(data) {
                    silver_log::debug!(
                        slot,
                        proposer_index,
                        "malformed block at a closed key: {error}"
                    );
                    return Err(error.feedback());
                }
                silver_log::debug!(slot, proposer_index, ?source, "another block holds the slot");
                return Err(Feedback::Ignore);
            }
        }
        let parsed = self.parse_and_verify_block(data).map_err(|error| match error {
            PrecheckError::BlockKnown { block_root } |
            PrecheckError::AwaitingData { block_root }
                if source == BlockSource::Rpc =>
            {
                self.detection.proposals.observe_known_public(data, &block_root);
                error.feedback()
            }
            PrecheckError::BlockKnown { .. } | PrecheckError::AwaitingData { .. }
                if source == BlockSource::LocalGossip =>
            {
                Feedback::AlreadySeen
            }
            error => error.feedback(),
        })?;
        let (slot, proposer_index) = (parsed.header.slot, parsed.header.proposer_index);
        let header = SignedHeader::of_block(data, &parsed.header.body_root);
        let public = source != BlockSource::LocalGossip;
        match self.detection.proposals.observe(header, public) {
            Observation::First | Observation::Repeat => Ok(parsed),
            Observation::Conflict { .. } if source == BlockSource::Rpc => Ok(parsed),
            Observation::Conflict { public_first: true } if !public => {
                Err(Self::refuse_local(Offence::DoubleProposal, proposer_index, slot))
            }
            Observation::Conflict { .. } => {
                silver_log::debug!(slot, proposer_index, ?source, "another block holds the slot");
                Err(Feedback::Ignore)
            }
        }
    }

    /// At most one proof of each kind per call, so the tile loop paces them.
    pub(super) fn publish_slashings(&mut self, producers: &mut Producers) {
        if !self.detection.has_proofs() {
            return;
        }
        let head = self.state.read_view(self.canonical_state_id());
        let proposers = &self.seen_proposer_slashings;
        let events = &mut self.events_producer;

        let slashable_proposer = |index| slashable(&head, proposers, index);
        if let Some(proof) = self.detection.proposals.next_proof(slashable_proposer) {
            let slot = ProposerSlashingView::h1_slot(proof);
            let proposer_index = ProposerSlashingView::h1_proposer_index(proof);
            if publish_gossip(events, GossipTopic::ProposerSlashing, proof, producers) {
                silver_log::info!(slot, proposer_index, "detected a double proposal");
                self.detection.proposals.pop_proof();
            }
        }
    }

    /// A local vote at a seen key. Only one conflicting with a public vote has
    /// its signature checked, to tell a refusal from garbage.
    pub(super) fn local_repeat_verdict(&self, single: &[u8; SINGLE_ATT_SIZE]) -> Feedback {
        let head = self.state.read_view(self.canonical_state_id());
        let signing_version = |epoch| head.epoch.fork_version_at(epoch);
        match self.detection.conflicts_with_public(single, signing_version) {
            None => Feedback::AlreadySeen,
            Some(_) if !verifies_in_view(&head, single) => Feedback::Reject(None),
            Some(offence) => {
                let validator_index = SingleAttestationView::attester_index(single);
                Self::refuse_local(offence, validator_index, SingleAttestationView::slot(single))
            }
        }
    }

    pub(super) fn refuse_local(offence: Offence, validator_index: u64, slot: Slot) -> Feedback {
        silver_log::error!(
            ?offence,
            validator_index,
            slot,
            "refused a slashable message from our validator client; conflicting evidence is public"
        );
        Feedback::Slashable
    }
}

/// False when the tcache has no room this loop; the caller keeps the message.
fn publish_gossip(
    events: &mut TProducer,
    topic: GossipTopic,
    ssz: &[u8],
    producers: &mut Producers,
) -> bool {
    let Some(ssz_read) = events.write_with(ssz.len(), |buffer| buffer.copy_from_slice(ssz)) else {
        silver_log::error!(?topic, "beacon_state tcache full; originated message deferred");
        return false;
    };
    producers.produce(BeaconStateEvent::PublishGossip { topic, ssz: ssz_read });
    true
}

// Activation requires finalization, so an active attester's key is stable
// across forks.
fn verifies_in_view(head: &StateReadView<'_>, single: &[u8; SINGLE_ATT_SIZE]) -> bool {
    let validator_index = SingleAttestationView::attester_index(single) as usize;
    if validator_index >= head.validators.count() {
        return false;
    }
    let data = SingleAttestationView::data(single);
    let domain = bls::compute_domain(
        bls::DOMAIN_BEACON_ATTESTER,
        head.epoch.fork_version_at(data.target_epoch()),
        &head.imm.genesis_validators_root,
    );
    let signing_root =
        bls::compute_signing_root(&ssz_hash::hash_attestation_data(data.as_bytes()), &domain);
    let pubkey = head.validators.pubkey_decompressed(validator_index);
    bls::verify_one(pubkey, SingleAttestationView::signature(single), &signing_root)
}

/// Spec `is_slashable_validator` at the head's epoch, for a validator no seen
/// slashing covers yet.
fn slashable(head: &StateReadView<'_>, seen: &SeenIndices, index: u64) -> bool {
    let index = index as usize;
    !seen.contains(index) &&
        index < head.validators.count() &&
        head.validators.is_slashable(index, head.slot.current_epoch())
}
