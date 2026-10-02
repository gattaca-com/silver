use flux::spine::SpineProducers;
use silver_beacon_state_data::{Slot, StateReadView};
use silver_common::{
    BeaconStateEvent, BlockSource, GossipTopic, NewGossipMsg, TCacheProducer, TProducer,
    ssz_view::{ProposerSlashingView, SignedBeaconBlockView, SingleAttestationView},
};
use silver_slashing::{Observation, Offence, SignedHeader};

use super::{
    BeaconStateTile, Feedback, Producers, block::ParsedBlock, seen_validators::SeenIndices,
};
use crate::error::PrecheckError;

impl BeaconStateTile {
    /// Closed gossip keys cannot add evidence, so they skip hashing and BLS.
    /// They still decode the body, as the spec rejects malformed payloads at
    /// any key. Pulled blocks still run the full validation path, as sync
    /// may need either block.
    pub(super) fn admit_block(
        &mut self,
        data: &[u8],
        source: BlockSource,
        pre_verified: bool,
    ) -> Result<ParsedBlock, PrecheckError> {
        if source == BlockSource::Gossip && SignedBeaconBlockView::check_size(data) {
            let slot = SignedBeaconBlockView::slot(data);
            let proposer_index = SignedBeaconBlockView::proposer_index(data);
            if self.detection.proposals.is_closed(slot, proposer_index, |index| {
                let head = self.state.read_view(self.canonical_state_id());
                slashable(&head, &self.seen_proposer_slashings, index)
            }) {
                self.decode_body(data)?;
                return Err(PrecheckError::SecondProposal { slot, proposer_index });
            }
        }
        let parsed = self.parse_and_verify_block(data, pre_verified).inspect_err(|error| {
            if let PrecheckError::BlockKnown { block_root } |
            PrecheckError::AwaitingData { block_root } = *error &&
                source == BlockSource::Rpc
            {
                self.detection.proposals.observe_public_copy(data, &block_root);
            }
        })?;
        let (slot, proposer_index) = (parsed.header.slot, parsed.header.proposer_index);
        let header = SignedHeader::of_block(data, &parsed.header.body_root);
        let public = source != BlockSource::LocalGossip;
        match self.detection.proposals.observe(header, public) {
            Observation::First | Observation::Repeat => Ok(parsed),
            Observation::Conflict { .. } if source == BlockSource::Rpc => Ok(parsed),
            Observation::Conflict { public_first: true } if !public => {
                refuse_local(Offence::DoubleProposal, proposer_index, slot);
                Err(PrecheckError::SlashableProposal { slot, proposer_index })
            }
            Observation::Conflict { .. } => {
                Err(PrecheckError::SecondProposal { slot, proposer_index })
            }
        }
    }

    /// A local vote at a seen key is refused when it conflicts with a public
    /// one. The API verified its signature under the spec's fork version, as
    /// gossip verified the public one. Refusal needs the head to verify both
    /// the same way.
    pub(super) fn seen_vote_feedback(&self, m: &NewGossipMsg, vote: &[u8]) -> Feedback {
        let (GossipTopic::BeaconAttestation(_), Ok(single)) = (m.topic, vote.try_into()) else {
            return Feedback::AlreadySeen;
        };
        if !m.is_api_verified() {
            return Feedback::AlreadySeen;
        }
        let head = self.state.read_view(self.canonical_state_id());
        let verifiable =
            |epoch| self.spec.fork_version_at(epoch) == head.epoch.fork_version_at(epoch);
        match self.detection.conflicts_with_public(single, verifiable) {
            Some(offence) => {
                let validator_index = SingleAttestationView::attester_index(single);
                refuse_local(offence, validator_index, SingleAttestationView::slot(single));
                Feedback::Slashable(offence)
            }
            None => Feedback::AlreadySeen,
        }
    }

    /// At most one proof of each kind per call, so the tile loop paces them.
    pub(super) fn publish_slashings(&mut self, producers: &mut Producers) {
        if !self.detection.has_proofs() {
            return;
        }
        let head = self.state.read_view(self.canonical_state_id());
        let proposers = &self.seen_proposer_slashings;
        let (events, stalled) = (&mut self.events_producer, &mut self.proof_handoff_stalled);

        let slashable_proposer = |index| slashable(&head, proposers, index);
        if let Some(proof) = self.detection.proposals.next_proof(slashable_proposer) {
            let slot = ProposerSlashingView::h1_slot(proof);
            let proposer_index = ProposerSlashingView::h1_proposer_index(proof);
            if publish_gossip(events, stalled, GossipTopic::ProposerSlashing, proof, producers) {
                silver_log::info!(slot, proposer_index, "detected a double proposal");
                self.detection.proposals.pop_proof();
            }
        }
    }
}

fn refuse_local(offence: Offence, validator_index: u64, slot: Slot) {
    silver_log::error!(
        ?offence,
        validator_index,
        slot,
        "refused a slashable message from our validator client; conflicting evidence is public"
    );
}

/// False when the tcache has no room this loop; the caller keeps the message.
/// A stall is logged once, not on every retry.
fn publish_gossip(
    events: &mut TProducer,
    stalled: &mut bool,
    topic: GossipTopic,
    ssz: &[u8],
    producers: &mut Producers,
) -> bool {
    let Some(ssz_read) = events.write_with(ssz.len(), |buffer| buffer.copy_from_slice(ssz)) else {
        if !std::mem::replace(stalled, true) {
            silver_log::error!(?topic, "beacon_state tcache full; originated message deferred");
        }
        return false;
    };
    *stalled = false;
    producers.produce(BeaconStateEvent::PublishGossip { topic, ssz: ssz_read });
    true
}

/// Spec `is_slashable_validator` at the head's epoch, for a validator no seen
/// slashing covers yet.
fn slashable(head: &StateReadView<'_>, seen: &SeenIndices, index: u64) -> bool {
    let index = index as usize;
    !seen.contains(index) &&
        index < head.validators.count() &&
        head.validators.is_slashable(index, head.slot.current_epoch())
}
