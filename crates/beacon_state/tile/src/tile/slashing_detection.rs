use flux::spine::SpineProducers;
use silver_beacon_state_data::{Slot, StateReadView};
use silver_common::{
    BeaconStateEvent, BlockSource, GossipTopic, NewGossipMsg, TCacheProducer, TProducer,
    ssz_view::{
        ProposerSlashingView, SINGLE_ATT_SIZE, SignedBeaconBlockView, SingleAttestationView,
    },
};
use silver_slashing::{Offence, SignedHeader};

use super::{BeaconStateTile, Producers, block::ParsedBlock, seen_validators::SeenIndices};
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
        let parsed = self.parse_and_verify_block(data, pre_verified)?;
        let (slot, proposer_index) = (parsed.header.slot, parsed.header.proposer_index);
        let header = SignedHeader::of_block(data, &parsed.header.body_root);
        let conflict = self.detection.proposals.observe(header, source == BlockSource::LocalGossip);
        match source {
            _ if !conflict => Ok(parsed),
            BlockSource::Rpc => Ok(parsed),
            BlockSource::LocalGossip => {
                refuse_local(Offence::DoubleProposal, proposer_index, slot);
                Err(PrecheckError::SlashableProposal { slot, proposer_index })
            }
            _ => Err(PrecheckError::SecondProposal { slot, proposer_index }),
        }
    }

    /// The API verified a local vote's signature under the spec's fork
    /// version, as gossip verified the public one. Refusal publishes nothing,
    /// so the head's fork schedule does not matter.
    pub(super) fn local_conflict(
        &self,
        m: &NewGossipMsg,
        single: &[u8; SINGLE_ATT_SIZE],
    ) -> Option<Offence> {
        if !m.is_api_verified() {
            return None;
        }
        let offence = self.detection.conflicts_with_public(single)?;
        let validator_index = SingleAttestationView::attester_index(single);
        refuse_local(offence, validator_index, SingleAttestationView::slot(single));
        Some(offence)
    }

    /// At most one proof of each kind per call, so the tile loop paces them.
    pub(super) fn publish_slashings(&mut self, producers: &mut Producers) {
        let wall_slot = self.ticker.current_slot();
        if !self.detection.has_proofs(wall_slot) {
            return;
        }
        let head = self.state.read_view(self.canonical_state_id());
        let (proposers, attesters) = (&self.seen_proposer_slashings, &self.seen_attester_slashed);
        let (events, stalled) = (&mut self.events_producer, &mut self.proof_handoff_stalled);

        let slashable_proposer = |index| slashable(&head, proposers, index);
        if let Some(proof) = self.detection.proposals.next_proof(slashable_proposer) {
            let slot = ProposerSlashingView::h1_slot(proof);
            let proposer_index = ProposerSlashingView::h1_proposer_index(proof);
            let (len, write) = (proof.len(), |ssz: &mut [u8]| ssz.copy_from_slice(proof));
            if publish_gossip(events, stalled, GossipTopic::ProposerSlashing, len, write, producers)
            {
                silver_log::info!(slot, proposer_index, "detected a double proposal");
                self.detection.proposals.pop_proof();
            }
        }

        let slashable_attester = |index| slashable(&head, attesters, index);
        let verifiable =
            |epoch| self.spec.fork_version_at(epoch) == head.epoch.fork_version_at(epoch);
        if let Some(proof) =
            self.detection.next_attester_proof(wall_slot, slashable_attester, verifiable)
        {
            let (offence, validator_index) = (proof.offence, proof.offenders().next());
            let offenders = proof.offenders().count();
            let (len, write) = (proof.slashing_len(), |ssz: &mut [u8]| proof.write_slashing(ssz));
            if publish_gossip(events, stalled, GossipTopic::AttesterSlashing, len, write, producers)
            {
                silver_log::info!(
                    ?offence,
                    validator_index,
                    offenders,
                    "detected an attester offence"
                );
                self.detection.pop_attester_proof();
            }
        }
    }
}

fn refuse_local(offence: Offence, validator_index: u64, slot: Slot) {
    silver_log::error!(
        ?offence,
        validator_index,
        slot,
        "refused a slashable message from our validator client"
    );
}

/// False when the tcache has no room this loop; the caller keeps the message.
/// A stall is logged once, not on every retry.
fn publish_gossip(
    events: &mut TProducer,
    stalled: &mut bool,
    topic: GossipTopic,
    len: usize,
    write: impl FnOnce(&mut [u8]),
    producers: &mut Producers,
) -> bool {
    let Some(ssz_read) = events.write_with(len, write) else {
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
