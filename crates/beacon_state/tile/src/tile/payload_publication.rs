use flux::spine::SpineProducers;
use silver_common::{
    BeaconApiRequest, BeaconApiResponse, BeaconStateEvent, BroadcastValidation, GossipTopic,
    LocalGossipFailure, PayloadFrame, ProposedPayload, TCacheProducer, TCacheRead,
    envelope_contents::SignedEnvelopeContents,
    ssz_view::{
        ExecutionPayloadEnvelopeView, ExecutionPayloadView, SignedExecutionPayloadEnvelopeView,
    },
};

use super::{BeaconStateTile, Producers, gossip::EnvelopeCheck};
use crate::{fork_choice::ExecutionStatus, stf};

impl BeaconStateTile {
    pub(super) fn publish_payload_envelope(
        &mut self,
        request_id: u64,
        ssz: TCacheRead,
        blob_data_included: bool,
        validation: BroadcastValidation,
        producers: &mut Producers,
    ) {
        if let Err(failure) = self.prepare_payload_publication(
            request_id,
            ssz,
            blob_data_included,
            validation,
            producers,
        ) {
            producers.produce(BeaconApiResponse::LocalGossipResponse {
                request_id,
                response: Err(failure),
            });
        }
    }

    fn prepare_payload_publication(
        &mut self,
        request_id: u64,
        ssz: TCacheRead,
        blob_data_included: bool,
        validation: BroadcastValidation,
        producers: &mut Producers,
    ) -> Result<(), LocalGossipFailure> {
        if self.sync_target.is_syncing() {
            return Err(LocalGossipFailure::NotSynced);
        }
        let acquired = self.reader.acquire(ssz);
        let (bytes, _) = acquired.buffer().map_err(|_| LocalGossipFailure::Internal)?;
        let contents = if blob_data_included {
            Some(SignedEnvelopeContents::parse(bytes).ok_or(LocalGossipFailure::Invalid)?)
        } else {
            None
        };
        let signed = contents.as_ref().map_or(bytes, |contents| contents.signed_envelope);
        if !SignedExecutionPayloadEnvelopeView::check_canonical(signed) {
            return Err(LocalGossipFailure::Invalid);
        }
        let envelope = SignedExecutionPayloadEnvelopeView::message(signed);
        let payload_bytes = ExecutionPayloadEnvelopeView::payload(envelope);
        let slot = ExecutionPayloadView::slot_number(payload_bytes);
        if !self.spec.is_gloas_at_slot(slot) {
            return Err(LocalGossipFailure::Invalid);
        }
        if slot > self.ticker.current_slot() {
            return Err(LocalGossipFailure::Future);
        }
        let (block_root, state_id) = match self.validate_execution_payload_envelope(signed) {
            EnvelopeCheck::Ready { block_root, state_id } => (block_root, state_id),
            EnvelopeCheck::AwaitBlock(_) => return Err(LocalGossipFailure::Unverifiable),
            EnvelopeCheck::Ignore => return Err(LocalGossipFailure::TooOld),
            EnvelopeCheck::Reject => return Err(LocalGossipFailure::Invalid),
        };
        let cached = if blob_data_included {
            None
        } else {
            Some(
                self.local_payload_envelope(slot, &block_root)
                    .ok_or(LocalGossipFailure::Unverifiable)?,
            )
        };
        let view = self.state.read_view(state_id);
        let state = view.slot.state();
        let consensus_valid = stf::envelope_withdrawals_match_expected(&view, signed);
        if !consensus_valid && validation != BroadcastValidation::Gossip {
            return Err(LocalGossipFailure::Invalid);
        }
        for node in &self.fork_choice.nodes {
            if node.block_root == block_root && node.execution_status == ExecutionStatus::Invalid {
                return Err(LocalGossipFailure::Invalid);
            }
            if validation == BroadcastValidation::ConsensusAndEquivocation &&
                node.slot == slot &&
                node.block_root != block_root &&
                self.state
                    .read_view(node.state_id)
                    .slot
                    .state()
                    .latest_block_header
                    .proposer_index ==
                    state.latest_block_header.proposer_index
            {
                return Err(LocalGossipFailure::ConflictingProposal);
            }
        }
        let commitments = &state.latest_execution_payload_bid.blob_kzg_commitments;
        let payload = if let Some(contents) = contents {
            if contents.blob_count() != commitments.len() {
                return Err(LocalGossipFailure::Invalid);
            }
            None
        } else {
            let cached = cached.expect("stateful publication has a cached payload");
            let frame_read = self.reader.acquire(cached.payload);
            let frame = PayloadFrame::parse(
                frame_read.buffer().map_err(|_| LocalGossipFailure::Internal)?.0,
            )
            .ok_or(LocalGossipFailure::Internal)?;
            if envelope[..cached.header.len()] != cached.header ||
                payload_bytes != frame.execution_payload ||
                ExecutionPayloadEnvelopeView::execution_requests(envelope) !=
                    frame.execution_requests ||
                frame.commitments != commitments.as_flattened()
            {
                return Err(LocalGossipFailure::Invalid);
            }
            Some(frame_read.to_read())
        };
        // Break the boundary-cache forwarding cycle before Control injects gossip.
        let ssz = self
            .events_producer
            .write_with(signed.len(), |out| out.copy_from_slice(signed))
            .ok_or(LocalGossipFailure::Internal)?;
        producers
            .produce(BeaconApiResponse::PayloadEnvelopeValidation { request_id, consensus_valid });
        if commitments.is_empty() {
            producers.produce(BeaconApiRequest::LocalGossip {
                request_id,
                topic: GossipTopic::ExecutionPayload,
                ssz,
            });
        } else {
            let commitments = self
                .events_producer
                .write_with(commitments.len() * 48, |out| {
                    out.copy_from_slice(commitments.as_flattened());
                })
                .ok_or(LocalGossipFailure::Internal)?;
            producers.produce(BeaconStateEvent::ProposedPayload(ProposedPayload {
                request_id,
                ssz,
                contents: acquired.to_read(),
                payload,
                commitments,
            }));
        }
        Ok(())
    }
}
