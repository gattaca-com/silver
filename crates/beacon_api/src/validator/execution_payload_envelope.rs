use silver_beacon_state_data::{B256, Slot, SpecConfig};
use silver_common::{
    BeaconApiRequest, PayloadFrame, ProducedEnvelope, TCacheReader, json_fields::parse_uint64,
};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::parse_root,
        response::Response,
        router::{Outcome, Request, SSZ_MEDIA_TYPE},
    },
};

pub(crate) fn execution_payload_envelope(
    req: &Request<'_>,
    _ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    if !req.accepts_ssz() {
        return resp.error(406, "only application/octet-stream is served");
    }
    let slot = req.params.get("slot").and_then(parse_uint64);
    let root = req.params.get("beacon_block_root").and_then(parse_root);
    let (Some(slot), Some(beacon_block_root)) = (slot, root) else {
        return resp.error(400, "invalid slot or beacon block root");
    };
    resp.defer(Outcome::AwaitingEnvelope(EnvelopeRequest { slot, beacon_block_root }));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EnvelopeRequest {
    pub(crate) slot: Slot,
    pub(crate) beacon_block_root: B256,
}

impl EnvelopeRequest {
    pub(crate) fn state_request(self, request_id: u64) -> BeaconApiRequest {
        BeaconApiRequest::ExecutionPayloadEnvelope {
            request_id,
            slot: self.slot,
            beacon_block_root: self.beacon_block_root,
        }
    }

    pub(crate) fn respond(
        self,
        resp: &mut Response<'_>,
        envelope: Option<ProducedEnvelope>,
        reader: &mut TCacheReader,
        spec: &SpecConfig,
    ) {
        let Some(envelope) = envelope else {
            return resp.error(404, "no cached execution payload envelope for this slot and root");
        };
        let acquired = reader.acquire(envelope.payload);
        let Ok((frame, _)) = acquired.buffer() else {
            return resp.error(404, "cached execution payload is no longer available");
        };
        let Some(frame) = PayloadFrame::parse(frame) else {
            return resp.error(500, "cached execution payload could not be read");
        };
        let headers = [("Eth-Consensus-Version", spec.fork_at_slot(self.slot).name())];
        resp.send(200, Some(SSZ_MEDIA_TYPE), &headers, &[
            &envelope.header,
            frame.execution_payload,
            frame.execution_requests,
        ]);
    }
}
