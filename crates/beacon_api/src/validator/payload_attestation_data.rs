use silver_common::ssz_view::PAYLOAD_ATTESTATION_DATA_SIZE;

use crate::{
    ctx::ApiCtx,
    http::{
        response::Response,
        router::{Request, SSZ_MEDIA_TYPE},
    },
    validator::attestation_data::uint64_query,
};

const VERSION: &str = "gloas";

/// Answers from the head block alone: a slot whose block is not the head has
/// no block this node would attest to, so it is a 204.
pub(crate) fn payload_attestation_data(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.follows_chain(resp) {
        return;
    }
    if ctx.node_status.execution_optimistic() {
        resp.error(503, "the head is optimistic, and validators must not attest to it");
        return;
    }
    let Some(slot) = uint64_query(req, "slot") else {
        resp.error(400, "slot is a required Uint64 query parameter");
        return;
    };
    if !ctx.spec.is_gloas_at_slot(slot) {
        resp.error(400, "payload attestations start at the Gloas fork");
        return;
    }
    if slot > ctx.node_status.wall_slot {
        resp.error(400, "slot is past the current slot");
        return;
    }
    let observed = ctx.node_status.head_ptc;
    if observed.slot != slot {
        resp.send(204, None, &[], &[]);
        return;
    }

    let mut ssz = [0u8; PAYLOAD_ATTESTATION_DATA_SIZE];
    ssz[0..32].copy_from_slice(&ctx.node_status.head_root);
    ssz[32..40].copy_from_slice(&slot.to_le_bytes());
    ssz[40] = observed.payload_present as u8;
    ssz[41] = observed.blob_data_available as u8;
    if req.accepts_ssz() {
        resp.send(200, Some(SSZ_MEDIA_TYPE), &[("Eth-Consensus-Version", VERSION)], &[&ssz]);
    } else {
        resp.versioned_json(VERSION, |json| json.payload_attestation_data(&ssz));
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{BeaconStateOwner, SpecConfig};
    use silver_common::{PtcObservation, SyncUpdate};
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::test_ctx,
        testing::{answer, json, request, status_code},
    };

    const SLOT: u64 = 9000;
    const ROOT: [u8; 32] = [0xAB; 32];

    fn ctx() -> ApiCtx {
        let owner = BeaconStateOwner::published_empty_test(SLOT);
        let mut spec = SpecConfig::mainnet();
        spec.gloas_fork_epoch = 0;
        let mut ctx = test_ctx(&spec, owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx.node_status.wall_slot = SLOT;
        ctx.node_status.head_root = ROOT;
        ctx.node_status.head_ptc =
            PtcObservation { slot: SLOT, payload_present: true, blob_data_available: false };
        ctx
    }

    fn get(ctx: &ApiCtx, query: &str, accept: Option<&str>) -> Vec<u8> {
        answer(ctx, &ParsedRequest {
            query,
            accept,
            ..request("GET", "/eth/v1/validator/payload_attestation_data")
        })
    }

    #[test]
    fn the_head_block_slot_answers_with_its_observation() {
        let ctx = ctx();
        let response = get(&ctx, "slot=9000", None);
        assert!(std::str::from_utf8(&response).unwrap().contains("Eth-Consensus-Version: gloas"));
        let body = json(&response);
        assert_eq!(body["version"], "gloas");
        assert_eq!(body["data"]["beacon_block_root"], format!("0x{}", hex::encode(ROOT)));
        assert_eq!(body["data"]["slot"], "9000");
        assert_eq!(body["data"]["payload_present"], true);
        assert_eq!(body["data"]["blob_data_available"], false);
    }

    #[test]
    fn ssz_is_the_container_bytes() {
        let ctx = ctx();
        let response = get(&ctx, "slot=9000", Some(SSZ_MEDIA_TYPE));
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let body_at = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let mut expected = ROOT.to_vec();
        expected.extend_from_slice(&SLOT.to_le_bytes());
        expected.extend_from_slice(&[1, 0]);
        assert_eq!(&response[body_at..], expected);
    }

    #[test]
    fn a_slot_without_the_head_block_is_204() {
        let mut ctx = ctx();
        ctx.node_status.head_ptc.slot = SLOT - 1;
        assert_eq!(status_code(&get(&ctx, "slot=9000", None)), "204");
        assert_eq!(status_code(&get(&ctx, "slot=8999", None)), "200");
    }

    #[test]
    fn bad_future_and_pre_gloas_slots_are_400() {
        let mut ctx = ctx();
        for query in ["", "slot=x", "slot=9001"] {
            assert_eq!(status_code(&get(&ctx, query, None)), "400", "{query:?}");
        }
        ctx.spec.gloas_fork_epoch = u64::MAX;
        assert_eq!(status_code(&get(&ctx, "slot=9000", None)), "400");
    }

    #[test]
    fn syncing_or_optimistic_is_503() {
        let mut ctx = ctx();
        ctx.node_status.head.optimistic = true;
        assert_eq!(status_code(&get(&ctx, "slot=9000", None)), "503");
        ctx.node_status.target = None;
        assert_eq!(status_code(&get(&ctx, "slot=9000", None)), "503");
    }
}
