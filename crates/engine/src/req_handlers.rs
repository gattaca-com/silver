use flux::spine::FluxSpine;
use silver_common::{
    EngineFcuReq, EngineGetBlobsReq, EngineGetPayloadBodiesByHashReq,
    EngineGetPayloadBodiesByRangeReq, EngineGetPayloadReq, EngineNewPayloadReq,
    EngineNewPayloadResp, EngineReq, EngineResp, PayloadValidationStatus, SilverSpine,
    TRandomAccess,
};

use crate::{
    EngineClient,
    client::{
        get_blobs, get_payload_bodies_by_hash, get_payload_bodies_by_range, send_fcu,
        send_new_payload,
    },
    types::{ForkchoiceState, PayloadAttributesV3, Withdrawal, decode_new_payload_data},
};

#[inline]
pub(crate) fn handle_request(
    client: &mut EngineClient,
    req_consumer: &mut TRandomAccess,
    req: &EngineReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    match req {
        EngineReq::Fcu(r) => handle_fcu(client, r),
        EngineReq::NewPayload(r) => handle_new_payload(client, req_consumer, r, producers),
        EngineReq::GetBlobs(r) => handle_get_blobs(client, r),
        EngineReq::GetPayloadBodiesByHash(r) => handle_get_payload_bodies_by_hash(client, r),
        EngineReq::GetPayloadBodiesByRange(r) => handle_get_payload_bodies_by_range(client, r),
        EngineReq::GetPayload(r) => handle_get_payload(client, *r),
    }
}

#[inline]
fn handle_fcu(client: &mut EngineClient, r: &EngineFcuReq) {
    let state = ForkchoiceState {
        head_block_hash: r.head_block_hash,
        safe_block_hash: r.safe_block_hash,
        finalized_block_hash: r.finalized_block_hash,
    };
    send_fcu(client, state, None, r.id);
}

#[inline]
fn handle_new_payload(
    client: &mut EngineClient,
    req_consumer: &mut TRandomAccess,
    r: &EngineNewPayloadReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    let acquired = req_consumer.acquire(r.data);
    let bytes = match acquired.buffer() {
        Ok((b, _)) => b.to_owned(),
        Err(e) => {
            tracing::warn!("engine tile: failed to read payload data: {e}");
            producers
                .engine_resps
                .produce(&EngineResp::NewPayload(invalid_new_payload_resp(r.id)).into());
            return;
        }
    };

    let (payload, exec_requests) = match decode_new_payload_data(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("engine tile: failed to decode payload: {e}");
            producers
                .engine_resps
                .produce(&EngineResp::NewPayload(invalid_new_payload_resp(r.id)).into());
            return;
        }
    };

    drop(acquired);
    req_consumer.free();

    let n = r.versioned_hash_count as usize;
    let versioned_hashes = r.versioned_hashes[..n].to_vec();
    send_new_payload(
        client,
        payload,
        versioned_hashes,
        r.parent_beacon_block_root,
        exec_requests,
        r.id,
    );
}

#[inline]
fn handle_get_blobs(client: &mut EngineClient, r: &EngineGetBlobsReq) {
    let n = r.hash_count as usize;
    let hashes: Vec<String> =
        r.hashes[..n].iter().map(|h| format!("0x{}", hex::encode(h))).collect();
    get_blobs(client, serde_json::json!([hashes]), r.id);
}

#[inline]
fn handle_get_payload_bodies_by_hash(
    client: &mut EngineClient,
    r: &EngineGetPayloadBodiesByHashReq,
) {
    let n = r.hash_count as usize;
    let hashes: Vec<String> =
        r.hashes[..n].iter().map(|h| format!("0x{}", hex::encode(h))).collect();
    get_payload_bodies_by_hash(client, serde_json::json!([hashes]), r.id);
}

#[inline]
fn handle_get_payload_bodies_by_range(
    client: &mut EngineClient,
    r: &EngineGetPayloadBodiesByRangeReq,
) {
    let start_hex = format!("0x{:x}", r.start);
    let count_hex = format!("0x{:x}", r.count);
    get_payload_bodies_by_range(client, serde_json::json!([start_hex, count_hex]), r.id);
}

#[inline]
fn handle_get_payload(client: &mut EngineClient, r: EngineGetPayloadReq) {
    let n = r.attrs_withdrawal_count as usize;
    let withdrawals = r.attrs_withdrawals[..n]
        .iter()
        .map(|w| Withdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: w.address,
            amount: w.amount,
        })
        .collect();
    let state = ForkchoiceState {
        head_block_hash: r.head_block_hash,
        safe_block_hash: r.safe_block_hash,
        finalized_block_hash: r.finalized_block_hash,
    };
    let attrs = Some(PayloadAttributesV3 {
        timestamp: r.attrs_timestamp,
        prev_randao: r.attrs_prev_randao,
        suggested_fee_recipient: r.attrs_fee_recipient,
        withdrawals,
        parent_beacon_block_root: r.attrs_parent_beacon_block_root,
    });
    send_fcu(client, state, attrs, r.id);
}

#[inline]
fn invalid_new_payload_resp(id: u64) -> EngineNewPayloadResp {
    EngineNewPayloadResp {
        id,
        status: PayloadValidationStatus::Invalid,
        latest_valid_hash: [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_new_payload_resp_fields() {
        let resp = invalid_new_payload_resp(99);
        assert_eq!(resp.id, 99);
        assert_eq!(resp.status, PayloadValidationStatus::Invalid);
        assert_eq!(resp.latest_valid_hash, [0u8; 32]);
    }

    #[test]
    fn invalid_new_payload_resp_preserves_id() {
        for id in [0, 1, u64::MAX] {
            assert_eq!(invalid_new_payload_resp(id).id, id);
        }
    }
}
