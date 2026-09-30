use flux::spine::FluxSpine;
use silver_common::{
    EngineFcuReq, EngineFcuResp, EngineGetBlobsReq, EngineGetBlobsResp, EngineGetPayloadReq,
    EngineGetPayloadResp, EngineNewPayloadEnvelopeReq, EngineNewPayloadReq, EngineNewPayloadResp,
    EnginePreparePayloadReq, EnginePreparePayloadResp, EngineReq, EngineResp,
    PayloadValidationStatus, SilverSpine, TCacheRead, TCacheReader, TProducer,
};

use crate::{
    EngineClient, EngineError,
    client::{
        get_blobs, get_payload, send_fcu, send_new_payload, send_new_payload_envelope,
        send_prepare_payload,
    },
    resp_handlers::write_tcache,
    types::{ForkchoiceState, PayloadAttributesV3, Withdrawal},
};

#[inline]
pub(crate) fn handle_request(
    client: &mut EngineClient,
    reader: &mut TCacheReader,
    req: &EngineReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    match req {
        EngineReq::Fcu(r) => handle_fcu(client, r),
        EngineReq::NewPayload(r) => handle_new_payload(client, reader, r, producers),
        EngineReq::NewPayloadEnvelope(r) => {
            handle_new_payload_envelope(client, reader, r, producers)
        }
        EngineReq::PreparePayload(r) => handle_prepare_payload(client, *r),
        EngineReq::GetPayload(r) => handle_get_payload(client, *r),
        EngineReq::GetBlobs(r) => handle_get_blobs(client, r),
    }
}

/// Unsafe no-EL testing mode: answer each request with a synthetic VALID
/// response without contacting an execution client. Built payloads can't be
/// fabricated, so those return no `data`; blob fetches answer
/// as a healthy EL that simply holds none of the requested blobs.
#[inline]
pub(crate) fn handle_request_no_el(
    resp_producer: &mut TProducer,
    req: &EngineReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    let resp = match req {
        EngineReq::Fcu(r) => EngineResp::Fcu(EngineFcuResp {
            block_root: r.block_root,
            status: PayloadValidationStatus::Valid,
            latest_valid_hash: Some(r.head_block_hash),
        }),
        EngineReq::NewPayload(r) => EngineResp::NewPayload(EngineNewPayloadResp {
            block_root: r.block_root,
            status: PayloadValidationStatus::Valid,
            latest_valid_hash: None,
        }),
        EngineReq::NewPayloadEnvelope(r) => EngineResp::NewPayload(EngineNewPayloadResp {
            block_root: r.block_root,
            status: PayloadValidationStatus::Valid,
            latest_valid_hash: None,
        }),
        EngineReq::PreparePayload(r) => EngineResp::PreparePayload(EnginePreparePayloadResp {
            id: r.id,
            payload_id: Some(r.id.to_le_bytes()),
        }),
        EngineReq::GetPayload(r) => {
            EngineResp::GetPayload(EngineGetPayloadResp { id: r.id, data: None })
        }
        // EL responded with none of the requested blobs: a count-0 frame.
        EngineReq::GetBlobs(r) => match write_tcache(resp_producer, &0u32.to_le_bytes()) {
            Some(data) => EngineResp::GetBlobs(EngineGetBlobsResp {
                block_root: r.block_root,
                slot: r.slot,
                blobs_present: 0,
                data: Some(data),
            }),
            None => EngineResp::GetBlobs(EngineGetBlobsResp::failed(r.block_root, r.slot)),
        },
    };
    producers.engine_resps.produce(&resp.into());
}

#[inline]
fn handle_fcu(client: &mut EngineClient, r: &EngineFcuReq) {
    silver_log::info!(head = %hex::encode(&r.head_block_hash[..4]), "FCU ← spine");
    let state = ForkchoiceState {
        head_block_hash: r.head_block_hash,
        safe_block_hash: r.safe_block_hash,
        finalized_block_hash: r.finalized_block_hash,
    };
    send_fcu(client, r.block_root, state);
}

#[inline]
fn handle_new_payload(
    client: &mut EngineClient,
    reader: &mut TCacheReader,
    r: &EngineNewPayloadReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    handle_new_payload_common(
        client,
        reader,
        r.data,
        r.block_root,
        producers,
        "payload",
        |client, bytes| send_new_payload(client, bytes, r.block_root),
    );
}

#[inline]
fn handle_new_payload_envelope(
    client: &mut EngineClient,
    reader: &mut TCacheReader,
    r: &EngineNewPayloadEnvelopeReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    let hash_count = (r.hash_count as usize).min(r.versioned_hashes.len());
    let versioned_hashes = &r.versioned_hashes[..hash_count];
    handle_new_payload_common(
        client,
        reader,
        r.data,
        r.block_root,
        producers,
        "envelope",
        |client, bytes| send_new_payload_envelope(client, bytes, versioned_hashes, r.block_root),
    );
}

#[allow(clippy::too_many_arguments)]
fn handle_new_payload_common(
    client: &mut EngineClient,
    reader: &mut TCacheReader,
    data: TCacheRead,
    block_root: [u8; 32],
    producers: &mut <SilverSpine as FluxSpine>::Producers,
    kind: &str,
    send: impl FnOnce(&mut EngineClient, &[u8]) -> Result<(), EngineError>,
) {
    let acquired = reader.acquire(data);
    let bytes = match acquired.buffer() {
        Ok((b, _)) => b,
        Err(e) => {
            silver_log::warn!("failed to read {kind} data: {e}");
            producers
                .engine_resps
                .produce(&EngineResp::NewPayload(invalid_new_payload_resp(block_root)).into());
            return;
        }
    };

    if let Err(e) = send(client, bytes) {
        silver_log::warn!("failed to encode {kind}: {e}");
        producers
            .engine_resps
            .produce(&EngineResp::NewPayload(invalid_new_payload_resp(block_root)).into());
    }
}

#[inline]
fn handle_get_blobs(client: &mut EngineClient, r: &EngineGetBlobsReq) {
    let n = r.hash_count as usize;
    let hashes: Vec<String> =
        r.hashes[..n].iter().map(|h| format!("0x{}", hex::encode(h))).collect();
    get_blobs(client, simd_json::json!([hashes]), r.block_root, r.slot);
}

#[inline]
fn handle_prepare_payload(client: &mut EngineClient, r: EnginePreparePayloadReq) {
    silver_log::info!(head = %hex::encode(&r.head_block_hash[..4]), id = r.id, "preparePayload ← spine");
    let withdrawals = r
        .attrs_withdrawals
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
    let attrs = PayloadAttributesV3 {
        timestamp: r.attrs_timestamp,
        prev_randao: r.attrs_prev_randao,
        suggested_fee_recipient: r.attrs_fee_recipient,
        withdrawals,
        parent_beacon_block_root: r.attrs_parent_beacon_block_root,
    };
    send_prepare_payload(client, r.id, state, attrs);
}

#[inline]
fn handle_get_payload(client: &mut EngineClient, r: EngineGetPayloadReq) {
    silver_log::info!(payload_id = %hex::encode(r.payload_id), id = r.id, "fetchPayload ← spine");
    get_payload(client, r.payload_id, r.id);
}

#[inline]
fn invalid_new_payload_resp(block_root: [u8; 32]) -> EngineNewPayloadResp {
    // Internal error (TCache read/decode failure) — use SYNCING, not INVALID.
    // INVALID tells the CL the block is definitively bad; we don't know that here.
    EngineNewPayloadResp {
        block_root,
        status: PayloadValidationStatus::Syncing,
        latest_valid_hash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_new_payload_resp_fields() {
        let resp = invalid_new_payload_resp([0u8; 32]);
        assert_eq!(resp.status, PayloadValidationStatus::Syncing);
        assert_eq!(resp.latest_valid_hash, None);
    }
}
