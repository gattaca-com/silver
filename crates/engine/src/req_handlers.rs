use flux::spine::FluxSpine;
use silver_common::{
    BlockSource, EngineFcuReq, EngineFcuResp, EngineGetBlobsReq, EngineGetBlobsResp,
    EngineGetPayloadBodiesByHashReq, EngineGetPayloadBodiesByRangeReq, EngineGetPayloadBodiesResp,
    EngineGetPayloadReq, EngineGetPayloadResp, EngineNewPayloadEnvelopeReq, EngineNewPayloadReq,
    EngineNewPayloadResp, EnginePreparePayloadReq, EngineReq, EngineResp, PayloadValidationStatus,
    SilverSpine, TCacheRead, TProducer, TRandomAccess,
};

use crate::{
    EngineClient, EngineError,
    client::{
        get_blobs, get_payload, get_payload_bodies_by_hash, get_payload_bodies_by_range, send_fcu,
        send_new_payload, send_new_payload_envelope,
    },
    resp_handlers::write_tcache,
    types::{ForkchoiceState, PayloadAttributesV3, Withdrawal},
};

#[inline]
pub(crate) fn handle_request(
    client: &mut EngineClient,
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    req: &EngineReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    match req {
        EngineReq::Fcu(r) => handle_fcu(client, r),
        EngineReq::NewPayload(r) => {
            handle_new_payload(client, gossip_consumer, rpc_consumer, r, producers)
        }
        EngineReq::NewPayloadEnvelope(r) => {
            handle_new_payload_envelope(client, gossip_consumer, rpc_consumer, r, producers)
        }
        EngineReq::PreparePayload(r) => handle_prepare_payload(client, *r),
        EngineReq::GetPayload(r) => handle_get_payload(client, *r),
        EngineReq::GetBlobs(r) => handle_get_blobs(client, r),
        EngineReq::GetPayloadBodiesByHash(r) => handle_get_payload_bodies_by_hash(client, r),
        EngineReq::GetPayloadBodiesByRange(r) => handle_get_payload_bodies_by_range(client, r),
    }
}

/// Unsafe no-EL testing mode: answer each request with a synthetic VALID
/// response without contacting an execution client. Built payloads and payload
/// bodies can't be fabricated, so those return `ok: false`; blob fetches answer
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
            latest_valid_hash: r.head_block_hash,
            has_payload_id: false,
            payload_id: [0u8; 8],
        }),
        EngineReq::NewPayload(r) => EngineResp::NewPayload(EngineNewPayloadResp {
            block_root: r.block_root,
            status: PayloadValidationStatus::Valid,
            latest_valid_hash: [0u8; 32],
        }),
        EngineReq::NewPayloadEnvelope(r) => EngineResp::NewPayload(EngineNewPayloadResp {
            block_root: r.block_root,
            status: PayloadValidationStatus::Valid,
            latest_valid_hash: [0u8; 32],
        }),
        // Proposal path correlates on payload_id; derive one from the spine id.
        EngineReq::PreparePayload(r) => EngineResp::Fcu(EngineFcuResp {
            block_root: [0u8; 32],
            status: PayloadValidationStatus::Valid,
            latest_valid_hash: [0u8; 32],
            has_payload_id: true,
            payload_id: r.id.to_le_bytes(),
        }),
        EngineReq::GetPayload(r) => EngineResp::GetPayload(EngineGetPayloadResp {
            id: r.id,
            ok: false,
            data: unsafe { std::mem::zeroed() },
        }),
        // EL responded with none of the requested blobs: a count-0 frame.
        EngineReq::GetBlobs(r) => match write_tcache(resp_producer, &0u32.to_le_bytes()) {
            Some(data) => EngineResp::GetBlobs(EngineGetBlobsResp {
                block_root: r.block_root,
                slot: r.slot,
                ok: true,
                blobs_present: 0,
                data,
            }),
            None => EngineResp::GetBlobs(EngineGetBlobsResp::failed(r.block_root, r.slot)),
        },
        EngineReq::GetPayloadBodiesByHash(r) => {
            EngineResp::GetPayloadBodies(EngineGetPayloadBodiesResp {
                id: r.id,
                ok: false,
                data: unsafe { std::mem::zeroed() },
            })
        }
        EngineReq::GetPayloadBodiesByRange(r) => {
            EngineResp::GetPayloadBodies(EngineGetPayloadBodiesResp {
                id: r.id,
                ok: false,
                data: unsafe { std::mem::zeroed() },
            })
        }
    };
    producers.engine_resps.produce(&resp.into());
}

#[inline]
fn handle_fcu(client: &mut EngineClient, r: &EngineFcuReq) {
    tracing::info!(head = %hex::encode(&r.head_block_hash[..4]), "FCU ← spine");
    let state = ForkchoiceState {
        head_block_hash: r.head_block_hash,
        safe_block_hash: r.safe_block_hash,
        finalized_block_hash: r.finalized_block_hash,
    };
    send_fcu(client, r.block_root, state, None);
}

#[inline]
fn handle_new_payload(
    client: &mut EngineClient,
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    r: &EngineNewPayloadReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    handle_new_payload_common(
        client,
        gossip_consumer,
        rpc_consumer,
        r.block_source,
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
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    r: &EngineNewPayloadEnvelopeReq,
    producers: &mut <SilverSpine as FluxSpine>::Producers,
) {
    let hash_count = (r.hash_count as usize).min(r.versioned_hashes.len());
    let versioned_hashes = &r.versioned_hashes[..hash_count];
    handle_new_payload_common(
        client,
        gossip_consumer,
        rpc_consumer,
        r.block_source,
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
    gossip_consumer: &mut TRandomAccess,
    rpc_consumer: &mut TRandomAccess,
    block_source: BlockSource,
    data: TCacheRead,
    block_root: [u8; 32],
    producers: &mut <SilverSpine as FluxSpine>::Producers,
    kind: &str,
    send: impl FnOnce(&mut EngineClient, &[u8]) -> Result<(), EngineError>,
) {
    let consumer = match block_source {
        BlockSource::Gossip => gossip_consumer,
        BlockSource::Rpc => rpc_consumer,
    };
    let acquired = consumer.acquire(data);
    let bytes = match acquired.buffer() {
        Ok((b, _)) => b,
        Err(e) => {
            tracing::warn!("failed to read {kind} data: {e}");
            producers
                .engine_resps
                .produce(&EngineResp::NewPayload(invalid_new_payload_resp(block_root)).into());
            return;
        }
    };

    if let Err(e) = send(client, bytes) {
        tracing::warn!("failed to encode {kind}: {e}");
        producers
            .engine_resps
            .produce(&EngineResp::NewPayload(invalid_new_payload_resp(block_root)).into());
    }
    consumer.free();
}

#[inline]
fn handle_get_blobs(client: &mut EngineClient, r: &EngineGetBlobsReq) {
    let n = r.hash_count as usize;
    let hashes: Vec<String> =
        r.hashes[..n].iter().map(|h| format!("0x{}", hex::encode(h))).collect();
    get_blobs(client, simd_json::json!([hashes]), r.block_root, r.slot);
}

#[inline]
fn handle_get_payload_bodies_by_hash(
    client: &mut EngineClient,
    r: &EngineGetPayloadBodiesByHashReq,
) {
    let n = r.hash_count as usize;
    let hashes: Vec<String> =
        r.hashes[..n].iter().map(|h| format!("0x{}", hex::encode(h))).collect();
    get_payload_bodies_by_hash(client, simd_json::json!([hashes]), r.id);
}

#[inline]
fn handle_get_payload_bodies_by_range(
    client: &mut EngineClient,
    r: &EngineGetPayloadBodiesByRangeReq,
) {
    let start_hex = format!("0x{:x}", r.start);
    let count_hex = format!("0x{:x}", r.count);
    get_payload_bodies_by_range(client, simd_json::json!([start_hex, count_hex]), r.id);
}

#[inline]
fn handle_prepare_payload(client: &mut EngineClient, r: EnginePreparePayloadReq) {
    tracing::info!(head = %hex::encode(&r.head_block_hash[..4]), id = r.id, "preparePayload ← spine");
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
    // Proposal path correlates on payload_id, not the head verdict.
    send_fcu(client, [0u8; 32], state, attrs);
}

#[inline]
fn handle_get_payload(client: &mut EngineClient, r: EngineGetPayloadReq) {
    tracing::info!(payload_id = %hex::encode(r.payload_id), id = r.id, "fetchPayload ← spine");
    get_payload(client, r.payload_id, r.id);
}

#[inline]
fn invalid_new_payload_resp(block_root: [u8; 32]) -> EngineNewPayloadResp {
    // Internal error (TCache read/decode failure) — use SYNCING, not INVALID.
    // INVALID tells the CL the block is definitively bad; we don't know that here.
    EngineNewPayloadResp {
        block_root,
        status: PayloadValidationStatus::Syncing,
        latest_valid_hash: [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_new_payload_resp_fields() {
        let resp = invalid_new_payload_resp([0u8; 32]);
        assert_eq!(resp.status, PayloadValidationStatus::Syncing);
        assert_eq!(resp.latest_valid_hash, [0u8; 32]);
    }
}
