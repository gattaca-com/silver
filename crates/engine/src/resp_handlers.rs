use flux::spine::SpineAdapter;
use silver_common::{
    ELSyncStatus, EngineFcuResp, EngineGetBlobsResp, EngineGetPayloadBodiesResp,
    EngineGetPayloadResp, EngineHealthEvent, EngineNewPayloadResp, EngineResp,
    PayloadValidationStatus, SilverSpine, TCacheProducer, TCacheRead, TProducer,
};
use simd_json::prelude::{ValueAsArray, ValueAsScalar, ValueObjectAccess};

use crate::{
    EngineError,
    client::extract_result,
    types::{
        ForkchoiceUpdatedResult, PayloadStatus,
        json_get_blobs_to_tcache, json_get_payload_bodies_to_tcache, json_get_payload_to_tcache,
    },
};

// Parse raw response bytes into an extracted OwnedValue result field.
// Used by all handlers except getPayload, which uses the zero-alloc path.
#[inline]
fn parse_rpc_response(
    raw: Result<Vec<u8>, EngineError>,
) -> Result<simd_json::OwnedValue, EngineError> {
    raw.and_then(|mut b| simd_json::from_slice(&mut b).map_err(EngineError::Json))
        .and_then(extract_result)
}

#[inline]
pub(crate) fn handle_capabilities_response(response: Result<Vec<u8>, EngineError>) -> &'static str {
    match parse_rpc_response(response) {
        Ok(val) => {
            let arr = val.as_array().map(|a| a.as_slice()).unwrap_or_default();
            let has = |m: &str| arr.iter().any(|v| v.as_str() == Some(m));
            if !has("engine_forkchoiceUpdatedV3") {
                tracing::warn!("EL does not support engine_forkchoiceUpdatedV3");
            }
            if !has("engine_newPayloadV4") {
                tracing::warn!("EL does not support engine_newPayloadV4");
            }
            if !has("engine_getPayloadBodiesByHashV1") {
                tracing::warn!("EL does not support engine_getPayloadBodiesByHashV1");
            }
            if !has("engine_getPayloadBodiesByRangeV1") {
                tracing::warn!("EL does not support engine_getPayloadBodiesByRangeV1");
            }
            let method = if has("engine_getPayloadV4") {
                "engine_getPayloadV4"
            } else {
                "engine_getPayloadV3"
            };
            tracing::info!("capabilities negotiated, using {method}");
            method
        }
        Err(e) => {
            tracing::warn!("engine_exchangeCapabilities failed: {e}");
            "engine_getPayloadV3"
        }
    }
}

#[inline]
pub(crate) fn handle_client_version_response(response: Result<Vec<u8>, EngineError>) {
    match parse_rpc_response(response) {
        Ok(val) => {
            if let Some(client) = val.as_array().and_then(|a| a.first()) {
                let name = client
                    .get("clientName")
                    .or_else(|| client.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let version = client.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                tracing::info!("EL client {name} {version}");
            }
        }
        Err(e) => {
            tracing::warn!("engine_getClientVersionV1 failed: {e}");
        }
    }
}

#[inline]
pub(crate) fn handle_sync_response(
    response: Result<Vec<u8>, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    sync_status: &mut ELSyncStatus,
    healthcheck_pending: &mut bool,
) {
    *healthcheck_pending = false;
    let new_status = parse_sync_status(parse_rpc_response(response));
    publish_health_if_changed(adapter, sync_status, new_status);
}

#[inline]
pub(crate) fn handle_fcu_response(
    spine_id: u64,
    response: Result<Vec<u8>, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    let resp = match parse_rpc_response(response).and_then(|v| {
        simd_json::serde::from_owned_value::<ForkchoiceUpdatedResult>(v).map_err(EngineError::Json)
    }) {
        Ok(r) => {
            let status = status_from_str(&r.payload_status.status);
            let latest_valid_hash = r.payload_status.latest_valid_hash.unwrap_or([0u8; 32]);
            let (has_payload_id, payload_id) = match r.payload_id {
                Some(id) => (true, id),
                None => (false, [0u8; 8]),
            };
            tracing::info!(
                status = %r.payload_status.status,
                latest_valid_hash = %r.payload_status.latest_valid_hash
                    .map(|h| hex::encode(&h[..4]))
                    .unwrap_or_else(|| "null".into()),
                id = spine_id,
                "FCU → Reth"
            );
            EngineFcuResp { id: spine_id, status, latest_valid_hash, has_payload_id, payload_id }
        }
        Err(e) => {
            tracing::warn!("forkchoiceUpdated error: {e}");
            // Transport/parse errors are not proof of invalidity — use SYNCING
            // so the CL doesn't treat an unreachable EL as a bad block.
            EngineFcuResp {
                id: spine_id,
                status: PayloadValidationStatus::Syncing,
                latest_valid_hash: [0u8; 32],
                has_payload_id: false,
                payload_id: [0u8; 8],
            }
        }
    };
    adapter.produce(EngineResp::Fcu(resp));
}

#[inline]
pub(crate) fn handle_new_payload_response(
    spine_id: u64,
    response: Result<Vec<u8>, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    let resp = match parse_rpc_response(response).and_then(|v| {
        simd_json::serde::from_owned_value::<PayloadStatus>(v).map_err(EngineError::Json)
    }) {
        Ok(ps) => {
            let status = status_from_str(&ps.status);
            let latest_valid_hash = ps.latest_valid_hash.unwrap_or([0u8; 32]);
            tracing::info!("newPayload → {:?}", status);
            EngineNewPayloadResp { id: spine_id, status, latest_valid_hash }
        }
        Err(e) => {
            tracing::warn!("newPayload error: {e}");
            EngineNewPayloadResp {
                id: spine_id,
                status: PayloadValidationStatus::Syncing,
                latest_valid_hash: [0u8; 32],
            }
        }
    };
    adapter.produce(EngineResp::NewPayload(resp));
}

#[inline]
pub(crate) fn handle_get_payload_fetch(
    spine_id: u64,
    response: Result<Vec<u8>, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    resp_producer: &mut TProducer,
    scratch: &mut Vec<u8>,
) {
    let resp = match response {
        Ok(mut raw) => {
            scratch.clear();
            match json_get_payload_to_tcache(&mut raw, scratch) {
                Ok(()) => match write_tcache(resp_producer, scratch) {
                    Some(data) => {
                        tracing::info!(id = spine_id, "getPayload ok");
                        EngineGetPayloadResp { id: spine_id, ok: true, data }
                    }
                    None => {
                        tracing::warn!("getPayload TCache full");
                        get_payload_error(spine_id)
                    }
                },
                Err(e) => {
                    tracing::warn!("getPayload parse error: {e}");
                    get_payload_error(spine_id)
                }
            }
        }
        Err(e) => {
            tracing::warn!("getPayload error: {e}");
            get_payload_error(spine_id)
        }
    };
    adapter.produce(EngineResp::GetPayload(resp));
}

#[inline]
pub(crate) fn handle_get_blobs_response(
    spine_id: u64,
    response: Result<Vec<u8>, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    resp_producer: &mut TProducer,
    scratch: &mut Vec<u8>,
) {
    let resp = match response {
        Ok(mut raw) => {
            scratch.clear();
            match json_get_blobs_to_tcache(&mut raw, scratch) {
                Ok(()) => match write_tcache(resp_producer, scratch) {
                    Some(data) => {
                        tracing::info!(id = spine_id, "getBlobsV2 ok");
                        EngineGetBlobsResp { id: spine_id, ok: true, data }
                    }
                    None => {
                        tracing::warn!("getBlobsV2 TCache full");
                        get_blobs_error(spine_id)
                    }
                },
                Err(e) => {
                    tracing::warn!("getBlobsV2 parse error: {e}");
                    get_blobs_error(spine_id)
                }
            }
        }
        Err(e) => {
            tracing::warn!("getBlobsV2 error: {e}");
            get_blobs_error(spine_id)
        }
    };
    adapter.produce(EngineResp::GetBlobs(resp));
}

#[inline]
pub(crate) fn handle_get_payload_bodies_response(
    spine_id: u64,
    response: Result<Vec<u8>, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    resp_producer: &mut TProducer,
    scratch: &mut Vec<u8>,
) {
    let resp = match response {
        Ok(mut raw) => {
            scratch.clear();
            match json_get_payload_bodies_to_tcache(&mut raw, scratch) {
                Ok(()) => match write_tcache(resp_producer, scratch) {
                    Some(data) => {
                        tracing::info!(id = spine_id, "getPayloadBodies ok");
                        EngineGetPayloadBodiesResp { id: spine_id, ok: true, data }
                    }
                    None => {
                        tracing::warn!("getPayloadBodies TCache full");
                        get_payload_bodies_error(spine_id)
                    }
                },
                Err(e) => {
                    tracing::warn!("getPayloadBodies parse error: {e}");
                    get_payload_bodies_error(spine_id)
                }
            }
        }
        Err(e) => {
            tracing::warn!("getPayloadBodies error: {e}");
            get_payload_bodies_error(spine_id)
        }
    };
    adapter.produce(EngineResp::GetPayloadBodies(resp));
}

#[inline]
fn publish_health_if_changed(
    adapter: &mut SpineAdapter<SilverSpine>,
    sync_status: &mut ELSyncStatus,
    new_status: ELSyncStatus,
) {
    if new_status != *sync_status {
        *sync_status = new_status;
        adapter.produce(EngineHealthEvent { sync_status: new_status });
        tracing::info!("EL health → {:?}", new_status);
    }
}

#[inline]
fn parse_sync_status(response: Result<simd_json::OwnedValue, EngineError>) -> ELSyncStatus {
    match response {
        Ok(val) if val.as_bool() == Some(false) => {
            tracing::info!("EL synced");
            ELSyncStatus::Synced
        }
        Ok(_) => {
            tracing::info!("EL syncing");
            ELSyncStatus::Syncing
        }
        Err(e) => {
            tracing::warn!("eth_syncing failed: {e}");
            ELSyncStatus::Offline
        }
    }
}

#[inline]
fn status_from_str(s: &str) -> PayloadValidationStatus {
    match s {
        "VALID" => PayloadValidationStatus::Valid,
        "SYNCING" => PayloadValidationStatus::Syncing,
        "ACCEPTED" => PayloadValidationStatus::Accepted,
        _ => PayloadValidationStatus::Invalid,
    }
}

#[inline]
fn write_tcache(producer: &mut TProducer, data: &[u8]) -> Option<TCacheRead> {
    use std::io::Write as _;
    let mut res =
        producer.reserve(data.len(), false).or_else(|| producer.reserve(data.len(), false))?;
    res.write_all(data).ok()?;
    res.flush().ok()?;
    Some(res.read())
}

#[inline]
fn get_payload_error(id: u64) -> EngineGetPayloadResp {
    EngineGetPayloadResp { id, ok: false, data: unsafe { std::mem::zeroed() } }
}

#[inline]
fn get_blobs_error(id: u64) -> EngineGetBlobsResp {
    EngineGetBlobsResp { id, ok: false, data: unsafe { std::mem::zeroed() } }
}

#[inline]
fn get_payload_bodies_error(id: u64) -> EngineGetPayloadBodiesResp {
    EngineGetPayloadBodiesResp { id, ok: false, data: unsafe { std::mem::zeroed() } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_from_str_valid() {
        assert_eq!(status_from_str("VALID"), PayloadValidationStatus::Valid);
    }

    #[test]
    fn status_from_str_syncing() {
        assert_eq!(status_from_str("SYNCING"), PayloadValidationStatus::Syncing);
    }

    #[test]
    fn status_from_str_accepted() {
        assert_eq!(status_from_str("ACCEPTED"), PayloadValidationStatus::Accepted);
    }

    #[test]
    fn status_from_str_unknown_maps_to_invalid() {
        assert_eq!(status_from_str("INVALID"), PayloadValidationStatus::Invalid);
        assert_eq!(status_from_str(""), PayloadValidationStatus::Invalid);
        assert_eq!(status_from_str("valid"), PayloadValidationStatus::Invalid);
        assert_eq!(status_from_str("UNKNOWN_STATUS"), PayloadValidationStatus::Invalid);
    }

    #[test]
    fn parse_sync_status_synced_on_false() {
        assert_eq!(parse_sync_status(Ok(simd_json::json!(false))), ELSyncStatus::Synced);
    }

    #[test]
    fn parse_sync_status_syncing_on_object() {
        let syncing_obj = simd_json::json!({
            "startingBlock": "0x0",
            "currentBlock": "0x100",
            "highestBlock": "0x200"
        });
        assert_eq!(parse_sync_status(Ok(syncing_obj)), ELSyncStatus::Syncing);
    }

    #[test]
    fn parse_sync_status_syncing_on_true() {
        assert_eq!(parse_sync_status(Ok(simd_json::json!(true))), ELSyncStatus::Syncing);
    }

    #[test]
    fn parse_sync_status_offline_on_error() {
        assert_eq!(
            parse_sync_status(Err(EngineError::Http("connection refused".into()))),
            ELSyncStatus::Offline
        );
    }

    #[test]
    fn parse_sync_status_offline_on_rpc_error() {
        assert_eq!(parse_sync_status(Err(EngineError::MissingResult)), ELSyncStatus::Offline);
    }
}
