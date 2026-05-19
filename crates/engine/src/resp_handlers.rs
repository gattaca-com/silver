use flux::spine::SpineAdapter;
use silver_common::{
    ELSyncStatus, EngineFcuResp, EngineGetBlobsResp, EngineGetPayloadBodiesResp,
    EngineGetPayloadResp, EngineHealthEvent, EngineNewPayloadResp, EngineResp,
    PayloadValidationStatus, SilverSpine, TCacheProducer, TCacheRead, TProducer,
};

use crate::{
    EngineError,
    types::{
        BlobAndProofV1, ExecutionPayloadBodyV1, ForkchoiceUpdatedResult, GetPayloadV4Response,
        PayloadStatus, encode_get_blobs_data, encode_get_payload_data, encode_payload_bodies_data,
    },
};

#[inline]
pub(crate) fn handle_capabilities_response(response: Result<serde_json::Value, EngineError>) {
    match response {
        Ok(val) => {
            let arr = val.as_array().map(|a| a.as_slice()).unwrap_or_default();
            let has = |m: &str| arr.iter().any(|v| v.as_str() == Some(m));
            if !has("engine_forkchoiceUpdatedV3") {
                tracing::warn!("engine tile: EL does not support engine_forkchoiceUpdatedV3");
            }
            if !has("engine_newPayloadV4") {
                tracing::warn!("engine tile: EL does not support engine_newPayloadV4");
            }
            if !has("engine_getPayloadBodiesByHashV1") {
                tracing::warn!("engine tile: EL does not support engine_getPayloadBodiesByHashV1");
            }
            if !has("engine_getPayloadBodiesByRangeV1") {
                tracing::warn!("engine tile: EL does not support engine_getPayloadBodiesByRangeV1");
            }
            tracing::info!("engine tile: capabilities negotiated");
        }
        Err(e) => {
            tracing::warn!("engine tile: engine_exchangeCapabilities failed: {e}");
        }
    }
}

#[inline]
pub(crate) fn handle_client_version_response(response: Result<serde_json::Value, EngineError>) {
    match response {
        Ok(val) => {
            if let Some(client) = val.as_array().and_then(|a| a.first()) {
                let name = client
                    .get("clientName")
                    .or_else(|| client.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let version = client.get("version").and_then(|v| v.as_str()).unwrap_or("?");
                tracing::info!("engine tile: EL client {name} {version}");
            }
        }
        Err(e) => {
            tracing::warn!("engine tile: engine_getClientVersionV1 failed: {e}");
        }
    }
}

#[inline]
pub(crate) fn handle_sync_response(
    response: Result<serde_json::Value, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    sync_status: &mut ELSyncStatus,
    healthcheck_pending: &mut bool,
) {
    *healthcheck_pending = false;
    let new_status = parse_sync_status(response);
    publish_health_if_changed(adapter, sync_status, new_status);
}

#[inline]
pub(crate) fn handle_fcu_response(
    spine_id: u64,
    response: Result<serde_json::Value, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    let resp = match response.and_then(|v| {
        serde_json::from_value::<ForkchoiceUpdatedResult>(v).map_err(EngineError::Json)
    }) {
        Ok(r) => {
            let status = status_from_str(&r.payload_status.status);
            let latest_valid_hash = r.payload_status.latest_valid_hash.unwrap_or([0u8; 32]);
            let (has_payload_id, payload_id) = match r.payload_id {
                Some(id) => (true, id),
                None => (false, [0u8; 8]),
            };
            tracing::info!("engine tile: forkchoiceUpdated → {:?}", status);
            EngineFcuResp { id: spine_id, status, latest_valid_hash, has_payload_id, payload_id }
        }
        Err(e) => {
            tracing::warn!("engine tile: forkchoiceUpdated error: {e}");
            EngineFcuResp {
                id: spine_id,
                status: PayloadValidationStatus::Invalid,
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
    response: Result<serde_json::Value, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    let resp = match response
        .and_then(|v| serde_json::from_value::<PayloadStatus>(v).map_err(EngineError::Json))
    {
        Ok(ps) => {
            let status = status_from_str(&ps.status);
            let latest_valid_hash = ps.latest_valid_hash.unwrap_or([0u8; 32]);
            tracing::info!("engine tile: newPayload → {:?}", status);
            EngineNewPayloadResp { id: spine_id, status, latest_valid_hash }
        }
        Err(e) => {
            tracing::warn!("engine tile: newPayload error: {e}");
            EngineNewPayloadResp {
                id: spine_id,
                status: PayloadValidationStatus::Invalid,
                latest_valid_hash: [0u8; 32],
            }
        }
    };
    adapter.produce(EngineResp::NewPayload(resp));
}

#[inline]
pub(crate) fn handle_get_payload_fcu(
    spine_id: u64,
    response: Result<serde_json::Value, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    pending_get_payload: &mut Option<([u8; 8], u64)>,
) {
    match response.and_then(|v| {
        serde_json::from_value::<ForkchoiceUpdatedResult>(v).map_err(EngineError::Json)
    }) {
        Ok(fcu) => match fcu.payload_id {
            Some(payload_id) => {
                *pending_get_payload = Some((payload_id, spine_id));
            }
            None => {
                tracing::warn!("engine tile: getPayload FCU returned no payload_id");
                adapter.produce(EngineResp::GetPayload(get_payload_error(spine_id)));
            }
        },
        Err(e) => {
            tracing::warn!("engine tile: getPayload FCU error: {e}");
            adapter.produce(EngineResp::GetPayload(get_payload_error(spine_id)));
        }
    }
}

#[inline]
pub(crate) fn handle_get_payload_fetch(
    spine_id: u64,
    response: Result<serde_json::Value, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    resp_producer: &mut TProducer,
) {
    let resp = match response {
        Ok(v) => match serde_json::from_value::<GetPayloadV4Response>(v) {
            Ok(p) => {
                let payload_ssz = p.execution_payload.to_ssz();
                let data = encode_get_payload_data(
                    &payload_ssz,
                    &p.blobs_bundle.commitments,
                    &p.blobs_bundle.proofs,
                    &p.blobs_bundle.blobs,
                    p.should_override_builder,
                    &p.execution_requests,
                );
                match write_tcache(resp_producer, &data) {
                    Some(data) => EngineGetPayloadResp { id: spine_id, ok: true, data },
                    None => {
                        tracing::warn!("engine tile: getPayload TCache full");
                        get_payload_error(spine_id)
                    }
                }
            }
            Err(e) => {
                tracing::warn!("engine tile: getPayload parse error: {e}");
                get_payload_error(spine_id)
            }
        },
        Err(e) => {
            tracing::warn!("engine tile: getPayload error: {e}");
            get_payload_error(spine_id)
        }
    };
    adapter.produce(EngineResp::GetPayload(resp));
}

#[inline]
pub(crate) fn handle_get_blobs_response(
    spine_id: u64,
    response: Result<serde_json::Value, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    resp_producer: &mut TProducer,
) {
    let items = match response {
        Ok(v) => match serde_json::from_value::<Vec<Option<BlobAndProofV1>>>(v) {
            Ok(items) => items,
            Err(e) => {
                tracing::warn!("engine tile: getBlobsV2 parse error: {e}");
                adapter.produce(EngineResp::GetBlobs(get_blobs_error(spine_id)));
                return;
            }
        },
        Err(e) => {
            tracing::warn!("engine tile: getBlobsV2 error: {e}");
            adapter.produce(EngineResp::GetBlobs(get_blobs_error(spine_id)));
            return;
        }
    };
    let data = encode_get_blobs_data(&items);
    let resp = match write_tcache(resp_producer, &data) {
        Some(data) => EngineGetBlobsResp { id: spine_id, ok: true, data },
        None => {
            tracing::warn!("engine tile: getBlobsV2 TCache full");
            get_blobs_error(spine_id)
        }
    };
    adapter.produce(EngineResp::GetBlobs(resp));
}

#[inline]
pub(crate) fn handle_get_payload_bodies_response(
    spine_id: u64,
    response: Result<serde_json::Value, EngineError>,
    adapter: &mut SpineAdapter<SilverSpine>,
    resp_producer: &mut TProducer,
) {
    let bodies = match response {
        Ok(v) => match serde_json::from_value::<Vec<Option<ExecutionPayloadBodyV1>>>(v) {
            Ok(bodies) => bodies,
            Err(e) => {
                tracing::warn!("engine tile: getPayloadBodies parse error: {e}");
                adapter.produce(EngineResp::GetPayloadBodies(get_payload_bodies_error(spine_id)));
                return;
            }
        },
        Err(e) => {
            tracing::warn!("engine tile: getPayloadBodies error: {e}");
            adapter.produce(EngineResp::GetPayloadBodies(get_payload_bodies_error(spine_id)));
            return;
        }
    };
    let data = encode_payload_bodies_data(&bodies);
    let resp = match write_tcache(resp_producer, &data) {
        Some(data) => EngineGetPayloadBodiesResp { id: spine_id, ok: true, data },
        None => {
            tracing::warn!("engine tile: getPayloadBodies TCache full");
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
        tracing::info!("engine tile: EL health → {:?}", new_status);
    }
}

#[inline]
fn parse_sync_status(response: Result<serde_json::Value, EngineError>) -> ELSyncStatus {
    match response {
        Ok(val) if val.as_bool() == Some(false) => {
            tracing::info!("engine tile: EL synced");
            ELSyncStatus::Synced
        }
        Ok(_) => {
            tracing::info!("engine tile: EL syncing");
            ELSyncStatus::Syncing
        }
        Err(e) => {
            tracing::warn!("engine tile: eth_syncing failed: {e}");
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
        assert_eq!(parse_sync_status(Ok(serde_json::Value::Bool(false))), ELSyncStatus::Synced);
    }

    #[test]
    fn parse_sync_status_syncing_on_object() {
        let syncing_obj = serde_json::json!({
            "startingBlock": "0x0",
            "currentBlock": "0x100",
            "highestBlock": "0x200"
        });
        assert_eq!(parse_sync_status(Ok(syncing_obj)), ELSyncStatus::Syncing);
    }

    #[test]
    fn parse_sync_status_syncing_on_true() {
        assert_eq!(parse_sync_status(Ok(serde_json::Value::Bool(true))), ELSyncStatus::Syncing);
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
