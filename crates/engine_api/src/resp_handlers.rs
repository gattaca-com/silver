use flux::spine::SpineAdapter;
use serde::Deserialize;
use silver_common::{
    ELSyncStatus, EngineFcuResp, EngineGetBlobsResp, EngineGetPayloadBodiesResp,
    EngineGetPayloadResp, EngineHealthEvent, EngineNewPayloadResp, EngineResp,
    PayloadValidationStatus, SilverSpine, TCacheProducer, TCacheRead, TProducer, merkle::B256,
};
use simd_json::prelude::{ValueAsArray, ValueAsScalar, ValueObjectAccess};

use crate::{
    EngineError,
    types::{
        ForkchoiceUpdatedResult, PayloadStatus, json_get_blobs_to_tcache,
        json_get_payload_bodies_to_tcache, json_get_payload_to_tcache,
    },
};

#[derive(Deserialize)]
struct RpcResult<'a, T> {
    result: Option<T>,
    #[serde(borrow, default)]
    error: Option<RpcError<'a>>,
}

#[derive(Deserialize)]
struct RpcError<'a> {
    message: &'a str,
}

#[inline]
pub(crate) fn handle_capabilities_response(
    response: Result<&mut [u8], EngineError>,
) -> &'static str {
    const FALLBACK: &str = "engine_getPayloadV3";
    let raw = match response {
        Err(e) => {
            tracing::warn!("engine_exchangeCapabilities failed: {e}");
            return FALLBACK;
        }
        Ok(b) => b,
    };
    let val = match simd_json::to_borrowed_value(raw) {
        Err(e) => {
            tracing::warn!("engine_exchangeCapabilities failed: {e}");
            return FALLBACK;
        }
        Ok(v) => v,
    };
    if let Some(err) = val.get("error") {
        tracing::warn!("engine_exchangeCapabilities rpc error: {err}");
        return FALLBACK;
    }
    let result = match val.get("result") {
        None => {
            tracing::warn!("engine_exchangeCapabilities: missing result");
            return FALLBACK;
        }
        Some(v) => v,
    };
    let arr = result.as_array().map(|a| a.as_slice()).unwrap_or_default();
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
    let method = if has("engine_getPayloadV4") { "engine_getPayloadV4" } else { FALLBACK };
    tracing::info!("capabilities negotiated, using {method}");
    method
}

#[inline]
pub(crate) fn handle_client_version_response(response: Result<&mut [u8], EngineError>) {
    let raw = match response {
        Err(e) => {
            tracing::warn!("engine_getClientVersionV1 failed: {e}");
            return;
        }
        Ok(b) => b,
    };
    let val = match simd_json::to_borrowed_value(raw) {
        Err(e) => {
            tracing::warn!("engine_getClientVersionV1 failed: {e}");
            return;
        }
        Ok(v) => v,
    };
    if let Some(err) = val.get("error") {
        tracing::warn!("engine_getClientVersionV1 rpc error: {err}");
        return;
    }
    let result = match val.get("result") {
        None => return,
        Some(v) => v,
    };
    if let Some(client) = result.as_array().and_then(|a| a.first()) {
        let name = client
            .get("clientName")
            .or_else(|| client.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let version = client.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        tracing::info!("EL client {name} {version}");
    }
}

pub(crate) struct Responses<'a> {
    adapter: &'a mut SpineAdapter<SilverSpine>,
    producer: &'a mut TProducer,
    scratch: &'a mut Vec<u8>,
}

impl<'a> Responses<'a> {
    pub(crate) fn new(
        adapter: &'a mut SpineAdapter<SilverSpine>,
        producer: &'a mut TProducer,
        scratch: &'a mut Vec<u8>,
    ) -> Self {
        Self { adapter, producer, scratch }
    }

    /// `Ok(None)` means the tcache had no room; `Err` is a parse failure.
    fn encode<T>(
        &mut self,
        raw: &mut [u8],
        to_tcache: impl FnOnce(&mut [u8], &mut Vec<u8>) -> Result<T, EngineError>,
    ) -> Result<Option<(T, TCacheRead)>, EngineError> {
        self.scratch.clear();
        let encoded = to_tcache(raw, self.scratch)?;
        Ok(write_tcache(self.producer, self.scratch).map(|data| (encoded, data)))
    }

    #[inline]
    pub(crate) fn syncing(
        &mut self,
        response: Result<&mut [u8], EngineError>,
        sync_status: &mut ELSyncStatus,
        healthcheck_pending: &mut bool,
    ) {
        *healthcheck_pending = false;
        let new_status = 'status: {
            let raw = match response {
                Err(e) => {
                    tracing::warn!("eth_syncing failed: {e}");
                    break 'status ELSyncStatus::Offline;
                }
                Ok(b) => b,
            };
            let val = match simd_json::to_borrowed_value(raw) {
                Err(e) => {
                    tracing::warn!("eth_syncing failed: {e}");
                    break 'status ELSyncStatus::Offline;
                }
                Ok(v) => v,
            };
            if let Some(err) = val.get("error") {
                tracing::warn!("eth_syncing rpc error: {err}");
                break 'status ELSyncStatus::Offline;
            }
            match val.get("result") {
                None => {
                    tracing::warn!("eth_syncing: missing result");
                    ELSyncStatus::Offline
                }
                Some(v) if v.as_bool() == Some(false) => {
                    tracing::info!("EL synced");
                    ELSyncStatus::Synced
                }
                Some(_) => {
                    tracing::info!("EL syncing");
                    ELSyncStatus::Syncing
                }
            }
        };
        publish_health_if_changed(self.adapter, sync_status, new_status);
    }

    #[inline]
    pub(crate) fn fcu(&mut self, block_root: [u8; 32], response: Result<&mut [u8], EngineError>) {
        let resp = 'parse: {
            let raw = match response {
                Err(e) => {
                    tracing::warn!("forkchoiceUpdated error: {e}");
                    break 'parse fcu_error(block_root);
                }
                Ok(b) => b,
            };
            match simd_json::serde::from_slice::<RpcResult<ForkchoiceUpdatedResult>>(raw) {
                Ok(RpcResult { result: Some(r), .. }) => {
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
                        "FCU → Reth"
                    );
                    EngineFcuResp {
                        block_root,
                        status,
                        latest_valid_hash,
                        has_payload_id,
                        payload_id,
                    }
                }
                Ok(RpcResult { error: Some(e), .. }) => {
                    tracing::warn!("forkchoiceUpdated rpc error: {}", e.message);
                    break 'parse fcu_error(block_root);
                }
                Ok(_) | Err(_) => {
                    tracing::warn!("forkchoiceUpdated: missing result");
                    break 'parse fcu_error(block_root);
                }
            }
        };
        self.adapter.produce(EngineResp::Fcu(resp));
    }

    #[inline]
    pub(crate) fn new_payload(
        &mut self,
        block_root: [u8; 32],
        response: Result<&mut [u8], EngineError>,
    ) {
        let resp = 'parse: {
            let raw = match response {
                Err(e) => {
                    tracing::warn!("newPayload error: {e}");
                    break 'parse new_payload_error(block_root);
                }
                Ok(b) => b,
            };
            match simd_json::serde::from_slice::<RpcResult<PayloadStatus>>(raw) {
                Ok(RpcResult { result: Some(ps), .. }) => {
                    let status = status_from_str(&ps.status);
                    let latest_valid_hash = ps.latest_valid_hash.unwrap_or([0u8; 32]);
                    tracing::info!("newPayload → {:?}", status);
                    EngineNewPayloadResp { block_root, status, latest_valid_hash }
                }
                Ok(RpcResult { error: Some(e), .. }) => {
                    tracing::warn!("newPayload rpc error: {}", e.message);
                    break 'parse new_payload_error(block_root);
                }
                Ok(_) | Err(_) => {
                    tracing::warn!("newPayload: missing result");
                    break 'parse new_payload_error(block_root);
                }
            }
        };
        self.adapter.produce(EngineResp::NewPayload(resp));
    }

    #[inline]
    pub(crate) fn get_payload(&mut self, spine_id: u64, response: Result<&mut [u8], EngineError>) {
        let resp = match response {
            Ok(raw) => match self.encode(raw, json_get_payload_to_tcache) {
                Ok(Some(((), data))) => {
                    tracing::info!(id = spine_id, "getPayload ok");
                    EngineGetPayloadResp { id: spine_id, ok: true, data }
                }
                Ok(None) => {
                    tracing::warn!("getPayload TCache full");
                    get_payload_error(spine_id)
                }
                Err(e) => {
                    tracing::warn!("getPayload parse error: {e}");
                    get_payload_error(spine_id)
                }
            },
            Err(e) => {
                tracing::warn!("getPayload error: {e}");
                get_payload_error(spine_id)
            }
        };
        self.adapter.produce(EngineResp::GetPayload(resp));
    }

    #[inline]
    pub(crate) fn get_blobs(
        &mut self,
        block_root: B256,
        slot: u64,
        response: Result<&mut [u8], EngineError>,
    ) {
        let resp = match response {
            Ok(raw) => match self.encode(raw, json_get_blobs_to_tcache) {
                Ok(Some((blobs_present, data))) => {
                    tracing::info!(
                        block = hex::encode(block_root),
                        slot,
                        blobs_present,
                        "getBlobsV2 ok"
                    );
                    EngineGetBlobsResp { block_root, slot, ok: true, blobs_present, data }
                }
                Ok(None) => {
                    tracing::warn!("getBlobsV2 TCache full");
                    EngineGetBlobsResp::failed(block_root, slot)
                }
                Err(e) => {
                    tracing::warn!("getBlobsV2 parse error: {e}");
                    EngineGetBlobsResp::failed(block_root, slot)
                }
            },
            Err(e) => {
                tracing::warn!("getBlobsV2 error: {e}");
                EngineGetBlobsResp::failed(block_root, slot)
            }
        };
        self.adapter.produce(EngineResp::GetBlobs(resp));
    }

    #[inline]
    pub(crate) fn payload_bodies(
        &mut self,
        spine_id: u64,
        response: Result<&mut [u8], EngineError>,
    ) {
        let resp = match response {
            Ok(raw) => match self.encode(raw, json_get_payload_bodies_to_tcache) {
                Ok(Some(((), data))) => {
                    tracing::info!(id = spine_id, "getPayloadBodies ok");
                    EngineGetPayloadBodiesResp { id: spine_id, ok: true, data }
                }
                Ok(None) => {
                    tracing::warn!("getPayloadBodies TCache full");
                    get_payload_bodies_error(spine_id)
                }
                Err(e) => {
                    tracing::warn!("getPayloadBodies parse error: {e}");
                    get_payload_bodies_error(spine_id)
                }
            },
            Err(e) => {
                tracing::warn!("getPayloadBodies error: {e}");
                get_payload_bodies_error(spine_id)
            }
        };
        self.adapter.produce(EngineResp::GetPayloadBodies(resp));
    }
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
fn status_from_str(s: &str) -> PayloadValidationStatus {
    match s {
        "VALID" => PayloadValidationStatus::Valid,
        "SYNCING" => PayloadValidationStatus::Syncing,
        "ACCEPTED" => PayloadValidationStatus::Accepted,
        _ => PayloadValidationStatus::Invalid,
    }
}

#[inline]
pub(crate) fn write_tcache(producer: &mut TProducer, data: &[u8]) -> Option<TCacheRead> {
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
fn get_payload_bodies_error(id: u64) -> EngineGetPayloadBodiesResp {
    EngineGetPayloadBodiesResp { id, ok: false, data: unsafe { std::mem::zeroed() } }
}

#[inline]
fn fcu_error(block_root: [u8; 32]) -> EngineFcuResp {
    EngineFcuResp {
        block_root,
        status: PayloadValidationStatus::Syncing,
        latest_valid_hash: [0u8; 32],
        has_payload_id: false,
        payload_id: [0u8; 8],
    }
}

#[inline]
fn new_payload_error(block_root: [u8; 32]) -> EngineNewPayloadResp {
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
}
