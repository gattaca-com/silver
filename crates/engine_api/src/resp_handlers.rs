use flux::spine::SpineAdapter;
use serde::Deserialize;
use silver_common::{
    ELSyncStatus, EngineFcuResp, EngineGetBlobsResp, EngineGetPayloadResp, EngineHealthEvent,
    EngineNewPayloadResp, EnginePreparePayloadResp, EngineResp, PayloadValidationStatus,
    SilverSpine, TCacheProducer, TCacheRead, TProducer, TapeScratch, merkle::B256,
};
use simd_json::prelude::{ValueAsArray, ValueAsScalar, ValueObjectAccess};

use crate::{
    EngineError,
    types::{
        ForkchoiceUpdatedResult, PayloadStatus, json_get_blobs_to_tcache,
        json_get_payload_to_tcache,
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
pub(crate) fn handle_capabilities_response(response: Result<&mut [u8], EngineError>) {
    let raw = match response {
        Err(e) => {
            silver_log::warn!("engine_exchangeCapabilities failed: {e}");
            return;
        }
        Ok(b) => b,
    };
    let val = match simd_json::to_borrowed_value(raw) {
        Err(e) => {
            silver_log::warn!("engine_exchangeCapabilities failed: {e}");
            return;
        }
        Ok(v) => v,
    };
    if let Some(err) = val.get("error") {
        silver_log::warn!("engine_exchangeCapabilities rpc error: {err}");
        return;
    }
    let result = match val.get("result") {
        None => {
            silver_log::warn!("engine_exchangeCapabilities: missing result");
            return;
        }
        Some(v) => v,
    };
    let arr = result.as_array().map(|a| a.as_slice()).unwrap_or_default();
    let has = |m: &str| arr.iter().any(|v| v.as_str() == Some(m));
    if !has("engine_forkchoiceUpdatedV3") {
        silver_log::warn!("EL does not support engine_forkchoiceUpdatedV3");
    }
    if !has("engine_newPayloadV4") {
        silver_log::warn!("EL does not support engine_newPayloadV4");
    }
    if !has("engine_getPayloadV5") {
        silver_log::warn!("EL does not support engine_getPayloadV5");
    }
    silver_log::info!("capabilities negotiated");
}

#[inline]
pub(crate) fn handle_client_version_response(response: Result<&mut [u8], EngineError>) {
    let raw = match response {
        Err(e) => {
            silver_log::warn!("engine_getClientVersionV1 failed: {e}");
            return;
        }
        Ok(b) => b,
    };
    let val = match simd_json::to_borrowed_value(raw) {
        Err(e) => {
            silver_log::warn!("engine_getClientVersionV1 failed: {e}");
            return;
        }
        Ok(v) => v,
    };
    if let Some(err) = val.get("error") {
        silver_log::warn!("engine_getClientVersionV1 rpc error: {err}");
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
        silver_log::info!("EL client {name} {version}");
    }
}

pub(crate) struct Responses<'a> {
    adapter: &'a mut SpineAdapter<SilverSpine>,
    producer: &'a mut TProducer,
    scratch: &'a mut TapeScratch,
}

impl<'a> Responses<'a> {
    pub(crate) fn new(
        adapter: &'a mut SpineAdapter<SilverSpine>,
        producer: &'a mut TProducer,
        scratch: &'a mut TapeScratch,
    ) -> Self {
        Self { adapter, producer, scratch }
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
                    silver_log::warn!("eth_syncing failed: {e}");
                    break 'status ELSyncStatus::Offline;
                }
                Ok(b) => b,
            };
            let val = match simd_json::to_borrowed_value(raw) {
                Err(e) => {
                    silver_log::warn!("eth_syncing failed: {e}");
                    break 'status ELSyncStatus::Offline;
                }
                Ok(v) => v,
            };
            if let Some(err) = val.get("error") {
                silver_log::warn!("eth_syncing rpc error: {err}");
                break 'status ELSyncStatus::Offline;
            }
            match val.get("result") {
                None => {
                    silver_log::warn!("eth_syncing: missing result");
                    ELSyncStatus::Offline
                }
                Some(v) if v.as_bool() == Some(false) => {
                    silver_log::info!("EL synced");
                    ELSyncStatus::Synced
                }
                Some(_) => {
                    silver_log::info!("EL syncing");
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
                    silver_log::warn!("forkchoiceUpdated error: {e}");
                    break 'parse fcu_error(block_root);
                }
                Ok(b) => b,
            };
            match simd_json::serde::from_slice::<RpcResult<ForkchoiceUpdatedResult>>(raw) {
                Ok(RpcResult { result: Some(r), .. }) => {
                    let status = status_from_str(&r.payload_status.status);
                    silver_log::info!(
                        status = %r.payload_status.status,
                        latest_valid_hash = %r.payload_status.latest_valid_hash
                            .map(|h| hex::encode(&h[..4]))
                            .unwrap_or_else(|| "null".into()),
                        "FCU → Reth"
                    );
                    EngineFcuResp {
                        block_root,
                        status,
                        latest_valid_hash: r.payload_status.latest_valid_hash,
                    }
                }
                Ok(RpcResult { error: Some(e), .. }) => {
                    silver_log::warn!("forkchoiceUpdated rpc error: {}", e.message);
                    break 'parse fcu_error(block_root);
                }
                Ok(_) | Err(_) => {
                    silver_log::warn!("forkchoiceUpdated: missing result");
                    break 'parse fcu_error(block_root);
                }
            }
        };
        self.adapter.produce(EngineResp::Fcu(resp));
    }

    #[inline]
    pub(crate) fn prepare_payload(
        &mut self,
        spine_id: u64,
        response: Result<&mut [u8], EngineError>,
    ) {
        let payload_id = 'parse: {
            let raw = match response {
                Err(e) => {
                    silver_log::warn!("forkchoiceUpdated with attributes error: {e}");
                    break 'parse None;
                }
                Ok(b) => b,
            };
            match simd_json::serde::from_slice::<RpcResult<ForkchoiceUpdatedResult>>(raw) {
                Ok(RpcResult { result: Some(r), .. }) => {
                    if r.payload_id.is_none() {
                        silver_log::warn!(
                            id = spine_id,
                            status = %r.payload_status.status,
                            "forkchoiceUpdated with attributes started no payload"
                        );
                    }
                    r.payload_id
                }
                Ok(RpcResult { error: Some(e), .. }) => {
                    silver_log::warn!("forkchoiceUpdated with attributes rpc error: {}", e.message);
                    None
                }
                Ok(_) | Err(_) => {
                    silver_log::warn!("forkchoiceUpdated with attributes: missing result");
                    None
                }
            }
        };
        self.adapter.produce(EngineResp::PreparePayload(EnginePreparePayloadResp {
            id: spine_id,
            payload_id,
        }));
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
                    silver_log::warn!("newPayload error: {e}");
                    break 'parse new_payload_error(block_root);
                }
                Ok(b) => b,
            };
            match simd_json::serde::from_slice::<RpcResult<PayloadStatus>>(raw) {
                Ok(RpcResult { result: Some(ps), .. }) => {
                    let status = status_from_str(&ps.status);
                    silver_log::info!("newPayload → {:?}", status);
                    EngineNewPayloadResp {
                        block_root,
                        status,
                        latest_valid_hash: ps.latest_valid_hash,
                    }
                }
                Ok(RpcResult { error: Some(e), .. }) => {
                    silver_log::warn!("newPayload rpc error: {}", e.message);
                    break 'parse new_payload_error(block_root);
                }
                Ok(_) | Err(_) => {
                    silver_log::warn!("newPayload: missing result");
                    break 'parse new_payload_error(block_root);
                }
            }
        };
        self.adapter.produce(EngineResp::NewPayload(resp));
    }

    #[inline]
    pub(crate) fn get_payload(&mut self, spine_id: u64, response: Result<&mut [u8], EngineError>) {
        let resp = match response {
            Ok(raw) => match self.scratch.encode(raw, self.producer, json_get_payload_to_tcache) {
                Ok(Some(((), data))) => {
                    silver_log::info!(id = spine_id, "getPayload ok");
                    EngineGetPayloadResp { id: spine_id, data: Some(data) }
                }
                Ok(None) => {
                    silver_log::warn!("getPayload TCache full");
                    get_payload_error(spine_id)
                }
                Err(e) => {
                    silver_log::warn!("getPayload parse error: {e}");
                    get_payload_error(spine_id)
                }
            },
            Err(e) => {
                silver_log::warn!("getPayload error: {e}");
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
            Ok(raw) => match self.scratch.encode(raw, self.producer, json_get_blobs_to_tcache) {
                Ok(Some((blobs_present, data))) => {
                    silver_log::info!(
                        block = hex::encode(block_root),
                        slot,
                        blobs_present,
                        "getBlobsV3 ok"
                    );
                    EngineGetBlobsResp { block_root, slot, blobs_present, data: Some(data) }
                }
                Ok(None) => {
                    silver_log::warn!("getBlobsV3 TCache full");
                    EngineGetBlobsResp::failed(block_root, slot)
                }
                Err(e) => {
                    silver_log::warn!("getBlobsV3 parse error: {e}");
                    EngineGetBlobsResp::failed(block_root, slot)
                }
            },
            Err(e) => {
                silver_log::warn!("getBlobsV3 error: {e}");
                EngineGetBlobsResp::failed(block_root, slot)
            }
        };
        self.adapter.produce(EngineResp::GetBlobs(resp));
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
        silver_log::info!("EL health → {:?}", new_status);
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
    EngineGetPayloadResp { id, data: None }
}

#[inline]
fn fcu_error(block_root: [u8; 32]) -> EngineFcuResp {
    EngineFcuResp { block_root, status: PayloadValidationStatus::Syncing, latest_valid_hash: None }
}

#[inline]
fn new_payload_error(block_root: [u8; 32]) -> EngineNewPayloadResp {
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
