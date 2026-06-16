use serde::{Deserialize, Deserializer, Serialize, Serializer};
use silver_common::ssz_view::{
    BEACON_BLOCK_BODY_FIXED, BeaconBlockBodyView, ExecutionPayloadView, SIGNED_BEACON_BLOCK_MIN,
    SignedBeaconBlockView,
};

pub type B256 = [u8; 32];
pub type ExecutionAddress = [u8; 20];

// Engine API wire-format helpers: binary ↔ "0x<hex>" JSON.
// Each submodule is a serde `with` target.
mod wire {
    use super::*;

    fn decode_hex_into<const N: usize>(s: &str) -> Result<[u8; N], String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut out = [0u8; N];
        hex::decode_to_slice(s, &mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }

    // 32-byte hash/root ↔ "0x<64 hex>"
    pub mod b256 {
        use super::*;
        pub fn serialize<S: Serializer>(v: &B256, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&format!("0x{}", hex::encode(v)))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<B256, D::Error> {
            decode_hex_into::<32>(&String::deserialize(d)?).map_err(serde::de::Error::custom)
        }
    }

    // Option<B256>: null or "0x<64 hex>"
    pub mod opt_b256 {
        use super::*;
        pub fn serialize<S: Serializer>(v: &Option<B256>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(b) => s.serialize_str(&format!("0x{}", hex::encode(b))),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<B256>, D::Error> {
            match Option::<String>::deserialize(d)? {
                None => Ok(None),
                Some(s) => decode_hex_into::<32>(&s).map(Some).map_err(serde::de::Error::custom),
            }
        }
    }

    // 20-byte execution address ↔ "0x<40 hex>"
    pub mod addr {
        use super::*;
        pub fn serialize<S: Serializer>(v: &ExecutionAddress, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&format!("0x{}", hex::encode(v)))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ExecutionAddress, D::Error> {
            decode_hex_into::<20>(&String::deserialize(d)?).map_err(serde::de::Error::custom)
        }
    }

    // u64 ↔ Ethereum QUANTITY ("0x0", "0x1a", ...)
    pub mod quantity {
        use super::*;
        pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&format!("0x{:x}", v))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
            let s = String::deserialize(d)?;
            let s = s.strip_prefix("0x").unwrap_or(&s);
            u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
        }
    }

    // Option<[u8; 8]> ↔ null or "0x<16 hex>" (payloadId)
    pub mod opt_payload_id {
        use super::*;
        pub fn serialize<S: Serializer>(v: &Option<[u8; 8]>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(b) => s.serialize_str(&format!("0x{}", hex::encode(b))),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 8]>, D::Error> {
            match Option::<String>::deserialize(d)? {
                None => Ok(None),
                Some(s) => decode_hex_into::<8>(&s).map(Some).map_err(serde::de::Error::custom),
            }
        }
    }
}

// --- forkchoiceUpdated ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceState {
    #[serde(with = "wire::b256")]
    pub head_block_hash: B256,
    #[serde(with = "wire::b256")]
    pub safe_block_hash: B256,
    #[serde(with = "wire::b256")]
    pub finalized_block_hash: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributesV3 {
    #[serde(with = "wire::quantity")]
    pub timestamp: u64,
    #[serde(with = "wire::b256")]
    pub prev_randao: B256,
    #[serde(with = "wire::addr")]
    pub suggested_fee_recipient: ExecutionAddress,
    pub withdrawals: Vec<Withdrawal>,
    #[serde(with = "wire::b256")]
    pub parent_beacon_block_root: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceUpdatedResult {
    pub payload_status: PayloadStatus,
    #[serde(with = "wire::opt_payload_id")]
    pub payload_id: Option<[u8; 8]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatus {
    pub status: String,
    #[serde(with = "wire::opt_b256")]
    pub latest_valid_hash: Option<B256>,
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(with = "wire::quantity")]
    pub index: u64,
    #[serde(with = "wire::quantity")]
    pub validator_index: u64,
    #[serde(with = "wire::addr")]
    pub address: ExecutionAddress,
    #[serde(with = "wire::quantity")]
    pub amount: u64,
}

const PAYLOAD_FIXED_LEN: usize = 528;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn append_hex(bytes: &[u8], out: &mut Vec<u8>) {
    let base = out.len();
    out.resize(base + bytes.len() * 2, 0);
    hex::encode_to_slice(bytes, &mut out[base..]).expect("hex encode_to_slice");
}

fn append_quantity_u64(v: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(b"\"0x");
    if v == 0 {
        out.push(b'0');
    } else {
        let mut buf = [0u8; 16];
        let mut n = 0usize;
        let mut tmp = v;
        while tmp > 0 {
            buf[15 - n] = HEX_LOWER[(tmp & 0xf) as usize];
            tmp >>= 4;
            n += 1;
        }
        out.extend_from_slice(&buf[16 - n..]);
    }
    out.push(b'"');
}

fn append_u256_le_quantity(le: &[u8; 32], out: &mut Vec<u8>) {
    let mut be = *le;
    be.reverse();
    let sig = be.iter().position(|&b| b != 0);
    out.extend_from_slice(b"\"0x");
    match sig {
        None => out.push(b'0'),
        Some(start) => {
            let first = be[start];
            if first >> 4 == 0 {
                out.push(HEX_LOWER[(first & 0xf) as usize]);
                append_hex(&be[start + 1..], out);
            } else {
                append_hex(&be[start..], out);
            }
        }
    }
    out.push(b'"');
}

fn write_txs_json(data: &[u8], out: &mut Vec<u8>) -> Result<(), crate::EngineError> {
    if data.is_empty() {
        return Ok(());
    }
    if data.len() < 4 {
        return Err(crate::EngineError::Ssz("tx list header too short".into()));
    }
    let first_off = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if first_off < 4 || !first_off.is_multiple_of(4) {
        return Err(crate::EngineError::Ssz("invalid tx first offset".into()));
    }
    let n = first_off / 4;
    if data.len() < n * 4 {
        return Err(crate::EngineError::Ssz("tx offsets exceed data".into()));
    }
    for i in 0..n {
        if i > 0 {
            out.push(b',');
        }
        let start = u32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        let end = if i + 1 < n {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 1) * 4 + 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        if start > data.len() || end > data.len() || start > end {
            return Err(crate::EngineError::Ssz("tx slice out of bounds".into()));
        }
        out.extend_from_slice(b"\"0x");
        append_hex(&data[start..end], out);
        out.push(b'"');
    }
    Ok(())
}

fn write_withdrawals_json(data: &[u8], out: &mut Vec<u8>) -> Result<(), crate::EngineError> {
    for (i, chunk) in data.chunks(44).enumerate() {
        if chunk.len() != 44 {
            return Err(crate::EngineError::Ssz("withdrawal chunk not 44 bytes".into()));
        }
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"index\":");
        append_quantity_u64(u64::from_le_bytes(chunk[0..8].try_into().unwrap()), out);
        out.extend_from_slice(b",\"validatorIndex\":");
        append_quantity_u64(u64::from_le_bytes(chunk[8..16].try_into().unwrap()), out);
        out.extend_from_slice(b",\"address\":\"0x");
        append_hex(&chunk[16..36], out);
        out.extend_from_slice(b"\",\"amount\":");
        append_quantity_u64(u64::from_le_bytes(chunk[36..44].try_into().unwrap()), out);
        out.push(b'}');
    }
    Ok(())
}

pub(crate) fn write_new_payload_params(
    data: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), crate::EngineError> {
    if data.len() < SIGNED_BEACON_BLOCK_MIN {
        return Err(crate::EngineError::Ssz(format!(
            "block too short: {} < {SIGNED_BEACON_BLOCK_MIN}",
            data.len()
        )));
    }
    let body = SignedBeaconBlockView::body(data);
    if body.len() < BEACON_BLOCK_BODY_FIXED {
        return Err(crate::EngineError::Ssz(format!(
            "body too short: {} < {BEACON_BLOCK_BODY_FIXED}",
            body.len()
        )));
    }
    let execution_payload_offset: usize =
        BeaconBlockBodyView::execution_payload_offset(body) as usize;
    let bls_to_execution_changes: usize =
        BeaconBlockBodyView::bls_to_execution_changes_offset(body) as usize;
    let blob_kzg_off: usize = BeaconBlockBodyView::blob_kzg_commitments_offset(body) as usize;
    let execution_requests_offset: usize =
        BeaconBlockBodyView::execution_requests_offset(body) as usize;
    if execution_payload_offset < BEACON_BLOCK_BODY_FIXED ||
        bls_to_execution_changes < execution_payload_offset ||
        blob_kzg_off < bls_to_execution_changes ||
        execution_requests_offset < blob_kzg_off ||
        body.len() < execution_requests_offset
    {
        return Err(crate::EngineError::Ssz("invalid body variable offsets".into()));
    }
    let execution_payload = &body[execution_payload_offset..bls_to_execution_changes];
    if execution_payload.len() < PAYLOAD_FIXED_LEN {
        return Err(crate::EngineError::Ssz(format!(
            "execution_payload too short: {} < {PAYLOAD_FIXED_LEN}",
            execution_payload.len()
        )));
    }
    let extra_off: usize = ExecutionPayloadView::extra_data_offset(execution_payload) as usize;
    let txs_off: usize = ExecutionPayloadView::transactions_offset(execution_payload) as usize;
    let wd_off: usize = ExecutionPayloadView::withdrawals_offset(execution_payload) as usize;
    if extra_off < PAYLOAD_FIXED_LEN ||
        txs_off < extra_off ||
        wd_off < txs_off ||
        execution_payload.len() < wd_off
    {
        return Err(crate::EngineError::Ssz("invalid execution_payload variable offsets".into()));
    }
    if !execution_payload[wd_off..].len().is_multiple_of(44) {
        return Err(crate::EngineError::Ssz("withdrawals length not multiple of 44".into()));
    }

    // params array open
    out.push(b'[');

    // ExecutionPayload object — field order matches serde declaration order.
    out.extend_from_slice(b"{\"parentHash\":\"0x");
    append_hex(ExecutionPayloadView::parent_hash(execution_payload), out);
    out.extend_from_slice(b"\",\"feeRecipient\":\"0x");
    append_hex(ExecutionPayloadView::fee_recipient(execution_payload), out);
    out.extend_from_slice(b"\",\"stateRoot\":\"0x");
    append_hex(ExecutionPayloadView::state_root(execution_payload), out);
    out.extend_from_slice(b"\",\"receiptsRoot\":\"0x");
    append_hex(ExecutionPayloadView::receipts_root(execution_payload), out);
    out.extend_from_slice(b"\",\"logsBloom\":\"0x");
    append_hex(ExecutionPayloadView::logs_bloom(execution_payload), out);
    out.extend_from_slice(b"\",\"prevRandao\":\"0x");
    append_hex(ExecutionPayloadView::prev_randao(execution_payload), out);
    out.extend_from_slice(b"\",\"blockNumber\":");
    append_quantity_u64(ExecutionPayloadView::block_number(execution_payload), out);
    out.extend_from_slice(b",\"gasLimit\":");
    append_quantity_u64(ExecutionPayloadView::gas_limit(execution_payload), out);
    out.extend_from_slice(b",\"gasUsed\":");
    append_quantity_u64(ExecutionPayloadView::gas_used(execution_payload), out);
    out.extend_from_slice(b",\"timestamp\":");
    append_quantity_u64(ExecutionPayloadView::timestamp(execution_payload), out);
    out.extend_from_slice(b",\"extraData\":\"0x");
    append_hex(&execution_payload[extra_off..txs_off], out);
    out.extend_from_slice(b"\",\"baseFeePerGas\":");
    append_u256_le_quantity(ExecutionPayloadView::base_fee_per_gas(execution_payload), out);
    out.extend_from_slice(b",\"blockHash\":\"0x");
    append_hex(ExecutionPayloadView::block_hash(execution_payload), out);
    out.extend_from_slice(b"\",\"transactions\":[");
    write_txs_json(&execution_payload[txs_off..wd_off], out)?;
    out.extend_from_slice(b"],\"withdrawals\":[");
    write_withdrawals_json(&execution_payload[wd_off..], out)?;
    out.extend_from_slice(b"],\"blobGasUsed\":");
    append_quantity_u64(ExecutionPayloadView::blob_gas_used(execution_payload), out);
    out.extend_from_slice(b",\"excessBlobGas\":");
    append_quantity_u64(ExecutionPayloadView::excess_blob_gas(execution_payload), out);
    out.push(b'}');

    // versionedHashes — derived from blob_kzg_commitments
    let blob_kzg_off: usize = BeaconBlockBodyView::blob_kzg_commitments_offset(body) as usize;
    let blob_kzg_data = &body[blob_kzg_off..execution_requests_offset];
    // blob_kzg_data is a flat list of 48-byte KZG commitments (no SSZ list offsets,
    // because each element is fixed-size, so SSZ encodes it as a plain
    // concatenation).
    if !blob_kzg_data.len().is_multiple_of(48) {
        return Err(crate::EngineError::Ssz(
            "blob_kzg_commitments length not multiple of 48".into(),
        ));
    }
    out.extend_from_slice(b",[");
    for (i, commitment) in blob_kzg_data.chunks(48).enumerate() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::digest(commitment);
        h[0] = 0x01;
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"\"0x");
        append_hex(&h, out);
        out.push(b'"');
    }
    out.push(b']');

    out.extend_from_slice(b",\"0x");
    append_hex(SignedBeaconBlockView::parent_root(data), out);
    out.push(b'"');

    // executionRequests — 3-field SSZ container at
    // body[execution_requests_offset..]
    let er = &body[execution_requests_offset..];
    if er.len() < 12 {
        return Err(crate::EngineError::Ssz("execution_requests too short".into()));
    }
    let dep_off = u32::from_le_bytes(er[0..4].try_into().unwrap()) as usize;
    let wd_off = u32::from_le_bytes(er[4..8].try_into().unwrap()) as usize;
    let cons_off = u32::from_le_bytes(er[8..12].try_into().unwrap()) as usize;
    if dep_off > wd_off || wd_off > cons_off || cons_off > er.len() {
        return Err(crate::EngineError::Ssz("invalid execution_requests offsets".into()));
    }

    // Per EIP-7685: only non-empty request types are included; type byte is
    // prepended. Type 0x00 = deposit requests, 0x01 = withdrawal requests, 0x02
    // = consolidation requests.
    let slices: [(u8, &[u8]); 3] =
        [(0x00, &er[dep_off..wd_off]), (0x01, &er[wd_off..cons_off]), (0x02, &er[cons_off..])];
    out.extend_from_slice(b",[");
    let mut first = true;
    for (type_byte, data) in &slices {
        if data.is_empty() {
            continue;
        }
        if !first {
            out.push(b',');
        }
        first = false;
        out.extend_from_slice(b"\"0x");
        append_hex(&[*type_byte], out);
        append_hex(data, out);
        out.push(b'"');
    }
    out.push(b']');

    out.push(b']');

    Ok(())
}

// ---------------------------------------------------------------------------
// Zero-alloc JSON → TCache frame converter for engine_getPayloadV4
//
// Parses the raw HTTP response body (full JSON-RPC envelope) using
// simd_json BorrowedValue so all string values borrow from the input
// buffer with no intermediate allocations. Hex fields are decoded
// directly into `out` with hex::decode_to_slice.
//
// `out` is cleared by the caller. On success it contains exactly the
// TCache frame (same layout as encode_get_payload_data).
// ---------------------------------------------------------------------------

fn hex_to_fixed<const N: usize>(s: &str) -> Result<[u8; N], crate::EngineError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|e| crate::EngineError::Ssz(e.to_string()))?;
    Ok(out)
}

// Append decoded bytes of hex string `s` to `out`.
fn hex_extend(s: &str, out: &mut Vec<u8>) -> Result<(), crate::EngineError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let base = out.len();
    out.resize(base + s.len() / 2, 0);
    hex::decode_to_slice(s, &mut out[base..]).map_err(|e| crate::EngineError::Ssz(e.to_string()))
}

// Append exactly N bytes: decode up to N bytes from hex, zero-pad remainder.
fn hex_extend_clamped<const N: usize>(
    s: &str,
    out: &mut Vec<u8>,
) -> Result<(), crate::EngineError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let n = (s.len() / 2).min(N);
    let mut buf = [0u8; N];
    if n > 0 {
        hex::decode_to_slice(&s[..n * 2], &mut buf[..n])
            .map_err(|e| crate::EngineError::Ssz(e.to_string()))?;
    }
    out.extend_from_slice(&buf);
    Ok(())
}

fn parse_quantity(s: &str) -> Result<u64, crate::EngineError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| crate::EngineError::Ssz(e.to_string()))
}

// Parse Ethereum QUANTITY "0x..." to [u8; 32] little-endian (uint256).
fn parse_u256_le(s: &str) -> Result<[u8; 32], crate::EngineError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() > 64 {
        return Err(crate::EngineError::Ssz("u256 too large".into()));
    }
    let mut padded = [b'0'; 64];
    padded[64 - s.len()..].copy_from_slice(s.as_bytes());
    let mut arr = [0u8; 32];
    hex::decode_to_slice(padded, &mut arr).map_err(|e| crate::EngineError::Ssz(e.to_string()))?;
    arr.reverse();
    Ok(arr)
}

fn fstr<'a>(
    v: &'a simd_json::BorrowedValue<'_>,
    field: &str,
) -> Result<&'a str, crate::EngineError> {
    use simd_json::prelude::{ValueAsScalar, ValueObjectAccess};
    v.get(field)
        .and_then(|f| f.as_str())
        .ok_or_else(|| crate::EngineError::Ssz(format!("missing field: {field}")))
}

// Write SSZ transaction list (offset header + tx bytes) from JSON hex-string
// array.
fn encode_txs_json(
    arr: &[simd_json::BorrowedValue<'_>],
    out: &mut Vec<u8>,
) -> Result<(), crate::EngineError> {
    use simd_json::prelude::ValueAsScalar;
    if arr.is_empty() {
        return Ok(());
    }
    let n = arr.len();
    let header_base = out.len();
    out.resize(header_base + n * 4, 0);
    let mut offset = (n * 4) as u32;
    for (i, tx) in arr.iter().enumerate() {
        let s = tx.as_str().ok_or_else(|| crate::EngineError::Ssz("tx not a string".into()))?;
        out[header_base + i * 4..header_base + i * 4 + 4].copy_from_slice(&offset.to_le_bytes());
        offset += (s.strip_prefix("0x").unwrap_or(s).len() / 2) as u32;
    }
    for tx in arr {
        let s = tx.as_str().ok_or_else(|| crate::EngineError::Ssz("tx not a string".into()))?;
        hex_extend(s, out)?;
    }
    Ok(())
}

fn encode_withdrawals_json(
    arr: &[simd_json::BorrowedValue<'_>],
    out: &mut Vec<u8>,
) -> Result<(), crate::EngineError> {
    for w in arr {
        out.extend_from_slice(&parse_quantity(fstr(w, "index")?)?.to_le_bytes());
        out.extend_from_slice(&parse_quantity(fstr(w, "validatorIndex")?)?.to_le_bytes());
        out.extend_from_slice(&hex_to_fixed::<20>(fstr(w, "address")?)?);
        out.extend_from_slice(&parse_quantity(fstr(w, "amount")?)?.to_le_bytes());
    }
    Ok(())
}

/// Parse a raw `engine_getPayloadV4` JSON-RPC response body and write the
/// TCache frame directly into `out` (same layout as `encode_get_payload_data`).
///
/// `raw` is mutated in-place by simd_json's SIMD parser. `out` must be empty
/// on entry and is filled with exactly the frame bytes on success.
///
/// Eliminates all intermediate allocations vs the serde path:
/// one `Vec<u8>` output, hex decoded directly from the borrowed JSON strings.
pub(crate) fn json_get_payload_to_tcache(
    raw: &mut [u8],
    out: &mut Vec<u8>,
) -> Result<(), crate::EngineError> {
    use simd_json::prelude::{ValueAsArray, ValueAsScalar, ValueObjectAccess};

    let root = simd_json::to_borrowed_value(raw).map_err(crate::EngineError::Json)?;

    if root.get("error").is_some() {
        return Err(crate::EngineError::Ssz("rpc error in getPayload response".into()));
    }
    let result = root.get("result").ok_or(crate::EngineError::MissingResult)?;

    let ep = result
        .get("executionPayload")
        .ok_or_else(|| crate::EngineError::Ssz("missing executionPayload".into()))?;
    let bb = result
        .get("blobsBundle")
        .ok_or_else(|| crate::EngineError::Ssz("missing blobsBundle".into()))?;
    let should_override =
        result.get("shouldOverrideBuilder").and_then(|v| v.as_bool()).unwrap_or(false);
    let exec_requests = result
        .get("executionRequests")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    // TCache frame header: placeholder for payload SSZ length.
    let tcache_hdr = out.len();
    out.extend_from_slice(&[0u8; 4]);

    // ExecutionPayload SSZ — fixed section (528 bytes).
    let ssz_start = out.len();
    let f = ssz_start;
    out.resize(f + PAYLOAD_FIXED_LEN, 0);

    out[f..f + 32].copy_from_slice(&hex_to_fixed::<32>(fstr(ep, "parentHash")?)?);
    out[f + 32..f + 52].copy_from_slice(&hex_to_fixed::<20>(fstr(ep, "feeRecipient")?)?);
    out[f + 52..f + 84].copy_from_slice(&hex_to_fixed::<32>(fstr(ep, "stateRoot")?)?);
    out[f + 84..f + 116].copy_from_slice(&hex_to_fixed::<32>(fstr(ep, "receiptsRoot")?)?);
    out[f + 116..f + 372].copy_from_slice(&hex_to_fixed::<256>(fstr(ep, "logsBloom")?)?);
    out[f + 372..f + 404].copy_from_slice(&hex_to_fixed::<32>(fstr(ep, "prevRandao")?)?);
    out[f + 404..f + 412].copy_from_slice(&parse_quantity(fstr(ep, "blockNumber")?)?.to_le_bytes());
    out[f + 412..f + 420].copy_from_slice(&parse_quantity(fstr(ep, "gasLimit")?)?.to_le_bytes());
    out[f + 420..f + 428].copy_from_slice(&parse_quantity(fstr(ep, "gasUsed")?)?.to_le_bytes());
    out[f + 428..f + 436].copy_from_slice(&parse_quantity(fstr(ep, "timestamp")?)?.to_le_bytes());
    // [f+436..f+440] extra_data offset — patched below
    out[f + 440..f + 472].copy_from_slice(&parse_u256_le(fstr(ep, "baseFeePerGas")?)?);
    out[f + 472..f + 504].copy_from_slice(&hex_to_fixed::<32>(fstr(ep, "blockHash")?)?);
    // [f+504..f+508] transactions offset — patched below
    // [f+508..f+512] withdrawals offset — patched below
    out[f + 512..f + 520].copy_from_slice(&parse_quantity(fstr(ep, "blobGasUsed")?)?.to_le_bytes());
    out[f + 520..f + 528]
        .copy_from_slice(&parse_quantity(fstr(ep, "excessBlobGas")?)?.to_le_bytes());

    // Variable fields — patch offsets into fixed section as we go.
    let extra_off = (out.len() - ssz_start) as u32;
    out[f + 436..f + 440].copy_from_slice(&extra_off.to_le_bytes());
    hex_extend(fstr(ep, "extraData")?, out)?;

    let txs_off = (out.len() - ssz_start) as u32;
    out[f + 504..f + 508].copy_from_slice(&txs_off.to_le_bytes());
    let txs = ep
        .get("transactions")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .ok_or_else(|| crate::EngineError::Ssz("missing transactions".into()))?;
    encode_txs_json(txs, out)?;

    let ws_off = (out.len() - ssz_start) as u32;
    out[f + 508..f + 512].copy_from_slice(&ws_off.to_le_bytes());
    let ws = ep
        .get("withdrawals")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .ok_or_else(|| crate::EngineError::Ssz("missing withdrawals".into()))?;
    encode_withdrawals_json(ws, out)?;

    // Patch payload SSZ length into TCache header.
    let payload_ssz_len = (out.len() - ssz_start) as u32;
    out[tcache_hdr..tcache_hdr + 4].copy_from_slice(&payload_ssz_len.to_le_bytes());

    // Blobs bundle.
    let commitments =
        bb.get("commitments").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
    let proofs = bb.get("proofs").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
    let blobs = bb.get("blobs").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
    let blob_count = commitments.len().min(proofs.len()).min(blobs.len()).min(255) as u8;
    out.push(blob_count);

    for i in 0..blob_count as usize {
        hex_extend_clamped::<48>(commitments[i].as_str().unwrap_or("0x"), out)?;
        hex_extend_clamped::<48>(proofs[i].as_str().unwrap_or("0x"), out)?;
        let b_s = blobs[i].as_str().unwrap_or("0x");
        let b_hex = b_s.strip_prefix("0x").unwrap_or(b_s);
        out.extend_from_slice(&((b_hex.len() / 2) as u32).to_le_bytes());
        hex_extend(b_s, out)?;
    }

    out.push(should_override as u8);

    let exec_count = exec_requests.len().min(255) as u8;
    out.push(exec_count);
    for req in exec_requests.iter().take(exec_count as usize) {
        let s = req.as_str().unwrap_or("0x");
        let hex_s = s.strip_prefix("0x").unwrap_or(s);
        out.extend_from_slice(&((hex_s.len() / 2) as u32).to_le_bytes());
        hex_extend(s, out)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Zero-alloc JSON → TCache frame converter for engine_getBlobsV2
//
// Same approach as json_get_payload_to_tcache: BorrowedValue borrows from the
// input buffer; hex decoded directly into `out` with hex::decode_to_slice.
// Wire layout: [u32 count] [u8 present] [u8 proof_count] [proof_count*48B] [u32
// blob_len] [blob bytes]
// ---------------------------------------------------------------------------

pub(crate) fn json_get_blobs_to_tcache(
    raw: &mut [u8],
    out: &mut Vec<u8>,
) -> Result<(), crate::EngineError> {
    use simd_json::prelude::{TypedScalarValue, ValueAsArray, ValueAsScalar, ValueObjectAccess};

    let root = simd_json::to_borrowed_value(raw).map_err(crate::EngineError::Json)?;
    let result = root.get("result").ok_or(crate::EngineError::MissingResult)?;

    if result.is_null() {
        out.extend_from_slice(&0u32.to_le_bytes());
        return Ok(());
    }

    let items = result
        .as_array()
        .ok_or_else(|| crate::EngineError::Ssz("getBlobsV2 result not array".into()))?;
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());

    for item in items {
        if item.is_null() {
            out.push(0);
            continue;
        }
        out.push(1);

        let proofs = item
            .get("proofs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| crate::EngineError::Ssz("missing proofs".into()))?;
        let proof_count = proofs.len().min(255) as u8;
        out.push(proof_count);
        for p in &proofs[..proof_count as usize] {
            let s =
                p.as_str().ok_or_else(|| crate::EngineError::Ssz("proof not a string".into()))?;
            hex_extend_clamped::<48>(s, out)?;
        }

        let blob_s = item
            .get("blob")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::EngineError::Ssz("missing blob".into()))?;
        let blob_s = blob_s.strip_prefix("0x").unwrap_or(blob_s);
        let blob_len = blob_s.len() / 2;
        out.extend_from_slice(&(blob_len as u32).to_le_bytes());
        let base = out.len();
        out.resize(base + blob_len, 0);
        hex::decode_to_slice(blob_s, &mut out[base..])
            .map_err(|e| crate::EngineError::Ssz(e.to_string()))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Zero-alloc JSON → TCache frame converter for
// engine_getPayloadBodiesByHashV1 / ByRangeV1
//
// Wire layout: [u32 count] [u8 present] [u32 tx_count] [u32 len][tx bytes]...
// [u32 withdrawal_count] [44B each]
// ---------------------------------------------------------------------------

pub(crate) fn json_get_payload_bodies_to_tcache(
    raw: &mut [u8],
    out: &mut Vec<u8>,
) -> Result<(), crate::EngineError> {
    use simd_json::prelude::{TypedScalarValue, ValueAsArray, ValueAsScalar, ValueObjectAccess};

    let root = simd_json::to_borrowed_value(raw).map_err(crate::EngineError::Json)?;
    let items =
        root.get("result").and_then(|v| v.as_array()).ok_or(crate::EngineError::MissingResult)?;

    out.extend_from_slice(&(items.len() as u32).to_le_bytes());

    for item in items {
        if item.is_null() {
            out.push(0);
            continue;
        }
        out.push(1);

        let txs = item
            .get("transactions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| crate::EngineError::Ssz("missing transactions".into()))?;
        out.extend_from_slice(&(txs.len() as u32).to_le_bytes());
        for tx in txs {
            let s = tx.as_str().ok_or_else(|| crate::EngineError::Ssz("tx not a string".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let len = s.len() / 2;
            out.extend_from_slice(&(len as u32).to_le_bytes());
            let base = out.len();
            out.resize(base + len, 0);
            hex::decode_to_slice(s, &mut out[base..])
                .map_err(|e| crate::EngineError::Ssz(e.to_string()))?;
        }

        let withdrawals: &[simd_json::BorrowedValue<'_>] =
            item.get("withdrawals").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
        out.extend_from_slice(&(withdrawals.len() as u32).to_le_bytes());
        for w in withdrawals {
            let index = parse_quantity(fstr(w, "index")?)?;
            let validator_index = parse_quantity(fstr(w, "validatorIndex")?)?;
            let address = hex_to_fixed::<20>(fstr(w, "address")?)?;
            let amount = parse_quantity(fstr(w, "amount")?)?;
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&validator_index.to_le_bytes());
            out.extend_from_slice(&address);
            out.extend_from_slice(&amount.to_le_bytes());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use simd_json::{
        owned::to_value,
        prelude::{ValueAsArray, ValueAsScalar, ValueObjectAccess},
    };

    use super::*;

    const SAMPLE_PAYLOAD_SSZ: &[u8] = include_bytes!("../testdata/sample_payload.ssz");
    // EF spec-test fixture (decompressed):
    // mainnet/fulu/ssz_static/SignedBeaconBlock/ssz_random/case_4.
    const SIGNED_BLOCK_SSZ: &[u8] = include_bytes!("../testdata/signed_block.ssz");
    // Expected newPayload params for the block above, derived independently
    // from the case's value.yaml.
    const SIGNED_BLOCK_PARAMS: &[u8] = include_bytes!("../testdata/signed_block_params.json");
    const EMPTY_VAR_PAYLOAD_SSZ: &[u8] = include_bytes!("../testdata/empty_var_payload.ssz");
    const MANY_TX_PAYLOAD_SSZ: &[u8] = include_bytes!("../testdata/many_tx_payload.ssz");
    const TX_SINGLE: &[u8] = include_bytes!("../testdata/tx_single.bin");
    const TX_MULTI: &[u8] = include_bytes!("../testdata/tx_multi.bin");
    const WITHDRAWALS: &[u8] = include_bytes!("../testdata/withdrawals.bin");
    const GET_PAYLOAD_TCACHE: &[u8] = include_bytes!("../testdata/get_payload_tcache.bin");

    // Wraps a bare ExecutionPayload SSZ in a minimal SignedBeaconBlock SSZ:
    // zeroed fixed fields, the five early body lists empty, empty
    // bls_to_execution_changes. `requests` are the raw bytes of the three
    // ExecutionRequests lists (deposits, withdrawals, consolidations).
    fn make_signed_block(
        payload_ssz: &[u8],
        kzg_commitments: &[[u8; 48]],
        requests: [&[u8]; 3],
        parent_root: [u8; 32],
    ) -> Vec<u8> {
        let mut out = vec![0u8; 184 + BEACON_BLOCK_BODY_FIXED];
        out[0..4].copy_from_slice(&100u32.to_le_bytes()); // message offset
        out[116..148].copy_from_slice(&parent_root);
        out[180..184].copy_from_slice(&84u32.to_le_bytes()); // body offset

        let fixed = BEACON_BLOCK_BODY_FIXED as u32;
        let ep_off = fixed;
        let bls_off = ep_off + payload_ssz.len() as u32;
        let kzg_off = bls_off;
        let er_off = kzg_off + 48 * kzg_commitments.len() as u32;
        for (pos, val) in [
            (200, fixed),
            (204, fixed),
            (208, fixed),
            (212, fixed),
            (216, fixed),
            (380, ep_off),
            (384, bls_off),
            (388, kzg_off),
            (392, er_off),
        ] {
            out[184 + pos..184 + pos + 4].copy_from_slice(&val.to_le_bytes());
        }
        out.extend_from_slice(payload_ssz);
        for c in kzg_commitments {
            out.extend_from_slice(c);
        }
        let mut off = 12u32;
        for r in &requests {
            out.extend_from_slice(&off.to_le_bytes());
            off += r.len() as u32;
        }
        for r in &requests {
            out.extend_from_slice(r);
        }
        out
    }

    // Constructs the getPayload JSON whose TCache encoding is
    // get_payload_tcache.bin.
    fn get_payload_json() -> Vec<u8> {
        let logs_bloom = "55".repeat(256);
        let commitment0 = "c0".repeat(48);
        let proof0 = "d0".repeat(48);
        let blob0 = "b0".repeat(128);
        let commitment1 = "c1".repeat(48);
        let proof1 = "d1".repeat(48);
        let blob1 = "b1".repeat(64);
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"executionPayload":{{"parentHash":"0x1111111111111111111111111111111111111111111111111111111111111111","feeRecipient":"0x2222222222222222222222222222222222222222","stateRoot":"0x3333333333333333333333333333333333333333333333333333333333333333","receiptsRoot":"0x4444444444444444444444444444444444444444444444444444444444444444","logsBloom":"0x{logs_bloom}","prevRandao":"0x6666666666666666666666666666666666666666666666666666666666666666","blockNumber":"0x3039","gasLimit":"0x1c9c380","gasUsed":"0x5208","timestamp":"0x6553f100","extraData":"0x6578747261","baseFeePerGas":"0x7777777777777777777777777777777777777777777777777777777777777777","blockHash":"0x8888888888888888888888888888888888888888888888888888888888888888","transactions":["0x010203","0x0405060708"],"withdrawals":[{{"index":"0x1","validatorIndex":"0x2a","address":"0x9999999999999999999999999999999999999999","amount":"0x3e8"}},{{"index":"0x2","validatorIndex":"0x2b","address":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","amount":"0x7d0"}}],"blobGasUsed":"0x20000","excessBlobGas":"0x40000"}},"blobsBundle":{{"commitments":["0x{commitment0}","0x{commitment1}"],"proofs":["0x{proof0}","0x{proof1}"],"blobs":["0x{blob0}","0x{blob1}"]}},"shouldOverrideBuilder":false,"executionRequests":["0x0102","0x03"]}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn ssz_variable_offsets_at_correct_positions() {
        let ssz = SAMPLE_PAYLOAD_SSZ;

        let extra_off = u32::from_le_bytes(ssz[436..440].try_into().unwrap()) as usize;
        let tx_off = u32::from_le_bytes(ssz[504..508].try_into().unwrap()) as usize;
        let wd_off = u32::from_le_bytes(ssz[508..512].try_into().unwrap()) as usize;

        assert_eq!(extra_off, 528, "extra_data offset must point past fixed section");
        assert_eq!(tx_off, 528 + 5); // extra_data = b"extra" (5 bytes)
        // withdrawals follow the SSZ transaction list
        assert!(wd_off > tx_off);
        assert_eq!(wd_off, ssz.len() - 2 * 44); // 2 withdrawals × 44 bytes each
    }

    // -----------------------------------------------------------------------
    // Wire format: serialize ↔ deserialize round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn wire_b256_round_trip() {
        let state = ForkchoiceState {
            head_block_hash: [0xab; 32],
            safe_block_hash: [0x00; 32],
            finalized_block_hash: [0xff; 32],
        };
        let json: ForkchoiceState = {
            let mut bytes = simd_json::to_vec(&state).unwrap();
            simd_json::from_slice(&mut bytes).unwrap()
        };
        assert_eq!(state.head_block_hash, json.head_block_hash);
        assert_eq!(state.safe_block_hash, json.safe_block_hash);
        assert_eq!(state.finalized_block_hash, json.finalized_block_hash);
    }

    #[test]
    fn wire_b256_correct_hex_encoding() {
        let state = ForkchoiceState {
            head_block_hash: [0xab; 32],
            safe_block_hash: [0; 32],
            finalized_block_hash: [0; 32],
        };
        let json = to_value(&mut simd_json::to_vec(&state).unwrap()).unwrap();
        let hex = json["headBlockHash"].as_str().unwrap();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 64);
        assert_eq!(&hex[2..4], "ab");
    }

    #[test]
    fn wire_quantity_round_trip() {
        // Withdrawal uses quantity for all numeric fields
        let w = Withdrawal { index: 0, validator_index: 0xdeadbeef, address: [0; 20], amount: 0 };
        let json: Withdrawal = {
            let mut bytes = simd_json::to_vec(&w).unwrap();
            simd_json::from_slice(&mut bytes).unwrap()
        };
        assert_eq!(w.validator_index, json.validator_index);
    }

    #[test]
    fn wire_opt_b256_none_round_trip() {
        let v: PayloadStatus = {
            let mut bytes =
                br#"{"status":"VALID","latestValidHash":null,"validationError":null}"#.to_vec();
            simd_json::from_slice(&mut bytes).unwrap()
        };
        assert_eq!(v.latest_valid_hash, None);
        let v2: PayloadStatus = {
            let mut bytes = simd_json::to_vec(&v).unwrap();
            simd_json::from_slice(&mut bytes).unwrap()
        };
        assert_eq!(v2.latest_valid_hash, None);
    }

    #[test]
    fn wire_opt_payload_id_round_trip() {
        let fcu_json = r#"{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":"0x0102030405060708"}"#;
        let fcu: ForkchoiceUpdatedResult = {
            let mut bytes = fcu_json.as_bytes().to_vec();
            simd_json::from_slice(&mut bytes).unwrap()
        };
        assert_eq!(fcu.payload_id, Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));
        let roundtrip: ForkchoiceUpdatedResult = {
            let mut bytes = simd_json::to_vec(&fcu).unwrap();
            simd_json::from_slice(&mut bytes).unwrap()
        };
        assert_eq!(fcu.payload_id, roundtrip.payload_id);
    }

    #[test]
    fn wire_opt_b256_some_round_trip() {
        let hash = "ab".repeat(32);
        let mut bytes =
            format!(r#"{{"status":"VALID","latestValidHash":"0x{hash}","validationError":null}}"#)
                .into_bytes();
        let v: PayloadStatus = simd_json::from_slice(&mut bytes).unwrap();
        assert_eq!(v.latest_valid_hash, Some([0xab; 32]));
    }

    #[test]
    fn wire_addr_round_trip() {
        let w = Withdrawal { index: 1, validator_index: 2, address: [0xab; 20], amount: 3 };
        let rt: Withdrawal = {
            let mut bytes = simd_json::to_vec(&w).unwrap();
            simd_json::from_slice(&mut bytes).unwrap()
        };
        assert_eq!(w.address, rt.address);
        let json = to_value(&mut simd_json::to_vec(&w).unwrap()).unwrap();
        let addr = json["address"].as_str().unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 2 + 40);
        assert_eq!(&addr[2..4], "ab");
    }

    // ---------------------------------------------------------------------------
    // append_hex
    // ---------------------------------------------------------------------------

    #[test]
    fn append_hex_empty() {
        let mut out = Vec::new();
        append_hex(&[], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn append_hex_bytes() {
        let mut out = Vec::new();
        append_hex(&[0xde, 0xad, 0xbe, 0xef], &mut out);
        assert_eq!(out, b"deadbeef");
    }

    #[test]
    fn append_hex_appends_to_existing() {
        let mut out = b"prefix".to_vec();
        append_hex(&[0x01], &mut out);
        assert_eq!(out, b"prefix01");
    }

    // ---------------------------------------------------------------------------
    // append_quantity_u64
    // ---------------------------------------------------------------------------

    #[test]
    fn quantity_u64_zero() {
        let mut out = Vec::new();
        append_quantity_u64(0, &mut out);
        assert_eq!(out, b"\"0x0\"");
    }

    #[test]
    fn quantity_u64_small() {
        let mut out = Vec::new();
        append_quantity_u64(0xdeadbeef, &mut out);
        assert_eq!(out, b"\"0xdeadbeef\"");
    }

    #[test]
    fn quantity_u64_max() {
        let mut out = Vec::new();
        append_quantity_u64(u64::MAX, &mut out);
        assert_eq!(out, b"\"0xffffffffffffffff\"");
    }

    #[test]
    fn quantity_u64_single_nibble() {
        let mut out = Vec::new();
        append_quantity_u64(0xf, &mut out);
        assert_eq!(out, b"\"0xf\"");
    }

    // ---------------------------------------------------------------------------
    // append_u256_le_quantity
    // ---------------------------------------------------------------------------

    #[test]
    fn u256_le_zero() {
        let mut out = Vec::new();
        append_u256_le_quantity(&[0u8; 32], &mut out);
        assert_eq!(out, b"\"0x0\"");
    }

    #[test]
    fn u256_le_one() {
        let mut le = [0u8; 32];
        le[0] = 1;
        let mut out = Vec::new();
        append_u256_le_quantity(&le, &mut out);
        assert_eq!(out, b"\"0x1\"");
    }

    #[test]
    fn u256_le_single_byte() {
        let mut le = [0u8; 32];
        le[0] = 0xff;
        let mut out = Vec::new();
        append_u256_le_quantity(&le, &mut out);
        assert_eq!(out, b"\"0xff\"");
    }

    #[test]
    fn u256_le_leading_nibble_stripped() {
        // 0x0a LE → BE has leading nibble 0, must be stripped → "0xa"
        let mut le = [0u8; 32];
        le[0] = 0x0a;
        let mut out = Vec::new();
        append_u256_le_quantity(&le, &mut out);
        assert_eq!(out, b"\"0xa\"");
    }

    #[test]
    fn u256_le_multi_byte() {
        // le[0]=0x02, le[1]=0x01 → BE = 0x0102 → "0x102"
        let mut le = [0u8; 32];
        le[0] = 0x02;
        le[1] = 0x01;
        let mut out = Vec::new();
        append_u256_le_quantity(&le, &mut out);
        assert_eq!(out, b"\"0x102\"");
    }

    #[test]
    fn u256_le_all_bytes_set() {
        let le = [0x77u8; 32];
        let mut out = Vec::new();
        append_u256_le_quantity(&le, &mut out);
        assert_eq!(out, b"\"0x7777777777777777777777777777777777777777777777777777777777777777\"");
    }

    // ---------------------------------------------------------------------------
    // write_txs_json
    // ---------------------------------------------------------------------------

    #[test]
    fn write_txs_json_empty() {
        let mut out = Vec::new();
        write_txs_json(&[], &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn write_txs_json_single() {
        // tx_single.bin: [u32 LE 4][deadbeef] → one tx: 0xdeadbeef
        let mut out = Vec::new();
        write_txs_json(TX_SINGLE, &mut out).unwrap();
        assert_eq!(out, b"\"0xdeadbeef\"");
    }

    #[test]
    fn write_txs_json_multi() {
        // tx_multi.bin: 5 txs of increasing length
        let mut out = Vec::new();
        write_txs_json(TX_MULTI, &mut out).unwrap();
        assert_eq!(
            out,
            b"\"0x010101\",\"0x020202020202\",\"0x030303030303030303\",\"0x040404040404040404040404\",\"0x050505050505050505050505050505\""
        );
    }

    #[test]
    fn write_txs_json_header_too_short() {
        let mut out = Vec::new();
        assert!(write_txs_json(&[0x01, 0x02], &mut out).is_err());
    }

    #[test]
    fn write_txs_json_invalid_first_offset() {
        // first_off=3: not a multiple of 4
        let mut out = Vec::new();
        assert!(write_txs_json(&[3, 0, 0, 0, 0xde, 0xad], &mut out).is_err());
    }

    // ---------------------------------------------------------------------------
    // write_withdrawals_json
    // ---------------------------------------------------------------------------

    #[test]
    fn write_withdrawals_json_empty() {
        let mut out = Vec::new();
        write_withdrawals_json(&[], &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn write_withdrawals_json_two() {
        // withdrawals.bin: [0] index=10 vi=20 addr=0101..01 amount=500
        //                  [1] index=11 vi=21 addr=0202..02 amount=600
        let mut out = Vec::new();
        write_withdrawals_json(WITHDRAWALS, &mut out).unwrap();
        let mut arr = format!("[{}]", std::str::from_utf8(&out).unwrap()).into_bytes();
        let val = simd_json::to_borrowed_value(&mut arr).unwrap();
        let items = val.as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].get("index").and_then(|v| v.as_str()), Some("0xa"));
        assert_eq!(items[0].get("validatorIndex").and_then(|v| v.as_str()), Some("0x14"));
        assert_eq!(
            items[0].get("address").and_then(|v| v.as_str()),
            Some("0x0101010101010101010101010101010101010101")
        );
        assert_eq!(items[0].get("amount").and_then(|v| v.as_str()), Some("0x1f4"));
        assert_eq!(items[1].get("index").and_then(|v| v.as_str()), Some("0xb"));
        assert_eq!(items[1].get("amount").and_then(|v| v.as_str()), Some("0x258"));
    }

    #[test]
    fn write_withdrawals_json_bad_chunk() {
        // 43 bytes: not a multiple of 44
        let mut out = Vec::new();
        assert!(write_withdrawals_json(&[0u8; 43], &mut out).is_err());
    }

    // ---------------------------------------------------------------------------
    // write_new_payload_params
    // ---------------------------------------------------------------------------

    #[test]
    fn write_new_payload_params_sample_fields() {
        let block = make_signed_block(
            SAMPLE_PAYLOAD_SSZ,
            &[[0xaau8; 48], [0xbbu8; 48]],
            [&[], &[], &[]],
            [0xccu8; 32],
        );
        let mut out = Vec::new();
        write_new_payload_params(&block, &mut out).unwrap();

        let val = simd_json::to_borrowed_value(&mut out).unwrap();
        let params = val.as_array().unwrap();
        assert_eq!(params.len(), 4);

        let ep = &params[0];
        assert_eq!(
            ep.get("parentHash").and_then(|v| v.as_str()),
            Some("0x1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(ep.get("blockNumber").and_then(|v| v.as_str()), Some("0x3039"));
        assert_eq!(ep.get("gasLimit").and_then(|v| v.as_str()), Some("0x1c9c380"));
        assert_eq!(ep.get("gasUsed").and_then(|v| v.as_str()), Some("0x5208"));
        assert_eq!(ep.get("timestamp").and_then(|v| v.as_str()), Some("0x6553f100"));
        assert_eq!(ep.get("extraData").and_then(|v| v.as_str()), Some("0x6578747261"));
        assert_eq!(
            ep.get("baseFeePerGas").and_then(|v| v.as_str()),
            Some("0x7777777777777777777777777777777777777777777777777777777777777777")
        );
        assert_eq!(ep.get("blobGasUsed").and_then(|v| v.as_str()), Some("0x20000"));
        assert_eq!(ep.get("excessBlobGas").and_then(|v| v.as_str()), Some("0x40000"));

        let txs = ep.get("transactions").and_then(|v| v.as_array()).unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].as_str(), Some("0x010203"));
        assert_eq!(txs[1].as_str(), Some("0x0405060708"));

        let wds = ep.get("withdrawals").and_then(|v| v.as_array()).unwrap();
        assert_eq!(wds.len(), 2);
        assert_eq!(wds[0].get("index").and_then(|v| v.as_str()), Some("0x1"));
        assert_eq!(wds[0].get("amount").and_then(|v| v.as_str()), Some("0x3e8"));
        assert_eq!(wds[1].get("index").and_then(|v| v.as_str()), Some("0x2"));
        assert_eq!(wds[1].get("amount").and_then(|v| v.as_str()), Some("0x7d0"));

        // sha256 of 48×0xaa / 48×0xbb with first byte forced to 0x01
        let vh = params[1].as_array().unwrap();
        assert_eq!(vh.len(), 2);
        assert_eq!(
            vh[0].as_str(),
            Some("0x01659f8a49133759d495ee5d15262cdc0050f9027e20c7bed3e0599e27adec4b")
        );
        assert_eq!(
            vh[1].as_str(),
            Some("0x018fc9d98c32189fe8232b46db86446b16895b4e2a911803d4b9c1d229838914")
        );

        assert_eq!(
            params[2].as_str(),
            Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );

        let reqs = params[3].as_array().unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn write_new_payload_params_exec_requests() {
        let block = make_signed_block(SAMPLE_PAYLOAD_SSZ, &[], [&[], &[0x02], &[0x03]], [0u8; 32]);
        let mut out = Vec::new();
        write_new_payload_params(&block, &mut out).unwrap();

        let val = simd_json::to_borrowed_value(&mut out).unwrap();
        let reqs = val.as_array().unwrap()[3].as_array().unwrap();
        // empty deposit list skipped; type byte prepended to the others
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].as_str(), Some("0x0102"));
        assert_eq!(reqs[1].as_str(), Some("0x0203"));
    }

    #[test]
    fn write_new_payload_params_spec_block() {
        let mut json = Vec::new();
        write_new_payload_params(SIGNED_BLOCK_SSZ, &mut json).unwrap();
        let actual = simd_json::to_owned_value(&mut json).unwrap();
        let expected = simd_json::to_owned_value(&mut SIGNED_BLOCK_PARAMS.to_vec()).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn write_new_payload_params_empty_variable_fields() {
        let block = make_signed_block(EMPTY_VAR_PAYLOAD_SSZ, &[], [&[], &[], &[]], [0u8; 32]);
        let mut out = Vec::new();
        write_new_payload_params(&block, &mut out).unwrap();

        let val = simd_json::to_borrowed_value(&mut out).unwrap();
        let ep = &val.as_array().unwrap()[0];
        assert_eq!(ep.get("extraData").and_then(|v| v.as_str()), Some("0x"));
        assert_eq!(ep.get("transactions").and_then(|v| v.as_array()).map(|a| a.len()), Some(0));
        assert_eq!(ep.get("withdrawals").and_then(|v| v.as_array()).map(|a| a.len()), Some(0));
    }

    #[test]
    fn write_new_payload_params_many_txs() {
        let block = make_signed_block(MANY_TX_PAYLOAD_SSZ, &[], [&[], &[], &[]], [0u8; 32]);
        let mut out = Vec::new();
        write_new_payload_params(&block, &mut out).unwrap();

        let val = simd_json::to_borrowed_value(&mut out).unwrap();
        let txs =
            val.as_array().unwrap()[0].get("transactions").and_then(|v| v.as_array()).unwrap();
        assert_eq!(txs.len(), 21);
        assert_eq!(txs[0].as_str(), Some("0x00"));
        assert_eq!(txs[20].as_str(), Some("0x141414141414141414141414141414141414141414"));
    }

    #[test]
    fn write_new_payload_params_too_short() {
        assert!(write_new_payload_params(&[0u8; 4], &mut Vec::new()).is_err());
    }

    #[test]
    fn write_new_payload_params_truncated_payload() {
        // body offsets point past the truncated end
        let block = make_signed_block(SAMPLE_PAYLOAD_SSZ, &[], [&[], &[], &[]], [0u8; 32]);
        let truncated = &block[..block.len() - 200];
        assert!(write_new_payload_params(truncated, &mut Vec::new()).is_err());
    }

    // ---------------------------------------------------------------------------
    // json_get_payload_to_tcache
    // ---------------------------------------------------------------------------

    #[test]
    fn json_get_payload_to_tcache_matches_fixture() {
        let mut json = get_payload_json();
        let mut out = Vec::new();
        json_get_payload_to_tcache(&mut json, &mut out).unwrap();
        assert_eq!(out, GET_PAYLOAD_TCACHE);
    }

    #[test]
    fn json_get_payload_to_tcache_rpc_error() {
        let mut json =
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"internal"}}"#.to_vec();
        assert!(json_get_payload_to_tcache(&mut json, &mut Vec::new()).is_err());
    }

    #[test]
    fn json_get_payload_to_tcache_missing_result() {
        let mut json = br#"{"jsonrpc":"2.0","id":1}"#.to_vec();
        assert!(json_get_payload_to_tcache(&mut json, &mut Vec::new()).is_err());
    }

    // ---------------------------------------------------------------------------
    // json_get_blobs_to_tcache
    // ---------------------------------------------------------------------------

    #[test]
    fn json_get_blobs_null_result() {
        let mut json = br#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_vec();
        let mut out = Vec::new();
        json_get_blobs_to_tcache(&mut json, &mut out).unwrap();
        assert_eq!(out, 0u32.to_le_bytes());
    }

    #[test]
    fn json_get_blobs_with_items() {
        let proof = "a0".repeat(48);
        let blob_hex = "b0".repeat(32);
        let mut json =
            format!(r#"{{"result":[{{"proofs":["0x{proof}"],"blob":"0x{blob_hex}"}},null]}}"#)
                .into_bytes();
        let mut out = Vec::new();
        json_get_blobs_to_tcache(&mut json, &mut out).unwrap();

        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 2);
        // item 0: present=1, proof_count=1, 48 proof bytes, blob_len=32, 32 blob bytes
        assert_eq!(out[4], 1);
        assert_eq!(out[5], 1);
        assert_eq!(&out[6..54], &[0xa0u8; 48]);
        assert_eq!(u32::from_le_bytes(out[54..58].try_into().unwrap()), 32);
        assert_eq!(&out[58..90], &[0xb0u8; 32]);
        // item 1: null → present=0
        assert_eq!(out[90], 0);
    }

    #[test]
    fn json_get_blobs_missing_result() {
        let mut json = br#"{"jsonrpc":"2.0","id":1}"#.to_vec();
        assert!(json_get_blobs_to_tcache(&mut json, &mut Vec::new()).is_err());
    }

    // ---------------------------------------------------------------------------
    // json_get_payload_bodies_to_tcache
    // ---------------------------------------------------------------------------

    #[test]
    fn json_get_payload_bodies_with_items() {
        let mut json = br#"{"result":[{"transactions":["0xdeadbeef","0xcafe"],"withdrawals":[{"index":"0x1","validatorIndex":"0x2","address":"0x1234567890123456789012345678901234567890","amount":"0xa"}]},null]}"#.to_vec();
        let mut out = Vec::new();
        json_get_payload_bodies_to_tcache(&mut json, &mut out).unwrap();

        let mut pos = 0usize;
        assert_eq!(u32::from_le_bytes(out[pos..pos + 4].try_into().unwrap()), 2);
        pos += 4;

        // item 0
        assert_eq!(out[pos], 1);
        pos += 1;
        assert_eq!(u32::from_le_bytes(out[pos..pos + 4].try_into().unwrap()), 2); // tx_count
        pos += 4;
        let tx0_len = u32::from_le_bytes(out[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        assert_eq!(tx0_len, 4);
        assert_eq!(&out[pos..pos + 4], &[0xde, 0xad, 0xbe, 0xef]);
        pos += tx0_len;
        let tx1_len = u32::from_le_bytes(out[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        assert_eq!(tx1_len, 2);
        assert_eq!(&out[pos..pos + 2], &[0xca, 0xfe]);
        pos += tx1_len;
        assert_eq!(u32::from_le_bytes(out[pos..pos + 4].try_into().unwrap()), 1); // wd_count
        pos += 4;
        assert_eq!(u64::from_le_bytes(out[pos..pos + 8].try_into().unwrap()), 1); // index
        pos += 8;
        assert_eq!(u64::from_le_bytes(out[pos..pos + 8].try_into().unwrap()), 2); // validator_index
        pos += 8;
        assert_eq!(
            &out[pos..pos + 20],
            hex::decode("1234567890123456789012345678901234567890").unwrap().as_slice()
        );
        pos += 20;
        assert_eq!(u64::from_le_bytes(out[pos..pos + 8].try_into().unwrap()), 10); // amount
        pos += 8;

        // item 1: null
        assert_eq!(out[pos], 0);
    }

    #[test]
    fn json_get_payload_bodies_missing_result() {
        let mut json = br#"{"jsonrpc":"2.0","id":1}"#.to_vec();
        assert!(json_get_payload_bodies_to_tcache(&mut json, &mut Vec::new()).is_err());
    }
}
