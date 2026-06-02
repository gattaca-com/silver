use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};

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

    fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| e.to_string())
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

    // [u8; 32] LE ↔ Ethereum QUANTITY (uint256, no leading zeros)
    // Used for base_fee_per_gas, which beacon_state stores as 32-byte LE.
    pub mod u256_le {
        use super::*;
        pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            let mut be = *v;
            be.reverse();
            let h = hex::encode(be);
            let trimmed = h.trim_start_matches('0');
            s.serialize_str(&format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed }))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let s = String::deserialize(d)?;
            let s = s.strip_prefix("0x").unwrap_or(&s);
            let padded = format!("{:0>64}", s);
            let mut out = [0u8; 32];
            hex::decode_to_slice(&padded, &mut out).map_err(serde::de::Error::custom)?;
            out.reverse();
            Ok(out)
        }
    }

    // [u8; 256] ↔ "0x<512 hex>" (logs_bloom)
    pub mod bytes256 {
        use super::*;
        pub fn serialize<S: Serializer>(v: &[u8; 256], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&format!("0x{}", hex::encode(v)))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 256], D::Error> {
            decode_hex_into::<256>(&String::deserialize(d)?).map_err(serde::de::Error::custom)
        }
    }

    // Vec<u8> ↔ "0x<hex>" (extra_data, blobs, proofs, ...)
    pub mod data {
        use super::*;
        pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&format!("0x{}", hex::encode(v)))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            decode_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
        }
    }

    // Vec<Vec<u8>> ↔ array of "0x<hex>" (transactions, execution requests)
    pub mod data_list {
        use super::*;
        pub fn serialize<S: Serializer>(v: &Vec<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for item in v {
                seq.serialize_element(&format!("0x{}", hex::encode(item)))?;
            }
            seq.end()
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
            Vec::<String>::deserialize(d)?
                .iter()
                .map(|s| decode_hex(s).map_err(serde::de::Error::custom))
                .collect()
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

// --- newPayload ---

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayload {
    #[serde(with = "wire::b256")]
    pub parent_hash: B256,
    #[serde(with = "wire::addr")]
    pub fee_recipient: ExecutionAddress,
    #[serde(with = "wire::b256")]
    pub state_root: B256,
    #[serde(with = "wire::b256")]
    pub receipts_root: B256,
    #[serde(with = "wire::bytes256")]
    pub logs_bloom: [u8; 256],
    #[serde(with = "wire::b256")]
    pub prev_randao: B256,
    #[serde(with = "wire::quantity")]
    pub block_number: u64,
    #[serde(with = "wire::quantity")]
    pub gas_limit: u64,
    #[serde(with = "wire::quantity")]
    pub gas_used: u64,
    #[serde(with = "wire::quantity")]
    pub timestamp: u64,
    #[serde(with = "wire::data")]
    pub extra_data: Vec<u8>,
    #[serde(with = "wire::u256_le")]
    pub base_fee_per_gas: [u8; 32],
    #[serde(with = "wire::b256")]
    pub block_hash: B256,
    #[serde(with = "wire::data_list")]
    pub transactions: Vec<Vec<u8>>,
    pub withdrawals: Vec<Withdrawal>,
    #[serde(with = "wire::quantity")]
    pub blob_gas_used: u64,
    #[serde(with = "wire::quantity")]
    pub excess_blob_gas: u64,
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

// ---------------------------------------------------------------------------
// SSZ encode / decode for ExecutionPayload
//
// Deneb/Pectra ExecutionPayload SSZ layout (field order per spec):
//
//   Fixed part (528 bytes):
//     parent_hash        [u8;32]   0..32
//     fee_recipient      [u8;20]   32..52
//     state_root         [u8;32]   52..84
//     receipts_root      [u8;32]   84..116
//     logs_bloom         [u8;256]  116..372
//     prev_randao        [u8;32]   372..404
//     block_number       u64 LE    404..412
//     gas_limit          u64 LE    412..420
//     gas_used           u64 LE    420..428
//     timestamp          u64 LE    428..436
//     extra_data offset  u32 LE    436..440   (variable)
//     base_fee_per_gas   [u8;32]   440..472   (uint256 LE)
//     block_hash         [u8;32]   472..504
//     transactions off   u32 LE    504..508   (variable)
//     withdrawals off    u32 LE    508..512   (variable)
//     blob_gas_used      u64 LE    512..520
//     excess_blob_gas    u64 LE    520..528
//
//   Variable part (appended in declaration order):
//     extra_data   bytes
//     transactions SSZ List<ByteList>  (u32 offsets header + raw tx bytes)
//     withdrawals  44-byte fixed chunks (index u64, validator_index u64,
//                                        address [u8;20], amount u64)
// ---------------------------------------------------------------------------

const PAYLOAD_FIXED_LEN: usize = 528;

impl ExecutionPayload {
    pub fn from_ssz(ssz: &[u8]) -> Result<Self, crate::EngineError> {
        if ssz.len() < PAYLOAD_FIXED_LEN {
            return Err(crate::EngineError::Ssz(format!(
                "payload too short: {} < {PAYLOAD_FIXED_LEN}",
                ssz.len()
            )));
        }
        let u32_at =
            |off: usize| u32::from_le_bytes(ssz[off..off + 4].try_into().unwrap()) as usize;
        let u64_at = |off: usize| u64::from_le_bytes(ssz[off..off + 8].try_into().unwrap());

        let extra_data_off = u32_at(436);
        let transactions_off = u32_at(504);
        let withdrawals_off = u32_at(508);

        if extra_data_off < PAYLOAD_FIXED_LEN ||
            transactions_off < extra_data_off ||
            withdrawals_off < transactions_off ||
            ssz.len() < withdrawals_off
        {
            return Err(crate::EngineError::Ssz("invalid variable offsets".into()));
        }

        let extra_data = ssz[extra_data_off..transactions_off].to_vec();
        let transactions = decode_transactions(&ssz[transactions_off..withdrawals_off])?;
        let withdrawals = decode_withdrawals(&ssz[withdrawals_off..])?;

        Ok(ExecutionPayload {
            parent_hash: ssz[0..32].try_into().unwrap(),
            fee_recipient: ssz[32..52].try_into().unwrap(),
            state_root: ssz[52..84].try_into().unwrap(),
            receipts_root: ssz[84..116].try_into().unwrap(),
            logs_bloom: ssz[116..372].try_into().unwrap(),
            prev_randao: ssz[372..404].try_into().unwrap(),
            block_number: u64_at(404),
            gas_limit: u64_at(412),
            gas_used: u64_at(420),
            timestamp: u64_at(428),
            extra_data,
            base_fee_per_gas: ssz[440..472].try_into().unwrap(),
            block_hash: ssz[472..504].try_into().unwrap(),
            transactions,
            withdrawals,
            blob_gas_used: u64_at(512),
            excess_blob_gas: u64_at(520),
        })
    }
}

fn decode_transactions(data: &[u8]) -> Result<Vec<Vec<u8>>, crate::EngineError> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    if data.len() < 4 {
        return Err(crate::EngineError::Ssz("transactions header too short".into()));
    }
    let first_off = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if !first_off.is_multiple_of(4) || first_off < 4 {
        return Err(crate::EngineError::Ssz("invalid transaction list offset".into()));
    }
    let n = first_off / 4;
    if data.len() < n * 4 {
        return Err(crate::EngineError::Ssz("transaction offsets exceed data".into()));
    }
    let offsets: Vec<usize> = (0..n)
        .map(|i| u32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().unwrap()) as usize)
        .collect();
    offsets
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let end = if i + 1 < n { offsets[i + 1] } else { data.len() };
            if start > data.len() || end > data.len() || start > end {
                return Err(crate::EngineError::Ssz("transaction slice out of bounds".into()));
            }
            Ok(data[start..end].to_vec())
        })
        .collect()
}

fn decode_withdrawals(data: &[u8]) -> Result<Vec<Withdrawal>, crate::EngineError> {
    if !data.len().is_multiple_of(44) {
        return Err(crate::EngineError::Ssz(format!(
            "withdrawals length {} is not a multiple of 44",
            data.len()
        )));
    }
    Ok(data
        .chunks(44)
        .map(|c| Withdrawal {
            index: u64::from_le_bytes(c[0..8].try_into().unwrap()),
            validator_index: u64::from_le_bytes(c[8..16].try_into().unwrap()),
            address: c[16..36].try_into().unwrap(),
            amount: u64::from_le_bytes(c[36..44].try_into().unwrap()),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// TCache data framing for engine_newPayloadV4
//
// Layout of the single TCache entry written by the producer (BridgeTile or
// BeaconStateTile) and read by EngineTile:
//
//   [u32 LE payload_ssz_len]
//   [payload_ssz_len bytes: ExecutionPayload SSZ]
//   [u8 exec_req_count]
//   [for each exec request: u32 LE len, then len bytes]
// ---------------------------------------------------------------------------

pub fn encode_new_payload_data(payload_ssz: &[u8], exec_requests: &[Vec<u8>]) -> Vec<u8> {
    let count = exec_requests.len().min(255) as u8;
    let total =
        4 + payload_ssz.len() + 1 + exec_requests.iter().map(|r| 4 + r.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(payload_ssz.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload_ssz);
    buf.push(count);
    for r in exec_requests.iter().take(count as usize) {
        buf.extend_from_slice(&(r.len() as u32).to_le_bytes());
        buf.extend_from_slice(r);
    }
    buf
}

pub(crate) fn decode_new_payload_data(
    data: &[u8],
) -> Result<(ExecutionPayload, Vec<Vec<u8>>), crate::EngineError> {
    if data.len() < 5 {
        return Err(crate::EngineError::Ssz("new-payload data too short".into()));
    }
    let payload_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + payload_len + 1 {
        return Err(crate::EngineError::Ssz("new-payload data truncated".into()));
    }
    let payload = ExecutionPayload::from_ssz(&data[4..4 + payload_len])?;
    let mut pos = 4 + payload_len;
    let count = data[pos] as usize;
    pos += 1;
    let mut exec_requests = Vec::with_capacity(count);
    for _ in 0..count {
        if data.len() < pos + 4 {
            return Err(crate::EngineError::Ssz("exec-request length truncated".into()));
        }
        let req_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if data.len() < pos + req_len {
            return Err(crate::EngineError::Ssz("exec-request body truncated".into()));
        }
        exec_requests.push(data[pos..pos + req_len].to_vec());
        pos += req_len;
    }
    Ok((payload, exec_requests))
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
pub fn json_get_payload_to_tcache(
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

pub fn json_get_blobs_to_tcache(
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

pub fn json_get_payload_bodies_to_tcache(
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
    use simd_json::{owned::to_value, prelude::ValueAsScalar, serde::from_owned_value};

    use super::*;

    const SAMPLE_PAYLOAD_SSZ: &[u8] = include_bytes!("../testdata/sample_payload.ssz");
    const EMPTY_VAR_PAYLOAD_SSZ: &[u8] = include_bytes!("../testdata/empty_var_payload.ssz");
    const LARGE_EXTRA_PAYLOAD_SSZ: &[u8] = include_bytes!("../testdata/large_extra_payload.ssz");
    const MANY_TX_PAYLOAD_SSZ: &[u8] = include_bytes!("../testdata/many_tx_payload.ssz");
    const GET_PAYLOAD_TCACHE: &[u8] = include_bytes!("../testdata/get_payload_tcache.bin");

    fn sample_payload() -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: [0x11; 32],
            fee_recipient: [0x22; 20],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: [0x55; 256],
            prev_randao: [0x66; 32],
            block_number: 12_345,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: b"extra".to_vec(),
            base_fee_per_gas: [0x77; 32],
            block_hash: [0x88; 32],
            transactions: vec![vec![1, 2, 3], vec![4, 5, 6, 7, 8]],
            withdrawals: vec![
                Withdrawal { index: 1, validator_index: 42, address: [0x99; 20], amount: 1000 },
                Withdrawal { index: 2, validator_index: 43, address: [0xaa; 20], amount: 2000 },
            ],
            blob_gas_used: 131_072,
            excess_blob_gas: 262_144,
        }
    }

    #[test]
    fn ssz_decode_sample_payload() {
        assert_eq!(ExecutionPayload::from_ssz(SAMPLE_PAYLOAD_SSZ).unwrap(), sample_payload());
    }

    #[test]
    fn ssz_decode_empty_variable_fields() {
        let mut p = sample_payload();
        p.extra_data = vec![];
        p.transactions = vec![];
        p.withdrawals = vec![];
        assert_eq!(ExecutionPayload::from_ssz(EMPTY_VAR_PAYLOAD_SSZ).unwrap(), p);
    }

    #[test]
    fn ssz_decode_large_extra_data() {
        let mut p = sample_payload();
        p.extra_data = vec![0xffu8; 32];
        assert_eq!(ExecutionPayload::from_ssz(LARGE_EXTRA_PAYLOAD_SSZ).unwrap(), p);
    }

    #[test]
    fn ssz_decode_many_transactions() {
        let mut p = sample_payload();
        p.transactions = (0u8..=20).map(|i| vec![i; i as usize + 1]).collect();
        assert_eq!(ExecutionPayload::from_ssz(MANY_TX_PAYLOAD_SSZ).unwrap(), p);
    }

    #[test]
    fn ssz_too_short_returns_error() {
        assert!(ExecutionPayload::from_ssz(&[0u8; 100]).is_err());
    }

    #[test]
    fn ssz_exact_fixed_length_no_variable_data() {
        // A 528-byte all-zero buffer has zero offsets, which fail the
        // `extra_data_off >= PAYLOAD_FIXED_LEN` guard.
        assert!(ExecutionPayload::from_ssz(&[0u8; 528]).is_err());
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
    // Transactions SSZ helpers
    // -----------------------------------------------------------------------

    const TX_SINGLE: &[u8] = include_bytes!("../testdata/tx_single.bin");
    const TX_MULTI: &[u8] = include_bytes!("../testdata/tx_multi.bin");
    const WITHDRAWALS: &[u8] = include_bytes!("../testdata/withdrawals.bin");

    #[test]
    fn transactions_empty_decodes_to_empty() {
        assert!(decode_transactions(&[]).unwrap().is_empty());
    }

    #[test]
    fn transactions_single_decode() {
        let txs = vec![vec![0xde, 0xad, 0xbe, 0xef]];
        assert_eq!(txs, decode_transactions(TX_SINGLE).unwrap());
    }

    #[test]
    fn transactions_multi_varying_lengths_decode() {
        let txs: Vec<Vec<u8>> = (1u8..=5).map(|i| vec![i; i as usize * 3]).collect();
        assert_eq!(txs, decode_transactions(TX_MULTI).unwrap());
    }

    // -----------------------------------------------------------------------
    // Withdrawals SSZ helpers
    // -----------------------------------------------------------------------

    #[test]
    fn withdrawals_decode() {
        let ws = vec![
            Withdrawal { index: 10, validator_index: 20, address: [0x01; 20], amount: 500 },
            Withdrawal { index: 11, validator_index: 21, address: [0x02; 20], amount: 600 },
        ];
        assert_eq!(ws, decode_withdrawals(WITHDRAWALS).unwrap());
    }

    #[test]
    fn withdrawals_non_multiple_of_44_returns_error() {
        assert!(decode_withdrawals(&[0u8; 45]).is_err());
    }

    // -----------------------------------------------------------------------
    // TCache framing: encode_new_payload_data / decode_new_payload_data
    // -----------------------------------------------------------------------

    #[test]
    fn new_payload_framing_round_trip_no_exec_requests() {
        let enc = encode_new_payload_data(SAMPLE_PAYLOAD_SSZ, &[]);
        let (decoded_p, decoded_reqs) = decode_new_payload_data(&enc).unwrap();
        assert_eq!(sample_payload(), decoded_p);
        assert!(decoded_reqs.is_empty());
    }

    #[test]
    fn new_payload_framing_round_trip_with_exec_requests() {
        let reqs = vec![vec![1u8, 2, 3], vec![0xde, 0xad]];
        let enc = encode_new_payload_data(SAMPLE_PAYLOAD_SSZ, &reqs);
        let (decoded_p, decoded_reqs) = decode_new_payload_data(&enc).unwrap();
        assert_eq!(sample_payload(), decoded_p);
        assert_eq!(reqs, decoded_reqs);
    }

    #[test]
    fn new_payload_framing_truncated_returns_error() {
        let enc = encode_new_payload_data(SAMPLE_PAYLOAD_SSZ, &[]);
        assert!(decode_new_payload_data(&enc[..4]).is_err());
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
    fn wire_u256_le_zero_round_trip() {
        let mut p = sample_payload();
        p.base_fee_per_gas = [0u8; 32];
        let json = to_value(&mut simd_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(json["baseFeePerGas"].as_str().unwrap(), "0x0");
        let decoded: ExecutionPayload = from_owned_value(json).unwrap();
        assert_eq!(decoded.base_fee_per_gas, [0u8; 32]);
    }

    #[test]
    fn wire_u256_le_nonzero_round_trip() {
        let mut p = sample_payload();
        p.base_fee_per_gas = [0u8; 32];
        p.base_fee_per_gas[0] = 1; // LE: value = 1
        let json = to_value(&mut simd_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(json["baseFeePerGas"].as_str().unwrap(), "0x1");
        let decoded: ExecutionPayload = from_owned_value(json).unwrap();
        assert_eq!(decoded.base_fee_per_gas, p.base_fee_per_gas);
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
    fn json_get_payload_to_tcache_output() {
        let payload = sample_payload();
        let commitments_hex: Vec<String> = vec![[0xc0u8; 48], [0xc1u8; 48]]
            .iter()
            .map(|c| format!("0x{}", hex::encode(c)))
            .collect();
        let proofs_hex: Vec<String> = vec![[0xd0u8; 48], [0xd1u8; 48]]
            .iter()
            .map(|p| format!("0x{}", hex::encode(p)))
            .collect();
        let blobs_hex: Vec<String> = vec![vec![0xb0u8; 128], vec![0xb1u8; 64]]
            .iter()
            .map(|b| format!("0x{}", hex::encode(b)))
            .collect();
        let exec_hex: Vec<String> = vec![vec![0x01u8, 0x02], vec![0x03u8]]
            .iter()
            .map(|r| format!("0x{}", hex::encode(r)))
            .collect();
        let envelope = simd_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "executionPayload": payload,
                "blobsBundle": {
                    "commitments": commitments_hex,
                    "proofs": proofs_hex,
                    "blobs": blobs_hex,
                },
                "shouldOverrideBuilder": false,
                "executionRequests": exec_hex,
            }
        });
        let mut raw = simd_json::to_vec(&envelope).unwrap();
        let mut out = Vec::new();
        json_get_payload_to_tcache(&mut raw, &mut out).expect("json_get_payload_to_tcache failed");
        assert_eq!(out, GET_PAYLOAD_TCACHE);
    }
}
