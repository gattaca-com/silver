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

// --- getPayloadV4 response ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetPayloadV4Response {
    pub execution_payload: ExecutionPayload,
    pub blobs_bundle: BlobsBundle,
    pub should_override_builder: bool,
    #[serde(default, with = "wire::data_list")]
    pub execution_requests: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BlobsBundle {
    #[serde(with = "wire::data_list")]
    pub commitments: Vec<Vec<u8>>,
    #[serde(with = "wire::data_list")]
    pub proofs: Vec<Vec<u8>>,
    #[serde(with = "wire::data_list")]
    pub blobs: Vec<Vec<u8>>,
}

// --- getBlobsV2 response ---

#[derive(Debug, Deserialize)]
pub(crate) struct BlobAndProofV1 {
    #[serde(with = "wire::data")]
    pub blob: Vec<u8>,
    #[serde(with = "wire::data")]
    pub proof: Vec<u8>,
}

// --- getPayloadBodiesByHashV1 / ByRangeV1 response ---

#[derive(Debug, Deserialize)]
pub(crate) struct ExecutionPayloadBodyV1 {
    #[serde(with = "wire::data_list")]
    pub transactions: Vec<Vec<u8>>,
    pub withdrawals: Option<Vec<Withdrawal>>,
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

    pub fn to_ssz(&self) -> Vec<u8> {
        let tx_ssz = encode_transactions(&self.transactions);
        let w_ssz = encode_withdrawals(&self.withdrawals);

        let extra_data_off = PAYLOAD_FIXED_LEN as u32;
        let transactions_off = extra_data_off + self.extra_data.len() as u32;
        let withdrawals_off = transactions_off + tx_ssz.len() as u32;

        let mut buf = Vec::with_capacity(
            PAYLOAD_FIXED_LEN + self.extra_data.len() + tx_ssz.len() + w_ssz.len(),
        );

        buf.extend_from_slice(&self.parent_hash);
        buf.extend_from_slice(&self.fee_recipient);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.receipts_root);
        buf.extend_from_slice(&self.logs_bloom);
        buf.extend_from_slice(&self.prev_randao);
        buf.extend_from_slice(&self.block_number.to_le_bytes());
        buf.extend_from_slice(&self.gas_limit.to_le_bytes());
        buf.extend_from_slice(&self.gas_used.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&extra_data_off.to_le_bytes());
        buf.extend_from_slice(&self.base_fee_per_gas);
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&transactions_off.to_le_bytes());
        buf.extend_from_slice(&withdrawals_off.to_le_bytes());
        buf.extend_from_slice(&self.blob_gas_used.to_le_bytes());
        buf.extend_from_slice(&self.excess_blob_gas.to_le_bytes());

        buf.extend_from_slice(&self.extra_data);
        buf.extend_from_slice(&tx_ssz);
        buf.extend_from_slice(&w_ssz);
        buf
    }
}

/// Encodes transactions as SSZ `List<ByteList>`.  The first `n * 4` bytes are
/// u32 LE offsets, each the absolute byte position of that transaction within
/// this buffer.  Transaction bytes follow immediately after the offset header.
/// The count is recoverable on decode as `first_offset / 4`.
fn encode_transactions(txs: &[Vec<u8>]) -> Vec<u8> {
    if txs.is_empty() {
        return vec![];
    }
    let header_bytes = txs.len() * 4;
    let mut offset = header_bytes as u32;
    let mut buf = Vec::with_capacity(header_bytes + txs.iter().map(|t| t.len()).sum::<usize>());
    for tx in txs {
        buf.extend_from_slice(&offset.to_le_bytes());
        offset += tx.len() as u32;
    }
    for tx in txs {
        buf.extend_from_slice(tx);
    }
    buf
}

fn decode_transactions(data: &[u8]) -> Result<Vec<Vec<u8>>, crate::EngineError> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    if data.len() < 4 {
        return Err(crate::EngineError::Ssz("transactions header too short".into()));
    }
    let first_off = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if first_off.is_multiple_of(4) || first_off < 4 {
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

/// Each `Withdrawal` is 44 bytes: index u64, validator_index u64, address
/// [u8;20], amount u64.
fn encode_withdrawals(ws: &[Withdrawal]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ws.len() * 44);
    for w in ws {
        buf.extend_from_slice(&w.index.to_le_bytes());
        buf.extend_from_slice(&w.validator_index.to_le_bytes());
        buf.extend_from_slice(&w.address);
        buf.extend_from_slice(&w.amount.to_le_bytes());
    }
    buf
}

fn decode_withdrawals(data: &[u8]) -> Result<Vec<Withdrawal>, crate::EngineError> {
    if data.len().is_multiple_of(44) {
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
// TCache data framing for engine_getPayloadV4
//
// Layout:
//   [u32 LE payload_ssz_len]
//   [payload_ssz_len bytes: ExecutionPayload SSZ]
//   [u8 blob_count]
//   for each blob:
//     [48 bytes commitment]
//     [48 bytes proof]
//     [u32 LE blob_len][blob_len bytes blob]
//   [u8 should_override_builder]
//   [u8 exec_req_count]
//   for each exec request: [u32 LE len][len bytes]
// ---------------------------------------------------------------------------

pub fn encode_get_payload_data(
    payload_ssz: &[u8],
    commitments: &[Vec<u8>],
    proofs: &[Vec<u8>],
    blobs: &[Vec<u8>],
    should_override_builder: bool,
    exec_requests: &[Vec<u8>],
) -> Vec<u8> {
    let blob_count = commitments.len().min(proofs.len()).min(blobs.len()).min(255) as u8;
    let exec_count = exec_requests.len().min(255) as u8;
    let blob_data_size: usize = blobs.iter().take(blob_count as usize).map(|b| 4 + b.len()).sum();
    let total = 4 +
        payload_ssz.len() +
        1 +
        blob_count as usize * (48 + 48) +
        blob_data_size +
        2 +
        exec_requests.iter().take(exec_count as usize).map(|r| 4 + r.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(payload_ssz.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload_ssz);
    buf.push(blob_count);
    for i in 0..blob_count as usize {
        let mut c48 = [0u8; 48];
        let c = &commitments[i];
        c48[..c.len().min(48)].copy_from_slice(&c[..c.len().min(48)]);
        buf.extend_from_slice(&c48);
        let mut p48 = [0u8; 48];
        let p = &proofs[i];
        p48[..p.len().min(48)].copy_from_slice(&p[..p.len().min(48)]);
        buf.extend_from_slice(&p48);
        buf.extend_from_slice(&(blobs[i].len() as u32).to_le_bytes());
        buf.extend_from_slice(&blobs[i]);
    }
    buf.push(should_override_builder as u8);
    buf.push(exec_count);
    for r in exec_requests.iter().take(exec_count as usize) {
        buf.extend_from_slice(&(r.len() as u32).to_le_bytes());
        buf.extend_from_slice(r);
    }
    buf
}

// ---------------------------------------------------------------------------
// TCache data framing for engine_getBlobsV2
//
// Layout:
//   [u32 LE count]
//   for each item:
//     [u8 present]  (0 = null)
//     if present:
//       [48 bytes proof]
//       [u32 LE blob_len][blob_len bytes blob]
// ---------------------------------------------------------------------------

pub fn encode_get_blobs_data(items: &[Option<BlobAndProofV1>]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        match item {
            None => buf.push(0),
            Some(bap) => {
                buf.push(1);
                let mut p48 = [0u8; 48];
                let p = &bap.proof;
                p48[..p.len().min(48)].copy_from_slice(&p[..p.len().min(48)]);
                buf.extend_from_slice(&p48);
                buf.extend_from_slice(&(bap.blob.len() as u32).to_le_bytes());
                buf.extend_from_slice(&bap.blob);
            }
        }
    }
    buf
}

// ---------------------------------------------------------------------------
// TCache data framing for engine_getPayloadBodiesByHashV1 / ByRangeV1
//
// Layout:
//   [u32 LE count]
//   for each body:
//     [u8 present]  (0 = null)
//     if present:
//       [u32 LE tx_count]
//       for each tx: [u32 LE len][bytes]
//       [u32 LE withdrawal_count]
//       for each withdrawal: 44 bytes (index u64 + validator_index u64 +
//                                      address [u8;20] + amount u64)
// ---------------------------------------------------------------------------

pub fn encode_payload_bodies_data(bodies: &[Option<ExecutionPayloadBodyV1>]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(bodies.len() as u32).to_le_bytes());
    for body in bodies {
        match body {
            None => buf.push(0),
            Some(b) => {
                buf.push(1);
                buf.extend_from_slice(&(b.transactions.len() as u32).to_le_bytes());
                for tx in &b.transactions {
                    buf.extend_from_slice(&(tx.len() as u32).to_le_bytes());
                    buf.extend_from_slice(tx);
                }
                let withdrawals = b.withdrawals.as_deref().unwrap_or(&[]);
                buf.extend_from_slice(&(withdrawals.len() as u32).to_le_bytes());
                for w in withdrawals {
                    buf.extend_from_slice(&w.index.to_le_bytes());
                    buf.extend_from_slice(&w.validator_index.to_le_bytes());
                    buf.extend_from_slice(&w.address);
                    buf.extend_from_slice(&w.amount.to_le_bytes());
                }
            }
        }
    }
    buf
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ssz_round_trip_with_all_fields() {
        let original = sample_payload();
        let decoded = ExecutionPayload::from_ssz(&original.to_ssz()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn ssz_round_trip_empty_variable_fields() {
        let mut p = sample_payload();
        p.extra_data = vec![];
        p.transactions = vec![];
        p.withdrawals = vec![];
        assert_eq!(p, ExecutionPayload::from_ssz(&p.to_ssz()).unwrap());
    }

    #[test]
    fn ssz_round_trip_large_extra_data() {
        let mut p = sample_payload();
        p.extra_data = vec![0xffu8; 32];
        assert_eq!(p, ExecutionPayload::from_ssz(&p.to_ssz()).unwrap());
    }

    #[test]
    fn ssz_round_trip_many_transactions() {
        let mut p = sample_payload();
        p.transactions = (0u8..=20).map(|i| vec![i; i as usize + 1]).collect();
        assert_eq!(p, ExecutionPayload::from_ssz(&p.to_ssz()).unwrap());
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
        let p = sample_payload();
        let ssz = p.to_ssz();

        let extra_off = u32::from_le_bytes(ssz[436..440].try_into().unwrap()) as usize;
        let tx_off = u32::from_le_bytes(ssz[504..508].try_into().unwrap()) as usize;
        let wd_off = u32::from_le_bytes(ssz[508..512].try_into().unwrap()) as usize;

        assert_eq!(extra_off, 528, "extra_data offset must point past fixed section");
        assert_eq!(tx_off, 528 + p.extra_data.len());
        // withdrawals follow the SSZ transaction list
        assert!(wd_off > tx_off);
        assert_eq!(wd_off, ssz.len() - p.withdrawals.len() * 44);
    }

    // -----------------------------------------------------------------------
    // Transactions SSZ helpers
    // -----------------------------------------------------------------------

    #[test]
    fn transactions_empty_round_trip() {
        let encoded = encode_transactions(&[]);
        assert!(encoded.is_empty());
        let decoded = decode_transactions(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn transactions_single_round_trip() {
        let txs = vec![vec![0xde, 0xad, 0xbe, 0xef]];
        assert_eq!(txs, decode_transactions(&encode_transactions(&txs)).unwrap());
    }

    #[test]
    fn transactions_multi_varying_lengths_round_trip() {
        let txs: Vec<Vec<u8>> = (1u8..=5).map(|i| vec![i; i as usize * 3]).collect();
        assert_eq!(txs, decode_transactions(&encode_transactions(&txs)).unwrap());
    }

    // -----------------------------------------------------------------------
    // Withdrawals SSZ helpers
    // -----------------------------------------------------------------------

    #[test]
    fn withdrawals_round_trip() {
        let ws = vec![
            Withdrawal { index: 10, validator_index: 20, address: [0x01; 20], amount: 500 },
            Withdrawal { index: 11, validator_index: 21, address: [0x02; 20], amount: 600 },
        ];
        let decoded = decode_withdrawals(&encode_withdrawals(&ws)).unwrap();
        assert_eq!(ws, decoded);
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
        let p = sample_payload();
        let ssz = p.to_ssz();
        let enc = encode_new_payload_data(&ssz, &[]);
        let (decoded_p, decoded_reqs) = decode_new_payload_data(&enc).unwrap();
        assert_eq!(p, decoded_p);
        assert!(decoded_reqs.is_empty());
    }

    #[test]
    fn new_payload_framing_round_trip_with_exec_requests() {
        let p = sample_payload();
        let ssz = p.to_ssz();
        let reqs = vec![vec![1u8, 2, 3], vec![0xde, 0xad]];
        let enc = encode_new_payload_data(&ssz, &reqs);
        let (decoded_p, decoded_reqs) = decode_new_payload_data(&enc).unwrap();
        assert_eq!(p, decoded_p);
        assert_eq!(reqs, decoded_reqs);
    }

    #[test]
    fn new_payload_framing_truncated_returns_error() {
        let enc = encode_new_payload_data(&sample_payload().to_ssz(), &[]);
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
        let json: ForkchoiceState =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
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
        let json = serde_json::to_value(&state).unwrap();
        let hex = json["headBlockHash"].as_str().unwrap();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 64);
        assert_eq!(&hex[2..4], "ab");
    }

    #[test]
    fn wire_quantity_round_trip() {
        // Withdrawal uses quantity for all numeric fields
        let w = Withdrawal { index: 0, validator_index: 0xdeadbeef, address: [0; 20], amount: 0 };
        let json: Withdrawal = serde_json::from_str(&serde_json::to_string(&w).unwrap()).unwrap();
        assert_eq!(w.validator_index, json.validator_index);
    }

    #[test]
    fn wire_u256_le_zero_round_trip() {
        let mut p = sample_payload();
        p.base_fee_per_gas = [0u8; 32];
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["baseFeePerGas"].as_str().unwrap(), "0x0");
        let decoded: ExecutionPayload = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.base_fee_per_gas, [0u8; 32]);
    }

    #[test]
    fn wire_u256_le_nonzero_round_trip() {
        let mut p = sample_payload();
        p.base_fee_per_gas = [0u8; 32];
        p.base_fee_per_gas[0] = 1; // LE: value = 1
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["baseFeePerGas"].as_str().unwrap(), "0x1");
        let decoded: ExecutionPayload = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.base_fee_per_gas, p.base_fee_per_gas);
    }

    #[test]
    fn wire_opt_b256_none_round_trip() {
        let v: PayloadStatus = serde_json::from_str(
            r#"{"status":"VALID","latestValidHash":null,"validationError":null}"#,
        )
        .unwrap();
        assert_eq!(v.latest_valid_hash, None);
        let json = serde_json::to_string(&v).unwrap();
        let v2: PayloadStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(v2.latest_valid_hash, None);
    }

    #[test]
    fn wire_opt_payload_id_round_trip() {
        let fcu_json = r#"{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":"0x0102030405060708"}"#;
        let fcu: ForkchoiceUpdatedResult = serde_json::from_str(fcu_json).unwrap();
        assert_eq!(fcu.payload_id, Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));
        let roundtrip: ForkchoiceUpdatedResult =
            serde_json::from_str(&serde_json::to_string(&fcu).unwrap()).unwrap();
        assert_eq!(fcu.payload_id, roundtrip.payload_id);
    }
}
