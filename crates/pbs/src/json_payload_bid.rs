use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, Visitor},
};
use silver_common::json_fields::uint64;
use silver_httpcore::ClientResponse;
use silver_ssz::ssz_view::EXECUTION_PAYLOAD_BID_MIN;

use crate::json_bid::{Bytes, Envelope, List};

/// The `ExecutionPayloadBid` fields before `blob_kzg_commitments`'s data,
/// at their SSZ offsets.
const FIXED_FIELDS: [(&str, usize, Field); 11] = [
    ("parent_block_hash", 0, Field::Root),
    ("parent_block_root", 32, Field::Root),
    ("block_hash", 64, Field::Root),
    ("prev_randao", 96, Field::Root),
    ("fee_recipient", 128, Field::Address),
    ("gas_limit", 148, Field::Uint64),
    ("builder_index", 156, Field::Uint64),
    ("slot", 164, Field::Uint64),
    ("value", 172, Field::Uint64),
    ("execution_payment", 180, Field::Uint64),
    ("execution_requests_root", 192, Field::Root),
];
const COMMITMENTS_OFFSET_AT: usize = 188;

#[derive(Clone, Copy)]
enum Field {
    Root,
    Address,
    Uint64,
}

/// The `message` offset, then the signature.
const MESSAGE_AT: usize = 4 + 96;

/// Re-encodes a JSON `SignedExecutionPayloadBid` (Gloas) as SSZ, for a
/// builder that answers JSON whatever `Accept` says. The buffer is reused
/// across bids.
pub(crate) struct JsonPayloadBid {
    ssz: Vec<u8>,
}

impl JsonPayloadBid {
    pub(crate) fn new() -> Self {
        Self { ssz: Vec::new() }
    }

    /// The response's bid as SSZ, empty when a JSON body does not decode.
    pub(crate) fn ssz_bid<'s>(&'s mut self, response: ClientResponse<'s>) -> &'s [u8] {
        let is_json = response
            .header("Content-Type")
            .is_some_and(|value| value.starts_with(b"application/json"));
        if is_json { self.reencode(response.body).unwrap_or_default() } else { response.body }
    }

    pub(crate) fn reencode(&mut self, json: &[u8]) -> Option<&[u8]> {
        let ssz = &mut self.ssz;
        ssz.clear();
        ssz.resize(MESSAGE_AT + EXECUTION_PAYLOAD_BID_MIN, 0);
        let mut deserializer = serde_json::Deserializer::from_slice(json);
        if let Err(error) = Envelope(SignedBid(ssz)).deserialize(&mut deserializer) {
            silver_log::warn!(%error, "builder bid is not a Gloas SignedExecutionPayloadBid");
            return None;
        }
        ssz[..4].copy_from_slice(&(MESSAGE_AT as u32).to_le_bytes());
        let commitments_offset = MESSAGE_AT + COMMITMENTS_OFFSET_AT;
        ssz[commitments_offset..commitments_offset + 4]
            .copy_from_slice(&(EXECUTION_PAYLOAD_BID_MIN as u32).to_le_bytes());
        Some(ssz)
    }
}

struct SignedBid<'s>(&'s mut Vec<u8>);

impl<'de> DeserializeSeed<'de> for SignedBid<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for SignedBid<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a SignedExecutionPayloadBid")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let (mut has_message, mut has_signature) = (false, false);
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "message" => {
                    map.next_value_seed(Message(&mut *self.0))?;
                    has_message = true;
                }
                "signature" => {
                    let signature = map.next_value::<Bytes<96>>()?.0;
                    self.0[4..MESSAGE_AT].copy_from_slice(&signature);
                    has_signature = true;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        match (has_message, has_signature) {
            (false, _) => Err(de::Error::missing_field("message")),
            (_, false) => Err(de::Error::missing_field("signature")),
            _ => Ok(()),
        }
    }
}

struct Message<'s>(&'s mut Vec<u8>);

impl<'de> DeserializeSeed<'de> for Message<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Message<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an ExecutionPayloadBid")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let ssz = self.0;
        let mut seen = 0u16;
        while let Some(key) = map.next_key::<&str>()? {
            if key == "blob_kzg_commitments" {
                map.next_value_seed(List::<Bytes<48>>::new(ssz))?;
                continue;
            }
            let Some(index) = FIXED_FIELDS.iter().position(|(name, ..)| *name == key) else {
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            let (_, at, field) = FIXED_FIELDS[index];
            let fixed = &mut ssz[MESSAGE_AT + at..];
            match field {
                Field::Root => fixed[..32].copy_from_slice(&map.next_value::<Bytes<32>>()?.0),
                Field::Address => fixed[..20].copy_from_slice(&map.next_value::<Bytes<20>>()?.0),
                Field::Uint64 => {
                    fixed[..8].copy_from_slice(&map.next_value::<Uint64>()?.0.to_le_bytes())
                }
            }
            seen |= 1 << index;
        }
        match FIXED_FIELDS.iter().enumerate().find(|(index, _)| seen & 1 << index == 0) {
            Some((_, (name, ..))) => Err(de::Error::missing_field(name)),
            None => Ok(()),
        }
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Uint64(#[serde(deserialize_with = "uint64")] u64);

#[cfg(test)]
pub(crate) mod tests {
    use silver_ssz::ssz_view::{ExecutionPayloadBidView, SignedExecutionPayloadBidView};

    use super::*;

    pub(crate) fn hex_of(byte: u8, len: usize) -> String {
        format!("0x{}", hex::encode(vec![byte; len]))
    }

    pub(crate) fn bid_json(commitments: &[String]) -> String {
        format!(
            r#"{{"version":"gloas","data":{{"message":{{"parent_block_hash":"{}","parent_block_root":"{}","block_hash":"{}","prev_randao":"{}","fee_recipient":"{}","gas_limit":"30000000","builder_index":"5","slot":"9","value":"1000","execution_payment":"20","blob_kzg_commitments":[{}],"execution_requests_root":"{}"}},"signature":"{}"}}}}"#,
            hex_of(0x11, 32),
            hex_of(0x22, 32),
            hex_of(0x33, 32),
            hex_of(0x44, 32),
            hex_of(0x55, 20),
            commitments.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(","),
            hex_of(0x66, 32),
            hex_of(0x99, 96),
        )
    }

    #[test]
    fn json_bid_reencodes_as_ssz() {
        let json = bid_json(&[hex_of(0xc0, 48), hex_of(0xc1, 48)]);
        let mut decoder = JsonPayloadBid::new();
        let ssz = decoder.reencode(json.as_bytes()).unwrap().to_vec();
        assert!(SignedExecutionPayloadBidView::check_size(&ssz));
        assert_eq!(SignedExecutionPayloadBidView::signature(&ssz), &[0x99; 96]);

        let bid = SignedExecutionPayloadBidView::message(&ssz);
        assert!(ExecutionPayloadBidView::check_size(bid));
        assert_eq!(ExecutionPayloadBidView::parent_block_hash(bid), &[0x11; 32]);
        assert_eq!(ExecutionPayloadBidView::parent_block_root(bid), &[0x22; 32]);
        assert_eq!(ExecutionPayloadBidView::block_hash(bid), &[0x33; 32]);
        assert_eq!(ExecutionPayloadBidView::prev_randao(bid), &[0x44; 32]);
        assert_eq!(ExecutionPayloadBidView::fee_recipient(bid), &[0x55; 20]);
        assert_eq!(ExecutionPayloadBidView::gas_limit(bid), 30_000_000);
        assert_eq!(ExecutionPayloadBidView::builder_index(bid), 5);
        assert_eq!(ExecutionPayloadBidView::slot(bid), 9);
        assert_eq!(ExecutionPayloadBidView::value(bid), 1000);
        assert_eq!(ExecutionPayloadBidView::execution_payment(bid), 20);
        assert_eq!(ExecutionPayloadBidView::execution_requests_root(bid), &[0x66; 32]);
        let commitments = [[0xc0; 48], [0xc1; 48]].concat();
        assert_eq!(ExecutionPayloadBidView::blob_kzg_commitments(bid), &commitments[..]);

        let empty = bid_json(&[]);
        let again = decoder.reencode(empty.as_bytes()).unwrap();
        assert_eq!(again.len(), 100 + EXECUTION_PAYLOAD_BID_MIN, "reused buffers start clean");
    }

    #[test]
    fn json_that_is_not_a_bid_is_refused() {
        let mut decoder = JsonPayloadBid::new();
        let without_slot = bid_json(&[]).replace(r#""slot":"9","#, "");
        assert!(decoder.reencode(without_slot.as_bytes()).is_none());
        assert!(decoder.reencode(br#"{"version":"gloas","data":{"message":{}}}"#).is_none());
        assert!(decoder.reencode(b"not json").is_none());
        assert!(decoder.reencode(br#"{"version":"gloas"}"#).is_none());
    }
}
