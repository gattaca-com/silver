use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use silver_common::json_fields::{BoundedHex, bytes, uint64, uint256};
use silver_httpcore::ClientResponse;
use silver_ssz::ssz_view::{
    BUILDER_BID_FULU_FIXED, EXECUTION_PAYLOAD_HEADER_FIXED, MAX_EXTRA_DATA_BYTES,
};

/// Re-encodes a JSON `SignedBuilderBid` (Fulu) as SSZ. Commit-Boost answers
/// SSZ when asked, but a sidecar may answer JSON whatever `Accept` says
/// (Vouch's blockrelay does). The buffers are reused across bids.
pub(crate) struct JsonBid {
    header: Vec<u8>,
    commitments: Vec<u8>,
    deposits: Vec<u8>,
    withdrawals: Vec<u8>,
    consolidations: Vec<u8>,
    value: [u8; 32],
    pubkey: [u8; 48],
    signature: [u8; 96],
    ssz: Vec<u8>,
}

impl JsonBid {
    pub(crate) fn new() -> Self {
        Self {
            header: Vec::new(),
            commitments: Vec::new(),
            deposits: Vec::new(),
            withdrawals: Vec::new(),
            consolidations: Vec::new(),
            value: [0; 32],
            pubkey: [0; 48],
            signature: [0; 96],
            ssz: Vec::new(),
        }
    }

    /// The response's `SignedBuilderBid` as SSZ, empty when a JSON body does
    /// not decode.
    pub(crate) fn ssz_bid<'s>(&'s mut self, response: ClientResponse<'s>) -> &'s [u8] {
        let is_json = response
            .header("Content-Type")
            .is_some_and(|value| value.starts_with(b"application/json"));
        if is_json { self.reencode(response.body).unwrap_or_default() } else { response.body }
    }

    fn reencode(&mut self, json: &[u8]) -> Option<&[u8]> {
        for buffer in [
            &mut self.header,
            &mut self.commitments,
            &mut self.deposits,
            &mut self.withdrawals,
            &mut self.consolidations,
            &mut self.ssz,
        ] {
            buffer.clear();
        }
        let mut deserializer = serde_json::Deserializer::from_slice(json);
        if let Err(error) = Envelope(self).deserialize(&mut deserializer) {
            silver_log::warn!(%error, "sidecar bid is not a Fulu SignedBuilderBid");
            return None;
        }
        self.encode();
        Some(&self.ssz)
    }

    /// `SignedBuilderBid { message: BuilderBid, signature }`, where
    /// `BuilderBid { header, blob_kzg_commitments, execution_requests, value,
    /// pubkey }` and `execution_requests` is three lists.
    fn encode(&mut self) {
        let Self { header, commitments, deposits, withdrawals, consolidations, ssz, .. } = self;
        let offset = |at: usize| (at as u32).to_le_bytes();
        let header_at = BUILDER_BID_FULU_FIXED;
        let commitments_at = header_at + header.len();
        let requests_at = commitments_at + commitments.len();
        ssz.extend_from_slice(&offset(100));
        ssz.extend_from_slice(&self.signature);
        for at in [header_at, commitments_at, requests_at] {
            ssz.extend_from_slice(&offset(at));
        }
        ssz.extend_from_slice(&self.value);
        ssz.extend_from_slice(&self.pubkey);
        ssz.extend_from_slice(header);
        ssz.extend_from_slice(commitments);
        let withdrawals_at = 12 + deposits.len();
        let consolidations_at = withdrawals_at + withdrawals.len();
        for at in [12, withdrawals_at, consolidations_at] {
            ssz.extend_from_slice(&offset(at));
        }
        for list in [deposits, withdrawals, consolidations] {
            ssz.extend_from_slice(list);
        }
    }
}

/// `{ "version": .., "data": SignedBuilderBid }`
struct Envelope<'s>(&'s mut JsonBid);

impl<'de> DeserializeSeed<'de> for Envelope<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Envelope<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a getHeader response")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "data" => map.next_value_seed(SignedBid(&mut *self.0))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct SignedBid<'s>(&'s mut JsonBid);

impl<'de> DeserializeSeed<'de> for SignedBid<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for SignedBid<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a SignedBuilderBid")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "message" => map.next_value_seed(Message(&mut *self.0))?,
                "signature" => self.0.signature = map.next_value::<Bytes<96>>()?.0,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct Message<'s>(&'s mut JsonBid);

impl<'de> DeserializeSeed<'de> for Message<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Message<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a BuilderBid")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let bid = self.0;
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "header" => map.next_value::<Header>()?.encode(&mut bid.header),
                "blob_kzg_commitments" => {
                    map.next_value_seed(List::<Bytes<48>>::new(&mut bid.commitments))?
                }
                "execution_requests" => map.next_value_seed(Requests(&mut *bid))?,
                "value" => bid.value = map.next_value::<Uint256>()?.0,
                "pubkey" => bid.pubkey = map.next_value::<Bytes<48>>()?.0,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct Requests<'s>(&'s mut JsonBid);

impl<'de> DeserializeSeed<'de> for Requests<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Requests<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("ExecutionRequests")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let bid = self.0;
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "deposits" => map.next_value_seed(List::<Deposit>::new(&mut bid.deposits))?,
                "withdrawals" => {
                    map.next_value_seed(List::<Withdrawal>::new(&mut bid.withdrawals))?
                }
                "consolidations" => {
                    map.next_value_seed(List::<Consolidation>::new(&mut bid.consolidations))?
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

/// An element of a JSON list that appends its own SSZ.
trait Element: for<'de> Deserialize<'de> {
    fn encode(&self, out: &mut Vec<u8>);
}

/// Streams a JSON list into `out`, element by element.
struct List<'s, T> {
    out: &'s mut Vec<u8>,
    element: std::marker::PhantomData<T>,
}

impl<'s, T> List<'s, T> {
    fn new(out: &'s mut Vec<u8>) -> Self {
        Self { out, element: std::marker::PhantomData }
    }
}

impl<'de, T: Element> DeserializeSeed<'de> for List<'_, T> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, T: Element> Visitor<'de> for List<'_, T> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a list")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(element) = seq.next_element::<T>()? {
            element.encode(self.out);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Bytes<const N: usize>(#[serde(deserialize_with = "bytes")] [u8; N]);

impl<const N: usize> Element for Bytes<N> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Uint256(#[serde(deserialize_with = "uint256")] [u8; 32]);

#[derive(Deserialize)]
struct Deposit {
    #[serde(deserialize_with = "bytes")]
    pubkey: [u8; 48],
    #[serde(deserialize_with = "bytes")]
    withdrawal_credentials: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    amount: u64,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
    #[serde(deserialize_with = "uint64")]
    index: u64,
}

impl Element for Deposit {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.withdrawal_credentials);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.index.to_le_bytes());
    }
}

#[derive(Deserialize)]
struct Withdrawal {
    #[serde(deserialize_with = "bytes")]
    source_address: [u8; 20],
    #[serde(deserialize_with = "bytes")]
    validator_pubkey: [u8; 48],
    #[serde(deserialize_with = "uint64")]
    amount: u64,
}

impl Element for Withdrawal {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source_address);
        out.extend_from_slice(&self.validator_pubkey);
        out.extend_from_slice(&self.amount.to_le_bytes());
    }
}

#[derive(Deserialize)]
struct Consolidation {
    #[serde(deserialize_with = "bytes")]
    source_address: [u8; 20],
    #[serde(deserialize_with = "bytes")]
    source_pubkey: [u8; 48],
    #[serde(deserialize_with = "bytes")]
    target_pubkey: [u8; 48],
}

impl Element for Consolidation {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source_address);
        out.extend_from_slice(&self.source_pubkey);
        out.extend_from_slice(&self.target_pubkey);
    }
}

/// `ExecutionPayloadHeader` (Deneb through Fulu).
#[derive(Deserialize)]
struct Header {
    #[serde(deserialize_with = "bytes")]
    parent_hash: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    fee_recipient: [u8; 20],
    #[serde(deserialize_with = "bytes")]
    state_root: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    receipts_root: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    logs_bloom: [u8; 256],
    #[serde(deserialize_with = "bytes")]
    prev_randao: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    block_number: u64,
    #[serde(deserialize_with = "uint64")]
    gas_limit: u64,
    #[serde(deserialize_with = "uint64")]
    gas_used: u64,
    #[serde(deserialize_with = "uint64")]
    timestamp: u64,
    extra_data: BoundedHex<MAX_EXTRA_DATA_BYTES>,
    #[serde(deserialize_with = "uint256")]
    base_fee_per_gas: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    block_hash: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    transactions_root: [u8; 32],
    #[serde(deserialize_with = "bytes")]
    withdrawals_root: [u8; 32],
    #[serde(deserialize_with = "uint64")]
    blob_gas_used: u64,
    #[serde(deserialize_with = "uint64")]
    excess_blob_gas: u64,
}

impl Header {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.parent_hash);
        out.extend_from_slice(&self.fee_recipient);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.receipts_root);
        out.extend_from_slice(&self.logs_bloom);
        out.extend_from_slice(&self.prev_randao);
        for number in [self.block_number, self.gas_limit, self.gas_used, self.timestamp] {
            out.extend_from_slice(&number.to_le_bytes());
        }
        out.extend_from_slice(&(EXECUTION_PAYLOAD_HEADER_FIXED as u32).to_le_bytes());
        out.extend_from_slice(&self.base_fee_per_gas);
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.transactions_root);
        out.extend_from_slice(&self.withdrawals_root);
        out.extend_from_slice(&self.blob_gas_used.to_le_bytes());
        out.extend_from_slice(&self.excess_blob_gas.to_le_bytes());
        out.extend_from_slice(self.extra_data.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use silver_ssz::ssz_view::{
        BuilderBidFuluView, ExecutionPayloadHeaderFuluView, ExecutionRequestsFuluView,
        SignedBuilderBidFuluView,
    };

    use super::*;

    fn hex_of(byte: u8, len: usize) -> String {
        format!("0x{}", hex::encode(vec![byte; len]))
    }

    /// One of each list entry, and extra data, so every offset is exercised.
    fn bid_json() -> String {
        format!(
            r#"{{"version":"fulu","data":{{"message":{{"header":{{"parent_hash":"{}","fee_recipient":"{}","state_root":"{}","receipts_root":"{}","logs_bloom":"{}","prev_randao":"{}","block_number":"7","gas_limit":"30000000","gas_used":"21000","timestamp":"1700000012","extra_data":"0xbeef","base_fee_per_gas":"340282366920938463463374607431768211456","block_hash":"{}","transactions_root":"{}","withdrawals_root":"{}","blob_gas_used":"131072","excess_blob_gas":"0"}},"blob_kzg_commitments":["{}"],"execution_requests":{{"deposits":[{{"pubkey":"{}","withdrawal_credentials":"{}","amount":"32000000000","signature":"{}","index":"3"}}],"withdrawals":[{{"source_address":"{}","validator_pubkey":"{}","amount":"1"}}],"consolidations":[{{"source_address":"{}","source_pubkey":"{}","target_pubkey":"{}"}}]}},"value":"1000000000000000000","pubkey":"{}"}},"signature":"{}"}}}}"#,
            hex_of(0x11, 32),
            hex_of(0x22, 20),
            hex_of(0x33, 32),
            hex_of(0x34, 32),
            hex_of(0x35, 256),
            hex_of(0x44, 32),
            hex_of(0x55, 32),
            hex_of(0x56, 32),
            hex_of(0x57, 32),
            hex_of(0xc0, 48),
            hex_of(0xd0, 48),
            hex_of(0xd1, 32),
            hex_of(0xd2, 96),
            hex_of(0xe0, 20),
            hex_of(0xe1, 48),
            hex_of(0xf0, 20),
            hex_of(0xf1, 48),
            hex_of(0xf2, 48),
            hex_of(0xa5, 48),
            hex_of(0x99, 96),
        )
    }

    #[test]
    fn json_bid_reencodes_as_canonical_ssz() {
        let json = bid_json();
        let mut decoder = JsonBid::new();
        let ssz = decoder.reencode(json.as_bytes()).unwrap().to_vec();
        assert!(SignedBuilderBidFuluView::check_canonical(&ssz));
        assert_eq!(SignedBuilderBidFuluView::signature(&ssz), &[0x99; 96]);

        let bid = SignedBuilderBidFuluView::message(&ssz);
        assert_eq!(BuilderBidFuluView::pubkey(bid), &[0xa5; 48]);
        let mut value = [0; 32];
        value[..8].copy_from_slice(&1_000_000_000_000_000_000u64.to_le_bytes());
        assert_eq!(BuilderBidFuluView::value(bid), &value);
        assert_eq!(BuilderBidFuluView::blob_kzg_commitments(bid), &[0xc0; 48]);

        let header = BuilderBidFuluView::header(bid);
        assert_eq!(ExecutionPayloadHeaderFuluView::parent_hash(header), &[0x11; 32]);
        assert_eq!(ExecutionPayloadHeaderFuluView::prev_randao(header), &[0x44; 32]);
        assert_eq!(ExecutionPayloadHeaderFuluView::block_number(header), 7);
        assert_eq!(ExecutionPayloadHeaderFuluView::gas_limit(header), 30_000_000);
        assert_eq!(ExecutionPayloadHeaderFuluView::timestamp(header), 1_700_000_012);
        assert_eq!(ExecutionPayloadHeaderFuluView::block_hash(header), &[0x55; 32]);
        assert_eq!(ExecutionPayloadHeaderFuluView::withdrawals_root(header), &[0x57; 32]);
        assert_eq!(ExecutionPayloadHeaderFuluView::extra_data(header), &[0xbe, 0xef]);
        let mut base_fee_per_gas = [0; 32];
        base_fee_per_gas[16] = 1;
        assert_eq!(&header[440..472], &base_fee_per_gas);

        let requests = BuilderBidFuluView::execution_requests(bid);
        assert!(ExecutionRequestsFuluView::check_canonical(requests));
        assert_eq!(requests.len(), 12 + 192 + 76 + 116);

        let again = decoder.reencode(json.as_bytes()).unwrap();
        assert_eq!(again, &ssz[..], "reused buffers start clean");
    }

    #[test]
    fn json_that_is_not_a_bid_is_refused() {
        let mut decoder = JsonBid::new();
        assert!(
            decoder.reencode(br#"{"version":"fulu","data":{"message":{"header":{}}}}"#).is_none()
        );
        assert!(decoder.reencode(b"not json").is_none());
    }
}
