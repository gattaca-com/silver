//! Synthetic gossip publish: build a protobuf `RPC { publish[0] = Message {
//! topic, data: snappy } }` frame directly in the publisher's mcache TCache
//! and return a `TCacheRead` referencing it.
//!
//! Same wire layout as `silver_compression`'s internal helper, replicated
//! here to avoid making production code pub for test-only use.

use buffa::{
    encoding::{Tag, WireType, encode_varint, varint_len},
    types::{bytes_encoded_len, encode_bytes, encode_string, string_encoded_len},
};
use silver_common::{TCacheError, TCacheRead, TProducer};

#[derive(Debug)]
pub enum InjectError {
    ReserveFailed,
    Buffer(TCacheError),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReserveFailed => f.write_str("mcache reserve failed"),
            Self::Buffer(e) => write!(f, "mcache buffer error: {e}"),
        }
    }
}

impl std::error::Error for InjectError {}

impl From<TCacheError> for InjectError {
    fn from(e: TCacheError) -> Self {
        Self::Buffer(e)
    }
}

pub fn build_publish_frame(
    mcache_producer: &mut TProducer,
    wire_topic: &str,
    snappy_data: &[u8],
) -> Result<TCacheRead, InjectError> {
    // Fields 1..=15 encode as 1-byte tags. RPC.publish = 2; Message.data = 2;
    // Message.topic = 4.
    const TAG_LEN: usize = 1;

    let inner_len =
        TAG_LEN + bytes_encoded_len(snappy_data) + TAG_LEN + string_encoded_len(wire_topic);
    let total = TAG_LEN + varint_len(inner_len as u64) + inner_len;

    let mut reservation = mcache_producer.reserve(total, true).ok_or(InjectError::ReserveFailed)?;
    let out = mcache_producer.reservation_buffer(&mut reservation)?;
    let mut cursor: &mut [u8] = &mut out[..total];

    Tag::new(2, WireType::LengthDelimited).encode(&mut cursor); // RPC.publish
    encode_varint(inner_len as u64, &mut cursor);

    Tag::new(2, WireType::LengthDelimited).encode(&mut cursor); // Message.data
    encode_bytes(snappy_data, &mut cursor);

    Tag::new(4, WireType::LengthDelimited).encode(&mut cursor); // Message.topic
    encode_string(wire_topic, &mut cursor);

    reservation.increment_offset(total);
    Ok(reservation.read())
}

/// snappy-raw compress. Tests craft opaque "SSZ-shaped" random payloads; the
/// echo side's GossipCompressionTile will reject them as invalid on the
/// downstream validator but the compression/dedup/mcache path will succeed —
/// which is what we're exercising.
pub fn snappy_compress(raw: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new().compress_vec(raw).expect("snappy encode")
}
