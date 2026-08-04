use std::io::Write;

use buffa::{
    encoding::{Tag, WireType, encode_varint, varint_len},
    types::{bytes_encoded_len, encode_bytes, encode_string, string_encoded_len},
};
use flux::timing::Nanos;
use silver_common::{
    Error, GossipTopic, MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE, MAX_GOSSIP_FRAME_SIZE, MessageId,
    NewGossipMsg, P2pStreamId, PeerEvent, TCacheProducer, TCacheRead, TProducer, TReservation,
    msg_id_invalid_snappy, msg_id_valid_snappy,
};

use crate::{GossipHandlerEvent, control::copy_idontwants_to_protobuf_output, dedup::DedupCache};

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_incoming(
    topic_string: &str,
    snappy_data: &[u8],
    stream_id: &P2pStreamId,
    fork_digest_hex: &str,
    recv_ts: Nanos,
    dedup_cache: &mut DedupCache,
    incoming_gossip_publish: &mut TProducer,
    mcache_publish: &mut TProducer,
    emit: &mut impl FnMut(GossipHandlerEvent),
) -> Result<(), Error> {
    validate_compressed_payload_size(snappy_data.len()).inspect_err(|_| {
        tracing::warn!(?stream_id, topic_string, "invalid gossip frame");
        emit(GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipInvalidFrame {
            p2p_peer: stream_id.peer(),
        }));
    })?;

    // Fast duplicate check.
    let fast_id = match dedup_cache.contains_fast(topic_string, snappy_data) {
        Some(fast_hash) => fast_hash,
        None => return Ok(()), // duplicate
    };

    let topic = GossipTopic::from_wire(topic_string, fork_digest_hex)?;
    tracing::trace!(?stream_id, ?topic, "Gossip message received");

    // Decompress: block snappy.
    let len = read_message_length(snappy_data, &topic).inspect_err(|_| {
        let hash = msg_id_invalid_snappy(topic_string, snappy_data);
        if dedup_cache.insert(fast_id, hash) {
            emit(GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipInvalidMsg {
                p2p_peer: stream_id.peer(),
                topic,
                hash,
            }));
        }
    })?;

    // Alloc into downstream tcache - SSZ message bytes
    let mut reservation = incoming_gossip_publish
        .reserve(len, false)
        .ok_or(Error::BufferTooSmall)
        .inspect_err(|e| {
            tracing::error!(?e, len, topic_string, "failed to reserve incoming gossip SSZ");
        })?;

    let msg_id = decompress_to_reservation(
        incoming_gossip_publish,
        snappy_data,
        &mut reservation,
        topic_string,
    )
    .inspect_err(|e| {
        tracing::error!(?stream_id, ?e, topic_string, "failed to decompress gossip msg")
    })?;

    if !dedup_cache.insert(fast_id, msg_id) {
        // Second dedup check. Different snappy bytes can decompress to the same message
        // bytes so this second check is required.
        return Ok(());
    }

    let ssz_read = reservation.read();
    let mcache_read = copy_compressed_to_protobuf_output(mcache_publish, snappy_data, topic_string)
        .inspect_err(|e| {
            tracing::error!(?e, "failed to write incoming gossip protobuf");
            let hash = msg_id_invalid_snappy(topic_string, snappy_data);
            if dedup_cache.insert(fast_id, hash) {
                emit(GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipInvalidMsg {
                    p2p_peer: stream_id.peer(),
                    topic,
                    hash,
                }));
            }
        })?;

    // Flush the reservation matching the gossip message available downstream.
    reservation.flush()?;

    emit(GossipHandlerEvent::NewGossip(NewGossipMsg {
        stream_id: *stream_id,
        topic,
        msg_hash: msg_id,
        recv_ts,
        ssz: ssz_read,
        protobuf: mcache_read,
    }));

    // Pre-encode an IDONTWANT control frame carrying this single id; the
    // peer manager fans it out to mesh peers (except the sender) as a
    // `P2pGossipSendDontWant` control.
    let idontwant = copy_idontwants_to_protobuf_output(mcache_publish, std::iter::once(&msg_id))?;
    emit(GossipHandlerEvent::PeerEvent(PeerEvent::NewGossip {
        p2p_peer: stream_id.peer(),
        topic,
        msg_hash: msg_id,
        idontwant,
    }));
    Ok(())
}

fn decompress_to_reservation(
    producer: &TProducer,
    data: &[u8],
    reservation: &mut TReservation,
    topic: &str,
) -> Result<MessageId, Error> {
    let mut snap_decoder = snap::raw::Decoder::new();
    let output_buffer = producer.reservation_buffer(reservation)?;

    let decompressed_len = snap_decoder.decompress(data, output_buffer)?;
    reservation.increment_offset(decompressed_len);

    let msg_id = msg_id_valid_snappy(topic, &output_buffer[..decompressed_len]);
    Ok(msg_id)
}

pub(crate) fn copy_compressed_to_protobuf_output(
    producer: &mut TProducer,
    snappy_data: &[u8],
    topic: &str,
) -> Result<TCacheRead, Error> {
    validate_compressed_payload_size(snappy_data.len())?;

    // Fields 1..=15 encode as 1-byte tags (varint < 128).
    // RPC.publish = field 2, Message.data = field 2, Message.topic = field 4.
    const TAG_LEN: usize = 1;

    let inner_len = TAG_LEN + bytes_encoded_len(snappy_data) + TAG_LEN + string_encoded_len(topic);

    let total = TAG_LEN + varint_len(inner_len as u64) + inner_len;
    if total > MAX_GOSSIP_FRAME_SIZE {
        return Err(Error::GossipFrameTooLarge);
    }

    let mut reservation = producer.reserve(total, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    // `&mut [u8]` implements `BufMut` and advances in-place on each put,
    // giving a single copy of `snappy_data` into the reservation via the
    // `put_slice` inside `encode_bytes`.
    let mut cursor: &mut [u8] = &mut out[..total];

    Tag::new(2, WireType::LengthDelimited).encode(&mut cursor); // RPC.publish
    encode_varint(inner_len as u64, &mut cursor);

    Tag::new(2, WireType::LengthDelimited).encode(&mut cursor); // Message.data
    encode_bytes(snappy_data, &mut cursor);

    Tag::new(4, WireType::LengthDelimited).encode(&mut cursor); // Message.topic
    encode_string(topic, &mut cursor);

    reservation.increment_offset(total);
    Ok(reservation.read())
}

fn validate_compressed_payload_size(len: usize) -> Result<(), Error> {
    if len > MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE {
        return Err(Error::GossipPayloadTooLarge);
    }
    Ok(())
}

fn read_message_length(msg: &[u8], gossip_topic: &GossipTopic) -> Result<usize, Error> {
    let len = snap::raw::decompress_len(msg).map_err(|_| Error::InvalidSnappy)?;
    if len > gossip_topic.max_uncompressed_size() {
        return Err(Error::GossipPayloadTooLarge);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use silver_common::encode_varint;

    use super::*;

    fn snappy_length_prefix(len: usize) -> Vec<u8> {
        let mut buf = [0; 10];
        let encoded = encode_varint(len as u64, &mut buf).unwrap();
        buf[..encoded].to_vec()
    }

    #[test]
    fn compressed_payload_boundaries() {
        assert!(validate_compressed_payload_size(MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE).is_ok());
        assert!(matches!(
            validate_compressed_payload_size(MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE + 1),
            Err(Error::GossipPayloadTooLarge)
        ));
    }

    #[test]
    fn uncompressed_payload_uses_topic_bound() {
        let topic = GossipTopic::BeaconAttestation(0);
        assert_eq!(read_message_length(&snappy_length_prefix(240), &topic).unwrap(), 240);
        assert!(matches!(
            read_message_length(&snappy_length_prefix(241), &topic),
            Err(Error::GossipPayloadTooLarge)
        ));
    }

    #[test]
    fn uncompressed_payload_uses_global_bound() {
        let topic = GossipTopic::BeaconBlock;
        assert_eq!(
            read_message_length(&snappy_length_prefix(topic.max_uncompressed_size()), &topic)
                .unwrap(),
            topic.max_uncompressed_size()
        );
        assert!(matches!(
            read_message_length(&snappy_length_prefix(topic.max_uncompressed_size() + 1), &topic),
            Err(Error::GossipPayloadTooLarge)
        ));
    }
}
