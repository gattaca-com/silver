use std::io::Write;

use buffa::{
    encoding::{Tag, WireType, encode_varint, varint_len},
    types::{bytes_encoded_len, encode_bytes, encode_string, string_encoded_len},
};
use flux::spine::SpineAdapter;
use silver_common::{
    Error, Gossip, GossipTopic, MessageId, NewGossipMsg, P2pStreamId, PeerEvent, SilverSpine,
    TCacheRead, TProducer, TReservation, msg_id_invalid_snappy, msg_id_valid_snappy,
};

use crate::{GossipCompressionTile, dedup::DedupCache, mcache::MessageCache};

impl GossipCompressionTile {
    pub(super) fn handle_incoming(
        topic_string: &str,
        snappy_data: &[u8],
        stream_id: &P2pStreamId,
        fork_digest_hex: &str,
        dedup_cache: &mut DedupCache,
        incoming_gossip_publish: &mut TProducer,
        mcache_publish: &mut TProducer,
        mcache: &mut MessageCache,
        adapter: &mut SpineAdapter<SilverSpine>,
    ) -> Result<(), Error> {
        // Fast duplicate check.
        let fast_id = match dedup_cache.contains_fast(snappy_data) {
            Some(fast_hash) => fast_hash,
            None => return Ok(()), // duplicate
        };

        let topic = GossipTopic::from_wire(topic_string, fork_digest_hex)?;

        // Decompress: block snappy.
        let len = read_message_length(snappy_data, &topic).inspect_err(|_| {
            let hash = msg_id_invalid_snappy(topic_string, snappy_data);
            if dedup_cache.insert(fast_id, hash) {
                adapter.produce(PeerEvent::P2pGossipInvalidMsg {
                    p2p_peer: stream_id.peer(),
                    topic,
                    hash,
                });
            }
        })?;

        // Alloc into downstream tcache - SSZ message bytes
        let mut reservation =
            incoming_gossip_publish.reserve(len, false).ok_or(Error::BufferTooSmall)?;

        let msg_id = decompress_to_reservation(
            incoming_gossip_publish,
            snappy_data,
            &mut reservation,
            topic_string,
        )?;

        if !dedup_cache.insert(fast_id, msg_id) {
            // Second dedup check. Different snappy bytes can decompress to the same message
            // bytes so this second check is required.
            return Ok(());
        }

        let ssz_read = reservation.read();
        let mcache_read =
            copy_compressed_to_protobuf_output(mcache_publish, snappy_data, topic_string)
                .inspect_err(|_| {
                    let hash = msg_id_invalid_snappy(topic_string, snappy_data);
                    if dedup_cache.insert(fast_id, hash) {
                        adapter.produce(PeerEvent::P2pGossipInvalidMsg {
                            p2p_peer: stream_id.peer(),
                            topic,
                            hash,
                        });
                    }
                })?;

        // Add message to message cache.
        mcache.insert(msg_id, topic, mcache_read);

        // Flush the reservation matching the gossip message available downstream.
        reservation.flush()?;

        adapter.produce(Gossip::NewInbound(NewGossipMsg {
            stream_id: *stream_id,
            topic,
            msg_hash: msg_id,
            ssz: ssz_read,
            protobuf: mcache_read,
        }));
        Ok(())
    }
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

    let msg_id = msg_id_valid_snappy(topic, &mut output_buffer[..decompressed_len]);
    Ok(msg_id)
}

fn copy_compressed_to_protobuf_output(
    producer: &mut TProducer,
    snappy_data: &[u8],
    topic: &str,
) -> Result<TCacheRead, Error> {
    // Fields 1..=15 encode as 1-byte tags (varint < 128).
    // RPC.publish = field 2, Message.data = field 2, Message.topic = field 4.
    const TAG_LEN: usize = 1;

    let inner_len = TAG_LEN + bytes_encoded_len(snappy_data) + TAG_LEN + string_encoded_len(topic);

    let total = TAG_LEN + varint_len(inner_len as u64) + inner_len;

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

fn read_message_length(msg: &[u8], _gossip_topic: &GossipTopic) -> Result<usize, Error> {
    // TODO check per topic message size limits
    // these are calculated from SSZ type defs.
    snap::raw::decompress_len(msg).map_err(|_| Error::InvalidSnappy)
}
