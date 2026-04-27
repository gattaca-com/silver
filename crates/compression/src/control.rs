use buffa::{
    RepeatedView,
    encoding::{Tag, WireType, encode_varint, varint_len},
    types::{encode_bytes, encode_string, string_encoded_len},
};
use flux::spine::SpineAdapter;
use silver_common::{
    Error, GossipTopic, MESSAGE_ID_LEN, MessageId, P2pStreamId, PeerEvent, SilverSpine, TCacheRead,
    TProducer,
};

use crate::{
    generated::{
        ControlGraftView, ControlIDontWantView, ControlIHaveView, ControlIWantView,
        ControlPruneView, rpc::SubOptsView,
    },
    mcache::MessageCache,
};

pub(super) fn handle_subscriptions<'a>(
    stream_id: &P2pStreamId,
    subscriptions: RepeatedView<'a, SubOptsView<'a>>,
    fork_digest_hex: &str,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    for subscription in subscriptions {
        if let Some(topic) = subscription.topic_id &&
            let Some(subscribe) = subscription.subscribe
        {
            let Ok(topic) = gossip_topic(topic, fork_digest_hex) else {
                continue;
            };
            if subscribe {
                adapter.produce(PeerEvent::P2pGossipTopicSubscribe {
                    p2p_peer: stream_id.peer(),
                    topic,
                });
            } else {
                adapter.produce(PeerEvent::P2pGossipTopicUnsubscribe {
                    p2p_peer: stream_id.peer(),
                    topic,
                });
            }
        }
    }
}

pub(super) fn handle_grafts<'a>(
    stream_id: &P2pStreamId,
    grafts: &RepeatedView<'a, ControlGraftView<'a>>,
    fork_digest_hex: &str,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    for graft in grafts {
        if let Some(topic) = graft.topic_id {
            let Ok(topic) = gossip_topic(topic, fork_digest_hex) else {
                continue;
            };
            adapter.produce(PeerEvent::P2pGossipTopicGraft { p2p_peer: stream_id.peer(), topic });
        }
    }
}

pub(super) fn handle_prunes<'a>(
    stream_id: &P2pStreamId,
    prunes: &RepeatedView<'a, ControlPruneView<'a>>,
    fork_digest_hex: &str,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    for prune in prunes {
        if let Some(topic) = prune.topic_id {
            let Ok(topic) = gossip_topic(topic, fork_digest_hex) else {
                continue;
            };
            // TODO: prune.peers may contain list of signed peer records of alternate peers
            // but e.g. Lighthouse does not send peer records. So maybe just ignore?
            adapter.produce(PeerEvent::P2pGossipTopicPrune { p2p_peer: stream_id.peer(), topic });
        }
    }
}

pub(super) fn handle_iwants<'a>(
    stream_id: &P2pStreamId,
    wants: &RepeatedView<'a, ControlIWantView<'a>>,
    mcache: &mut MessageCache,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    for iwant in wants {
        for want in &iwant.message_ids {
            let Some(hash) = message_id(want, stream_id, adapter) else {
                continue;
            };

            if let Some(tcache) = mcache.get(&hash) {
                adapter.produce(PeerEvent::P2pGossipWant {
                    p2p_peer: stream_id.peer(),
                    hash,
                    tcache,
                });
            }
        }
    }
}

pub(super) fn handle_idontwants<'a>(
    stream_id: &P2pStreamId,
    wants: &RepeatedView<'a, ControlIDontWantView<'a>>,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    for idontwant in wants {
        for dontwant in &idontwant.message_ids {
            let Some(hash) = message_id(dontwant, stream_id, adapter) else {
                continue;
            };
            adapter.produce(PeerEvent::P2pGossipDontWant { p2p_peer: stream_id.peer(), hash });
        }
    }
}

pub(super) fn handle_ihaves<'a>(
    stream_id: &P2pStreamId,
    haves: &RepeatedView<'a, ControlIHaveView<'a>>,
    fork_digest_hex: &str,
    mcache: &MessageCache,
    mcache_publish: &mut TProducer,
    adapter: &mut SpineAdapter<SilverSpine>,
    scratch_buffer: &mut Vec<MessageId>,
) {
    scratch_buffer.clear();
    for ihave in haves {
        if let Some(topic) = ihave.topic_id {
            let Ok(topic) = gossip_topic(topic, fork_digest_hex) else {
                continue;
            };
            for have in &ihave.message_ids {
                let Some(hash) = message_id(have, stream_id, adapter) else {
                    continue;
                };
                // Emit for every id, including ones we already have — the
                // peer manager uses the total count for rate/flood scoring.
                // `already_seen` tells it whether an IWANT is implied.
                let already_seen = mcache.has(&hash);
                adapter.produce(PeerEvent::P2pGossipHave {
                    p2p_peer: stream_id.peer(),
                    hash,
                    topic,
                    already_seen,
                });

                if !already_seen {
                    scratch_buffer.push(hash);
                }
            }
        }
    }
    if scratch_buffer.is_empty() {
        return;
    }
    if let Ok(cache_read) = copy_iwants_to_protobuf_output(mcache_publish, scratch_buffer.iter()) {
        adapter.produce(PeerEvent::OutboundIWant { p2p_peer: stream_id.peer(), iwant: cache_read });
    }
}

/// Encode an `RPC { control: ControlMessage { ihave: [ ControlIHave { topic_id,
/// message_ids } ] } }` frame directly into a TCache reservation. Single copy
/// per `MessageId` (via `encode_bytes`'s `put_slice`), no intermediate heap.
pub(crate) fn copy_ihaves_to_protobuf_output<'a>(
    producer: &mut TProducer,
    topic: &str,
    message_ids: impl ExactSizeIterator<Item = &'a MessageId>,
) -> Result<TCacheRead, Error> {
    // Fields 1..=15 encode as 1-byte tags (varint < 128).
    // RPC.control = field 3, ControlMessage.ihave = field 1,
    // ControlIHave.topic_id = field 1, ControlIHave.message_ids = field 2.
    const TAG_LEN: usize = 1;
    let (id_count, _) = message_ids.size_hint();
    let ids_len = id_count * (TAG_LEN + varint_len(MESSAGE_ID_LEN as u64) + MESSAGE_ID_LEN);
    //let ids_len: usize =
    //    message_ids.iter().map(|id| TAG_LEN + bytes_encoded_len(&id[..])).sum();
    let ihave_inner_len = TAG_LEN + string_encoded_len(topic) + ids_len;
    let control_inner_len = TAG_LEN + varint_len(ihave_inner_len as u64) + ihave_inner_len;
    let total = TAG_LEN + varint_len(control_inner_len as u64) + control_inner_len;

    let mut reservation = producer.reserve(total, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    // `&mut [u8]` implements `BufMut` and advances in-place on each put.
    let mut cursor: &mut [u8] = &mut out[..total];

    // RPC.control (field 3, LD).
    Tag::new(3, WireType::LengthDelimited).encode(&mut cursor);
    encode_varint(control_inner_len as u64, &mut cursor);

    // ControlMessage.ihave (field 1, LD) — single ControlIHave entry.
    Tag::new(1, WireType::LengthDelimited).encode(&mut cursor);
    encode_varint(ihave_inner_len as u64, &mut cursor);

    // ControlIHave.topic_id (field 1, string).
    Tag::new(1, WireType::LengthDelimited).encode(&mut cursor);
    encode_string(topic, &mut cursor);

    // ControlIHave.message_ids (field 2, bytes, repeated).
    for id in message_ids {
        Tag::new(2, WireType::LengthDelimited).encode(&mut cursor);
        encode_bytes(&id[..], &mut cursor);
    }

    reservation.increment_offset(total);
    Ok(reservation.read())
}

/// Encode an `RPC { control: ControlMessage { iwant: [ ControlIWant {
/// message_ids } ] } }` frame directly into a TCache reservation. No
/// topic_id field (IWANT is not topic-scoped).
pub fn copy_iwants_to_protobuf_output<'a>(
    producer: &mut TProducer,
    message_ids: impl ExactSizeIterator<Item = &'a MessageId>,
) -> Result<TCacheRead, Error> {
    // RPC.control = field 3, ControlMessage.iwant = field 2,
    // ControlIWant.message_ids = field 1. All ≤ 15 → 1-byte tags.
    const TAG_LEN: usize = 1;
    let (id_count, _) = message_ids.size_hint();
    let ids_len = id_count * (TAG_LEN + varint_len(MESSAGE_ID_LEN as u64) + MESSAGE_ID_LEN);
    let iwant_inner_len = ids_len;
    let control_inner_len = TAG_LEN + varint_len(iwant_inner_len as u64) + iwant_inner_len;
    let total = TAG_LEN + varint_len(control_inner_len as u64) + control_inner_len;

    let mut reservation = producer.reserve(total, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    let mut cursor: &mut [u8] = &mut out[..total];

    // RPC.control (field 3, LD).
    Tag::new(3, WireType::LengthDelimited).encode(&mut cursor);
    encode_varint(control_inner_len as u64, &mut cursor);

    // ControlMessage.iwant (field 2, LD) — single ControlIWant entry.
    Tag::new(2, WireType::LengthDelimited).encode(&mut cursor);
    encode_varint(iwant_inner_len as u64, &mut cursor);

    // ControlIWant.message_ids (field 1, bytes, repeated).
    for id in message_ids {
        Tag::new(1, WireType::LengthDelimited).encode(&mut cursor);
        encode_bytes(&id[..], &mut cursor);
    }

    reservation.increment_offset(total);
    Ok(reservation.read())
}

/// Encode an `RPC { control: ControlMessage { idontwant: [ ControlIDontWant
/// { message_ids } ] } }` frame directly into a TCache reservation. IDONTWANT
/// is not topic-scoped.
pub(crate) fn copy_idontwants_to_protobuf_output<'a>(
    producer: &mut TProducer,
    message_ids: impl ExactSizeIterator<Item = &'a MessageId>,
) -> Result<TCacheRead, Error> {
    // RPC.control = field 3, ControlMessage.idontwant = field 5,
    // ControlIDontWant.message_ids = field 1. All ≤ 15 → 1-byte tags.
    const TAG_LEN: usize = 1;
    let (id_count, _) = message_ids.size_hint();
    let ids_len = id_count * (TAG_LEN + varint_len(MESSAGE_ID_LEN as u64) + MESSAGE_ID_LEN);
    let idontwant_inner_len = ids_len;
    let control_inner_len = TAG_LEN + varint_len(idontwant_inner_len as u64) + idontwant_inner_len;
    let total = TAG_LEN + varint_len(control_inner_len as u64) + control_inner_len;

    let mut reservation = producer.reserve(total, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    let mut cursor: &mut [u8] = &mut out[..total];

    // RPC.control (field 3, LD).
    Tag::new(3, WireType::LengthDelimited).encode(&mut cursor);
    encode_varint(control_inner_len as u64, &mut cursor);

    // ControlMessage.idontwant (field 5, LD) — single ControlIDontWant entry.
    Tag::new(5, WireType::LengthDelimited).encode(&mut cursor);
    encode_varint(idontwant_inner_len as u64, &mut cursor);

    // ControlIDontWant.message_ids (field 1, bytes, repeated).
    for id in message_ids {
        Tag::new(1, WireType::LengthDelimited).encode(&mut cursor);
        encode_bytes(&id[..], &mut cursor);
    }

    reservation.increment_offset(total);
    Ok(reservation.read())
}

/// Encode an `RPC { subscriptions: [SubOpts { subscribe = true, topic_id }*] }`
/// frame — one entry per topic. `topics` are wire-form strings (the result
/// of `GossipTopic::to_wire`).
pub fn copy_subscribes_to_protobuf_output(
    producer: &mut TProducer,
    topics: &[&str],
) -> Result<TCacheRead, Error> {
    encode_sub_opts(producer, topics, true)
}

/// As `copy_subscribes_to_protobuf_output` but with `subscribe = false`
/// in every entry.
pub fn copy_unsubscribes_to_protobuf_output(
    producer: &mut TProducer,
    topics: &[&str],
) -> Result<TCacheRead, Error> {
    encode_sub_opts(producer, topics, false)
}

/// Subscribe / unsubscribe share wire shape; only the bool differs.
fn encode_sub_opts(
    producer: &mut TProducer,
    topics: &[&str],
    subscribe: bool,
) -> Result<TCacheRead, Error> {
    // RPC.subscriptions = field 1 (LD, repeated SubOpts).
    // SubOpts.subscribe = field 1 (varint), topic_id = field 2 (string).
    // All field numbers ≤ 15 → 1-byte tags. Bool encodes as 1-byte varint.
    const TAG_LEN: usize = 1;
    const BOOL_LEN: usize = 1;

    let total: usize = topics
        .iter()
        .map(|t| {
            let inner = TAG_LEN + BOOL_LEN + TAG_LEN + string_encoded_len(t);
            TAG_LEN + varint_len(inner as u64) + inner
        })
        .sum();

    let mut reservation = producer.reserve(total, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    let mut cursor: &mut [u8] = &mut out[..total];

    for topic in topics {
        let inner = TAG_LEN + BOOL_LEN + TAG_LEN + string_encoded_len(topic);
        // RPC.subscriptions (field 1, LD) — one wrap per entry.
        Tag::new(1, WireType::LengthDelimited).encode(&mut cursor);
        encode_varint(inner as u64, &mut cursor);
        // SubOpts.subscribe (field 1, varint).
        Tag::new(1, WireType::Varint).encode(&mut cursor);
        encode_varint(subscribe as u64, &mut cursor);
        // SubOpts.topic_id (field 2, string).
        Tag::new(2, WireType::LengthDelimited).encode(&mut cursor);
        encode_string(topic, &mut cursor);
    }

    reservation.increment_offset(total);
    Ok(reservation.read())
}

/// Encode `RPC { control: ControlMessage { graft: [ControlGraft { topic_id }*]
/// } }`.
pub fn copy_grafts_to_protobuf_output(
    producer: &mut TProducer,
    topics: &[&str],
) -> Result<TCacheRead, Error> {
    encode_control_topics(producer, topics, /* ControlMessage.graft */ 3)
}

/// Encode `RPC { control: ControlMessage { prune: [ControlPrune { topic_id }*]
/// } }`. PX peer hints (`ControlPrune.peers`, field 2) and `backoff` (field 3)
/// are omitted — peer-exchange isn't wired up and most clients
/// (e.g. Lighthouse) don't send peer records anyway.
pub fn copy_prunes_to_protobuf_output(
    producer: &mut TProducer,
    topics: &[&str],
) -> Result<TCacheRead, Error> {
    encode_control_topics(producer, topics, /* ControlMessage.prune */ 4)
}

/// Graft and prune share wire shape: a `ControlGraft`/`ControlPrune` per
/// topic, each carrying just `topic_id` (field 1, string), wrapped in a
/// single `ControlMessage` whose field number distinguishes them.
fn encode_control_topics(
    producer: &mut TProducer,
    topics: &[&str],
    cm_field: u32,
) -> Result<TCacheRead, Error> {
    // RPC.control = field 3 (LD), ControlMessage.{graft|prune} = field 3|4
    // (LD, repeated), {ControlGraft|ControlPrune}.topic_id = field 1
    // (string). All field numbers ≤ 15 → 1-byte tags.
    const TAG_LEN: usize = 1;

    let cm_inner: usize = topics
        .iter()
        .map(|t| {
            let entry = TAG_LEN + string_encoded_len(t);
            TAG_LEN + varint_len(entry as u64) + entry
        })
        .sum();
    let total = TAG_LEN + varint_len(cm_inner as u64) + cm_inner;

    let mut reservation = producer.reserve(total, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    let mut cursor: &mut [u8] = &mut out[..total];

    // RPC.control (field 3, LD).
    Tag::new(3, WireType::LengthDelimited).encode(&mut cursor);
    encode_varint(cm_inner as u64, &mut cursor);

    for topic in topics {
        let entry = TAG_LEN + string_encoded_len(topic);
        // ControlMessage.{graft|prune} (LD, repeated).
        Tag::new(cm_field, WireType::LengthDelimited).encode(&mut cursor);
        encode_varint(entry as u64, &mut cursor);
        // ControlGraft|ControlPrune.topic_id (field 1, string).
        Tag::new(1, WireType::LengthDelimited).encode(&mut cursor);
        encode_string(topic, &mut cursor);
    }

    reservation.increment_offset(total);
    Ok(reservation.read())
}

fn gossip_topic(topic: &str, fork_digest_hex: &str) -> Result<GossipTopic, Error> {
    GossipTopic::from_wire(topic, fork_digest_hex).inspect_err(|_| {
        tracing::warn!(topic, "invalid gossipsub topic");
    })
}

fn message_id(
    bytes: &[u8],
    stream_id: &P2pStreamId,
    adapter: &mut SpineAdapter<SilverSpine>,
) -> Option<MessageId> {
    match (bytes).try_into() {
        Ok(hash) => Some(MessageId { id: hash }),
        Err(_) => {
            tracing::warn!(?bytes, ?stream_id, "invalid message hash");
            adapter.produce(PeerEvent::P2pGossipInvalidControl { p2p_peer: stream_id.peer() });
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use buffa::MessageView;
    use silver_common::TCache;

    use super::*;
    use crate::generated::RPCView;

    fn read_bytes(tc: TCacheRead, producer: &silver_common::TProducer) -> Vec<u8> {
        let consumer = producer.cache_ref().random_access().unwrap();
        let (bytes, _) = consumer.read_at(tc.seq()).unwrap();
        bytes.to_vec()
    }

    #[test]
    fn subscribes_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let topics = ["beacon_block", "voluntary_exit"];
        let topic_refs: Vec<&str> = topics.iter().copied().collect();
        let tc = copy_subscribes_to_protobuf_output(&mut producer, &topic_refs).unwrap();

        let bytes = read_bytes(tc, &producer);
        let rpc = RPCView::decode_view(&bytes).unwrap();
        let subs: Vec<_> = (&rpc.subscriptions).into_iter().collect();
        assert_eq!(subs.len(), 2);
        for (s, expect) in subs.iter().zip(topics.iter()) {
            assert_eq!(s.subscribe, Some(true));
            assert_eq!(s.topic_id, Some(*expect));
        }
    }

    #[test]
    fn unsubscribes_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let topic_refs: Vec<&str> = vec!["beacon_block"];
        let tc = copy_unsubscribes_to_protobuf_output(&mut producer, &topic_refs).unwrap();

        let bytes = read_bytes(tc, &producer);
        let rpc = RPCView::decode_view(&bytes).unwrap();
        let subs: Vec<_> = (&rpc.subscriptions).into_iter().collect();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].subscribe, Some(false));
        assert_eq!(subs[0].topic_id, Some("beacon_block"));
    }

    #[test]
    fn grafts_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let topic_refs: Vec<&str> = vec!["beacon_block", "sync_committee_3"];
        let tc = copy_grafts_to_protobuf_output(&mut producer, &topic_refs).unwrap();

        let bytes = read_bytes(tc, &producer);
        let rpc = RPCView::decode_view(&bytes).unwrap();
        let ctrl = rpc.control.as_option().expect("control present");
        let grafts: Vec<_> = (&ctrl.graft).into_iter().collect();
        assert_eq!(grafts.len(), 2);
        assert_eq!(grafts[0].topic_id, Some("beacon_block"));
        assert_eq!(grafts[1].topic_id, Some("sync_committee_3"));
        // Prune list is empty in a graft frame.
        assert_eq!((&ctrl.prune).into_iter().count(), 0);
    }

    #[test]
    fn prunes_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let topic_refs: Vec<&str> = vec!["data_column_sidecar_42"];
        let tc = copy_prunes_to_protobuf_output(&mut producer, &topic_refs).unwrap();

        let bytes = read_bytes(tc, &producer);
        let rpc = RPCView::decode_view(&bytes).unwrap();
        let ctrl = rpc.control.as_option().expect("control present");
        let prunes: Vec<_> = (&ctrl.prune).into_iter().collect();
        assert_eq!(prunes.len(), 1);
        assert_eq!(prunes[0].topic_id, Some("data_column_sidecar_42"));
        assert_eq!((&ctrl.graft).into_iter().count(), 0);
    }
}
