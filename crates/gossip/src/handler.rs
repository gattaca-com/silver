use std::{collections::VecDeque, io::Write, time::Instant};

use buffa::MessageView;
use flux::spine::SpineAdapter;
use silver_common::{
    Error, GOSSIP_TOPIC_COUNTER_SLOTS, GossipMsgIn, GossipMsgOut, GossipTopic,
    LOCAL_GOSSIP_STREAM_ID, MessageId, Nanos, NewGossipMsg, P2pStreamId, PeerControl, PeerEvent,
    SilverSpine, TCacheProducer, TCacheRead, TProducer, TRandomAccess, msg_id_valid_snappy,
    ssz_view::StatusView,
};

use crate::{
    GossipHandlerEvent,
    control::{
        self, copy_ihaves_to_protobuf_output, handle_grafts, handle_idontwants, handle_ihaves,
        handle_iwants, handle_prunes, handle_subscriptions,
    },
    dedup::DedupCache,
    generated::RPCView,
    mcache::MessageCache,
    message::{copy_compressed_to_protobuf_output, handle_incoming},
};

/// Reads all incoming gossip protobuf messages (sequential consumer):
/// - handles control messages and emits spine messages
/// - deduplicates individual gossip messages
///   - decompresses individual messages and writes SSZ to downstream TCache
///   - copies individual message snappy to message cache TCache wrapped in
///     protobuf ready for sending
///   - produces `NewGossipMsg` on spine for downstream consumers
///  - periodically generates new IHAVE messages
///    - produces `NewIHaveMsg`s on spine
pub struct GossipHandler {
    incoming_gossip: TRandomAccess,
    incoming_gossip_publish: TProducer,
    pub fork_digest_hex: String,
    dedup_cache: DedupCache,

    // publisher of gossip message protobufs.
    pub mcache_publish: TProducer,
    mcache: MessageCache,

    // scratch buffer for iwant meessage ids.
    iwant_buffer: Vec<MessageId>,

    // snappy block-compression for locally published messages.
    snap_encoder: snap::raw::Encoder,
    snap_scratch: Vec<u8>,

    events: VecDeque<GossipHandlerEvent>,
}

impl GossipHandler {
    pub fn new(
        incoming_gossip: TRandomAccess,
        ssz_gossip_publish: TProducer,
        protobuf_gossip_publish: TProducer,
        fork_digest_hex: String,
    ) -> Result<Self, Error> {
        let mcache_consumer =
            protobuf_gossip_publish.cache_ref().random_access("gossip_mcache", false)?;
        let mcache = MessageCache::new(mcache_consumer);

        Ok(Self {
            incoming_gossip,
            incoming_gossip_publish: ssz_gossip_publish,
            fork_digest_hex,
            dedup_cache: DedupCache::default(),
            mcache_publish: protobuf_gossip_publish,
            mcache,
            iwant_buffer: Vec::with_capacity(256),
            snap_encoder: snap::raw::Encoder::new(),
            snap_scratch: Vec::new(),
            events: VecDeque::with_capacity(64),
        })
    }

    fn generate_ihave_messages(&mut self, now: Instant, emit: &mut impl FnMut(GossipHandlerEvent)) {
        if self.mcache.generate_ihaves(now) {
            let mut seen = [false; GOSSIP_TOPIC_COUNTER_SLOTS];
            for topic in self.mcache.topics() {
                if seen[topic.counter_slot()] {
                    continue;
                }
                seen[topic.counter_slot()] = true;

                let msgs_iter = self.mcache.get_ihaves(topic);
                let (msg_count, _) = msgs_iter.size_hint(); // exact size iterator
                if msg_count > 0 {
                    if let Ok(tcache) = copy_ihaves_to_protobuf_output(
                        &mut self.mcache_publish,
                        &topic.to_wire(&self.fork_digest_hex),
                        msgs_iter,
                    ) {
                        emit(GossipHandlerEvent::PeerEvent(PeerEvent::OutboundIHave {
                            topic: *topic,
                            msg_count,
                            protobuf: tcache,
                        }));
                    }
                }
            }
        }
    }

    /// Publish a locally-obtained, already-validated message on `topic`:
    /// compress, wrap as protobuf into the outgoing tcache, register with
    /// dedup + mcache (so gossip copies dedupe and IWANTs can be served).
    /// Returns `None` when the message was already seen via gossip, or
    /// pre-Status (no fork digest yet).
    pub fn publish(&mut self, topic: GossipTopic, ssz: &[u8]) -> Option<(MessageId, TCacheRead)> {
        if self.fork_digest_hex.is_empty() {
            return None;
        }
        if ssz.len() > topic.max_uncompressed_size() {
            tracing::error!(?topic, len = ssz.len(), "outgoing gossip payload too large");
            return None;
        }
        let wire = topic.to_wire(&self.fork_digest_hex);
        self.snap_scratch.resize(snap::raw::max_compress_len(ssz.len()), 0);
        let n = match self.snap_encoder.compress(ssz, &mut self.snap_scratch) {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(?e, ?topic, "publish snappy compress failed");
                return None;
            }
        };
        let msg_id = msg_id_valid_snappy(&wire, ssz);
        let fast_hash = self.dedup_cache.contains_fast(&wire, &self.snap_scratch[..n]).ok()?;
        if !self.dedup_cache.insert(fast_hash, msg_id) {
            return None;
        }
        let read = copy_compressed_to_protobuf_output(
            &mut self.mcache_publish,
            &self.snap_scratch[..n],
            &wire,
        )
        .inspect_err(|e| tracing::error!(?e, ?topic, "publish protobuf write failed"))
        .ok()?;
        self.mcache.insert(msg_id, topic, read);
        Some((msg_id, read))
    }

    /// Inject a locally-originated, not-yet-validated SSZ message at the same
    /// boundary as decoded inbound gossip. The queued TCache references are
    /// retained by `NewGossipMsg` until Beacon State accepts or rejects it;
    /// mcache insertion remains on the accepted `PeerEvent::SendGossip` path.
    ///
    /// Local submissions deliberately bypass inbound deduplication so every
    /// API request receives a Beacon State validation outcome. `Ok(None)`
    /// means the fork digest is not available yet.
    pub fn inject_local(
        &mut self,
        topic: GossipTopic,
        ssz: &[u8],
        recv_ts: Nanos,
    ) -> Result<Option<MessageId>, Error> {
        if self.fork_digest_hex.is_empty() {
            return Ok(None);
        }
        if ssz.len() > topic.max_uncompressed_size() {
            return Err(Error::GossipPayloadTooLarge);
        }

        let wire = topic.to_wire(&self.fork_digest_hex);
        self.snap_scratch.resize(snap::raw::max_compress_len(ssz.len()), 0);
        let compressed_len = self.snap_encoder.compress(ssz, &mut self.snap_scratch)?;
        let compressed = &self.snap_scratch[..compressed_len];
        let msg_id = msg_id_valid_snappy(&wire, ssz);
        let fast_hash = self.dedup_cache.contains_fast(&wire, compressed).ok();

        let mut ssz_reservation =
            self.incoming_gossip_publish.reserve(ssz.len(), false).ok_or(Error::BufferTooSmall)?;
        ssz_reservation.write_all(ssz)?;
        let ssz_read = ssz_reservation.read();

        // From here onward a network duplicate must not race this local
        // candidate into Beacon State first. Roll the entry back if either
        // TCache message cannot be completed.
        let inserted =
            fast_hash.is_some_and(|fast_hash| self.dedup_cache.insert(fast_hash, msg_id));
        let protobuf =
            match copy_compressed_to_protobuf_output(&mut self.mcache_publish, compressed, &wire) {
                Ok(protobuf) => protobuf,
                Err(error) => {
                    if inserted {
                        self.dedup_cache.remove(fast_hash.unwrap(), &msg_id);
                    }
                    return Err(error);
                }
            };
        if let Err(error) = ssz_reservation.flush() {
            if inserted {
                self.dedup_cache.remove(fast_hash.unwrap(), &msg_id);
            }
            return Err(error.into());
        }

        self.events.push_back(GossipHandlerEvent::NewGossip(NewGossipMsg {
            stream_id: LOCAL_GOSSIP_STREAM_ID,
            topic,
            msg_hash: msg_id,
            recv_ts,
            ssz: ssz_read,
            protobuf,
        }));
        Ok(Some(msg_id))
    }

    pub fn set_fork_digest(&mut self, status_ssz: &[u8; 92]) {
        self.fork_digest_hex = hex::encode(StatusView::fork_digest(status_ssz));
    }

    pub fn handle_peer_control(&mut self, peer_control: PeerControl) {
        let mut events = std::mem::take(&mut self.events);
        self.handle_peer_control_inner(peer_control, &mut |e| events.push_back(e));
        self.events = events;
    }

    pub fn mcache_insert(&mut self, id: MessageId, topic: GossipTopic, protobuf: TCacheRead) {
        self.mcache.insert(id, topic, protobuf);
    }

    pub fn pop_event(&mut self) -> Option<GossipHandlerEvent> {
        self.events.pop_front()
    }

    fn handle_peer_control_inner(
        &mut self,
        peer_control: PeerControl,
        emit: &mut impl FnMut(GossipHandlerEvent),
    ) {
        match peer_control {
            PeerControl::P2pGossipSubscribe { p2p: _, p2p_connection, topic } => {
                if let Ok(tcache) =
                    control::copy_subscribes_to_protobuf_output(&mut self.mcache_publish, &[
                        &topic.to_wire(&self.fork_digest_hex)
                    ])
                {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip subscribe");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            PeerControl::P2pGossipUnsubscribe { p2p: _, p2p_connection, topic } => {
                if let Ok(tcache) =
                    control::copy_unsubscribes_to_protobuf_output(&mut self.mcache_publish, &[
                        &topic.to_wire(&self.fork_digest_hex),
                    ])
                {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip unsubscribe");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            PeerControl::P2pGossipGraft { p2p: _, p2p_connection, topic } => {
                if let Ok(tcache) =
                    control::copy_grafts_to_protobuf_output(&mut self.mcache_publish, &[
                        &topic.to_wire(&self.fork_digest_hex)
                    ])
                {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip graft");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            PeerControl::P2pGossipPrune { p2p: _, p2p_connection, topic, backoff_seconds } => {
                if let Ok(tcache) = control::copy_prunes_to_protobuf_output(
                    &mut self.mcache_publish,
                    &[&topic.to_wire(&self.fork_digest_hex)],
                    backoff_seconds,
                ) {
                    tracing::debug!(p2p_connection, ?topic, "Emit new gossip prune");
                    emit(GossipHandlerEvent::SendGossip(GossipMsgOut {
                        peer_id: p2p_connection,
                        tcache,
                    }));
                }
            }
            _ => {} // no_ops for this tile
        }
    }

    pub fn spin(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        let mut events = std::mem::take(&mut self.events);
        let did_work = self.spin_inner(adapter, &mut |e| events.push_back(e));
        self.events = events;
        did_work
    }

    fn spin_inner(
        &mut self,
        adapter: &mut SpineAdapter<SilverSpine>,
        emit: &mut impl FnMut(GossipHandlerEvent),
    ) -> bool {
        let mut did_work = false;
        let now = Instant::now();
        self.dedup_cache.maybe_rotate(now);
        self.mcache.maybe_rotate(now);
        self.generate_ihave_messages(now, emit);
        self.incoming_gossip.free();

        adapter.consume(|msg: GossipMsgIn, _producers| {
            did_work = true;

            let acquired = self.incoming_gossip.acquire(msg.tcache);
            let Ok((mut buffer, recv_ts)) = acquired.buffer() else {
                return;
            };

            // Incoming gossip messages are prefixed with P2pStreamId
            let stream_id: &P2pStreamId = buffer.into();
            tracing::trace!(?stream_id, len = buffer.len(), "gossip protobuf recv");

            buffer = &buffer[size_of::<P2pStreamId>()..];

            let gossip_proto = match RPCView::decode_view(buffer) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(?stream_id, len = buffer.len(), ?e, "RPC decode failed");
                    None
                }
            };
            if let Some(gossip_proto) = gossip_proto {
                handle_subscriptions(
                    stream_id,
                    gossip_proto.subscriptions,
                    &self.fork_digest_hex,
                    emit,
                );

                if let Some(control) = gossip_proto.control.as_option() {
                    handle_grafts(stream_id, &control.graft, &self.fork_digest_hex, emit);
                    handle_prunes(stream_id, &control.prune, &self.fork_digest_hex, emit);
                    handle_iwants(stream_id, &control.iwant, &mut self.mcache, emit);
                    handle_idontwants(stream_id, &control.idontwant, emit);
                    handle_ihaves(
                        stream_id,
                        &control.ihave,
                        &self.fork_digest_hex,
                        &self.mcache,
                        &self.dedup_cache,
                        &mut self.mcache_publish,
                        emit,
                        &mut self.iwant_buffer,
                    );
                }

                for gossip_msg in &gossip_proto.publish {
                    if gossip_msg.key.is_some() ||
                        gossip_msg.signature.is_some() ||
                        gossip_msg.seqno.is_some() ||
                        gossip_msg.from.is_some()
                    {
                        // Spec violation
                        emit(GossipHandlerEvent::PeerEvent(PeerEvent::P2pGossipInvalidFrame {
                            p2p_peer: stream_id.peer(),
                        }));
                        continue;
                    }
                    if let Some(snappy_data) = gossip_msg.data {
                        if let Err(e) = handle_incoming(
                            gossip_msg.topic,
                            snappy_data,
                            stream_id,
                            &self.fork_digest_hex,
                            recv_ts,
                            &mut self.dedup_cache,
                            &mut self.incoming_gossip_publish,
                            &mut self.mcache_publish,
                            emit,
                        ) {
                            tracing::error!(
                                ?e,
                                ?stream_id,
                                topic = gossip_msg.topic,
                                "error handling incoming gossip message"
                            );
                        }
                    }
                }
            }
        });

        // Free read data.
        self.incoming_gossip.free();

        did_work
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{TCache, TCacheProducer, ssz_view::SINGLE_ATT_SIZE};

    use super::*;

    #[test]
    fn local_injection_uses_inbound_tcaches_without_precaching() {
        let incoming = TCache::producer("inject_local_in", 1 << 12);
        let incoming_consumer = incoming
            .cache_ref()
            .random_access("inject_local_handler", true)
            .expect("incoming consumer");

        let ssz_producer = TCache::producer("inject_local_ssz", 1 << 12);
        let mut ssz_consumer = ssz_producer
            .cache_ref()
            .random_access("inject_local_ssz_test", true)
            .expect("ssz consumer");
        let protobuf_producer = TCache::producer("inject_local_protobuf", 1 << 12);
        let mut protobuf_consumer = protobuf_producer
            .cache_ref()
            .random_access("inject_local_protobuf_test", true)
            .expect("protobuf consumer");

        let mut handler = GossipHandler::new(
            incoming_consumer,
            ssz_producer,
            protobuf_producer,
            "01020304".to_owned(),
        )
        .expect("gossip handler");
        let topic = GossipTopic::BeaconAttestation(7);
        let ssz = [42; SINGLE_ATT_SIZE];

        let msg_id = handler
            .inject_local(topic, &ssz, Nanos::now())
            .expect("local injection")
            .expect("new message");
        let message = match handler.pop_event().expect("new gossip event") {
            GossipHandlerEvent::NewGossip(message) => message,
            GossipHandlerEvent::PeerEvent(_) | GossipHandlerEvent::SendGossip(_) => {
                panic!("unexpected local injection event")
            }
        };

        assert_eq!(message.stream_id, LOCAL_GOSSIP_STREAM_ID);
        assert_eq!(message.topic, topic);
        assert_eq!(message.msg_hash, msg_id);
        assert_eq!(ssz_consumer.acquire(message.ssz).buffer().unwrap().0, ssz);
        assert!(!protobuf_consumer.acquire(message.protobuf).buffer().unwrap().0.is_empty());
        assert!(handler.dedup_cache.has(&msg_id));
        assert!(!handler.mcache.has(&msg_id));

        assert_eq!(handler.inject_local(topic, &ssz, Nanos::now()).unwrap(), Some(msg_id));
        let duplicate = match handler.pop_event().expect("duplicate local gossip event") {
            GossipHandlerEvent::NewGossip(message) => message,
            GossipHandlerEvent::PeerEvent(_) | GossipHandlerEvent::SendGossip(_) => {
                panic!("unexpected duplicate local injection event")
            }
        };
        assert_eq!(duplicate.msg_hash, msg_id);

        handler.mcache_insert(msg_id, topic, message.protobuf);
        assert!(handler.mcache.has(&msg_id));
    }
}
