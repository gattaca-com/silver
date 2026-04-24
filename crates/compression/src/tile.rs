use std::time::Instant;

use buffa::MessageView;
use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{Error, MessageId, P2pStreamId, PeerEvent, SilverSpine, TConsumer, TProducer};

use crate::{
    control::{
        copy_ihaves_to_protobuf_output, handle_grafts, handle_idontwants, handle_ihaves,
        handle_iwants, handle_prunes, handle_subscriptions,
    },
    dedup::DedupCache,
    generated::RPCView,
    mcache::MessageCache,
    message::handle_incoming,
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
pub struct GossipCompressionTile {
    incoming_gossip: TConsumer,
    incoming_gossip_publish: TProducer,
    fork_digest_hex: String,
    dedup_cache: DedupCache,

    // publisher of gossip message protobufs.
    mcache_publish: TProducer,
    mcache: MessageCache,

    // scratch buffer for iwant meessage ids.
    iwant_buffer: Vec<MessageId>,
}

impl GossipCompressionTile {
    pub fn new(
        incoming_gossip: TConsumer,
        ssz_gossip_publish: TProducer,
        protobuf_gossip_publish: TProducer,
        fork_digest_hex: String,
    ) -> Result<Self, Error> {
        let mcache_consumer = protobuf_gossip_publish.cache_ref().random_access()?;
        let mcache = MessageCache::new(mcache_consumer);

        Ok(Self {
            incoming_gossip,
            incoming_gossip_publish: ssz_gossip_publish,
            fork_digest_hex,
            dedup_cache: DedupCache::default(),
            mcache_publish: protobuf_gossip_publish,
            mcache,
            iwant_buffer: Vec::with_capacity(256),
        })
    }

    fn generate_ihave_messages(&mut self, now: Instant, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.mcache.generate_ihaves(now) {
            for topic in self.mcache.topics() {
                let msgs_iter = self.mcache.get_ihaves(topic);
                let (msg_count, _) = msgs_iter.size_hint(); // exact size iterator
                if msg_count > 0 {
                    if let Ok(tcache) = copy_ihaves_to_protobuf_output(
                        &mut self.mcache_publish,
                        &topic.to_wire(&self.fork_digest_hex),
                        msgs_iter,
                    ) {
                        adapter.produce(PeerEvent::OutboundIHave {
                            topic: *topic,
                            msg_count,
                            protobuf: tcache,
                        });
                    }
                }
            }
        }
    }
}

impl Tile<SilverSpine> for GossipCompressionTile {
    fn loop_body(&mut self, adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        let now = Instant::now();
        self.dedup_cache.maybe_rotate(now);
        self.mcache.maybe_rotate(now);
        self.generate_ihave_messages(now, adapter);

        while let Ok((mut buffer, recv_ts)) = self.incoming_gossip.read() {
            // Incoming gossip messages are prefixed with P2pStreamId
            let stream_id: &P2pStreamId = buffer.into();
            buffer = &buffer[size_of::<P2pStreamId>()..];

            if let Ok(gossip_proto) = RPCView::decode_view(buffer) {
                handle_subscriptions(
                    stream_id,
                    gossip_proto.subscriptions,
                    &self.fork_digest_hex,
                    adapter,
                );

                if let Some(control) = gossip_proto.control.as_option() {
                    handle_grafts(stream_id, &control.graft, &self.fork_digest_hex, adapter);
                    handle_prunes(stream_id, &control.prune, &self.fork_digest_hex, adapter);
                    handle_iwants(stream_id, &control.iwant, &mut self.mcache, adapter);
                    handle_idontwants(stream_id, &control.idontwant, adapter);
                    handle_ihaves(
                        stream_id,
                        &control.ihave,
                        &self.fork_digest_hex,
                        &self.mcache,
                        &mut self.mcache_publish,
                        adapter,
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
                        adapter.produce(PeerEvent::P2pGossipInvalidFrame {
                            p2p_peer: stream_id.peer(),
                        });
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
                            &mut self.mcache,
                            adapter,
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
            self.incoming_gossip.free();
        }
    }
}
