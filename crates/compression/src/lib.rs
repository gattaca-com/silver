use std::time::Instant;

use buffa::MessageView;
use flux::tile::Tile;
use silver_common::{P2pStreamId, SilverSpine, TConsumer, TProducer};

use crate::{
    control::{
        handle_grafts, handle_idontwants, handle_ihaves, handle_iwants, handle_prunes,
        handle_subscriptions,
    },
    dedup::DedupCache,
    generated::RPCView,
    mcache::MessageCache,
};

mod control;
mod dedup;
#[path = "generated/protobuf.gossipsub.rs"]
#[allow(dead_code)]
mod generated;
mod mcache;
mod message;

/// Reads all incoming gossip protobuf messages (sequential consumer):
/// - handles control messages and emits spine messages
/// - deduplicates individual gossip messages
///   - decompresses individual messages and writes SSZ to downstream TCache
///   - copies individual message snappy to message cache TCache wrapped in
///     protobuf ready for sending
///   - publishes TCacheRead for message cache messages
///   - produces NewGossipMsg on spine for downstream consumers
pub struct GossipCompressionTile {
    incoming_gossip: TConsumer,
    incoming_gossip_publish: TProducer,
    fork_digest_hex: String,
    dedup_cache: DedupCache,

    // publisher of gossip message protobufs.
    mcache_publish: TProducer,
    mcache: MessageCache,
}

impl Tile<SilverSpine> for GossipCompressionTile {
    fn loop_body(&mut self, adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        let now = Instant::now();
        self.dedup_cache.maybe_rotate(now);
        self.mcache.maybe_rotate(now);

        // Mark consumed messages as free.
        self.incoming_gossip.free();

        while let Ok(mut buffer) = self.incoming_gossip.read() {
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
                    handle_iwants(stream_id, &control.iwant, &self.mcache, adapter);
                    handle_idontwants(stream_id, &control.idontwant, adapter);
                    handle_ihaves(
                        stream_id,
                        &control.ihave,
                        &self.fork_digest_hex,
                        &self.mcache,
                        adapter,
                    );
                }

                for gossip_msg in &gossip_proto.publish {
                    if gossip_msg.key.is_some() ||
                        gossip_msg.signature.is_some() ||
                        gossip_msg.seqno.is_some() ||
                        gossip_msg.from.is_some()
                    {
                        // Spec violation
                        // TODO peer behaviour message
                        continue;
                    }
                    if let Some(snappy_data) = gossip_msg.data {
                        if let Err(e) = Self::handle_incoming(
                            gossip_msg.topic,
                            snappy_data,
                            stream_id,
                            &self.fork_digest_hex,
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
        }
    }
}
