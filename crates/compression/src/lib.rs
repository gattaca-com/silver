use std::{io::Write, time::Instant};

use buffa::MessageView;
use flux::tile::Tile;
use silver_common::{DecompressedGossipMsg, Error, GossipTopic, P2pStreamId, PeerEvent, SilverSpine, TConsumer, TProducer, TReservation};

use crate::{dedup::DedupCache, generated::RPCView, hash::MessageId};

#[path = "generated/protobuf.gossipsub.rs"]
mod generated;

mod dedup;
pub mod hash;

pub struct GossipCompressionTile {
    incoming_gossip: TConsumer,
    incoming_gossip_publish: TProducer,
    outgoing_gossip: TConsumer,
    outgoing_gossip_publish: TProducer,
    fork_digest_hex: String,
    dedup_cache: DedupCache,
}

impl Tile<SilverSpine> for GossipCompressionTile {
    fn loop_body(&mut self, adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        let now = Instant::now();
        self.dedup_cache.maybe_rotate(now);

        // Mark consumed messages as free.
        self.incoming_gossip.free();

        while let Ok(mut buffer) = self.incoming_gossip.read() {
            // Incoming gossip messages are prefixed with P2pStreamId
            let stream_id: &P2pStreamId = buffer.into();
            buffer = &buffer[size_of::<P2pStreamId>()..];

            if let Ok(gossip_proto) = RPCView::decode_view(buffer) {   
                // TODO too many subscription is bad behaviour

                for subscription in gossip_proto.subscriptions {
                    if let Some(topic) = subscription.topic_id && let Some(subscribe) = subscription.subscribe {
                        let topic = match GossipTopic::from_wire(topic, &self.fork_digest_hex) {
                            Ok(topic) => topic,
                            Err(_) => {
                                tracing::warn!(topic, "invalid gossipsub topic");
                                continue;
                            }
                        };
                        if subscribe {
                            adapter.produce(PeerEvent::P2pGossipTopicSubscribe { p2p_peer: stream_id.peer(), topic });
                        } else {
                            adapter.produce(PeerEvent::P2pGossipTopicUnsubscribe { p2p_peer: stream_id.peer(), topic });
                        }
                    }
                }

                // TODO too many controls is bad behaviour

                if let Some(control) = gossip_proto.control.as_option() {
                    for graft in &control.graft {
                        if let Some(topic) = graft.topic_id {
                            let topic = match GossipTopic::from_wire(topic, &self.fork_digest_hex) {
                                Ok(topic) => topic,
                                Err(_) => {
                                    tracing::warn!(topic, "invalid gossipsub topic");
                                    continue;
                                }
                            };
                            adapter.produce(PeerEvent::P2pGossipTopicGraft { p2p_peer: stream_id.peer(), topic });
                        }
                    }
                    for prune in &control.prune {
                        if let Some(topic) = prune.topic_id {
                            let topic = match GossipTopic::from_wire(topic, &self.fork_digest_hex) {
                                Ok(topic) => topic,
                                Err(_) => {
                                    tracing::warn!(topic, "invalid gossipsub topic");
                                    continue;
                                }
                            };
                            adapter.produce(PeerEvent::P2pGossipTopicPrune { p2p_peer: stream_id.peer(), topic });
                        }
                    }
                    for iwant in &control.iwant {
                        for want in &iwant.message_ids {
                            let hash: MessageId = match (*want).try_into() {
                                Ok(hash) => hash,
                                Err(_) => {
                                    tracing::warn!(?want, ?stream_id, "invalid want hash");
                                    // TODO produce peer behaviour msg
                                    continue;
                                }
                            };
                            adapter.produce(PeerEvent::P2pGossipWant { p2p_peer: stream_id.peer(), hash }); 
                        }
                    }
                    for idontwant in &control.idontwant {
                        for dontwant in &idontwant.message_ids {
                            let hash: MessageId = match (*dontwant).try_into() {
                                Ok(hash) => hash,
                                Err(_) => {
                                    tracing::warn!(?dontwant, ?stream_id, "invalid dontwant hash");
                                    // TODO produce peer behaviour msg
                                    continue;
                                }
                            };
                            adapter.produce(PeerEvent::P2pGossipDontWant { p2p_peer: stream_id.peer(), hash }); 
                        }
                    }
                    for ihave in &control.ihave {
                        if let Some(topic) = ihave.topic_id {
                            let topic = match GossipTopic::from_wire(topic, &self.fork_digest_hex) {
                                Ok(topic) => topic,
                                Err(_) => {
                                    tracing::warn!(topic, "invalid gossipsub topic");
                                    continue;
                                }
                            };
                            for have in &ihave.message_ids {
                                let hash: MessageId = match (*have).try_into() {
                                    Ok(hash) => hash,
                                    Err(_) => {
                                        tracing::warn!(?have, ?stream_id, "invalid dontwant hash");
                                        // TODO produce peer behaviour msg
                                        continue;
                                    }
                                };
                                adapter.produce(PeerEvent::P2pGossipHave { p2p_peer: stream_id.peer(), hash, topic }); 
                            }
                        }
                    }
                }

                // TODO too many gossip msg is bad beaviour

                for gossip_msg in &gossip_proto.publish {
                    if gossip_msg.key.is_some() || gossip_msg.signature.is_some() || gossip_msg.seqno.is_some() || gossip_msg.from.is_some() {
                        // Spec violation
                        // TODO peer behaviour message
                        continue;
                    }
                    if let Some(data) = gossip_msg.data {
                        // Fast duplicate check. 
                        let fast_id = match self.dedup_cache.contains_fast(data) {
                            Some(fast_hash) => fast_hash,
                            None => continue, // duplicate
                        };

                        let topic = match GossipTopic::from_wire(gossip_msg.topic, &self.fork_digest_hex) {
                            Ok(topic) => topic,
                            Err(_) => {
                                tracing::warn!(topic=gossip_msg.topic, "invalid gossipsub topic");
                                continue;
                            }
                        };
                        // Decompress: block snappy. 
                        match read_message_length(data, &topic) {
                            Ok(len) => {
                                // TODO max ssz size check by topic / type

                                // Alloc into upstream tcache.
                                let length = len + size_of::<DecompressedGossipMsg>();
                                let mut reservation = match self.incoming_gossip_publish.reserve(length, false) {
                                    Some(reservation) => reservation,
                                    None => {
                                        tracing::error!(?stream_id, len, "failed to allocate space to decompress gossip message!");
                                        continue;
                                    }
                                };
                                match decompress_to_reservation(&self.incoming_gossip_publish, data, &mut reservation, stream_id, gossip_msg.topic) {
                                    // Second dedup check. Different snappy bytes can decompress to the same message bytes so
                                    // this second chekc is required. 
                                    Ok(msg_id) if self.dedup_cache.insert(fast_id, msg_id) => {
                                        if let Err(e) = reservation.flush() {
                                            tracing::error!(?e, ?stream_id, ?topic, "failed to flush reservaton");
                                        }
                                    }
                                    _ => {
                                        let hash = hash::msg_id_invalid_snappy(gossip_msg.topic, data);
                                        if self.dedup_cache.insert(fast_id, hash) {
                                            adapter.produce(PeerEvent::P2pGossipInvalidMsg { p2p_peer: stream_id.peer(), topic, hash });
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                let hash = hash::msg_id_invalid_snappy(gossip_msg.topic, data);
                                if self.dedup_cache.insert(fast_id, hash) {
                                    adapter.produce(PeerEvent::P2pGossipInvalidMsg { p2p_peer: stream_id.peer(), topic, hash });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn decompress_to_reservation(producer: &TProducer, data: &[u8], reservation: &mut TReservation, stream_id: &P2pStreamId, topic: &str) -> Result<MessageId, Error> {
    reservation.write(DecompressedGossipMsg::new(*stream_id).as_ref())?;
    let mut snap_decoder = snap::raw::Decoder::new();
    let output_buffer = producer.reservation_buffer(reservation)?;

    let start = size_of::<DecompressedGossipMsg>();
    let decompressed_len = snap_decoder.decompress(data, &mut output_buffer[start..])?;
    let end = start + decompressed_len;
    let msg_id = hash::msg_id_valid_snappy(topic, &mut output_buffer[start..end]); 

    let msg: &mut DecompressedGossipMsg = output_buffer.into();
    msg.msg_hash = msg_id;
    Ok(msg_id)
} 

fn read_message_length(msg: &[u8], _gossip_topic: &GossipTopic) -> Result<usize, Error> {
    // TODO check per topic message size limits
    // these are calculated from SSZ type defs.
    snap::raw::decompress_len(msg).map_err(|_| Error::InvalidSnappy)
}