use buffa::RepeatedView;
use flux::spine::SpineAdapter;
use silver_common::{Error, GossipTopic, MessageId, P2pStreamId, PeerEvent, SilverSpine};

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
            adapter.produce(PeerEvent::P2pGossipTopicPrune { p2p_peer: stream_id.peer(), topic });
        }
    }
}

pub(super) fn handle_iwants<'a>(
    stream_id: &P2pStreamId,
    wants: &RepeatedView<'a, ControlIWantView<'a>>,
    mcache: &MessageCache,
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    for iwant in wants {
        for want in &iwant.message_ids {
            let Some(hash) = message_id(*want, stream_id, adapter) else {
                continue;
            };
            // TODO we could serve IWANT directly from message cache, but forward
            // for flow control.
            match mcache.get(&hash) {
                Some(tcache) => adapter.produce(PeerEvent::P2pGossipWant {
                    p2p_peer: stream_id.peer(),
                    hash,
                    tcache,
                }),
                None => adapter
                    .produce(PeerEvent::P2pGossipWantUnknown { p2p_peer: stream_id.peer(), hash }),
            };
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
            let Some(hash) = message_id(*dontwant, stream_id, adapter) else {
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
    adapter: &mut SpineAdapter<SilverSpine>,
) {
    for ihave in haves {
        if let Some(topic) = ihave.topic_id {
            let Ok(topic) = gossip_topic(topic, fork_digest_hex) else {
                continue;
            };
            for have in &ihave.message_ids {
                let Some(hash) = message_id(*have, stream_id, adapter) else {
                    continue;
                };
                if !mcache.has(&hash) {
                    // We don't care if a peer has a message, if we already have it.
                    adapter.produce(PeerEvent::P2pGossipHave {
                        p2p_peer: stream_id.peer(),
                        hash,
                        topic,
                    });
                }
            }
        }
    }
}

fn gossip_topic(topic: &str, fork_digest_hex: &str) -> Result<GossipTopic, Error> {
    GossipTopic::from_wire(topic, &fork_digest_hex).inspect_err(|_| {
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
