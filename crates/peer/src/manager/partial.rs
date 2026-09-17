use silver_common::GossipTopic;

use super::PeerManager;

#[derive(Clone, Copy, Debug)]
pub struct PartialPeer {
    pub connection: usize,
    pub requests: bool,
    pub meshed: bool,
}

impl PeerManager {
    pub fn partial_peer(
        &self,
        connection: usize,
        topic: GossipTopic,
        digest: [u8; 4],
    ) -> Option<PartialPeer> {
        if !self.active_gossip_digests.contains(&Some(digest)) || !self.our_topics.contains(&topic)
        {
            return None;
        }
        let peer = self.peers.get(&connection)?;
        let caps = peer.subscriptions.get(&(digest, topic))?;
        if !peer.partial_extensions ||
            !caps.supports_sending ||
            peer.gossip_gate_score() < self.params.gossip_threshold
        {
            return None;
        }
        Some(PartialPeer {
            connection,
            requests: caps.requests,
            meshed: self
                .mesh
                .get(&topic)
                .and_then(|m| m.get(digest))
                .is_some_and(|m| m.peers.contains(&connection)),
        })
    }

    pub fn partial_peers(
        &self,
        topic: GossipTopic,
        digest: [u8; 4],
    ) -> impl Iterator<Item = PartialPeer> + '_ {
        self.peers.keys().filter_map(move |&peer| self.partial_peer(peer, topic, digest))
    }

    pub fn lazy_gossip_limit(&self) -> usize {
        self.params.d_lazy as usize
    }
}
