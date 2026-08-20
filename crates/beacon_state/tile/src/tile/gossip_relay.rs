use flux::spine::SpineProducers;
use silver_common::{GossipTopic, MessageId, NewGossipMsg, P2pStreamId, PeerEvent, TCacheRead};

use super::Producers;

#[derive(Clone, Copy, Debug)]
pub(super) struct RelayMetadata {
    pub(super) stream_id: P2pStreamId,
    pub(super) topic: GossipTopic,
    pub(super) msg_hash: MessageId,
    pub(super) recv_ts: flux::timing::Nanos,
    pub(super) protobuf: TCacheRead,
}

impl RelayMetadata {
    pub(super) fn relay(&self, producers: &mut Producers) {
        producers.produce(PeerEvent::SendGossip {
            originator_stream_id: self.stream_id,
            topic: self.topic,
            msg_hash: self.msg_hash,
            recv_ts: self.recv_ts,
            protobuf: self.protobuf,
        });
    }
}

impl From<&NewGossipMsg> for RelayMetadata {
    fn from(message: &NewGossipMsg) -> Self {
        Self {
            stream_id: message.stream_id,
            topic: message.topic,
            msg_hash: message.msg_hash,
            recv_ts: message.recv_ts,
            protobuf: message.protobuf,
        }
    }
}
