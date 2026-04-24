#![allow(improper_ctypes, improper_ctypes_definitions)]

use flux::{communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo};
pub use messages::{
    Gossip, GossipFeedback, GossipIHaveOut, GossipMsgIn, GossipMsgOut, IpBytes, NewGossipMsg,
    PeerControl, PeerEvent, PeerGossipIn, PeerGossipOut, PeerRpcIn, PeerRpcOut, RpcMsgIn,
    RpcMsgOut, RpcOutType,
};
pub use stream_id::P2pStreamId;
pub use stream_protocol::{ALL_PROTOCOLS, MULTISTREAM_V1, REJECT_RESPONSE, StreamProtocol};
pub use tcache::{
    Consumer, Error, Producer, RandomAccessConsumer, Reservation, TCache, TCacheRead, TCacheRef,
};

mod messages;
mod stream_id;
mod stream_protocol;
mod tcache;

#[from_spine("silver")]
#[derive(Debug)]
pub struct SilverSpine {
    pub tile_info: ShmemData<TileInfo>,

    /// New gossip messages
    #[queue(size(2usize.pow(16)))]
    pub new_gossip: SpineQueue<Gossip>,
    /// Gossip send messages.
    #[queue(size(2usize.pow(16)))]
    pub gossip_outgoing: SpineQueue<GossipMsgOut>,
    /// RPC send messages.
    #[queue(size(2usize.pow(16)))]
    pub rpc_outgoing: SpineQueue<RpcMsgOut>,
    #[queue(size(2usize.pow(14)))]
    pub peer_events: SpineQueue<PeerEvent>,

    // Used by BeaconState tile
    #[queue(size(2usize.pow(14)))]
    pub peer_gossip_in: SpineQueue<PeerGossipIn>,
    #[queue(size(2usize.pow(14)))]
    pub peer_gossip_out: SpineQueue<PeerGossipOut>,
    #[queue(size(2usize.pow(14)))]
    pub peer_rpc_in: SpineQueue<PeerRpcIn>,
    #[queue(size(2usize.pow(14)))]
    pub peer_rpc_out: SpineQueue<PeerRpcOut>,
    pub gossip_feedback: SpineQueue<GossipFeedback>,
}
