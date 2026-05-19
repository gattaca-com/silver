#![allow(improper_ctypes, improper_ctypes_definitions)]

use flux::{communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo};
pub use messages::{
    BeaconStateEvent, DataColumnsAvailable, GossipMsgOut, IpBytes, NewGossipMsg, P2pSend,
    PeerControl, PeerEvent, PeerStatus, RejectSource, RpcInbound, RpcMsg, RpcOutbound, RpcRequest,
    RpcRequestInbound, RpcRequestOutbound, RpcResponse, RpcResponseInbound, RpcResponseOutbound,
    RpcSeverity, SyncUpdate,
};
pub use stream_id::P2pStreamId;
pub use stream_protocol::{
    ALL_PROTOCOLS, MULTISTREAM_V1, REJECT_RESPONSE, RPC_PROTOCOLS, StreamProtocol,
};
pub use tcache::{
    AcquiredRead, Consumer, Error, MultiProducer, Producer, RandomAccessConsumer, Reservation,
    TCache, TCacheProducer, TCacheRead, TCacheRef,
};

mod messages;
mod stream_id;
mod stream_protocol;
mod tcache;

#[from_spine("silver")]
#[derive(Debug)]
pub struct SilverSpine {
    pub tile_info: ShmemData<TileInfo>,

    /// New incoming gossip messages
    #[queue(size(2usize.pow(16)))]
    pub new_gossip: SpineQueue<NewGossipMsg>,
    /// P2p send messages.
    #[queue(size(2usize.pow(16)))]
    pub p2p_send: SpineQueue<P2pSend>,
    /// RPC recv messages.
    #[queue(size(2usize.pow(14)))]
    pub rpc_inbound: SpineQueue<RpcInbound>,
    #[queue(size(2usize.pow(14)))]
    pub peer_events: SpineQueue<PeerEvent>,
    #[queue(size(2usize.pow(14)))]
    pub peer_control: SpineQueue<PeerControl>,
    #[queue(size(2usize.pow(14)))]
    pub beacon_events: SpineQueue<BeaconStateEvent>,
    #[queue(size(2usize.pow(12)))]
    pub data_columns: SpineQueue<DataColumnsAvailable>,
    #[queue(size(2usize.pow(10)))]
    pub sync_target: SpineQueue<SyncUpdate>,
}
