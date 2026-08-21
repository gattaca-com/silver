#![allow(improper_ctypes, improper_ctypes_definitions)]

use flux::{communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo};
pub use messages::{
    AgentString, BeaconStateEvent, BlockSource, ColumnSource, DataColumnsEvent, ELSyncStatus,
    EngineFcuReq, EngineFcuResp, EngineGetBlobsReq, EngineGetBlobsResp,
    EngineGetPayloadBodiesByHashReq, EngineGetPayloadBodiesByRangeReq, EngineGetPayloadBodiesResp,
    EngineGetPayloadReq, EngineGetPayloadResp, EngineHealthEvent, EngineNewPayloadEnvelopeReq,
    EngineNewPayloadReq, EngineNewPayloadResp, EnginePreparePayloadReq, EngineReq, EngineResp,
    GossipMsgIn, GossipMsgOut, IpBytes, MAX_BLOBS_PER_BLOCK, MAX_PAYLOAD_BODIES_PER_REQ,
    NewGossipMsg, P2pConnectionStats, P2pSend, PayloadValidationStatus, PeerControl, PeerEvent,
    PeerScores, PeerStats, PeerStatus, PeerTopicScores, ReplayBlock, RpcInbound, RpcOutbound,
    RpcRequest, RpcRequestInbound, RpcRequestOutbound, RpcResponse, RpcResponseInbound,
    RpcResponseOutbound, RpcSeverity, SyncNeed, SyncUpdate, SyncingStrategy, WithdrawalInline,
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

    /// New incoming network gossip messages
    #[queue(size(2usize.pow(24)))]
    pub gossip_in: SpineQueue<GossipMsgIn>,
    /// New incoming gossip messages
    #[queue(size(2usize.pow(20)))]
    pub new_gossip: SpineQueue<NewGossipMsg>,
    /// P2p send messages.
    #[queue(size(2usize.pow(24)))]
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
    pub data_columns: SpineQueue<DataColumnsEvent>,
    #[queue(size(2usize.pow(10)))]
    pub sync_target: SpineQueue<SyncUpdate>,
    #[queue(size(2usize.pow(14)))]
    pub sync_needs: SpineQueue<SyncNeed>,
    #[queue(size(2usize.pow(12)))]
    pub replay_blocks: SpineQueue<ReplayBlock>,
    #[queue(size(2usize.pow(1)))]
    pub syncing_strategy: SpineQueue<SyncingStrategy>,

    #[queue(size(2usize.pow(10)))]
    pub engine_reqs: SpineQueue<EngineReq>,
    #[queue(size(2usize.pow(10)))]
    pub engine_resps: SpineQueue<EngineResp>,
    #[queue(size(2usize.pow(8)))]
    pub engine_health: SpineQueue<EngineHealthEvent>,

    #[queue(size(2usize.pow(12)))]
    pub peer_stats: SpineQueue<PeerStats>,
}
