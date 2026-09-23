#![allow(improper_ctypes, improper_ctypes_definitions)]

use flux::{communication::ShmemData, spine::SpineQueue, spine_derive::from_spine, tile::TileInfo};
pub use messages::{
    AgentString, BeaconApiRequest, BeaconApiResponse, BeaconStateEvent, BlockLookup, BlockSource,
    BlockStage, ClusterIn, ClusterMsgIn, ClusterMsgOut, ColumnOrigin, DataColumnsEvent,
    ELSyncStatus, EngineFcuReq, EngineFcuResp, EngineGetBlobsReq, EngineGetBlobsResp,
    EngineGetPayloadReq, EngineGetPayloadResp, EngineHealthEvent, EngineNewPayloadEnvelopeReq,
    EngineNewPayloadReq, EngineNewPayloadResp, EnginePreparePayloadReq, EngineReq, EngineResp,
    GossipMsgIn, GossipMsgOut, HeadChange, HeadRoots, IpBytes, LocalGossipFailure,
    LocalGossipResult, MAX_BLOBS_PER_BLOCK, NewGossipMsg, P2pConnectionStats, P2pSend,
    PREFILL_SLOTS, PayloadResolution, PayloadValidationStatus, PeerControl, PeerEvent, PeerScores,
    PeerStats, PeerStatus, PeerTopicScores, Prefill, ReplayBlock, RpcInbound, RpcOutbound,
    RpcRequest, RpcRequestInbound, RpcRequestOutbound, RpcResponse, RpcResponseInbound,
    RpcResponseOutbound, RpcSeverity, SelfBuiltGossip, ServedBlock, SszCache, SyncNeed, SyncUpdate,
    SyncingStrategy, WithdrawalInline,
};
pub use stream_id::{LOCAL_GOSSIP_STREAM_ID, P2pStreamId};
pub use stream_protocol::{
    ALL_PROTOCOLS, MULTISTREAM_V1, REJECT_RESPONSE, RPC_PROTOCOLS, StreamProtocol,
};
pub use tcache::{
    AcquiredCacheFrame, AcquiredCacheSegment, AcquiredRange, AcquiredRead, AcquiredSubReservation,
    AcquiredSubReservationList, AcquiredWithOffset, CacheFrameError, CacheFrameRef,
    CacheFrameSegment, CacheFrameView, CacheSegment, Consumer, Error, MAX_CACHE_SEGMENTS,
    PendingSubReservation, Producer, ReadMode, Reservation, SubLayout, SubReservation,
    SubReservationError, SubReservationList, SubReservationRef, SubReservationView, SubValidation,
    SubWrite, TCache, TCacheCounters, TCacheId, TCacheProducer, TCacheRead, TCacheReader,
    TCacheRef, TCacheTable, TileId,
};

use crate::cell_store::{CellStoreEvent, RetentionEvent};

mod messages;
mod stream_id;
mod stream_protocol;
mod tcache;

#[from_spine("silver")]
#[derive(Debug)]
pub struct SilverSpine {
    pub tile_info: ShmemData<TileInfo>,

    /// New incoming network gossip messages
    #[queue(size(2usize.pow(19)))]
    pub gossip_in: SpineQueue<GossipMsgIn>,
    /// New incoming gossip messages
    #[queue(size(2usize.pow(18)))]
    pub new_gossip: SpineQueue<NewGossipMsg>,
    /// P2p send messages.
    #[queue(size(2usize.pow(19)))]
    pub p2p_send: SpineQueue<P2pSend>,
    /// RPC recv messages.
    #[queue(size(2usize.pow(14)))]
    pub rpc_inbound: SpineQueue<RpcInbound>,
    /// Raft messages received from other cluster nodes.
    #[queue(size(2usize.pow(14)))]
    pub cluster_inbound: SpineQueue<ClusterIn>,
    /// Raft messages to send to other cluster nodes.
    #[queue(size(2usize.pow(14)))]
    pub cluster_outbound: SpineQueue<ClusterMsgOut>,
    /// Requests submitted by the Beacon API.
    #[queue(size(2usize.pow(14)))]
    pub beacon_api_requests: SpineQueue<BeaconApiRequest>,
    /// Responses returned to the Beacon API.
    #[queue(size(2usize.pow(14)))]
    pub beacon_api_responses: SpineQueue<BeaconApiResponse>,
    #[queue(size(2usize.pow(16)))]
    pub peer_events: SpineQueue<PeerEvent>,
    #[queue(size(2usize.pow(16)))]
    pub peer_control: SpineQueue<PeerControl>,
    #[queue(size(2usize.pow(14)))]
    pub beacon_events: SpineQueue<BeaconStateEvent>,
    #[queue(size(2usize.pow(13)))]
    pub data_columns: SpineQueue<DataColumnsEvent>,
    #[queue(size(2usize.pow(10)))]
    pub retention: SpineQueue<RetentionEvent>,
    #[queue(size(2usize.pow(13)))]
    pub cells: SpineQueue<CellStoreEvent>,
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
