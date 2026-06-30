use std::net::{IpAddr, SocketAddr};

use flux::timing::Nanos;

use crate::{
    Enr, GossipTopic, Identify, MessageId, P2pStreamId, PeerId, StreamProtocol, TCacheError,
    TCacheRead,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView,
        DC_BY_RANGE_REQ_MAX, DataColumnSidecarFuluView, DataColumnSidecarsByRangeRequestView,
        DataColumnsByRootIdentifierView, GOODBYE_SIZE, GoodbyeView, METADATA_SIZE, MetadataView,
        PING_SIZE, PingView, STATUS_V1_SIZE, STATUS_V2_SIZE, SignedBeaconBlockView, SszView,
        StatusView,
    },
};

/// Consumed by network tile. Gossip message indicated by `tcache` will be sent
/// to specified peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipMsgOut {
    pub peer_id: usize,
    pub tcache: TCacheRead,
}

/// New inbound, decoded gossip message. Consumed by beacon state tile. The
/// `protobuf` message can be broadcast by producing `PeerEvent::SendGossip`
/// with details from this message.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NewGossipMsg {
    pub stream_id: P2pStreamId,
    pub topic: GossipTopic,
    pub msg_hash: MessageId,
    pub recv_ts: Nanos,
    /// Decompressed message SSZ
    pub ssz: TCacheRead,
    /// Protobuf wrapped snappy compressed - as received.
    /// Use this cache ref in `PeerEvent::SendGossip` and `GossipMsgOut`.
    pub protobuf: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::large_enum_variant)]
#[repr(C)]
pub enum RpcRequest {
    StatusV1([u8; STATUS_V1_SIZE]),
    StatusV2([u8; STATUS_V2_SIZE]),
    Ping([u8; PING_SIZE]),
    Goodbye([u8; GOODBYE_SIZE]),
    MetaData,
    BlocksByRange([u8; BLOCKS_BY_RANGE_REQ_SIZE]),
    BlockByRoot(TCacheRead),
    DataColumnsByRange { ssz: [u8; DC_BY_RANGE_REQ_MAX], len: usize },
    DataColumnsByRoot(TCacheRead),
}

impl RpcRequest {
    pub fn protocol(&self) -> StreamProtocol {
        match self {
            RpcRequest::StatusV1(_) => StreamProtocol::StatusV1,
            RpcRequest::StatusV2(_) => StreamProtocol::StatusV2,
            RpcRequest::Ping(_) => StreamProtocol::Ping,
            RpcRequest::Goodbye(_) => StreamProtocol::Goodbye,
            RpcRequest::MetaData => StreamProtocol::Metadata,
            RpcRequest::BlocksByRange(_) => StreamProtocol::BeaconBlocksByRange,
            RpcRequest::BlockByRoot { .. } => StreamProtocol::BeaconBlocksByRoot,
            RpcRequest::DataColumnsByRange { .. } => StreamProtocol::DataColumnSidecarsByRange,
            RpcRequest::DataColumnsByRoot { .. } => StreamProtocol::DataColumnSidecarsByRoot,
        }
    }

    pub fn rate_limit_tokens(&self) -> Result<u64, TCacheError> {
        let tokens = match self {
            RpcRequest::StatusV1(_) |
            RpcRequest::StatusV2(_) |
            RpcRequest::Ping(_) |
            RpcRequest::Goodbye(_) |
            RpcRequest::MetaData => 1,
            RpcRequest::BlocksByRange(ssz) => BeaconBlocksByRangeRequestView::count(ssz),
            RpcRequest::BlockByRoot(read) => fixed_width_list_tokens(read.len()?, 32),
            RpcRequest::DataColumnsByRange { ssz, len } => {
                let Some(buf) = ssz.get(..*len) else { return Ok(1) };
                if !DataColumnSidecarsByRangeRequestView::check_size(buf) {
                    1
                } else {
                    let count = DataColumnSidecarsByRangeRequestView::count(buf);
                    let columns = DataColumnSidecarsByRangeRequestView::columns(buf).len() / 8;
                    count.saturating_mul(columns as u64)
                }
            }
            RpcRequest::DataColumnsByRoot(read) => {
                data_columns_by_root_tokens_from_len(read.len()?)
            }
        };
        Ok(tokens.max(1))
    }
}

fn fixed_width_list_tokens(len: usize, width: usize) -> u64 {
    len.div_ceil(width) as u64
}

fn data_columns_by_root_tokens_from_len(len: usize) -> u64 {
    // Silver currently emits one DataColumnsByRootIdentifier per request:
    // 4B outer-list offset + 32B block root + 4B inner-list offset + N*8B columns.
    // Length-derived accounting avoids acquiring the TCache payload in the hot
    // path.
    len.saturating_sub(4 + 32 + 4).div_ceil(8) as u64
}

/// An RPC request recevied from a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcRequestInbound {
    pub stream_id: P2pStreamId,
    pub request: RpcRequest,
}

/// An RPC request to be sent to a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcRequestOutbound {
    pub application_id: u64,
    pub peer: usize,
    pub request: RpcRequest,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum RpcResponse {
    StatusV1([u8; STATUS_V1_SIZE]),
    StatusV2([u8; STATUS_V2_SIZE]),
    Ping([u8; PING_SIZE]),
    MetaData([u8; METADATA_SIZE]),
    BeaconBlock {
        fork_digest: [u8; 4],
        ssz: TCacheRead,
    },
    DataColumnSidecar {
        fork_digest: [u8; 4],
        ssz: TCacheRead,
    },
    Error {
        error: u8,
        msg: [u8; 256],
        len: usize,
    },
    /// Indicates that a multi-part response is complete / stream is closed.
    /// Produced following `BeaconBlock`s or `DataColumnSidecar`s unless an
    /// `Error` is produced first.
    Complete,
}

/// High word of `application_id` tagging an RPC request issued by the storage
/// tile's historical backfill. Block responses are broadcast to every tile, not
/// routed by issuer, so non-storage tiles use this to recognise and skip
/// backfill traffic.
pub const BACKFILL_REQUEST_ID: u64 = 0xbacc_f111 << 32;
pub const COLUMN_BACKFILL_REQUEST_ID: u64 = 0xc01b_accf << 32;
pub const BASE_REQUEST_ID: u64 = 0x00da_5da5 << 32; // DAS prefix.
pub const REQUEST_ID_PREFIX_MASK: u64 = 0xffff_ffff_0000_0000;

/// RPC response received from a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcResponseInbound {
    pub application_id: u64,
    pub stream_id: P2pStreamId,
    pub response: RpcResponse,
}

impl RpcResponseInbound {
    #[inline]
    pub fn is_backfill(&self) -> bool {
        self.application_id & BACKFILL_REQUEST_ID == BACKFILL_REQUEST_ID
    }

    #[inline]
    pub fn is_column_backfill(&self) -> bool {
        self.application_id & REQUEST_ID_PREFIX_MASK == COLUMN_BACKFILL_REQUEST_ID
    }

    #[inline]
    pub fn is_live_column_request(&self) -> bool {
        self.application_id & REQUEST_ID_PREFIX_MASK == BASE_REQUEST_ID
    }
}

/// RPC response to send to a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcResponseOutbound {
    pub stream_id: P2pStreamId,
    pub response: RpcResponse,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[allow(clippy::large_enum_variant)]
pub enum RpcInbound {
    Request(RpcRequestInbound),
    Response(RpcResponseInbound),
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[allow(clippy::large_enum_variant)]
pub enum RpcOutbound {
    Request(RpcRequestOutbound),
    Response(RpcResponseOutbound),
}

impl RpcOutbound {
    pub fn peer_id(&self) -> usize {
        match self {
            RpcOutbound::Request(req) => req.peer,
            RpcOutbound::Response(rsp) => rsp.stream_id.peer(),
        }
    }

    pub fn protocol(&self) -> StreamProtocol {
        match self {
            RpcOutbound::Request(req) => req.request.protocol(),
            RpcOutbound::Response(rsp) => rsp.stream_id.protocol(),
        }
    }

    pub fn tcache_read(&self) -> Option<&TCacheRead> {
        match self {
            RpcOutbound::Request(req) => match &req.request {
                RpcRequest::BlockByRoot(tcache_read) => Some(tcache_read),
                RpcRequest::DataColumnsByRoot(tcache_read) => Some(tcache_read),
                _ => None,
            },
            RpcOutbound::Response(rsp) => match &rsp.response {
                RpcResponse::BeaconBlock { fork_digest: _, ssz } => Some(ssz),
                RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => Some(ssz),
                _ => None,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
#[allow(clippy::large_enum_variant)]
pub enum PeerEvent {
    /// Peer_id_full contains the secp256k1 pubkey and can be used to derive
    /// discovery id
    P2pNewConnection {
        p2p_peer_id: usize,
        peer_id_full: PeerId,
        ip: IpBytes,
        port: u16,
        local_dial: bool,
    },
    P2pDisconnect {
        p2p_peer: usize,
        peer_id: PeerId,
    },
    P2pCannotCreateStream {
        p2p_peer: usize,
        protocol: StreamProtocol,
    },
    P2pStreamClosed {
        stream_id: P2pStreamId,
    },
    P2pOutboundMessageDropped {
        p2p_peer: usize,
        protocol: StreamProtocol,
    },
    P2pGossipTopicSubscribe {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipTopicUnsubscribe {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipTopicGraft {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipTopicPrune {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipWant {
        p2p_peer: usize,
        hash: MessageId,
        tcache: TCacheRead,
    },
    P2pGossipDontWant {
        p2p_peer: usize,
        hash: MessageId,
    },
    P2pGossipHave {
        p2p_peer: usize,
        topic: GossipTopic,
        hash: MessageId,
        /// `true` if we already have this message in our dedup/mcache
        /// (no IWANT will be sent; counts toward IHAVE rate limits only).
        /// `false` if the id is new-to-us — an IWANT is implied.
        already_seen: bool,
    },
    P2pGossipInvalidMsg {
        p2p_peer: usize,
        topic: GossipTopic,
        hash: MessageId,
    },
    P2pGossipInvalidControl {
        p2p_peer: usize,
    },
    P2pGossipInvalidFrame {
        p2p_peer: usize,
    },
    DiscNodeFound {
        enr: Enr,
    },
    DiscExternalAddress {
        address: SocketAddr,
    },
    /// A fully-validated inbound gossip message arrived (post-dedup). Carries
    /// the sending peer, topic, msg id (for promise/score accounting) and a
    /// pre-encoded IDONTWANT protobuf frame the peer manager can fan out to
    /// mesh peers without re-encoding per target.
    NewGossip {
        p2p_peer: usize,
        topic: GossipTopic,
        msg_hash: MessageId,
        idontwant: TCacheRead,
    },
    /// Compression tile has prepared a batched IHAVE frame for `topic`.
    /// Peer manager fans it out to non-mesh subscribers with acceptable score.
    OutboundIHave {
        topic: GossipTopic,
        msg_count: usize,
        protobuf: TCacheRead,
    },
    OutboundIWant {
        p2p_peer: usize,
        iwant: TCacheRead,
    },
    /// Emitted in order to trigger sending of a gossip message.
    /// Peer manager will generate select peers to send to.
    SendGossip {
        originator_stream_id: P2pStreamId,
        topic: GossipTopic,
        msg_hash: MessageId,
        recv_ts: Nanos,
        protobuf: TCacheRead,
    },
    /// Misbehaviour observed on the RPC (req/resp) sub-protocol. The peer
    /// manager translates `severity` into a P5 application-score delta;
    /// `Fatal` is calibrated to push the peer below `graylist_threshold`
    /// outright so the next `tick` evicts them.
    RpcMisbehaviour {
        p2p_peer: usize,
        severity: RpcSeverity,
    },
    /// Peer status received over RPC
    P2pPeerStatus {
        p2p_peer: usize,
        status_ssz: PeerStatus,
    },
    /// Peer metadata recevied over RPC
    P2pPeerMetadata {
        p2p_peer: usize,
        metadata_ssz: [u8; METADATA_SIZE],
    },
    /// Goodbye received from peer
    P2pPeerGoodbye {
        p2p_peer: usize,
        status: u64,
    },
    /// Peer identity information.
    P2pPeerIdentity {
        p2p_peer: usize,
        /// Identify information.
        identify: Identify,
    },
    /// Request to send data column RPC request
    /// Sent by the storage tile.
    SendDataColumnsByRootRequest {
        request_id: u64,
        columns: u128,
        block_root: [u8; 32],
    },
    /// Request to send block RPC request
    /// Sent by the beacon state tile.
    SendBlocksByRootRequest {
        request_id: u64,
        /// Set if there is a peer that is more likely to have the block - i.e.
        /// they attested to the child block.
        p2p_peer: Option<usize>,
        block_root: [u8; 32],
    },
    SendRpcRequest {
        request_id: u64,
        rpc: RpcRequest,
    },
    EarliestSlot(u64),
    /// Storage's startup-scan backfill report: the block gap to fill backward
    /// (`[block_floor, earliest_present)`) + the column-retention floor.
    BackfillState {
        block_floor: u64,
        earliest_present: u64,
        column_floor: u64,
    },
    /// A persisted block whose custody columns aren't all on disk (`missing`),
    /// found by the scan or pulled in by block backfill. `missing == 0` clears
    /// a previously-reported need (the block's columns are now complete).
    ColumnNeed {
        block_root: [u8; 32],
        slot: u64,
        missing: u128,
    },
}

/// Sync target chosen by the peer manager.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C, u8)]
pub enum SyncUpdate {
    /// Chase a specific finalized checkpoint. Pinned until reached or
    /// rejected.
    SyncingFinalized {
        target_epoch: u64,
        target_root: [u8; 32],
    },
    /// Catch up on head slot.
    SyncingHead {
        head_root: [u8; 32],
        head_slot: u64,
    },
    Following,
}

impl core::fmt::Debug for SyncUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use crate::util::hex32;
        match self {
            Self::SyncingFinalized { target_epoch, target_root } => f
                .debug_struct("SyncingFinalized")
                .field("target_epoch", target_epoch)
                .field("target_root", &format_args!("0x{}", hex32(target_root)))
                .finish(),
            Self::SyncingHead { head_root, head_slot } => f
                .debug_struct("SyncingHead")
                .field("head_slot", head_slot)
                .field("head_root", &format_args!("0x{}", hex32(head_root)))
                .finish(),
            Self::Following => f.write_str("Following"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
pub enum PeerStatus {
    V1([u8; STATUS_V1_SIZE]),
    V2([u8; STATUS_V2_SIZE]),
}

/// Severity levels for RPC misbehaviour reports. Mirrors lighthouse's
/// `PeerAction` taxonomy. Mapping to score deltas lives in the peer manager.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum RpcSeverity {
    /// Cryptographic violation (bad signature on a chunk), fork-digest
    /// mismatch on Status, or response root mismatch with the request.
    Fatal,
    /// Invalid SSZ, malformed RPC chunk envelope, chunk-count overflow.
    LowTolerance,
    /// Stream timeout, slow response, missing-but-not-malicious chunks.
    MidTolerance,
    /// Soft signal — single dropped message, transient stream issue.
    HighTolerance,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
#[allow(clippy::large_enum_variant)]
pub enum P2pSend {
    Gossip(GossipMsgOut),
    Identify(usize),
    Rpc(RpcOutbound),
}

impl P2pSend {
    pub fn peer_id(&self) -> usize {
        match self {
            P2pSend::Gossip(gossip_msg_out) => gossip_msg_out.peer_id,
            P2pSend::Identify(peer) => *peer,
            P2pSend::Rpc(rpc_outbound) => rpc_outbound.peer_id(),
        }
    }

    pub fn protocol(&self) -> StreamProtocol {
        match self {
            P2pSend::Gossip(_) => StreamProtocol::GossipSub,
            P2pSend::Identify(_) => StreamProtocol::Identity,
            P2pSend::Rpc(rpc_outbound) => rpc_outbound.protocol(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
// `P2pDial { enr }` carries the full ~200B `Enr` while most variants fit in
// ~60B. Boxing would break `Copy` (used widely in this enum's hot path) for
// the sake of one cold-path variant — the spine already pays the larger
// variant's footprint per slot, so we accept the disparity.
#[allow(clippy::large_enum_variant)]
pub enum PeerControl {
    Ban {
        p2p: PeerId,
    },
    BanIp {
        ip: IpAddr,
    },
    DiscoverNodes,
    P2pGossipSubscribe {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    P2pGossipUnsubscribe {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    P2pGossipGraft {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    P2pGossipPrune {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    /// Open a libp2p connection to the peer described by `enr`. Emitted by
    /// the peer manager on `DiscNodeFound` when capacity allows. The network
    /// tile dedupes against in-flight dials and existing connections.
    P2pDial {
        p2p: PeerId,
        enr: Enr,
    },
    P2pSend(P2pSend),
    /// Generate a data columns by root request.
    P2pDataColumnsRequest {
        app_id: u64,
        peer: usize,
        block_root: [u8; 32],
        columns: u128,
    },
    /// Generate a blocks by root request.
    P2pBlockByRootRequest {
        app_id: u64,
        peer: usize,
        block_root: [u8; 32],
    },
    P2pDisconnect {
        p2p: PeerId,
        p2p_connection: usize,
    },
    /// Peer-level ban has timed out — counterpart to `Ban`. Network tile
    /// removes the peer from any deny-list / discv5 routing-table eviction
    /// state. Emitted from `tick` when the per-peer ban TTL expires.
    Unban {
        p2p: PeerId,
    },
    /// IP-level ban has timed out — counterpart to `BanIp`. Network tile
    /// removes the IP from its socket-level deny set. Emitted from `tick`
    /// when `banned_ip_ttl` elapses since the ban.
    UnbanIp {
        ip: IpAddr,
    },
    PersistPeer {
        enr: Enr,
    },
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum IpBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl From<IpAddr> for IpBytes {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => IpBytes::V4(ipv4_addr.octets()),
            IpAddr::V6(ipv6_addr) => IpBytes::V6(ipv6_addr.octets()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum RpcMsg {
    // Status v2 and MetaData v3 are symmetric: same view for req and resp.
    Status(StatusView),
    /// `Ping` request and `Pong` response share wire shape (uint64 seq).
    Ping(PingView),
    /// `Goodbye` is request-only (uint64 reason).
    Goodbye(GoodbyeView),
    /// `MetaData` request body is empty; this carries the response only.
    MetaData(MetadataView),
    BlocksRangeReq(BeaconBlocksByRangeRequestView),
    BlocksRootReq(BeaconBlocksByRootRequestView),
    DataColumnRangeReq(DataColumnSidecarsByRangeRequestView),
    DataColumnByRoot(DataColumnsByRootIdentifierView),
    // rpc response chunks (one per successful response_chunk)
    BlocksRangeResp(SignedBeaconBlockView),
    BlocksRootResp(SignedBeaconBlockView),
    DataColumnRangeResp(DataColumnSidecarFuluView),
    DataColumnByRootResp(DataColumnSidecarFuluView),
    Empty,
}

impl From<&RpcInbound> for RpcMsg {
    fn from(value: &RpcInbound) -> Self {
        match value {
            RpcInbound::Request(req) => match req.request {
                RpcRequest::StatusV1(_) => RpcMsg::Status(StatusView),
                RpcRequest::StatusV2(_) => RpcMsg::Status(StatusView),
                RpcRequest::Ping(_) => RpcMsg::Ping(PingView),
                RpcRequest::Goodbye(_) => RpcMsg::Goodbye(GoodbyeView),
                RpcRequest::MetaData => RpcMsg::Empty,
                RpcRequest::BlocksByRange(_) => {
                    RpcMsg::BlocksRangeReq(BeaconBlocksByRangeRequestView)
                }
                RpcRequest::BlockByRoot(_) => RpcMsg::BlocksRootReq(BeaconBlocksByRootRequestView),
                RpcRequest::DataColumnsByRange { .. } => {
                    RpcMsg::DataColumnRangeReq(DataColumnSidecarsByRangeRequestView)
                }
                RpcRequest::DataColumnsByRoot(_) => {
                    RpcMsg::DataColumnByRoot(DataColumnsByRootIdentifierView)
                }
            },
            RpcInbound::Response(rsp) => match rsp.response {
                RpcResponse::StatusV1(_) => RpcMsg::Status(StatusView),
                RpcResponse::StatusV2(_) => RpcMsg::Status(StatusView),
                RpcResponse::Ping(_) => RpcMsg::Ping(PingView),
                RpcResponse::MetaData(_) => RpcMsg::MetaData(MetadataView),
                RpcResponse::BeaconBlock { .. } => RpcMsg::BlocksRangeResp(SignedBeaconBlockView),
                RpcResponse::DataColumnSidecar { .. } => {
                    RpcMsg::DataColumnByRootResp(DataColumnSidecarFuluView)
                }
                _ => RpcMsg::Empty,
            },
        }
    }
}

/// Origin of a rejected block. PM treats RPC rejects as evidence that the
/// active catchup target is bad (chain poisoning); gossip rejects are not
/// chain-attributable and only blacklist the individual block_root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockSource {
    Gossip,
    Rpc,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum BeaconStateEvent {
    Status { ssz: [u8; STATUS_V2_SIZE], latest_block_slot: u64, wall_slot: u64 },
    PersistBlock { ssz: TCacheRead, source: BlockSource },
    BlockRejected { block_root: [u8; 32], source: BlockSource },
    ReplayComplete,
    BacktrackStall,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
pub enum ReplayBlock {
    Block { ssz: TCacheRead },
    Done,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum SyncingStrategy {
    SyncFromPeers,
    ReplayDisk,
}

/// Maximum blob commitments per block (Fulu target; increase as the spec
/// evolves).
pub const MAX_BLOBS_PER_BLOCK: usize = 21;

/// Maximum number of block hashes in a single `getPayloadBodiesByHash` request.
pub const MAX_PAYLOAD_BODIES_PER_REQ: usize = 128;

/// Execution-payload validation result returned by the EL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadValidationStatus {
    Valid = 0,
    Invalid = 1,
    Syncing = 2,
    Accepted = 3,
}

/// A single withdrawal, inlined into `EngineFcuReq` payload attributes.
/// Field order avoids interior padding (all u64s first, then the 20-byte
/// address).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct WithdrawalInline {
    pub index: u64,
    pub validator_index: u64,
    pub amount: u64,
    pub address: [u8; 20],
}

/// `engine_forkchoiceUpdatedV3` request.  Fully inline — no TCache needed.
///
/// `block_root` is the beacon root of the `head_block_hash` block. The EL
/// response carries no beacon identity, so the engine tile echoes it in
/// `EngineFcuResp` to let fork choice apply the verdict.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineFcuReq {
    pub block_root: [u8; 32],
    pub head_block_hash: [u8; 32],
    pub safe_block_hash: [u8; 32],
    pub finalized_block_hash: [u8; 32],
}

/// `engine_newPayloadV4` request.
///
/// `data` is a single TCache entry whose layout is:
/// ```text
/// [u32 LE payload_ssz_len] [payload_ssz_len bytes: ExecutionPayload SSZ]
/// [u8 exec_req_count]      [for each: u32 LE len, then bytes]
/// ```
/// `versioned_hashes[..versioned_hash_count]` are the expected KZG commitment
/// hashes for the blobs carried by this payload.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineNewPayloadReq {
    pub data: TCacheRead,
    pub block_root: [u8; 32],
    pub block_source: BlockSource,
}

/// Response to `engine_forkchoiceUpdatedV3`.  Fully inline.
///
/// `block_root` echoes the request's head beacon root (zeros for the
/// prepare-payload path). `latest_valid_hash` is all-zeros when the EL did
/// not return one. `payload_id` is meaningful only when `has_payload_id` is
/// true.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineFcuResp {
    pub block_root: [u8; 32],
    pub status: PayloadValidationStatus,
    pub latest_valid_hash: [u8; 32],
    pub has_payload_id: bool,
    pub payload_id: [u8; 8],
}

/// Response to `engine_newPayloadV4`.  Fully inline.
///
/// `latest_valid_hash` is all-zeros when the EL did not return one.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineNewPayloadResp {
    pub block_root: [u8; 32],
    pub status: PayloadValidationStatus,
    pub latest_valid_hash: [u8; 32],
}

/// The engine tile sends `engine_forkchoiceUpdatedV3` with payload attributes
/// and returns the `payload_id` assigned by the EL. The caller should use.
/// this to fetch the built payload.
///
/// Field layout mirrors `EngineFcuReq` (attrs are always present for payload
/// building).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EnginePreparePayloadReq {
    pub id: u64,
    pub head_block_hash: [u8; 32],
    pub safe_block_hash: [u8; 32],
    pub finalized_block_hash: [u8; 32],
    pub attrs_timestamp: u64,
    pub attrs_prev_randao: [u8; 32],
    pub attrs_fee_recipient: [u8; 20],
    pub attrs_parent_beacon_block_root: [u8; 32],
    pub attrs_withdrawal_count: u8,
    pub attrs_withdrawals: [WithdrawalInline; 16],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetPayloadReq {
    pub id: u64,
    pub payload_id: [u8; 8],
}

/// Response to `EngineGetPayloadReq`.
/// When `ok` is true, `data` is a TCache slot with the encoded EL payload:
/// `{executionPayload, blobsBundle, shouldOverrideBuilder, executionRequests}`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetPayloadResp {
    pub id: u64,
    pub ok: bool,
    pub data: TCacheRead,
}

/// `engine_getBlobsV2` request. `hashes[..hash_count]` are the versioned hashes
/// derived from the block's KZG commitments.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetBlobsReq {
    pub id: u64,
    pub hash_count: u8,
    pub hashes: [[u8; 32]; MAX_BLOBS_PER_BLOCK],
}

/// Response to `EngineGetBlobsReq`.
/// When `ok` is true, `data` is a TCache slot with binary-encoded blobs:
/// `[u32 count] ([u8 present] [u8 proof_count] [48B proof]* [u32 blob_len]
/// [blob bytes])*` `present == 0` means the entry is null (blob missing).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetBlobsResp {
    pub id: u64,
    pub ok: bool,
    pub data: TCacheRead,
}

/// `engine_getPayloadBodiesByHashV1` request.
/// `hashes[..hash_count]` are the execution block hashes to fetch bodies for.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetPayloadBodiesByHashReq {
    pub id: u64,
    pub hash_count: u8,
    pub hashes: [[u8; 32]; MAX_PAYLOAD_BODIES_PER_REQ],
}

/// `engine_getPayloadBodiesByRangeV1` request. Fully inline.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetPayloadBodiesByRangeReq {
    pub id: u64,
    pub start: u64,
    pub count: u64,
}

/// Response to either `getPayloadBodiesByHash` or `getPayloadBodiesByRange`.
/// When `ok` is true, `data` is a TCache slot with binary-encoded bodies:
/// `[u32 count] ([u8 present] [u32 tx_count] ([u32 tx_len][tx bytes])* [u32
/// withdrawal_count] ([u32 index][u32 validator_index][20B address][u64
/// amount])*)*` `present == 0` means the entry is null (block missing).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetPayloadBodiesResp {
    pub id: u64,
    pub ok: bool,
    pub data: TCacheRead,
}

/// Multiplexed engine request. A single spine queue carries FCU,
/// new-payload, and raw passthrough requests, preserving strict FIFO ordering.
#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
#[allow(clippy::large_enum_variant)]
pub enum EngineReq {
    Fcu(EngineFcuReq),
    NewPayload(EngineNewPayloadReq),
    PreparePayload(EnginePreparePayloadReq),
    GetPayload(EngineGetPayloadReq),
    GetBlobs(EngineGetBlobsReq),
    GetPayloadBodiesByHash(EngineGetPayloadBodiesByHashReq),
    GetPayloadBodiesByRange(EngineGetPayloadBodiesByRangeReq),
}

/// Multiplexed engine response.
#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
#[allow(clippy::large_enum_variant)]
pub enum EngineResp {
    Fcu(EngineFcuResp),
    NewPayload(EngineNewPayloadResp),
    GetPayload(EngineGetPayloadResp),
    GetBlobs(EngineGetBlobsResp),
    GetPayloadBodies(EngineGetPayloadBodiesResp),
}

/// Sync status of the attached execution layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ELSyncStatus {
    Unknown = 0,
    Syncing = 1,
    Synced = 2,
    Offline = 3,
}

/// Published to the `engine_health` spine queue whenever the EL sync status
/// changes.  Other tiles subscribe to suppress block proposals during outages
/// or to gate fork-choice updates on EL liveness.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineHealthEvent {
    pub sync_status: ELSyncStatus,
}

impl BeaconStateEvent {
    pub fn view(&self) -> SszView {
        match self {
            Self::Status { .. } => SszView::Status(StatusView {}),
            Self::PersistBlock { .. } => SszView::SignedBeaconBlock(SignedBeaconBlockView {}),
            Self::BlockRejected { .. } | Self::ReplayComplete | Self::BacktrackStall => {
                SszView::None
            }
        }
    }
}

/// Message sent by the data column tile when all custody data columns for a
/// block have been received and KZG-validated.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DataColumnsAvailable {
    pub block_root: [u8; 32],
    pub slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestCategory {
    LiveSync,
    BlockBackfill,
    ColumnBackfill,
}

impl RequestCategory {
    pub fn from_request_id(request_id: u64) -> Self {
        match request_id & REQUEST_ID_PREFIX_MASK {
            COLUMN_BACKFILL_REQUEST_ID => RequestCategory::ColumnBackfill,
            BACKFILL_REQUEST_ID => RequestCategory::BlockBackfill,
            _ => RequestCategory::LiveSync,
        }
    }

    pub fn is_backfill(self) -> bool {
        matches!(self, RequestCategory::ColumnBackfill | RequestCategory::BlockBackfill)
    }
}
