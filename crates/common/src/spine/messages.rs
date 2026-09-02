use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use flux::timing::Nanos;
use silver_beacon_state_data::SLOTS_PER_EPOCH;

use crate::{
    DataKind, Enr, GossipTopic, Identify, MessageId, Origin, P2pStreamId, PeerId, StreamProtocol,
    TCacheProducer, TCacheRead, TMultiProducer,
    column_util::columns_of,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, DC_BY_RANGE_REQ_MAX,
        EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE, GOODBYE_SIZE, METADATA_SIZE, PING_SIZE,
        STATUS_V1_SIZE, STATUS_V2_SIZE, SignedBeaconBlockView, SignedExecutionPayloadEnvelopeView,
        SszView, StatusView,
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

// Consumed by controller tile.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipMsgIn {
    pub p2p_id: P2pStreamId,
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
    ExecutionPayloadEnvelopesByRange([u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE]),
    ExecutionPayloadEnvelopesByRoot(TCacheRead),
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
            RpcRequest::ExecutionPayloadEnvelopesByRange(_) => {
                StreamProtocol::ExecutionPayloadEnvelopesByRange
            }
            RpcRequest::ExecutionPayloadEnvelopesByRoot { .. } => {
                StreamProtocol::ExecutionPayloadEnvelopesByRoot
            }
        }
    }

    pub fn blocks_by_range(start_slot: u64, count: u64) -> Self {
        let mut ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        ssz[0..8].copy_from_slice(&start_slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&count.to_le_bytes());
        // `step` is deprecated in the spec and every range we ask for is dense.
        ssz[16..24].copy_from_slice(&1u64.to_le_bytes());
        Self::BlocksByRange(ssz)
    }

    pub fn envelopes_by_range(start_slot: u64, count: u64) -> Self {
        let mut ssz = [0u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE];
        ssz[..8].copy_from_slice(&start_slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&count.to_le_bytes());
        Self::ExecutionPayloadEnvelopesByRange(ssz)
    }

    /// `start_slot | count | offset(=20) | column indices (u64 LE each)`,
    /// expanding the custody bitmask to the indices it names.
    pub fn data_columns_by_range(start_slot: u64, count: u64, columns: u128) -> Self {
        let mut ssz = [0u8; DC_BY_RANGE_REQ_MAX];
        ssz[0..8].copy_from_slice(&start_slot.to_le_bytes());
        ssz[8..16].copy_from_slice(&count.to_le_bytes());
        ssz[16..20].copy_from_slice(&20u32.to_le_bytes());
        let mut len = 20;
        for column in columns_of(columns) {
            ssz[len..len + 8].copy_from_slice(&column.to_le_bytes());
            len += 8;
        }
        Self::DataColumnsByRange { ssz, len }
    }

    /// A `List[Root, N]` of one root — the only shape we ask for.
    pub fn by_root(
        producer: &mut TMultiProducer,
        root: &[u8; 32],
    ) -> Result<TCacheRead, std::io::Error> {
        let Some(mut reservation) = producer.reserve(32, true) else {
            return Err(std::io::ErrorKind::StorageFull.into());
        };
        reservation.write_all(root)?;
        reservation.flush()?;
        Ok(reservation.read())
    }

    /// A `List[DataColumnsByRootIdentifier, N]` of one entry: `N x 4B` list
    /// offsets (so `offset[0] / 4` is the length), then the 32B block root, the
    /// 4B inner-list offset (always 36), and one 8B index per column.
    pub fn data_columns_by_root(
        producer: &mut TMultiProducer,
        root: &[u8; 32],
        columns: u128,
    ) -> Result<TCacheRead, std::io::Error> {
        let length = 4 + 32 + 4 + 8 * columns.count_ones() as usize;
        let Some(mut reservation) = producer.reserve(length, true) else {
            return Err(std::io::ErrorKind::StorageFull.into());
        };
        reservation.write_all(&4u32.to_le_bytes())?;
        reservation.write_all(root)?;
        reservation.write_all(&36u32.to_le_bytes())?;
        for column in columns_of(columns) {
            reservation.write_all(&column.to_le_bytes())?;
        }
        reservation.flush()?;
        Ok(reservation.read())
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcRequestInbound {
    pub stream_id: P2pStreamId,
    pub request: RpcRequest,
}

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
    ExecutionPayloadEnvelope {
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

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcResponseInbound {
    pub application_id: u64,
    pub stream_id: P2pStreamId,
    pub response: RpcResponse,
}

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
                RpcRequest::ExecutionPayloadEnvelopesByRoot(tcache_read) => Some(tcache_read),
                _ => None,
            },
            RpcOutbound::Response(rsp) => match &rsp.response {
                RpcResponse::BeaconBlock { fork_digest: _, ssz } => Some(ssz),
                RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => Some(ssz),
                RpcResponse::ExecutionPayloadEnvelope { fork_digest: _, ssz } => Some(ssz),
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
        /// Failed send was an outbound RPC request: the PM must release the
        /// `outbound_in_flight` slot admitted for it, else it leaks.
        rpc_request: bool,
        /// Response targeted a stream already closed/reset, as opposed to
        /// stream-credit exhaustion opening a new request stream.
        stream_gone: bool,
    },
    P2pStreamClosed {
        stream_id: P2pStreamId,
    },
    /// Storage tile finished (or aborted) serving an inbound RPC request;
    /// the PM logs it with peer identity.
    RpcServeOutcome {
        p2p_peer: usize,
        protocol: StreamProtocol,
        units_total: u32,
        units_sent: u32,
        /// Terminated with ResourceUnavailable on a missing unit rather than
        /// draining to `Complete`.
        missing: bool,
        first_chunk_ms: u64,
        elapsed_ms: u64,
    },
    P2pOutboundMessageDropped {
        p2p_peer: usize,
        protocol: StreamProtocol,
        rpc_request: bool,
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
        backoff_seconds: Option<u64>,
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
    GossipDuplicate {
        p2p_peer: usize,
        topic: GossipTopic,
        hash: MessageId,
        recv_ts: Nanos,
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
        reload: bool,
    },
    DiscExternalAddress {
        address: SocketAddr,
        seq: u64,
    },
    /// A fully-validated inbound gossip message arrived (post-dedup). Carries
    /// the sending peer, topic, msg id (for promise/score accounting) and a
    /// pre-encoded IDONTWANT protobuf frame the peer manager can fan out to
    /// mesh peers without re-encoding per target.
    NewGossip {
        p2p_peer: usize,
        topic: GossipTopic,
        msg_hash: MessageId,
        recv_ts: Nanos,
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
    /// A data column sidecar validated from a non-gossip source (RPC
    /// by-root / EL blobs). Control re-publishes it on its subnet: the
    /// gossip handler wraps the SSZ (a ref into `incoming_rpc`) as
    /// protobuf and PM fans it out to the topic mesh, excluding
    /// `originator` (the peer that served it to us).
    PublishDataColumn {
        originator: P2pStreamId,
        topic: GossipTopic,
        ssz: TCacheRead,
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
    /// The earliest slot we can serve history from, for our own `Status`.
    EarliestSlot(u64),
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
pub enum SyncNeed {
    Missing { root: [u8; 32], slot: u64, kind: DataKind, columns: u128, origin: Origin },
    Arrived { root: [u8; 32], slot: u64, kind: DataKind, origin: Origin },
    BackfillGap { kind: DataKind, floor: u64, next: u64 },
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
    /// Sync to a peer's head slot.
    SyncingHead {
        head_root: [u8; 32],
        head_slot: u64,
    },
    Following,
}

impl Default for SyncUpdate {
    fn default() -> Self {
        Self::SyncingHead { head_root: [0; 32], head_slot: 0 }
    }
}

impl SyncUpdate {
    pub fn is_following(self) -> bool {
        matches!(self, SyncUpdate::Following)
    }

    pub fn data_availability_floor(self, local_finalized_slot: u64) -> u64 {
        let settled_by_target = match self {
            Self::SyncingFinalized { target_epoch, .. } => target_epoch * SLOTS_PER_EPOCH,
            Self::SyncingHead { .. } | Self::Following => 0,
        };
        local_finalized_slot.max(settled_by_target)
    }

    pub fn end_slot(self) -> u64 {
        const EPOCHS_TO_FINALIZE: u64 = 2;
        match self {
            Self::SyncingFinalized { target_epoch, .. } => {
                target_epoch.saturating_add(EPOCHS_TO_FINALIZE).saturating_mul(SLOTS_PER_EPOCH)
            }
            Self::SyncingHead { head_slot, .. } => head_slot,
            Self::Following => 0,
        }
    }

    pub fn same_target_as(self, other: Self) -> bool {
        match (self, other) {
            (Self::Following, Self::Following) => true,
            (
                Self::SyncingFinalized { target_epoch: e1, target_root: r1 },
                Self::SyncingFinalized { target_epoch: e2, target_root: r2 },
            ) => e1 == e2 && r1 == r2,
            (Self::SyncingHead { head_root: r1, .. }, Self::SyncingHead { head_root: r2, .. }) => {
                r1 == r2
            }
            _ => false,
        }
    }

    pub fn is_served_by(&self, peer_status: &[u8]) -> bool {
        match self {
            Self::Following => true,
            Self::SyncingFinalized { target_epoch, .. } => {
                *target_epoch <= StatusView::finalized_epoch(peer_status)
            }
            Self::SyncingHead { head_slot, .. } => *head_slot <= StatusView::head_slot(peer_status),
        }
    }
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
        /// How long we will refuse a re-GRAFT on this topic, advertised so
        /// the remote's own default doesn't diverge from what we enforce.
        /// `None` on unsubscribe, where we record no backoff.
        backoff_seconds: Option<u64>,
    },
    /// Open a libp2p connection to the peer described by `enr`. Emitted by
    /// the peer manager on `DiscNodeFound` when capacity allows. The network
    /// tile dedupes against in-flight dials and existing connections.
    P2pDial {
        p2p: PeerId,
        enr: Enr,
    },
    P2pSend(P2pSend),
    P2pDataColumnsRequest {
        app_id: u64,
        peer: usize,
        block_root: [u8; 32],
        columns: u128,
    },
    P2pBlockByRootRequest {
        app_id: u64,
        peer: usize,
        block_root: [u8; 32],
    },
    P2pEnvelopeByRootRequest {
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

/// Origin of a rejected block. PM treats RPC rejects as evidence that the
/// active syncing target is bad (chain poisoning); gossip rejects are not
/// chain-attributable and only blacklist the individual block_root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockSource {
    Gossip,
    Rpc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ColumnSource {
    Gossip,
    Rpc,
    El,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum BeaconStateEvent {
    ReplayComplete,
    Status {
        ssz: [u8; STATUS_V2_SIZE],
        latest_block_slot: u64,
        wall_slot: u64,
        enr_fork_id: [u8; 16],
    },
    EnvelopeAvailable {
        ssz: TCacheRead,
        source: BlockSource,
        slot: u64,
        block_root: [u8; 32],
    },
    BlockReceived {
        slot: u64,
        block_root: [u8; 32],
        stage: BlockStage,
        source: BlockSource,
        // missing if we haven't seen the parent, which is then reported
        // separately as `RequestBlock`
        parent_slot: Option<u64>,
    },
    BlockRejected {
        block_root: [u8; 32],
        source: BlockSource,
    },
    Reorg {
        lca_slot: u64,
    },
    PersistBlock {
        ssz: TCacheRead,
        source: BlockSource,
        slot: u64,
        block_root: [u8; 32],
    },
}

/// Why a received block is not in fork choice yet, or that it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockStage {
    /// Held on a missing parent or parent payload; nothing computed yet.
    AwaitParent,
    /// Imported into fork choice.
    Applied,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
pub enum ReplayBlock {
    Block { ssz: TCacheRead },
    Envelope { ssz: TCacheRead },
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub slot: u64,
    pub block_source: BlockSource,
}

/// `engine_newPayloadV4` for a Gloas `SignedExecutionPayloadEnvelope`. Unlike a
/// pre-Gloas block, the payload / `parent_beacon_block_root` / execution
/// requests live in the envelope (`data`), but the blob KZG commitments do not
/// — so the caller derives `versioned_hashes[..hash_count]` from the committed
/// bid in state and passes them here.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineNewPayloadEnvelopeReq {
    pub data: TCacheRead,
    pub block_root: [u8; 32],
    pub block_source: BlockSource,
    pub hash_count: u8,
    pub versioned_hashes: [[u8; 32]; MAX_BLOBS_PER_BLOCK],
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
/// derived from the block's KZG commitments; the block root is the request's
/// identity and is echoed back on the response.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetBlobsReq {
    pub block_root: [u8; 32],
    pub slot: u64,
    pub hash_count: u8,
    pub hashes: [[u8; 32]; MAX_BLOBS_PER_BLOCK],
}

/// Response to `EngineGetBlobsReq`.
/// When `ok` is true, `data` is a TCache slot with binary-encoded blobs:
/// `[u32 count] ([u8 present] [u8 proof_count] [48B proof]* [u32 blob_len]
/// [blob bytes])*`, where `present == 0` is a null entry and is that byte
/// alone. `ok` is true even when the EL returned nothing, so `blobs_present`
/// is the field that says whether it delivered.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EngineGetBlobsResp {
    pub block_root: [u8; 32],
    pub slot: u64,
    pub ok: bool,
    pub blobs_present: u8,
    pub data: TCacheRead,
}

impl EngineGetBlobsResp {
    pub fn failed(block_root: [u8; 32], slot: u64) -> Self {
        Self { block_root, slot, ok: false, blobs_present: 0, data: unsafe { std::mem::zeroed() } }
    }
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
    NewPayloadEnvelope(EngineNewPayloadEnvelopeReq),
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
            Self::EnvelopeAvailable { .. } => {
                SszView::SignedExecutionPayloadEnvelope(SignedExecutionPayloadEnvelopeView {})
            }
            Self::BlockRejected { .. } |
            Self::ReplayComplete |
            Self::BlockReceived { .. } |
            Self::Reorg { .. } => SszView::None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum DataColumnsEvent {
    /// The block's data is available; its DA gate opens. Once per block root.
    Available { block_root: [u8; 32], slot: u64 },
    /// Message sent when a data column has been validated.
    Persist {
        ssz: TCacheRead,
        source: ColumnSource,
        block_root: [u8; 32],
        column_index: u64,
        slot: u64,
    },
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum PeerStats {
    P2p(P2pConnectionStats),
    Scores(PeerScores),
    Topic(PeerTopicScores),
}

/// Fixed-size copy of an identify user-agent, sized to match
/// `Identify::user_agent`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AgentString {
    bytes: [u8; 64],
    len: u8,
}

impl Default for AgentString {
    fn default() -> Self {
        Self { bytes: [0u8; 64], len: 0 }
    }
}

impl AgentString {
    pub fn new(s: &str) -> Self {
        let mut len = s.len().min(64);
        while !s.is_char_boundary(len) {
            len -= 1;
        }
        let mut bytes = [0u8; 64];
        bytes[..len].copy_from_slice(&s.as_bytes()[..len]);
        Self { bytes, len: len as u8 }
    }

    pub fn as_str(&self) -> &str {
        str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

/// One meshed (peer, topic) pair's raw gossipsub counters — the per-topic
/// inputs behind the P1–P4 components in [`PeerScores`].
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PeerTopicScores {
    pub id: PeerId,
    pub topic: GossipTopic,
    pub meshed_secs: u64,
    pub first_deliveries: f64,
    pub mesh_deliveries: f64,
    /// `false` when the topic class is not delivery-scored at all, in which
    /// case `mesh_active` never becomes true.
    pub p3_scored: bool,
    pub mesh_active: bool,
    pub fanout_total: u64,
    pub fanout_sent: u64,
    pub mesh_failure_penalty: f64,
    pub invalid_deliveries: f64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct P2pConnectionStats {
    pub id: PeerId,
    pub connection: usize,
    pub addr: SocketAddr,
    pub connected: Duration,
    pub rtt: Duration,
    pub lost_packets: u64,
    pub rx_blocking: u64,
    pub tx_blocking: u64,
    pub rx_datagrams: u64,
    pub tx_datagrams: u64,
    /// Live stream states on the connection. Climbing toward the remote's
    /// MAX_STREAMS limit precedes "cannot create stream" bursts.
    pub streams: u64,
    /// Peer dialed us (QUIC server side), as opposed to us dialing them.
    pub inbound: bool,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PeerScores {
    pub id: PeerId,
    pub user_agent: AgentString,
    pub mesh_count: u32,
    pub p1_time_in_mesh: f64,
    pub p2_first_deliveries: f64,
    pub p3_mesh_deficit: f64,
    pub p3b_mesh_failure: f64,
    pub p4_invalid: f64,
    pub p5_application: f64,
    pub p6_ip_colocation: f64,
    pub p7_behaviour: f64,
    pub total: f64,
}
