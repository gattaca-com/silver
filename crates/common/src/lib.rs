extern crate self as silver_common;

pub use spine::{
    AcquiredCacheFrame, AcquiredCacheSegment, CacheFrameError, CacheFrameRef, CacheFrameSegment,
    CacheFrameView, CacheSegment, MAX_CACHE_SEGMENTS,
};

pub use crate::{
    error::Error,
    gossip::{
        ATTESTATION_SUBNETS, GOSSIP_EXTENSIONS_ANNOUNCEMENT_FRAME,
        GOSSIP_PARTIAL_EXTENSIONS_ANNOUNCEMENT_FRAME, GOSSIP_TOPIC_COUNTER_SLOTS, GossipDomain,
        GossipTopic, MAX_GOSSIP_COMPRESSED_PAYLOAD_SIZE, MAX_GOSSIP_FRAME_SIZE,
        MAX_GOSSIP_UNCOMPRESSED_PAYLOAD_SIZE, MESSAGE_ID_LEN, MessageId, MessageIdHasher,
        SYNC_COMMITTEE_SUBNETS, gossip_topic_for_counter_slot, msg_id_invalid_snappy,
        msg_id_valid_snappy,
    },
    id::{Keypair, PeerId, decode_protobuf_pubkey, encode_secp256k1_protobuf},
    identity::{
        AGENT_VERSION, Eth2Addr, Identify, PROTOCOL_VERSION, encode_observed_addr,
        parse_eth2_multiaddr,
    },
    request::{DataKind, Origin, RequestId, Scope, SyncRequest},
    spine::{
        ALL_PROTOCOLS, AcquiredRange, AcquiredRead as TRead, AcquiredSubReservation,
        AcquiredSubReservationList, AcquiredWithOffset, AgentString, BeaconApiRequest,
        BeaconApiResponse, BeaconStateEvent, BlockLookup, BlockSource, BlockStage, ClusterIn,
        ClusterMsgIn, ClusterMsgOut, ColumnOrigin, Consumer as TConsumer, DataColumnsEvent,
        ELSyncStatus, EngineFcuReq, EngineFcuResp, EngineGetBlobsReq, EngineGetBlobsResp,
        EngineGetPayloadBodiesByHashReq, EngineGetPayloadBodiesByRangeReq,
        EngineGetPayloadBodiesResp, EngineGetPayloadReq, EngineGetPayloadResp, EngineHealthEvent,
        EngineNewPayloadEnvelopeReq, EngineNewPayloadReq, EngineNewPayloadResp,
        EnginePreparePayloadReq, EngineReq, EngineResp, Error as TCacheError, GossipMsgIn,
        GossipMsgOut, HeadChange, HeadRoots, IpBytes, LOCAL_GOSSIP_STREAM_ID,
        LocalAttestationFailure, LocalAttestationResult, MAX_BLOBS_PER_BLOCK,
        MAX_PAYLOAD_BODIES_PER_REQ, MULTISTREAM_V1, MultiProducer as TMultiProducer, NewGossipMsg,
        P2pConnectionStats, P2pSend, P2pStreamId, PREFILL_SLOTS, PayloadResolution,
        PayloadValidationStatus, PeerControl, PeerEvent, PeerScores, PeerStats, PeerStatus,
        PeerTopicScores, PendingSubReservation, Prefill, Producer as TProducer, REJECT_RESPONSE,
        RPC_PROTOCOLS, RandomAccessConsumer as TRandomAccess, ReplayBlock,
        Reservation as TReservation, RpcInbound, RpcOutbound, RpcRequest, RpcRequestInbound,
        RpcRequestOutbound, RpcResponse, RpcResponseInbound, RpcResponseOutbound, RpcSeverity,
        SelfBuiltGossip, ServedBlock, SilverSpine, SilverSpineProducers, SszCache, StreamProtocol,
        SubLayout, SubReservation, SubReservationError, SubReservationList, SubReservationRef,
        SubReservationView, SubValidation, SubWrite, SyncNeed, SyncUpdate, SyncingStrategy, TCache,
        TCacheProducer, TCacheRead, TCacheRef, WithdrawalInline,
    },
    util::{create_self_signed_certificate, decode_varint, encode_varint, hex32},
    wheel::Wheel,
    wither::{CountingWitherFilter, WitherFilter},
};

mod block_root;
pub mod cell_store;
pub mod column_util;
mod enr;
mod error;
mod request;
pub mod rpc_rate_limit;
pub use silver_metrics::{self as metrics, declare_counters, profiler};
#[path = "generated/protobuf.identify.rs"]
#[allow(clippy::all, dead_code, non_snake_case)]
#[rustfmt::skip]
mod generated;
mod gossip;
mod id;
mod identity;
mod spine;
pub use block_root::{block_root, block_root_fulu, block_root_gloas, body_root, body_root_at};
pub use silver_beacon_state_data::{FAR_FUTURE_EPOCH, ForkName, SLOTS_PER_EPOCH};
pub use silver_ssz::{merkle, progressive, ssz_hash, ssz_hash_gloas, ssz_view};
#[cfg(feature = "test-util")]
pub mod test_util;
pub mod ticker;
pub mod tracing;
mod util;
mod wheel;
mod wither;

pub use enr::{
    EPOCHS_PER_SUBNET_SUBSCRIPTION, Enr, NUMBER_OF_CUSTODY_GROUPS, NodeId, SAMPLES_PER_SLOT,
    SUBNETS_PER_NODE, attnet_subnets,
};
pub use flux::timing::{IngestionTime, Nanos};
pub use generated::{Identify as ProtoIdentify, IdentifyView as ProtoIdentifyView};

pub const APP_NAME: &str = "silver";
