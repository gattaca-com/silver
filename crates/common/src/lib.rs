extern crate self as silver_common;

pub use crate::{
    error::Error,
    gossip::{
        GossipTopic, MESSAGE_ID_LEN, MessageId, MessageIdHasher, msg_id_invalid_snappy,
        msg_id_valid_snappy,
    },
    id::{Keypair, PeerId, decode_protobuf_pubkey, encode_secp256k1_protobuf},
    identity::{
        AGENT_VERSION, Eth2Addr, Identify, PROTOCOL_VERSION, encode_observed_addr,
        parse_eth2_multiaddr,
    },
    spine::{
        ALL_PROTOCOLS, AcquiredRead as TRead, BeaconStateEvent, BlockSource, Consumer as TConsumer,
        DataColumnsAvailable, ELSyncStatus, EngineFcuReq, EngineFcuResp, EngineGetBlobsReq,
        EngineGetBlobsResp, EngineGetPayloadBodiesByHashReq, EngineGetPayloadBodiesByRangeReq,
        EngineGetPayloadBodiesResp, EngineGetPayloadReq, EngineGetPayloadResp, EngineHealthEvent,
        EngineNewPayloadReq, EngineNewPayloadResp, EnginePreparePayloadReq, EngineReq, EngineResp,
        Error as TCacheError, GossipMsgOut, IpBytes, MAX_BLOBS_PER_BLOCK,
        MAX_PAYLOAD_BODIES_PER_REQ, MULTISTREAM_V1, MultiProducer as TMultiProducer, NewGossipMsg,
        P2pSend, P2pStreamId, PayloadValidationStatus, PeerControl, PeerEvent, PeerStatus,
        Producer as TProducer, REJECT_RESPONSE, RPC_PROTOCOLS,
        RandomAccessConsumer as TRandomAccess, Reservation as TReservation, RpcInbound, RpcMsg,
        RpcOutbound, RpcRequest, RpcRequestInbound, RpcRequestOutbound, RpcResponse,
        RpcResponseInbound, RpcResponseOutbound, RpcSeverity, SilverSpine, SilverSpineProducers,
        StreamProtocol, SyncUpdate, TCache, TCacheProducer, TCacheRead, TCacheRef,
        WithdrawalInline,
    },
    util::{create_self_signed_certificate, decode_varint, encode_varint, hex32},
    wheel::Wheel,
    wither::{CountingWitherFilter, WitherFilter},
};

pub mod allocator;
mod enr;
mod error;
pub use silver_metrics::{self as metrics, declare_counters, flamegraph_timer};
#[path = "generated/protobuf.identify.rs"]
#[allow(clippy::all, dead_code, non_snake_case)]
#[rustfmt::skip]
mod generated;
mod gossip;
mod id;
mod identity;
mod spine;
pub use silver_ssz::{ssz_hash, ssz_view};
pub mod ticker;
mod util;
mod wheel;
mod wither;

pub use enr::{Enr, NodeId};
pub use flux::timing::Nanos;
pub use generated::{Identify as ProtoIdentify, IdentifyView as ProtoIdentifyView};
