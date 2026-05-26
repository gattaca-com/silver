extern crate self as silver_common;

pub use crate::{
    arena::{ArenaPtr, TierPool},
    beacon_state::{
        BeaconState, BeaconStateOwner, BeaconStateReader, DeltaBuffer, StateDeltaView,
        StateDeltaViewMut, types::*,
    },
    config::{BlobParameters, Config, DiscoveryConfig, ScoreParams, SpecConfig, SyncingConfig},
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
        ALL_PROTOCOLS, AcquiredRead as TRead, BeaconStateEvent, Consumer as TConsumer,
        DataColumnsAvailable, Error as TCacheError, GossipMsgOut, IpBytes, MULTISTREAM_V1,
        MultiProducer as TMultiProducer, NewGossipMsg, P2pSend, P2pStreamId, PeerControl,
        PeerEvent, PeerStatus, Producer as TProducer, REJECT_RESPONSE, RPC_PROTOCOLS,
        RandomAccessConsumer as TRandomAccess, RejectSource, Reservation as TReservation,
        RpcInbound, RpcMsg, RpcOutbound, RpcRequest, RpcRequestInbound, RpcRequestOutbound,
        RpcResponse, RpcResponseInbound, RpcResponseOutbound, RpcSeverity, SilverSpine,
        SilverSpineProducers, StreamProtocol, SyncUpdate, TCache, TCacheProducer, TCacheRead,
        TCacheRef,
    },
    util::{create_self_signed_certificate, decode_varint, encode_varint},
    wheel::Wheel,
    wither::{CountingWitherFilter, WitherFilter},
};

pub mod allocator;
pub mod arena;
pub mod beacon_state;
mod config;
mod enr;
mod error;
pub mod metrics;
#[path = "generated/protobuf.identify.rs"]
#[allow(clippy::all, dead_code, non_snake_case)]
#[rustfmt::skip]
mod generated;
mod gossip;
mod id;
mod identity;
mod spine;
pub mod ssz_hash;
pub mod ssz_view;
mod util;
mod wheel;
mod wither;

pub use enr::{Enr, NodeId};
pub use flux::timing::Nanos;
pub use generated::{Identify as ProtoIdentify, IdentifyView as ProtoIdentifyView};
