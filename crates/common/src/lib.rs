extern crate self as silver_common;

pub use crate::{
    error::Error,
    gossip::*,
    id::{Keypair, PeerId, decode_protobuf_pubkey, encode_secp256k1_protobuf},
    identity::{
        AGENT_VERSION, Eth2Addr, Identify, PROTOCOL_VERSION, encode_observed_addr,
        parse_eth2_multiaddr,
    },
    request::{DataKind, Origin, RequestId, Scope, SyncRequest},
    spine::{
        AcquiredRead as TRead, Consumer as TConsumer, Error as TCacheError, Producer as TProducer,
        ReadMode as TReadMode, Reservation as TReservation, *,
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
mod payload_frame;
mod request;
pub mod rpc_rate_limit;
mod slab;
mod tape_scratch;
pub use silver_metrics::{self as metrics, declare_counters, profiler};
#[path = "generated/protobuf.identify.rs"]
#[allow(clippy::all, dead_code, non_snake_case)]
#[rustfmt::skip]
mod generated;
mod gossip;
mod id;
mod identity;
mod node_chain;
mod spine;
pub use block_root::{block_root, block_root_fulu, block_root_gloas, body_root, body_root_at};
pub use node_chain::NodeChain;
pub use payload_frame::PayloadFrame;
pub use silver_beacon_state_data::{FAR_FUTURE_EPOCH, ForkName, SLOTS_PER_EPOCH};
pub use silver_ssz::{block_contents, merkle, progressive, ssz_hash, ssz_hash_gloas, ssz_view};
pub use slab::Slab;
pub use tape_scratch::{FrameOut, TapeError, TapeScratch};
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

pub const MAX_CLUSTER_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
