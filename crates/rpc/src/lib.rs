//! Per-protocol RPC (req/resp) wiring for eth2's `/eth2/beacon_chain/req/*`
//! sub-protocols.
//!
//! `silver_rpc` owns:
//! * Per-protocol SSZ encoders (`encode::encode_*`) for outbound payloads.
//! * Per-protocol SSZ shape + bounds validation (`validate::check_*`).
//! * Inbound dispatch from raw bytes → typed `RpcMsg` (`decode::decode`).
//! * The `RpcTile` that bridges `RpcInboundFrame` from the network tile to
//!   typed `PeerRpcIn` on the spine, emitting `PeerEvent::RpcMisbehaviour` on
//!   any shape-level violation.
//!
//! What lives elsewhere:
//! * Stream-level chunk framing (varint length, snappy frames, response
//!   result-code byte) — the network tile's `RpcInboundState` /
//!   `RpcOutboundState` already implement this.
//! * Cryptographic verification (BLS proposer sig, KZG proofs, response- root
//!   match) — the consumer of `PeerRpcIn` (typically beacon_state). These
//!   produce `PeerEvent::RpcMisbehaviour { severity: Fatal }` when they fail.

pub mod decode;
pub mod encode;
pub mod tile;
pub mod validate;

pub use decode::{Direction, decode};
pub use encode::{
    encode_blocks_by_range_request, encode_blocks_by_root_request, encode_goodbye, encode_metadata,
    encode_ping, encode_status, encode_status_v2,
};
pub use tile::RpcTile;
pub use validate::ValidationError;
