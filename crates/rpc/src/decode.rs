//! Decode an inbound RPC payload into a typed `RpcMsg`. Operates on the
//! already-snappy-decompressed SSZ bytes — the network tile is responsible
//! for stream-chunk framing (varint length, snappy frame, leading
//! result-code byte) before invoking us.
//!
//! Multi-chunk responses (BeaconBlocksByRange returns N blocks, etc.) are
//! decoded one chunk at a time; the network tile emits one
//! `RpcInboundFrame` per chunk and we produce one `RpcMsg` per call.

use silver_common::{RpcMsg, StreamProtocol};

use crate::validate::{
    self, ValidationError, check_blocks_by_range_request, check_blocks_by_root_request,
    check_goodbye, check_metadata, check_ping, check_status,
};

/// Whether the payload we're decoding is a request or a response chunk.
/// For symmetric protocols (Status, Ping, MetaData) the choice of variant
/// is the same; for asymmetric ones (BlocksByRange/Root, DataColumn*) the
/// request and response payloads have different shapes.
#[derive(Clone, Copy, Debug)]
pub enum Direction {
    Request,
    Response,
}

/// Decode `bytes` according to the negotiated `protocol` and `direction`.
/// Returns the typed `RpcMsg` variant on success or a `ValidationError` on
/// shape/bounds failure. The caller (silver_rpc tile) translates an error
/// into a `PeerEvent::RpcMisbehaviour { severity: LowTolerance }` and
/// drops the frame.
pub fn decode(
    protocol: StreamProtocol,
    direction: Direction,
    bytes: &[u8],
) -> Result<RpcMsg, ValidationError> {
    match (protocol, direction) {
        // Symmetric protocols: same payload shape both ways.
        (StreamProtocol::StatusV1 | StreamProtocol::StatusV2, _) => {
            check_status(bytes)?;
            Ok(RpcMsg::Status(silver_common::ssz_view::StatusView))
        }
        (StreamProtocol::Ping, _) => {
            check_ping(bytes)?;
            Ok(RpcMsg::Ping(silver_common::ssz_view::PingView))
        }
        (StreamProtocol::Goodbye, Direction::Request) => {
            check_goodbye(bytes)?;
            Ok(RpcMsg::Goodbye(silver_common::ssz_view::GoodbyeView))
        }
        (StreamProtocol::Metadata, Direction::Response) => {
            check_metadata(bytes)?;
            Ok(RpcMsg::MetaData(silver_common::ssz_view::MetadataView))
        }
        // Asymmetric: request shape.
        (StreamProtocol::BeaconBlocksByRange, Direction::Request) => {
            check_blocks_by_range_request(bytes)?;
            Ok(RpcMsg::BlocksRangeReq(silver_common::ssz_view::BeaconBlocksByRangeRequestView))
        }
        (StreamProtocol::BeaconBlocksByRoot, Direction::Request) => {
            check_blocks_by_root_request(bytes)?;
            Ok(RpcMsg::BlocksRootReq(silver_common::ssz_view::BeaconBlocksByRootRequestView))
        }
        // TODO: data-column request decoders (DataColumnSidecarsByRange,
        // DataColumnSidecarsByRoot) — same pattern, separate validate fns.
        // TODO: SignedBeaconBlock / DataColumnSidecar response-chunk
        // shape checks. The view types are bytes-only so a "decode" here
        // is really just a size-cap + structural sanity check.
        // TODO: Goodbye::Response / Ping reverse direction (Ping is
        // symmetric, Goodbye is request-only by spec).
        _ => Err(ValidationError::BadShape),
    }
}

// Suppress dead-code warning until the validate module helpers are all
// referenced by `decode` arms above.
#[allow(dead_code)]
const _: fn() -> validate::ValidationError = || ValidationError::BadShape;

#[cfg(test)]
mod tests {
    use silver_common::ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, GOODBYE_SIZE, METADATA_SIZE, PING_SIZE, STATUS_V1_SIZE,
        STATUS_V2_SIZE,
    };

    use super::*;

    #[test]
    fn status_v1_v2_decode() {
        let buf = vec![0u8; STATUS_V1_SIZE];
        assert!(matches!(
            decode(StreamProtocol::StatusV1, Direction::Request, &buf).unwrap(),
            RpcMsg::Status(_)
        ));
        let buf2 = vec![0u8; STATUS_V2_SIZE];
        assert!(matches!(
            decode(StreamProtocol::StatusV2, Direction::Response, &buf2).unwrap(),
            RpcMsg::Status(_)
        ));
    }

    #[test]
    fn status_wrong_size_rejected() {
        let buf = vec![0u8; 50];
        assert!(matches!(
            decode(StreamProtocol::StatusV1, Direction::Request, &buf),
            Err(ValidationError::BadSize)
        ));
    }

    #[test]
    fn ping_decodes_both_directions() {
        let buf = vec![0u8; PING_SIZE];
        assert!(matches!(
            decode(StreamProtocol::Ping, Direction::Request, &buf).unwrap(),
            RpcMsg::Ping(_)
        ));
        assert!(matches!(
            decode(StreamProtocol::Ping, Direction::Response, &buf).unwrap(),
            RpcMsg::Ping(_)
        ));
    }

    #[test]
    fn goodbye_request_only() {
        let buf = vec![0u8; GOODBYE_SIZE];
        assert!(matches!(
            decode(StreamProtocol::Goodbye, Direction::Request, &buf).unwrap(),
            RpcMsg::Goodbye(_)
        ));
        // Goodbye has no response side per spec.
        assert!(matches!(
            decode(StreamProtocol::Goodbye, Direction::Response, &buf),
            Err(ValidationError::BadShape)
        ));
    }

    #[test]
    fn metadata_response_only() {
        let buf = vec![0u8; METADATA_SIZE];
        assert!(matches!(
            decode(StreamProtocol::Metadata, Direction::Response, &buf).unwrap(),
            RpcMsg::MetaData(_)
        ));
        // Request body is empty; we don't decode it as a MetaData.
        assert!(matches!(
            decode(StreamProtocol::Metadata, Direction::Request, &buf),
            Err(ValidationError::BadShape)
        ));
    }

    #[test]
    fn blocks_by_range_decode() {
        let mut buf = vec![0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        buf[8..16].copy_from_slice(&8u64.to_le_bytes()); // count
        buf[16..24].copy_from_slice(&1u64.to_le_bytes()); // step
        assert!(matches!(
            decode(StreamProtocol::BeaconBlocksByRange, Direction::Request, &buf).unwrap(),
            RpcMsg::BlocksRangeReq(_)
        ));
    }

    #[test]
    fn blocks_by_range_bad_shape() {
        let mut buf = vec![0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        buf[16..24].copy_from_slice(&2u64.to_le_bytes()); // step != 1
        assert!(matches!(
            decode(StreamProtocol::BeaconBlocksByRange, Direction::Request, &buf),
            Err(ValidationError::BadShape)
        ));
    }

    #[test]
    fn blocks_by_root_decode() {
        let buf = vec![0u8; 32 * 3];
        assert!(matches!(
            decode(StreamProtocol::BeaconBlocksByRoot, Direction::Request, &buf).unwrap(),
            RpcMsg::BlocksRootReq(_)
        ));
    }

    #[test]
    fn unsupported_protocol_arms_return_bad_shape() {
        let buf = vec![0u8; 32];
        // No request decoder for Metadata; no response decoder for Goodbye.
        assert!(matches!(
            decode(StreamProtocol::Metadata, Direction::Request, &buf),
            Err(ValidationError::BadShape)
        ));
    }
}
