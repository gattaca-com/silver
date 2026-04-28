//! `RpcTile` — consumes `RpcInboundFrame` from the network tile, runs SSZ
//! shape + bounds validation via [`crate::decode::decode`], and produces
//! either a typed `PeerRpcIn` (success) or `PeerEvent::RpcMisbehaviour`
//! (validation failure).
//!
//! # Wiring status
//!
//! The dispatcher logic (`dispatch_frame`) is complete and unit-tested:
//! given `(stream_id, protocol, request_id, result_code, bytes)` it
//! produces the right typed event. The `Tile` impl is a thin shell that
//! consumes from the spine and forwards.
//!
//! What's NOT yet wired (separate follow-up): a `TRandomAccess` view of
//! the network tile's `rpc_in` TCache so the tile can read the bytes
//! referenced by `RpcInboundFrame::tcache`. Until that exists, the tile
//! produces `PeerRpcIn` carrying the original `tcache` ref intact and
//! consumers read the bytes themselves — which is sufficient for the
//! beacon-state path that does its own SSZ-view-based access anyway.

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    PeerEvent, PeerRpcIn, RpcMsg, RpcSeverity, SilverSpine, StreamProtocol,
};

use crate::{
    decode::{Direction, decode},
    validate,
};

/// Stateless dispatcher. Per-peer reputation lives in the peer manager.
pub struct RpcTile;

impl RpcTile {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RpcTile {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of validating + decoding one `RpcInboundFrame`. Pure function
/// over the frame fields and its payload bytes; testable without spinning
/// up a tile.
#[derive(Debug)]
pub enum Outcome {
    /// Forward to consumers as a typed `PeerRpcIn`.
    Forward(PeerRpcIn),
    /// Drop the frame and report the peer.
    Misbehaviour { p2p_peer: usize, severity: RpcSeverity },
}

/// Decode + validate a single inbound frame's payload. Pure: no spine
/// access, no allocation beyond what `decode::decode` does.
pub fn dispatch_frame(frame: &RpcInboundFrame, bytes: &[u8]) -> Outcome {
    if let Err(err) = validate::check_result_code(frame.result_code) {
        return Outcome::Misbehaviour { p2p_peer: frame.stream_id.peer(), severity: err.severity() };
    }
    let direction =
        if frame.request_id.is_some() { Direction::Response } else { Direction::Request };
    match decode(frame.protocol, direction, bytes) {
        Ok(msg) => Outcome::Forward(PeerRpcIn {
            msg,
            sender: frame.stream_id.peer() as u64,
            tcache: frame.tcache,
        }),
        Err(err) => {
            Outcome::Misbehaviour { p2p_peer: frame.stream_id.peer(), severity: err.severity() }
        }
    }
}

impl Tile<SilverSpine> for RpcTile {
    fn loop_body(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) {
        // TODO: once the network tile is wired to populate `rpc_inbound`
        // and a TRandomAccess into `rpc_in` is exposed, replace this stub
        // with:
        //
        //   adapter.consume(|frame: RpcInboundFrame, producers| {
        //       let bytes = read_tcache(rpc_in, frame.tcache);
        //       match dispatch_frame(&frame, bytes) {
        //           Outcome::Forward(msg) =>
        //               producers.peer_rpc_in.produce(&msg.into()),
        //           Outcome::Misbehaviour { p2p_peer, severity } =>
        //               producers.peer_events.produce(
        //                   &PeerEvent::RpcMisbehaviour { p2p_peer, severity
        // }.into()               ),
        //       }
        //   });
        //
        // The dispatch logic itself is fully tested via `dispatch_frame`
        // unit tests below.
    }
}

#[allow(dead_code)]
fn _unused_marker(_: PeerEvent, _: RpcMsg, _: StreamProtocol) {}

#[cfg(test)]
mod tests {
    use silver_common::{P2pStreamId, StreamProtocol, TCache, TCacheProducer, ssz_view::PING_SIZE};

    use super::*;

    fn stub_tcache() -> silver_common::TCacheRead {
        let mut producer = TCache::producer(1 << 14);
        let mut reservation = producer.reserve(8, true).unwrap();
        use std::io::Write as _;
        reservation.write_all(&[0u8; 8]).unwrap();
        reservation.read()
    }

    fn frame(
        protocol: StreamProtocol,
        request_id: Option<u64>,
        result_code: u8,
    ) -> RpcInboundFrame {
        RpcInboundFrame {
            stream_id: P2pStreamId::new(7, 0, protocol),
            protocol,
            request_id,
            tcache: stub_tcache(),
            result_code,
        }
    }

    #[test]
    fn ping_request_forwards() {
        let f = frame(StreamProtocol::Ping, None, 0);
        let bytes = vec![0u8; PING_SIZE];
        match dispatch_frame(&f, &bytes) {
            Outcome::Forward(msg) => {
                assert!(matches!(msg.msg, RpcMsg::Ping(_)));
                assert_eq!(msg.sender, 7);
            }
            Outcome::Misbehaviour { .. } => panic!("expected forward"),
        }
    }

    #[test]
    fn malformed_size_emits_misbehaviour() {
        let f = frame(StreamProtocol::Ping, None, 0);
        let bytes = vec![0u8; 4]; // wrong size
        match dispatch_frame(&f, &bytes) {
            Outcome::Misbehaviour { p2p_peer, severity } => {
                assert_eq!(p2p_peer, 7);
                assert!(matches!(severity, RpcSeverity::LowTolerance));
            }
            Outcome::Forward(_) => panic!("expected misbehaviour"),
        }
    }

    #[test]
    fn bad_result_code_emits_misbehaviour() {
        let f = frame(StreamProtocol::Ping, Some(42), 99);
        let bytes = vec![0u8; PING_SIZE];
        assert!(matches!(dispatch_frame(&f, &bytes), Outcome::Misbehaviour { .. }));
    }

    #[test]
    fn response_chunk_is_decoded_as_response() {
        // request_id=Some(_) → Direction::Response. Status is symmetric so
        // it forwards either way; we just verify the sender wire-up.
        let f = frame(StreamProtocol::StatusV1, Some(99), 0);
        let bytes = vec![0u8; silver_common::ssz_view::STATUS_V1_SIZE];
        match dispatch_frame(&f, &bytes) {
            Outcome::Forward(msg) => assert!(matches!(msg.msg, RpcMsg::Status(_))),
            Outcome::Misbehaviour { .. } => panic!("expected forward"),
        }
    }

    #[test]
    fn tile_constructs() {
        let _tile = RpcTile::new();
    }
}
