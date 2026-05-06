use std::{
    ops::Deref,
    time::{Duration, Instant},
};

use flux::tile::Tile;
use silver_common::{
    P2pSend, PeerEvent, PeerStatus, RpcInbound, RpcOutbound, RpcRequest, RpcRequestInbound,
    RpcRequestOutbound, RpcResponse, RpcResponseInbound, RpcResponseOutbound, RpcSeverity,
    SilverSpine, StreamProtocol,
    ssz_view::{METADATA_SIZE, MetadataView, STATUS_V2_SIZE, StatusView},
};
use silver_peer::PeerManager;

/// Result-byte values for eth2 RPC error chunks. Per
/// `consensus-specs/p2p-interface.md`, only 0x01..=0x03 are spec-defined;
/// 0x14 is a lighthouse extension some clients emit and others tolerate.
const RPC_ERR_INVALID_REQUEST: u8 = 0x01;
const RPC_ERR_SERVER_ERROR: u8 = 0x02;
const RPC_ERR_RESOURCE_UNAVAILABLE: u8 = 0x03;
const RPC_ERR_RATE_LIMITED: u8 = 0x14;

/// Map a received `RpcResponse::Error` to an `RpcSeverity`. Returns `None`
/// when the error is informational and shouldn't impact peer score (notably
/// `ResourceUnavailable` for blob/column-by-root, where missing data is
/// expected). All RpcResponse::Error events at this layer are responses to
/// requests **we** initiated (the inbound branch handles request parsing
/// errors separately via the network tile), so direction is always
/// "outgoing-from-us" — the conditional ban on outbound BlocksByRange /
/// BlocksByRoot ResourceUnavailable is unconditional here.
fn severity_for_error_response(code: u8, protocol: StreamProtocol) -> Option<RpcSeverity> {
    match code {
        // Peer says our request was malformed. Either we're buggy or peer is
        // — LowTolerance gives a few strikes before disconnect.
        RPC_ERR_INVALID_REQUEST => Some(RpcSeverity::LowTolerance),
        // Peer's internal trouble. Not malicious — tolerate, but track.
        RPC_ERR_SERVER_ERROR => Some(RpcSeverity::MidTolerance),
        RPC_ERR_RESOURCE_UNAVAILABLE => match protocol {
            // Peer can't serve blocks they should have. Useless to keep
            // around — ban (mirrors lighthouse for outbound block sync).
            StreamProtocol::BeaconBlocksByRange | StreamProtocol::BeaconBlocksByRoot => {
                Some(RpcSeverity::Fatal)
            }
            // By-root is naturally sparse: many peers won't custody every
            // requested root. No penalty.
            StreamProtocol::DataColumnSidecarsByRoot => None,
            // By-range — peer should custody columns in their group;
            // missing column data is suspicious but not necessarily
            // malicious.
            StreamProtocol::DataColumnSidecarsByRange => Some(RpcSeverity::MidTolerance),
            // Status/Ping/Goodbye/MetaData/Identity/GossipSub — odd but
            // not abusive.
            _ => Some(RpcSeverity::HighTolerance),
        },
        // Lighthouse-emitted rate-limit signal. Means we're hammering them,
        // not that they're misbehaving — back off, don't ban.
        RPC_ERR_RATE_LIMITED => Some(RpcSeverity::MidTolerance),
        // Unknown / reserved code. Spec may add new codes — forward-compat
        // mild penalty rather than crash.
        _ => Some(RpcSeverity::HighTolerance),
    }
}

pub struct Controller {
    peer_manager: PeerManager,
    last_tick: Instant,
    /// Latest beacon status - set on sync.
    status: Option<[u8; STATUS_V2_SIZE]>,
    metadata: [u8; METADATA_SIZE],
    /// When false, the 700ms heartbeat skips the per-peer Ping fan-out.
    /// Tests use this to keep the peer-state machine ticking without
    /// generating background Ping traffic that would interfere with
    /// targeted RPC assertions.
    auto_ping: bool,
}

impl Controller {
    /// Build a Controller with a fresh `PeerManager`. `status` and
    /// `metadata` start empty — callers update them via `set_status` /
    /// `set_metadata` once chain state is available.
    pub fn new(peer_manager: PeerManager) -> Self {
        Self {
            peer_manager,
            last_tick: Instant::now(),
            status: None,
            metadata: [0u8; METADATA_SIZE],
            auto_ping: true,
        }
    }

    pub fn set_status(&mut self, status: [u8; STATUS_V2_SIZE]) {
        self.status = Some(status);
    }

    pub fn set_metadata(&mut self, metadata: [u8; METADATA_SIZE]) {
        self.metadata = metadata;
    }

    /// Toggle the heartbeat-driven outbound Ping fan-out. Default is on.
    pub fn set_auto_ping(&mut self, enabled: bool) {
        self.auto_ping = enabled;
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }
}

impl Tile<SilverSpine> for Controller {
    fn loop_body(&mut self, adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        let now = Instant::now();
        adapter.consume(|event: PeerEvent, producers| {
            self.peer_manager.handle_event(event, now, &mut |pc| {
                match pc {
                    silver_common::PeerControl::P2pSend(send) => {
                        producers.p2p_send.produce(&send.into())
                    }
                    other => producers.peer_control.produce(&other.into()),
                };
            });
        });
        adapter.consume(|rpc: RpcInbound, producers| {
            let mut on_event = |pc| {
                match pc {
                    silver_common::PeerControl::P2pSend(send) => {
                        producers.p2p_send.produce(&send.into())
                    }
                    other => producers.peer_control.produce(&other.into()),
                };
            };

            match rpc {
                RpcInbound::Request(RpcRequestInbound { stream_id, request }) => match request {
                    RpcRequest::StatusV1(status_v1) => {
                        self.peer_manager.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V1(status_v1),
                            },
                            now,
                            &mut on_event,
                        );
                        if let Some(status) = self.status.as_ref() {
                            let status = StatusView::as_v1(status).try_into().unwrap();
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::StatusV1(status),
                                }))
                                .into(),
                            );
                        } else {
                            let mut msg = [0u8; 256];
                            let err_bytes = "peer not initialised".as_bytes();
                            msg[..err_bytes.len()].copy_from_slice(err_bytes);
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::Error {
                                        error: 2,
                                        msg,
                                        len: err_bytes.len(),
                                    },
                                }))
                                .into(),
                            );
                        }
                    }
                    RpcRequest::StatusV2(status_v2) => {
                        self.peer_manager.handle_event(
                            PeerEvent::P2pPeerStatus {
                                p2p_peer: stream_id.peer(),
                                status_ssz: PeerStatus::V2(status_v2),
                            },
                            now,
                            &mut on_event,
                        );
                        if let Some(status) = self.status.as_ref() {
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::StatusV2(*status),
                                }))
                                .into(),
                            );
                        } else {
                            let mut msg = [0u8; 256];
                            let err_bytes = "peer not initialised".as_bytes();
                            msg[..err_bytes.len()].copy_from_slice(err_bytes);
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                    stream_id,
                                    response: RpcResponse::Error {
                                        error: 2,
                                        msg,
                                        len: err_bytes.len(),
                                    },
                                }))
                                .into(),
                            );
                        }
                    }
                    RpcRequest::Ping(ping) => {
                        let current_peer_metadata_seq =
                            self.peer_manager.peer_metadata_seq(stream_id.peer());
                        let metadata_seq = u64::from_le_bytes(ping);
                        producers.p2p_send.produce(
                            &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                stream_id,
                                response: RpcResponse::Ping(
                                    MetadataView::seq_number(&self.metadata).to_le_bytes(),
                                ),
                            }))
                            .into(),
                        );

                        if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq) {
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                                    application_id: 0,
                                    peer: stream_id.peer(),
                                    request: RpcRequest::MetaData,
                                }))
                                .into(),
                            );
                        }
                    }
                    RpcRequest::Goodbye(goodbye) => self.peer_manager.handle_event(
                        PeerEvent::P2pPeerGoodbye {
                            p2p_peer: stream_id.peer(),
                            status: u64::from_le_bytes(goodbye),
                        },
                        now,
                        &mut on_event,
                    ),
                    RpcRequest::MetaData => {
                        producers.p2p_send.produce(
                            &P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                stream_id,
                                response: RpcResponse::MetaData(self.metadata),
                            }))
                            .into(),
                        );
                    }
                    _ => {} // block and data column request not handled here
                },
                RpcInbound::Response(RpcResponseInbound {
                    application_id,
                    stream_id,
                    response,
                }) => match response {
                    RpcResponse::StatusV1(status_v1) => self.peer_manager.handle_event(
                        PeerEvent::P2pPeerStatus {
                            p2p_peer: stream_id.peer(),
                            status_ssz: PeerStatus::V1(status_v1),
                        },
                        now,
                        &mut on_event,
                    ),
                    RpcResponse::StatusV2(status_v2) => self.peer_manager.handle_event(
                        PeerEvent::P2pPeerStatus {
                            p2p_peer: stream_id.peer(),
                            status_ssz: PeerStatus::V2(status_v2),
                        },
                        now,
                        &mut on_event,
                    ),
                    RpcResponse::Ping(ping) => {
                        let current_peer_metadata_seq =
                            self.peer_manager.peer_metadata_seq(stream_id.peer());
                        let metadata_seq = u64::from_le_bytes(ping);
                        if !matches!(current_peer_metadata_seq, Some(seq) if seq == metadata_seq) {
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                                    application_id: 0,
                                    peer: stream_id.peer(),
                                    request: RpcRequest::MetaData,
                                }))
                                .into(),
                            );
                        }
                    }
                    RpcResponse::Error { error, msg, len } => {
                        let err = String::from_utf8_lossy(&msg[..len]);
                        tracing::error!(
                            error,
                            err = err.deref(),
                            application_id,
                            ?stream_id,
                            "rpc error response"
                        );

                        if let Some(severity) =
                            severity_for_error_response(error, stream_id.protocol())
                        {
                            self.peer_manager.handle_event(
                                PeerEvent::RpcMisbehaviour { p2p_peer: stream_id.peer(), severity },
                                now,
                                &mut on_event,
                            );
                        }
                    }
                    _ => {}
                },
            };
        });

        if self.last_tick.elapsed() > Duration::from_millis(700) {
            self.last_tick = now;
            self.peer_manager.tick(now, &mut |event| {
                match event {
                    silver_common::PeerControl::P2pSend(send) => adapter.produce(send),
                    other => adapter.produce(other),
                };
            });

            // send pings
            if self.auto_ping {
                let ping = RpcRequest::Ping(MetadataView::seq_number(&self.metadata).to_le_bytes());
                for peer in self.peer_manager.live_peers() {
                    adapter.produce(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                        application_id: 0,
                        peer,
                        request: ping,
                    })));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_request_is_low_tolerance() {
        // Same severity for any protocol — peer claims our request was bad.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_INVALID_REQUEST, StreamProtocol::Ping),
            Some(RpcSeverity::LowTolerance)
        ));
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_INVALID_REQUEST,
                StreamProtocol::BeaconBlocksByRange
            ),
            Some(RpcSeverity::LowTolerance)
        ));
    }

    #[test]
    fn server_error_is_mid_tolerance() {
        assert!(matches!(
            severity_for_error_response(RPC_ERR_SERVER_ERROR, StreamProtocol::StatusV2),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn resource_unavailable_blocks_outbound_is_fatal() {
        // Ban: peer admits they can't serve us blocks we expected.
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::BeaconBlocksByRange
            ),
            Some(RpcSeverity::Fatal)
        ));
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::BeaconBlocksByRoot
            ),
            Some(RpcSeverity::Fatal)
        ));
    }

    #[test]
    fn resource_unavailable_columns_by_root_is_silent() {
        // Sparse custody — no penalty.
        assert!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::DataColumnSidecarsByRoot
            )
            .is_none()
        );
    }

    #[test]
    fn resource_unavailable_columns_by_range_is_mid() {
        assert!(matches!(
            severity_for_error_response(
                RPC_ERR_RESOURCE_UNAVAILABLE,
                StreamProtocol::DataColumnSidecarsByRange
            ),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn resource_unavailable_other_is_high_tolerance() {
        // Status/Ping/Goodbye/MetaData/Identity/GossipSub all share this.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_RESOURCE_UNAVAILABLE, StreamProtocol::Ping),
            Some(RpcSeverity::HighTolerance)
        ));
    }

    #[test]
    fn rate_limited_is_mid_tolerance() {
        // Self-throttle, don't ban.
        assert!(matches!(
            severity_for_error_response(RPC_ERR_RATE_LIMITED, StreamProtocol::BeaconBlocksByRange),
            Some(RpcSeverity::MidTolerance)
        ));
    }

    #[test]
    fn unknown_code_is_high_tolerance() {
        // Forward-compat: spec might add new codes — don't crash, don't ban.
        assert!(matches!(
            severity_for_error_response(0xff, StreamProtocol::Ping),
            Some(RpcSeverity::HighTolerance)
        ));
        assert!(matches!(
            severity_for_error_response(0x42, StreamProtocol::BeaconBlocksByRange),
            Some(RpcSeverity::HighTolerance)
        ));
    }
}
