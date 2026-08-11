use std::time::Instant;

use buffa::Message;
use silver_common::{
    P2pStreamId, RpcInbound, RpcRequest, RpcRequestInbound, RpcResponse, RpcResponseInbound,
    StreamProtocol, encode_observed_addr,
    rpc_rate_limit::{RpcRateLimit, RpcRateLimitSet},
};

use super::{
    gossip_in::{GOSSIP_BODY_STALL_TIMEOUT, GossipReadState},
    gossip_out::GossipWriteState,
};
use crate::{
    NetEvent,
    p2p::{
        context::Context,
        streams::{
            AcquiredRpcOutbound, StreamError, StreamIo,
            identify_in::WriteIdentifyResponse,
            identify_out::ReadIdentifyResponse,
            negotiate::NegotiateState,
            rpc::{
                AcquiredRpcResponse, RpcCodec, RpcIn, RpcOut, RpcReadRequest, RpcReadResponse,
                RpcWriteRequest, RpcWriteResponse,
            },
        },
    },
};

#[derive(Debug, Default)]
#[allow(clippy::large_enum_variant)]
pub enum StreamState {
    Negotiate(NegotiateState),
    Gossip {
        read: GossipReadState,
        write: GossipWriteState,
    },
    IncomingRpc {
        rpc: RpcIn,
        codec: Box<RpcCodec>,
    },
    OutgoingRpc {
        rpc: RpcOut,
        codec: Box<RpcCodec>,
    },
    IncomingIdentify(WriteIdentifyResponse),
    OutgoingIdentify(ReadIdentifyResponse),
    #[default]
    Finished,
}

enum InboundRpcAdmission {
    Admit,
    RateLimited,
    Drop,
}

fn admit_inbound_rpc(
    limits: &mut RpcRateLimitSet,
    stream_id: P2pStreamId,
    request: &RpcRequest,
    now: Instant,
) -> InboundRpcAdmission {
    let protocol = request.protocol();
    let tokens = request.rate_limit_tokens().unwrap_or(1);
    match limits.admit_inbound(protocol, tokens, now) {
        RpcRateLimit::Allowed => InboundRpcAdmission::Admit,
        RpcRateLimit::TooLarge | RpcRateLimit::TooSoon => {
            tracing::debug!(?stream_id, ?protocol, tokens, "inbound rpc request rate limited");
            if protocol == StreamProtocol::Goodbye {
                InboundRpcAdmission::Drop
            } else {
                InboundRpcAdmission::RateLimited
            }
        }
    }
}

impl StreamState {
    pub fn new_inbound() -> Self {
        Self::Negotiate(NegotiateState::new_inbound())
    }

    pub fn new_outbound(protocol: StreamProtocol) -> Self {
        Self::Negotiate(NegotiateState::new_outbound(protocol))
    }

    /// Cheap variant name for diagnostics (stream-error logging). Captured
    /// before `spin` consumes the state so a teardown log can report which
    /// phase the stream was in.
    pub fn name(&self) -> &'static str {
        match self {
            StreamState::Negotiate(_) => "Negotiate",
            StreamState::Gossip { .. } => "Gossip",
            StreamState::IncomingRpc { .. } => "IncomingRpc",
            StreamState::OutgoingRpc { .. } => "OutgoingRpc",
            StreamState::IncomingIdentify(_) => "IncomingIdentify",
            StreamState::OutgoingIdentify(_) => "OutgoingIdentify",
            StreamState::Finished => "Finished",
        }
    }

    // TODO `is_complete` + `on_close` are unused pending a recv-EOF
    // hook. The multipart RPC terminator is "peer FIN on recv half";
    // there is currently no event-driven trigger for that —
    // `StreamEvent::{Finished,Stopped}` from quinn are send-half only.
    // When recv-EOF detection lands, the caller should consult
    // `is_complete` to decide between clean teardown and emitting
    // `NetEvent::StreamClosed`, and call `on_close` to emit the
    // synthetic `RpcResponse::Complete`.
    #[allow(dead_code)]
    pub fn is_complete(&self) -> bool {
        match self {
            StreamState::Negotiate(_) => false,
            StreamState::Gossip { read, write } => {
                matches!(read, GossipReadState::Closed) && matches!(write, GossipWriteState::Idle)
            }
            StreamState::IncomingRpc { rpc, .. } => {
                matches!(rpc, RpcIn::WriteResponse(RpcWriteResponse::Idle))
            }
            StreamState::OutgoingRpc { rpc, .. } => {
                matches!(rpc, RpcOut::ReadResponse(RpcReadResponse::ReadingPrefix { read, .. }) if *read == 0)
            }
            StreamState::IncomingIdentify(write) => matches!(write, WriteIdentifyResponse::Done),
            StreamState::OutgoingIdentify(_) => false,
            StreamState::Finished => true,
        }
    }

    /// Parked waiting on a tcache reservation. Space frees when another tile
    /// consumes — no quinn event fires, so the owner must poll-retry.
    pub fn awaiting_alloc(&self) -> bool {
        matches!(
            self,
            StreamState::Gossip { read: GossipReadState::AllocBody { .. }, .. } |
                StreamState::IncomingRpc {
                    rpc: RpcIn::ReadRequest(RpcReadRequest::AllocBody { .. }),
                    ..
                } |
                StreamState::OutgoingRpc {
                    rpc: RpcOut::ReadResponse(RpcReadResponse::AllocBody { .. }),
                    ..
                }
        )
    }

    /// Write side parked idle, able to pull a queued outbound msg. Starting
    /// that pull is spin-only work — no quinn event fires for it. Mid-write
    /// parks are excluded: they are write-blocked and Writable re-drives
    /// them; re-spinning would busy-loop until the peer grants credit.
    pub fn write_idle(&self) -> bool {
        matches!(
            self,
            StreamState::Gossip { write: GossipWriteState::Idle, .. } |
                StreamState::IncomingRpc {
                    rpc: RpcIn::WriteResponse(RpcWriteResponse::Idle),
                    ..
                }
        )
    }

    /// Instant at which this state times out if not spun; `None` when no
    /// timeout applies. A silent peer produces no quinn event, so the owner
    /// must arrange a spin at this deadline.
    pub fn deadline(&self) -> Option<Instant> {
        match self {
            StreamState::OutgoingRpc { rpc: RpcOut::ReadResponse(read_response), .. } => {
                read_response.deadline()
            }
            StreamState::Gossip {
                read: GossipReadState::ReadingBody { last_read, .. }, ..
            } => Some(*last_read + GOSSIP_BODY_STALL_TIMEOUT),
            _ => None,
        }
    }

    pub fn is_receive_only(&self, protocol: StreamProtocol) -> bool {
        match self {
            StreamState::Negotiate(state) => matches!(state, NegotiateState::OutReading { .. }),
            StreamState::Gossip { read, write } => {
                matches!(write, GossipWriteState::Idle) && !matches!(read, GossipReadState::Closed)
            }
            StreamState::IncomingRpc { .. } => protocol == StreamProtocol::Goodbye,
            StreamState::OutgoingRpc { rpc, .. } => {
                matches!(rpc, RpcOut::ReadResponse(_)) || protocol == StreamProtocol::Metadata
            }
            StreamState::IncomingIdentify(_) => false,
            StreamState::OutgoingIdentify(_) => true,
            StreamState::Finished => true,
        }
    }

    #[allow(dead_code)]
    pub fn on_close<F>(&self, p2p_id: &P2pStreamId, emit: &mut F)
    where
        F: FnMut(NetEvent),
    {
        if p2p_id.protocol().has_multipart_response() &&
            let StreamState::OutgoingRpc {
                rpc: RpcOut::ReadResponse(RpcReadResponse::ReadingPrefix { app_id, .. }),
                ..
            } = self
        {
            emit(NetEvent::RpcInbound(RpcInbound::Response(RpcResponseInbound {
                application_id: *app_id,
                stream_id: *p2p_id,
                response: RpcResponse::Complete,
            })))
        }
    }

    /// Step the stream state.
    pub fn spin<S, F>(
        self,
        io: &mut S,
        id: &mut P2pStreamId,
        context: &mut Context,
        now: Instant,
        inbound_rpc_limits: &mut RpcRateLimitSet,
        emit: &mut F,
    ) -> Result<Self, StreamError>
    where
        S: StreamIo,
        F: FnMut(NetEvent),
    {
        match self {
            StreamState::Negotiate(negotiate_state) => {
                match negotiate_state.spin(id.stream_id(), io)? {
                    NegotiateState::Done(stream_protocol) => {
                        // Pin the negotiated protocol onto the stream id
                        // so downstream RPC reservation / out-buffer logic
                        // can dispatch on it.
                        id.set_protocol(stream_protocol);
                        match stream_protocol {
                            StreamProtocol::Unset => unreachable!(),
                            StreamProtocol::GossipSub => Ok(Self::Gossip {
                                read: GossipReadState::default(),
                                write: GossipWriteState::Idle,
                            }),
                            StreamProtocol::Identity => {
                                if id.is_incoming() {
                                    // TODO identify should always be present post-startup.
                                    let mut identify = context.identify.clone().unwrap();
                                    tracing::trace!(
                                        "send identify protocols: {:?}",
                                        identify.protocols
                                    );
                                    identify.observedAddr =
                                        Some(encode_observed_addr(&io.remote_addr()));
                                    let identify_protobuf = identify.encode_to_vec();
                                    Ok(Self::IncomingIdentify(WriteIdentifyResponse::new(
                                        identify_protobuf,
                                    )?))
                                } else {
                                    io.close_write(id.stream_id())?;
                                    Ok(Self::OutgoingIdentify(ReadIdentifyResponse::default()))
                                }
                            }
                            rpc => {
                                if id.is_incoming() {
                                    if rpc == StreamProtocol::Metadata {
                                        // Per spec MetaData has no request body —
                                        // emit the inbound request now so the
                                        // controller can issue a response without
                                        // silver trying to read a non-existent
                                        // varint+snappy body off the wire.
                                        let request = RpcRequest::MetaData;
                                        match admit_inbound_rpc(
                                            inbound_rpc_limits,
                                            *id,
                                            &request,
                                            now,
                                        ) {
                                            InboundRpcAdmission::Admit => {
                                                emit(NetEvent::RpcInbound(RpcInbound::Request(
                                                    RpcRequestInbound { stream_id: *id, request },
                                                )));
                                                Ok(Self::IncomingRpc {
                                                    rpc: RpcIn::WriteResponse(
                                                        RpcWriteResponse::Idle,
                                                    ),
                                                    codec: RpcCodec::incoming(),
                                                })
                                            }
                                            InboundRpcAdmission::RateLimited => {
                                                Ok(Self::IncomingRpc {
                                                    rpc: RpcIn::WriteResponse(
                                                        RpcWriteResponse::new(
                                                            AcquiredRpcResponse::rate_limited(),
                                                        )?,
                                                    ),
                                                    codec: RpcCodec::incoming(),
                                                })
                                            }
                                            InboundRpcAdmission::Drop => {
                                                io.close_write(id.stream_id())?;
                                                Ok(Self::Finished)
                                            }
                                        }
                                    } else {
                                        Ok(Self::IncomingRpc {
                                            rpc: RpcIn::ReadRequest(RpcReadRequest::default()),
                                            codec: RpcCodec::incoming(),
                                        })
                                    }
                                } else {
                                    let (app_id, request) = match io.rpc_next() {
                                        Some(AcquiredRpcOutbound::Request(req)) => {
                                            (req.application_id, req.request)
                                        }
                                        _ => return Err(StreamError::InvalidRpc),
                                    };
                                    Ok(Self::OutgoingRpc {
                                        rpc: RpcOut::WriteRequest(RpcWriteRequest::new(
                                            app_id, request,
                                        )?),
                                        codec: RpcCodec::outgoing(),
                                    })
                                }
                            }
                        }
                    }
                    other => Ok(Self::Negotiate(other)),
                }
            }
            StreamState::Gossip { mut read, mut write } => {
                read = read.spin(io, &mut context.gossip_producer, id, now)?;
                write = write.spin(io, id)?;

                if matches!(read, GossipReadState::Closed) && id.is_incoming() {
                    // read closed on incoming gossip stream - terminate.
                    Ok(Self::Finished)
                } else {
                    Ok(Self::Gossip { read, write })
                }
            }
            StreamState::IncomingRpc { rpc, mut codec } => match rpc {
                RpcIn::ReadRequest(read_request) => {
                    match read_request.spin(io, id, &mut context.rpc_producer, &mut codec.dec)? {
                        RpcReadRequest::Complete { msg } => {
                            match admit_inbound_rpc(inbound_rpc_limits, *id, &msg, now) {
                                InboundRpcAdmission::Admit => {
                                    emit(NetEvent::RpcInbound(RpcInbound::Request(
                                        RpcRequestInbound { stream_id: *id, request: msg },
                                    )));
                                    Ok(Self::IncomingRpc {
                                        rpc: RpcIn::WriteResponse(RpcWriteResponse::Idle),
                                        codec,
                                    })
                                }
                                InboundRpcAdmission::RateLimited => Ok(Self::IncomingRpc {
                                    rpc: RpcIn::WriteResponse(RpcWriteResponse::new(
                                        AcquiredRpcResponse::rate_limited(),
                                    )?),
                                    codec,
                                }),
                                InboundRpcAdmission::Drop => {
                                    io.close_write(id.stream_id())?;
                                    Ok(Self::Finished)
                                }
                            }
                        }
                        other => Ok(Self::IncomingRpc { rpc: RpcIn::ReadRequest(other), codec }),
                    }
                }
                RpcIn::WriteResponse(mut write_response) => {
                    write_response = write_response.spin(id, io, &mut codec.enc)?;
                    Ok(Self::IncomingRpc { rpc: RpcIn::WriteResponse(write_response), codec })
                }
            },
            StreamState::OutgoingRpc { rpc, mut codec } => match rpc {
                RpcOut::WriteRequest(write_request) => {
                    match write_request.spin(id, io, &mut codec.enc)? {
                        RpcWriteRequest::Complete(app_id) => {
                            // close write side
                            io.close_write(id.stream_id())?;
                            let read = RpcReadResponse::new(app_id, 0, now, &mut codec.dec);
                            Ok(Self::OutgoingRpc { rpc: RpcOut::ReadResponse(read), codec })
                        }
                        other => Ok(Self::OutgoingRpc { rpc: RpcOut::WriteRequest(other), codec }),
                    }
                }
                RpcOut::ReadResponse(read_response) => {
                    let mut read_response = read_response;
                    loop {
                        match read_response.spin(
                            io,
                            id,
                            now,
                            &mut context.rpc_producer,
                            &mut codec.dec,
                        )? {
                            RpcReadResponse::Complete { app_id, chunk, msg } => {
                                // For multipart, `RpcResponse::Complete` is the
                                // synthetic terminator emitted on recv-EOF — at
                                // that point the stream is done from our side
                                // and re-arming `ReadingPrefix` would just hit
                                // `ClosedStream` on the next poll, tripping the
                                // spin error path and a spurious
                                // `P2pStreamClosed` peer-score hit. Re-arm only
                                // for non-terminator chunks; transition to
                                // `Finished` on `Complete`/`Error`.
                                let terminal = !id.protocol().has_multipart_response() ||
                                    matches!(
                                        msg,
                                        RpcResponse::Complete | RpcResponse::Error { .. }
                                    );
                                emit(NetEvent::RpcInbound(RpcInbound::Response(
                                    RpcResponseInbound {
                                        application_id: app_id,
                                        stream_id: *id,
                                        response: msg,
                                    },
                                )));
                                if terminal {
                                    io.close_write(id.stream_id())?;
                                    return Ok(Self::Finished);
                                }
                                // Loop: the next chunk may already be buffered
                                // in quinn with no further Readable coming.
                                read_response =
                                    RpcReadResponse::new(app_id, chunk + 1, now, &mut codec.dec);
                            }
                            other => {
                                return Ok(Self::OutgoingRpc {
                                    rpc: RpcOut::ReadResponse(other),
                                    codec,
                                });
                            }
                        }
                    }
                }
            },
            StreamState::IncomingIdentify(incoming_identify) => {
                match incoming_identify.spin(id, io)? {
                    WriteIdentifyResponse::Done => {
                        io.close_write(id.stream_id())?;
                        Ok(Self::Finished)
                    }
                    other => Ok(Self::IncomingIdentify(other)),
                }
            }
            StreamState::OutgoingIdentify(outgoing_identify) => {
                match outgoing_identify.spin(io, id)? {
                    ReadIdentifyResponse::Complete { identify } => {
                        io.close_write(id.stream_id())?;
                        emit(NetEvent::PeerIdentify { peer: id.peer(), identify });
                        Ok(Self::Finished)
                    }
                    other => Ok(Self::OutgoingIdentify(other)),
                }
            }
            StreamState::Finished => Err(StreamError::StreamClosed),
        }
    }
}
