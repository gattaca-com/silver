use buffa::Message;
use silver_common::{
    P2pStreamId, RpcInbound, RpcRequest, RpcRequestInbound, RpcResponse, RpcResponseInbound,
    StreamProtocol, encode_observed_addr,
};

use super::{gossip_in::GossipReadState, gossip_out::GossipWriteState};
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
                RpcIn, RpcOut, RpcReadRequest, RpcReadResponse, RpcWriteRequest, RpcWriteResponse,
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
    IncomingRpc(RpcIn),
    OutgoingRpc(RpcOut),
    IncomingIdentify(WriteIdentifyResponse),
    OutgoingIdentify(ReadIdentifyResponse),
    #[default]
    Finished,
}

impl StreamState {
    pub fn new_inbound() -> Self {
        Self::Negotiate(NegotiateState::new_inbound())
    }

    pub fn new_outbound(protocol: StreamProtocol) -> Self {
        Self::Negotiate(NegotiateState::new_outbound(protocol))
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
            StreamState::IncomingRpc(rpc_in) => {
                matches!(rpc_in, RpcIn::WriteResponse(RpcWriteResponse::Idle))
            }
            StreamState::OutgoingRpc(rpc_out) => {
                matches!(rpc_out, RpcOut::ReadResponse(RpcReadResponse::ReadingPrefix { read, .. }) if *read == 0)
            }
            StreamState::IncomingIdentify(write) => matches!(write, WriteIdentifyResponse::Done),
            StreamState::OutgoingIdentify(_) => false,
            StreamState::Finished => true,
        }
    }

    pub fn is_receive_only(&self, protocol: StreamProtocol) -> bool {
        match self {
            StreamState::Negotiate(state) => matches!(state, NegotiateState::OutReading { .. }),
            StreamState::Gossip { read, write } => {
                matches!(write, GossipWriteState::Idle) && !matches!(read, GossipReadState::Closed)
            }
            StreamState::IncomingRpc(inc) => {
                matches!(inc, RpcIn::ReadRequest(_)) && protocol == StreamProtocol::Goodbye
            }
            StreamState::OutgoingRpc(rpc_out) => matches!(rpc_out, RpcOut::ReadResponse(_)),
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
            let StreamState::OutgoingRpc(RpcOut::ReadResponse(RpcReadResponse::ReadingPrefix {
                app_id,
                ..
            })) = self
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
                                        emit(NetEvent::RpcInbound(RpcInbound::Request(
                                            RpcRequestInbound {
                                                stream_id: *id,
                                                request: RpcRequest::MetaData,
                                            },
                                        )));
                                        Ok(Self::IncomingRpc(RpcIn::WriteResponse(
                                            RpcWriteResponse::Idle,
                                        )))
                                    } else {
                                        Ok(Self::IncomingRpc(RpcIn::ReadRequest(
                                            RpcReadRequest::default(),
                                        )))
                                    }
                                } else {
                                    let (app_id, request) = match io.rpc_next() {
                                        Some(AcquiredRpcOutbound::Request(req)) => {
                                            (req.application_id, req.request)
                                        }
                                        _ => return Err(StreamError::InvalidRpc),
                                    };
                                    Ok(Self::OutgoingRpc(RpcOut::WriteRequest(
                                        RpcWriteRequest::new(app_id, request)?,
                                    )))
                                }
                            }
                        }
                    }
                    other => Ok(Self::Negotiate(other)),
                }
            }
            StreamState::Gossip { mut read, mut write } => {
                read = read.spin(io, &mut context.gossip_producer, id)?;
                write = write.spin(io, id)?;

                if matches!(read, GossipReadState::Closed) && id.is_incoming() {
                    // read closed on incoming gossip stream - terminate.
                    Ok(Self::Finished)
                } else {
                    Ok(Self::Gossip { read, write })
                }
            }
            StreamState::IncomingRpc(rpc_in) => match rpc_in {
                RpcIn::ReadRequest(read_request) => {
                    match read_request.spin(io, id, &mut context.rpc_producer)? {
                        RpcReadRequest::Complete { msg } => {
                            emit(NetEvent::RpcInbound(RpcInbound::Request(RpcRequestInbound {
                                stream_id: *id,
                                request: msg,
                            })));
                            Ok(Self::IncomingRpc(RpcIn::WriteResponse(RpcWriteResponse::Idle)))
                        }
                        other => Ok(Self::IncomingRpc(RpcIn::ReadRequest(other))),
                    }
                }
                RpcIn::WriteResponse(mut write_response) => {
                    write_response = write_response.spin(id, io)?;
                    Ok(Self::IncomingRpc(RpcIn::WriteResponse(write_response)))
                }
            },
            StreamState::OutgoingRpc(rpc_out) => match rpc_out {
                RpcOut::WriteRequest(write_request) => {
                    match write_request.spin(id, io)? {
                        RpcWriteRequest::Complete(app_id) => {
                            // close write side
                            io.close_write(id.stream_id())?;
                            Ok(Self::OutgoingRpc(RpcOut::ReadResponse(RpcReadResponse::new(
                                app_id,
                            ))))
                        }
                        other => Ok(Self::OutgoingRpc(RpcOut::WriteRequest(other))),
                    }
                }
                RpcOut::ReadResponse(read_response) => {
                    match read_response.spin(io, id, &mut context.rpc_producer)? {
                        RpcReadResponse::Complete { app_id, msg } => {
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
                                matches!(msg, RpcResponse::Complete | RpcResponse::Error { .. });
                            emit(NetEvent::RpcInbound(RpcInbound::Response(RpcResponseInbound {
                                application_id: app_id,
                                stream_id: *id,
                                response: msg,
                            })));
                            if terminal {
                                io.close_write(id.stream_id())?;
                                Ok(Self::Finished)
                            } else {
                                Ok(Self::OutgoingRpc(RpcOut::ReadResponse(RpcReadResponse::new(
                                    app_id,
                                ))))
                            }
                        }
                        other => Ok(Self::OutgoingRpc(RpcOut::ReadResponse(other))),
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
