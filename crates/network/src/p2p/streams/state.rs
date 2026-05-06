use buffa::Message;
use silver_common::{
    P2pStreamId, RpcInbound, RpcOutbound, RpcRequestInbound, RpcResponseInbound, StreamProtocol,
    encode_observed_addr,
};

use super::{gossip_in::GossipReadState, gossip_out::GossipWriteState};
use crate::{
    NetEvent,
    p2p::{
        context::Context,
        streams::{
            StreamError, StreamIo,
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

    /// Step the stream state.
    pub fn spin<S, F>(
        self,
        io: &mut S,
        id: &P2pStreamId,
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
                    NegotiateState::Done(stream_protocol) => match stream_protocol {
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
                                Ok(Self::OutgoingIdentify(ReadIdentifyResponse::default()))
                            }
                        }
                        rpc => {
                            if id.is_incoming() {
                                Ok(Self::IncomingRpc(RpcIn::ReadRequest(RpcReadRequest::default())))
                            } else {
                                let (app_id, request) = match io.rpc_next() {
                                    Some(RpcOutbound::Request(req)) => {
                                        (req.application_id, req.request)
                                    }
                                    _ => return Err(StreamError::InvalidRpc),
                                };
                                Ok(Self::OutgoingRpc(RpcOut::WriteRequest(RpcWriteRequest::new(
                                    app_id, request,
                                )?)))
                            }
                        }
                    },
                    other => Ok(Self::Negotiate(other)),
                }
            }
            StreamState::Gossip { mut read, mut write } => {
                read = read.spin(io, &mut context.gossip_producer, id)?;
                write = write.spin(io, id, &mut context.gossip_consumer)?;
                Ok(Self::Gossip { read, write })
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
                    write_response = write_response.spin(id, io, &mut context.rpc_consumer)?;
                    Ok(Self::IncomingRpc(RpcIn::WriteResponse(write_response)))
                }
            },
            StreamState::OutgoingRpc(rpc_out) => match rpc_out {
                RpcOut::WriteRequest(write_request) => {
                    match write_request.spin(id, io, &mut context.rpc_consumer)? {
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
                            emit(NetEvent::RpcInbound(RpcInbound::Response(RpcResponseInbound {
                                application_id: app_id,
                                stream_id: *id,
                                response: msg,
                            })));
                            Ok(Self::OutgoingRpc(RpcOut::ReadResponse(RpcReadResponse::new(
                                app_id,
                            ))))
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
