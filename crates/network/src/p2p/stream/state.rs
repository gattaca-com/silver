use std::io::Error;

use flux::utils::DCacheRef;

use super::StreamProtocol;
use crate::p2p::stream::{MULTISTREAM_V1, snappy::SnappyDecoder};

pub(super) enum StreamState {
    OutgoingSetup(OutgoingMultiStream),
    IncomingSetup(IncomingMultiStream),
    GossipConnected { inbound: ConnectedInState, outbound: ConnectedOutState },
    RpcDiallerConnected(RpcDiallerConnected),
    RpcReceiverConnected(RpcReceiverConnected),
}

impl StreamState {
    pub(super) fn read_bytes_max(&self) -> usize {
        match self {
            StreamState::OutgoingSetup(outgoing_multi_stream) => match outgoing_multi_stream {
                OutgoingMultiStream::WritingMultiStream { .. } => 0,
                OutgoingMultiStream::ReadingMultiStream { protocol, read, .. } => {
                    MULTISTREAM_V1.len() + protocol.multiselect().len() - read
                }
            },
            StreamState::IncomingSetup(incoming_multi_stream) => match incoming_multi_stream {
                IncomingMultiStream::ReadingMultiStream { buffer, read } => buffer.len() - read,
                IncomingMultiStream::ReadingProtocol { limit, read, .. } => limit - read,
                IncomingMultiStream::WritingMultiStream { .. } => 0,
                IncomingMultiStream::WritingReject { .. } => 0,
            },
            StreamState::GossipConnected { inbound, outbound } => todo!(),
            StreamState::RpcDiallerConnected(dialler) => match dialler {
                RpcDiallerConnected::WritingRequest { .. } => 0,
                RpcDiallerConnected::ReadingResult => 1,
                RpcDiallerConnected::ReadingResponseLength { buffer, read } => buffer.len() - read,
                RpcDiallerConnected::ReadingResponse { .. } => usize::MAX, // read all
            },
            StreamState::RpcReceiverConnected(receiver) => match receiver {
                RpcReceiverConnected::ReadingRequestLength { buffer, read } => buffer.len() - read,
                RpcReceiverConnected::ReadingRequest { .. } => usize::MAX, // read all
                RpcReceiverConnected::WritingError => 0,
                RpcReceiverConnected::WritingResponseLength { .. } => 0,
                RpcReceiverConnected::WritingResponse { .. } => 0,
            },
        }
    }

    pub(super) fn read(mut self, data: &[u8]) -> Result<Self, Error> {
        match &mut self {
            StreamState::OutgoingSetup(outgoing_multi_stream) => match outgoing_multi_stream {
                OutgoingMultiStream::WritingMultiStream { .. } => Ok(self),
                OutgoingMultiStream::ReadingMultiStream { protocol, buffer, read } => {
                    let to_read = (MULTISTREAM_V1.len() + protocol.multiselect().len() - *read)
                        .min(data.len());
                    buffer[*read..*read + to_read].copy_from_slice(&data[..to_read]);
                    *read += to_read;

                    if *read < MULTISTREAM_V1.len() + protocol.multiselect().len() {
                        Ok(self)
                    } else {
                        // Check that the protcol matches.
                        if &buffer[MULTISTREAM_V1.len()..*read] == protocol.multiselect() {
                            if protocol.is_request_response() {
                                let dcache_ref = DCacheRef { offset: 0, len: 0 }; // TODO
                                Ok(Self::RpcDiallerConnected(RpcDiallerConnected::WritingRequest {
                                    request: dcache_ref,
                                    written: 0,
                                }))
                            } else {
                                Ok(Self::GossipConnected {
                                    inbound: ConnectedInState::Ready,
                                    outbound: ConnectedOutState::Ready,
                                })
                            }
                        } else {
                            Ok(self)
                        }
                    }

                    //Ok(self)
                }
            },
            StreamState::IncomingSetup(incoming_multi_stream) => todo!(),
            StreamState::GossipConnected { inbound, outbound } => todo!(),
            StreamState::RpcDiallerConnected(rpc_dialler_connected) => todo!(),
            StreamState::RpcReceiverConnected(rpc_receiver_connected) => todo!(),
        }
    }
}

pub(super) enum OutgoingMultiStream {
    WritingMultiStream {
        protocol: StreamProtocol,
        written: usize,
    },
    ReadingMultiStream {
        protocol: StreamProtocol,
        buffer: [u8; 96], // 87 bytes is max size of the multistream headers
        read: usize,
    },
}

pub(super) enum IncomingMultiStream {
    ReadingMultiStream {
        buffer: [u8; 21], // multistream header + protocol length
        read: usize,
    },
    ReadingProtocol {
        buffer: [u8; 66], // protocol string
        limit: usize,
        read: usize,
    },
    WritingMultiStream {
        protocol: StreamProtocol,
        written: usize,
    },
    WritingReject {
        written: usize,
    },
}

pub(super) enum RpcDiallerConnected {
    WritingRequest {
        request: DCacheRef,
        written: usize,
    },
    /// reading result byte
    /// 0 - success
    /// 1 - bad request
    /// 2 - server error
    /// 3 - resource unavailable
    ReadingResult,
    /// reading var-int length
    ReadingResponseLength {
        buffer: [u8; 8],
        read: usize,
    },
    /// reading compressed response
    ReadingResponse {
        decoder: SnappyDecoder,
        response: DCacheRef,
        read: usize,
    },
}

pub(super) enum RpcReceiverConnected {
    ReadingRequestLength {
        buffer: [u8; 8],
        read: usize,
    },
    /// reading compressed request
    ReadingRequest {
        decoder: SnappyDecoder,
        request: DCacheRef,
        read: usize,
    },
    /// writing error result byte
    /// 1 - bad request
    /// 2 - server error
    /// 3 - resource unavailable
    WritingError,
    /// Writing var-int length
    WritingResponseLength {
        buffer: [u8; 8],
        to_write: usize,
    },
    /// reading compressed response
    WritingResponse {
        //encoder: FrameEncoder,
        request: DCacheRef,
        written: usize,
    },
}

pub(super) enum ConnectedOutState {
    Ready,
}

pub(super) enum ConnectedInState {
    Ready,
}
