use buffa::MessageView;
use silver_common::{Identify, P2pStreamId, ProtoIdentifyView, decode_varint};

use crate::p2p::streams::{StreamError, StreamIo};

const MAX_MESSAGE_SIZE: u64 = 4096;

/// State machine for reading identift protobuf
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ReadIdentifyResponse {
    /// Reading the response varint length
    ReadingLength { buf: [u8; 10], read: usize },
    /// Reading protobuf bytes.
    ReadingBody { buffer: Vec<u8>, read: usize },
    /// Request read completed
    Complete { identify: Identify },
}

impl Default for ReadIdentifyResponse {
    fn default() -> Self {
        Self::ReadingLength { buf: [0; 10], read: 0 }
    }
}

enum Spin {
    Ok(ReadIdentifyResponse),
    Next(ReadIdentifyResponse),
}

impl ReadIdentifyResponse {
    pub fn spin<S: StreamIo>(
        mut self,
        io: &mut S,
        p2p_id: &P2pStreamId,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, p2p_id)? {
                Spin::Ok(read_state) => return Ok(read_state),
                Spin::Next(read_state) => {
                    self = read_state;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo>(
        self,
        io: &mut S,
        p2p_id: &P2pStreamId,
    ) -> Result<Spin, StreamError> {
        match self {
            ReadIdentifyResponse::ReadingLength { mut buf, mut read } => {
                read += io.read_from_stream(p2p_id.stream_id(), &mut buf[read..])?;
                if read > 0 {
                    for pos in 0..read {
                        if buf[pos] & 0x80 == 0 {
                            // last byte of varint.
                            let (length, offset) = decode_varint(&buf[..read], 0)?;
                            if length > MAX_MESSAGE_SIZE {
                                return Err(StreamError::IdentifyTooBig);
                            }

                            let mut buffer = vec![0u8; length as usize];
                            let body = &buf[offset..read];
                            buffer
                                .get_mut(..body.len())
                                .ok_or(StreamError::InvalidIdentify)?
                                .copy_from_slice(body);

                            return Ok(Spin::Next(Self::ReadingBody { buffer, read: body.len() }));
                        }
                    }
                }
                if read == buf.len() {
                    return Err(StreamError::InvalidIdentify);
                }
                Ok(Spin::Ok(Self::ReadingLength { buf, read }))
            }
            ReadIdentifyResponse::ReadingBody { mut buffer, mut read } => {
                read +=
                    io.read_from_stream(p2p_id.stream_id(), &mut buffer.as_mut_slice()[read..])?;

                if read == buffer.len() {
                    let view = ProtoIdentifyView::decode_view(&buffer)?;
                    Ok(Spin::Ok(Self::Complete { identify: view.try_into()? }))
                } else {
                    Ok(Spin::Ok(Self::ReadingBody { buffer, read }))
                }
            }
            ReadIdentifyResponse::Complete { identify } => {
                Ok(Spin::Ok(Self::Complete { identify }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use quinn_proto::StreamId;
    use silver_common::{StreamProtocol, TRead};

    use super::*;
    use crate::p2p::{
        quic::{Leased, OutboundGossip},
        streams::AcquiredRpcOutbound,
    };

    struct MockIo {
        data: Vec<u8>,
        pos: usize,
    }

    impl StreamIo for MockIo {
        fn write_to_stream(&mut self, _id: StreamId, _data: &[u8]) -> Result<usize, StreamError> {
            unreachable!("read-only test io")
        }

        fn read_from_stream(
            &mut self,
            _id: StreamId,
            buf: &mut [u8],
        ) -> Result<usize, StreamError> {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }

        fn close_write(&mut self, _id: StreamId) -> Result<(), StreamError> {
            Ok(())
        }

        fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
            None
        }

        fn gossip_next(&mut self) -> Option<OutboundGossip> {
            None
        }

        fn remote_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn cluster_next(&mut self) -> Option<Leased<TRead>> {
            None
        }
    }

    fn spin(data: Vec<u8>) -> Result<ReadIdentifyResponse, StreamError> {
        let p2p_id = P2pStreamId::new(0, 4, StreamProtocol::Identity, false);
        ReadIdentifyResponse::default().spin(&mut MockIo { data, pos: 0 }, &p2p_id)
    }

    #[test]
    fn body_longer_than_declared_length_is_rejected() {
        let mut wire = vec![0u8];
        wire.extend_from_slice(&[0x41; 9]);
        assert!(matches!(spin(wire), Err(StreamError::InvalidIdentify)));
    }

    #[test]
    fn unterminated_length_is_rejected() {
        assert!(matches!(spin(vec![0x80; 10]), Err(StreamError::InvalidIdentify)));
    }
}
