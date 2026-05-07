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
                            if offset < read {
                                // copy remainder into the response buffer
                                buffer[..(read - offset)].copy_from_slice(&buf[offset..read]);
                            }

                            return Ok(Spin::Next(Self::ReadingBody {
                                buffer,
                                read: read - offset,
                            }));
                        }
                    }
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
