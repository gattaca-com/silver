use std::io::Error as IoError;

use silver_common::{P2pStreamId, decode_varint};

use crate::StreamData;

/// State machine for an incoming Identity protocol stream (/ipfs/id/1.0.0).
/// When a peer opens an Identity stream to us, there is no request message.
/// We immediately write our node's Identify protobuf message and close
/// the stream.
#[derive(Debug)]
pub enum IdentifyInboundState {
    /// Write our local node's identify payload back to the peer.
    /// `current` tracks `(length, offset)` for the outbound message.
    WritingResponse { current: Option<(usize, usize)> },
    /// Finished writing, stream cleanly closing.
    Done,
}

impl IdentifyInboundState {
    pub fn new() -> Self {
        Self::WritingResponse { current: None }
    }

    /// No incoming data is expected for an inbound identify stream.
    pub fn feed_chunk(&mut self, _chunk: &[u8]) -> Result<(), IoError> {
        Ok(())
    }

    pub(crate) fn drive_write<S: StreamData>(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        stream_id: &P2pStreamId,
        data: &mut S,
    ) -> super::super::StreamEvent {
        match self {
            Self::WritingResponse { current } => {
                let (total, result) = super::drive_send(current, send, stream_id, data);
                if matches!(result, super::WriteResult::Done) {
                    *self = Self::Done;
                }
                if matches!(result, super::WriteResult::Failed) {
                    return super::super::StreamEvent::Failed;
                }
                if total > 0 {
                    super::super::StreamEvent::Sent(total)
                } else {
                    super::super::StreamEvent::Pending
                }
            }
            _ => super::super::StreamEvent::Pending,
        }
    }
}

/// State machine for an outbound Identity protocol stream.
/// When we open this stream to a peer, we send nothing, and immediately await
/// the peer's length-prefixed protobuf Identify message.
#[derive(Debug)]
pub enum IdentifyOutboundState {
    /// Reading the varint length of the peer's identify protobuf.
    ReadingLength {
        buf: [u8; 10],
        read: usize,
    },
    /// Reading the raw, uncompressed protobuf payload.
    ReadingBody {
        remaining: usize,
    },
    Done,
}

impl IdentifyOutboundState {
    pub fn new() -> Self {
        Self::ReadingLength { buf: [0; 10], read: 0 }
    }

    pub fn feed_chunk(
        &mut self,
        mut chunk: &[u8],
        mut out_buf: &mut [u8],
    ) -> Result<usize, IoError> {
        let mut total_decoded = 0;

        while !chunk.is_empty() {
            match self {
                Self::ReadingLength { buf, read } => {
                    let b = chunk[0];
                    buf[*read] = b;
                    *read += 1;
                    chunk = &chunk[1..];

                    if b & 0x80 == 0 {
                        let (length, _) = decode_varint(&buf[..*read], 0)
                            .map_err(|_| IoError::other("invalid varint"))?;
                        *self = Self::ReadingBody { remaining: length as usize };
                    }
                }
                Self::ReadingBody { remaining } => {
                    if out_buf.is_empty() {
                        break;
                    }
                    let out_limit = (*remaining).min(out_buf.len());
                    let transfer = chunk.len().min(out_limit);

                    out_buf[..transfer].copy_from_slice(&chunk[..transfer]);

                    *remaining -= transfer;
                    chunk = &chunk[transfer..];
                    out_buf = &mut out_buf[transfer..];
                    total_decoded += transfer;

                    if *remaining == 0 {
                        *self = Self::Done;
                    }
                }
                Self::Done => break,
            }
        }
        Ok(total_decoded)
    }
}
