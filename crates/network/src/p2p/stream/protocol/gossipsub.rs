use std::io::Error as IoError;

use silver_common::{P2pStreamId, decode_varint, encode_varint};

use crate::p2p::StreamHandler;

/// Helper to apply Snappy block decompression to the inner payload of a
/// GossipSub message. The output vector is precisely sized according to the
/// Snappy header to prevent DOS vectors.
pub fn decompress_gossipsub_payload(compressed_data: &[u8]) -> Result<Vec<u8>, IoError> {
    let uncompressed_len = snap::raw::decompress_len(compressed_data)
        .map_err(|e| IoError::other(format!("snappy length decode failed: {e:?}")))?;

    // Gossipsub maximum decompressed message size in eth2 is 10 MiB, safety limit
    if uncompressed_len > 10 * 1024 * 1024 {
        return Err(IoError::other("snappy decompressed length exceeds absolute protocol limits"));
    }

    let mut decoder = snap::raw::Decoder::new();
    decoder
        .decompress_vec(compressed_data)
        .map_err(|e| IoError::other(format!("snappy block compression fail: {e:?}")))
}

/// Helper to apply Snappy block compression to a raw SSZ object for GossipSub.
pub fn compress_gossipsub_payload(uncompressed_ssz: &[u8]) -> Result<Vec<u8>, IoError> {
    let mut encoder = snap::raw::Encoder::new();
    encoder
        .compress_vec(uncompressed_ssz)
        .map_err(|e| IoError::other(format!("snappy block compression fail: {e:?}")))
}

/// State machine for handling gossipsub messages over a long-lived
/// bidirectional mesh stream. Gossipsub streams multiplex many individual
/// protobuf envelope messages back-to-back.
#[derive(Debug)]
enum GossipReadState<S: StreamHandler> {
    ReadingLength { buf: [u8; 10], read: usize },
    ReadingBody { buffer_id: S::BufferId, remaining: usize },
}

#[derive(Debug)]
enum GossipWriteState<S: StreamHandler> {
    Idle,
    WritingLength { buffer_id: S::BufferId, buffer: [u8; 10], limit: usize, written: usize },
    Writing { buffer_id: S::BufferId, written: usize },
}

#[derive(Debug)]
pub struct GossipsubState<S: StreamHandler> {
    stream: P2pStreamId,
    read_state: GossipReadState<S>,
    write_state: GossipWriteState<S>,
}

impl<S: StreamHandler> GossipsubState<S> {
    pub fn new(stream: P2pStreamId) -> Self {
        Self {
            stream,
            read_state: GossipReadState::ReadingLength { buf: [0; 10], read: 0 },
            write_state: GossipWriteState::Idle,
        }
    }

    pub fn recv(&mut self, mut chunk: &[u8], handler: &mut S) -> Result<usize, IoError> {
        let start_len = chunk.len();

        while !chunk.is_empty() {
            match &mut self.read_state {
                GossipReadState::ReadingLength { buf, read } => {
                    let b = chunk[0];
                    buf[*read] = b;
                    *read += 1;
                    chunk = &chunk[1..];

                    if b & 0x80 == 0 {
                        let (length, _) = decode_varint(&buf[..*read], 0)
                            .map_err(|_| IoError::other("invalid varint"))?;

                        let buffer_id = handler.recv_new(length as usize, self.stream)?;
                        self.read_state =
                            GossipReadState::ReadingBody { buffer_id, remaining: length as usize };
                    }
                }
                GossipReadState::ReadingBody { buffer_id, remaining } => {
                    let limit = chunk.len().min(*remaining);
                    let read = handler.recv(buffer_id, &chunk[..limit])?;

                    *remaining -= read;
                    chunk = &chunk[read..];

                    if *remaining == 0 {
                        self.read_state = GossipReadState::ReadingLength { buf: [0; 10], read: 0 };
                    }
                }
            }
        }

        Ok(start_len - chunk.len())
    }

    pub(crate) fn drive_write(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        handler: &mut S,
    ) -> Result<(), IoError> {
        loop {
            match &mut self.write_state {
                GossipWriteState::Idle => match handler.poll_new_send(&self.stream) {
                    Some((buffer_id, length)) => {
                        let mut length_buffer = [0u8; 10];
                        let offset = encode_varint(length as u64, &mut length_buffer)
                            .map_err(IoError::other)?;
                        match send.write(&length_buffer[..offset]) {
                            Ok(wrote) => {
                                if wrote < offset {
                                    self.write_state = GossipWriteState::WritingLength {
                                        buffer_id,
                                        buffer: length_buffer,
                                        limit: offset,
                                        written: wrote,
                                    };
                                    break;
                                } else {
                                    self.write_state =
                                        GossipWriteState::Writing { buffer_id, written: 0 };
                                }
                            }
                            Err(quinn_proto::WriteError::Blocked) => {
                                self.write_state = GossipWriteState::WritingLength {
                                    buffer_id,
                                    buffer: length_buffer,
                                    limit: offset,
                                    written: 0,
                                };
                                break;
                            }
                            Err(e) => return Err(IoError::other(e)),
                        }
                    }
                    None => break,
                },
                GossipWriteState::WritingLength { buffer_id, buffer, limit, written } => {
                    match send.write(&buffer[*written..*limit]) {
                        Ok(wrote) => {
                            *written += wrote;
                            if *written < *limit {
                                break;
                            } else {
                                self.write_state = GossipWriteState::Writing {
                                    buffer_id: buffer_id.clone(),
                                    written: 0,
                                };
                            }
                        }
                        Err(quinn_proto::WriteError::Blocked) => break,
                        Err(e) => return Err(IoError::other(e)),
                    }
                }
                GossipWriteState::Writing { buffer_id, written } => {
                    match handler.poll_send(&buffer_id, *written) {
                        Some(data) if !data.is_empty() => match send.write(data) {
                            Ok(wrote) => {
                                *written += wrote;
                                if wrote < data.len() {
                                    break;
                                }
                            }
                            Err(quinn_proto::WriteError::Blocked) => break,
                            Err(e) => return Err(IoError::other(e)),
                        },
                        _ => {
                            // complete
                            self.write_state = GossipWriteState::Idle;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
