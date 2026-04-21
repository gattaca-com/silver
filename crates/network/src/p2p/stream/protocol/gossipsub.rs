use std::io::Error as IoError;

use silver_common::{P2pStreamId, decode_varint, encode_varint};

use crate::StreamData;

/// Helper to apply Snappy block decompression to the inner payload of a
/// GossipSub message.
#[allow(dead_code)] // decompress tile
pub fn decompress_gossipsub_payload(compressed_data: &[u8]) -> Result<Vec<u8>, IoError> {
    let uncompressed_len = snap::raw::decompress_len(compressed_data)
        .map_err(|e| IoError::other(format!("snappy length decode failed: {e:?}")))?;

    if uncompressed_len > 10 * 1024 * 1024 {
        return Err(IoError::other("snappy decompressed length exceeds absolute protocol limits"));
    }

    let mut decoder = snap::raw::Decoder::new();
    decoder
        .decompress_vec(compressed_data)
        .map_err(|e| IoError::other(format!("snappy block compression fail: {e:?}")))
}

/// Helper to apply Snappy block compression to a raw SSZ object for GossipSub.
#[allow(dead_code)] // decompress tile
pub fn compress_gossipsub_payload(uncompressed_ssz: &[u8]) -> Result<Vec<u8>, IoError> {
    let mut encoder = snap::raw::Encoder::new();
    encoder
        .compress_vec(uncompressed_ssz)
        .map_err(|e| IoError::other(format!("snappy block compression fail: {e:?}")))
}

/// Read-side state for gossipsub: varint length prefix then body.
#[derive(Debug)]
enum GossipReadState {
    /// Reading varint length prefix (byte by byte).
    ReadingLength { buf: [u8; 10], read: usize },
    /// Reading message body. `remaining` bytes left.
    ReadingBody { remaining: usize },
}

/// Write-side state for gossipsub: idle → varint length → body.
#[derive(Debug)]
enum GossipWriteState {
    Idle,
    /// Writing varint length prefix.
    WritingLength {
        buffer: [u8; 10],
        limit: usize,
        written: usize,
        length: usize,
    },
    /// Writing body. `offset`/`length` track progress into the current
    /// message; the handler provides body bytes via `send_data`.
    Writing {
        offset: usize,
        length: usize,
    },
}

#[derive(Debug)]
pub struct GossipsubState {
    stream: P2pStreamId,
    read_state: GossipReadState,
    write_state: GossipWriteState,
}

impl GossipsubState {
    pub fn new(stream: P2pStreamId) -> Self {
        Self {
            stream,
            read_state: GossipReadState::ReadingLength { buf: [0; 10], read: 0 },
            write_state: GossipWriteState::Idle,
        }
    }

    /// Feed received bytes, copying message bodies into handler-supplied
    /// buffers. Returns total input bytes consumed.
    pub fn recv<S: StreamData>(
        &mut self,
        mut chunk: &[u8],
        data: &mut S,
    ) -> Result<usize, IoError> {
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

                        // TODO: check vs MAX_FRAME_SIZE 

                        data.alloc_recv(&self.stream, length as usize)?;
                        self.read_state =
                            GossipReadState::ReadingBody { remaining: length as usize };
                    }
                }
                GossipReadState::ReadingBody { remaining } => {
                    let limit = chunk.len().min(*remaining);
                    let buf = data.recv_buf(&self.stream)?;
                    let n = buf.len().min(limit);
                    buf[..n].copy_from_slice(&chunk[..n]);
                    data.recv_advance(&self.stream, n)?;

                    *remaining -= n;
                    chunk = &chunk[n..];

                    if *remaining == 0 {
                        self.read_state = GossipReadState::ReadingLength { buf: [0; 10], read: 0 };
                    } else if n == 0 {
                        // Handler buffer full but body not complete — bail to
                        // avoid infinite loop.
                        break;
                    }
                }
            }
        }

        Ok(start_len - chunk.len())
    }

    pub(crate) fn drive_write<S: StreamData>(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        data: &mut S,
    ) -> Result<(), IoError> {
        loop {
            match &mut self.write_state {
                GossipWriteState::Idle => match data.poll_send(&self.stream) {
                    Some(length) => {
                        let mut length_buffer = [0u8; 10];
                        let offset = encode_varint(length as u64, &mut length_buffer)
                            .map_err(IoError::other)?;
                        match send.write(&length_buffer[..offset]) {
                            Ok(wrote) => {
                                if wrote < offset {
                                    self.write_state = GossipWriteState::WritingLength {
                                        buffer: length_buffer,
                                        limit: offset,
                                        written: wrote,
                                        length,
                                    };
                                    break;
                                } else {
                                    self.write_state =
                                        GossipWriteState::Writing { offset: 0, length };
                                }
                            }
                            Err(quinn_proto::WriteError::Blocked) => {
                                self.write_state = GossipWriteState::WritingLength {
                                    buffer: length_buffer,
                                    limit: offset,
                                    written: 0,
                                    length,
                                };
                                break;
                            }
                            Err(e) => return Err(IoError::other(e)),
                        }
                    }
                    None => break,
                },
                GossipWriteState::WritingLength { buffer, limit, written, length } => {
                    match send.write(&buffer[*written..*limit]) {
                        Ok(wrote) => {
                            *written += wrote;
                            if *written < *limit {
                                break;
                            } else {
                                self.write_state =
                                    GossipWriteState::Writing { offset: 0, length: *length };
                            }
                        }
                        Err(quinn_proto::WriteError::Blocked) => break,
                        Err(e) => return Err(IoError::other(e)),
                    }
                }
                GossipWriteState::Writing { offset, length } => {
                    if *offset >= *length {
                        data.send_complete(&self.stream);
                        self.write_state = GossipWriteState::Idle;
                        continue;
                    }
                    match data.send_data(&self.stream, *offset) {
                        Some(data) if !data.is_empty() => match send.write(data) {
                            Ok(wrote) => {
                                *offset += wrote;
                                if wrote < data.len() {
                                    break;
                                }
                            }
                            Err(quinn_proto::WriteError::Blocked) => break,
                            Err(e) => return Err(IoError::other(e)),
                        },
                        _ => break,
                    }
                }
            }
        }
        Ok(())
    }
}
