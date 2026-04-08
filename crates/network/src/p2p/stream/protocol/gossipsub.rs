use std::io::Error as IoError;
use silver_common::decode_varint;

/// Helper to apply Snappy block decompression to the inner payload of a GossipSub message.
/// The output vector is precisely sized according to the Snappy header to prevent DOS vectors.
pub fn decompress_gossipsub_payload(compressed_data: &[u8]) -> Result<Vec<u8>, IoError> {
    let uncompressed_len = snap::raw::decompress_len(compressed_data)
        .map_err(|e| IoError::other(format!("snappy length decode failed: {e:?}")))?;

    // Gossipsub maximum decompressed message size in eth2 is 10 MiB, safety limit
    if uncompressed_len > 10 * 1024 * 1024 {
        return Err(IoError::other("snappy decompressed length exceeds absolute protocol limits"));
    }

    let mut decoder = snap::raw::Decoder::new();
    decoder.decompress_vec(compressed_data)
        .map_err(|e| IoError::other(format!("snappy block compression fail: {e:?}")))
}

/// Helper to apply Snappy block compression to a raw SSZ object for GossipSub.
pub fn compress_gossipsub_payload(uncompressed_ssz: &[u8]) -> Result<Vec<u8>, IoError> {
    let mut encoder = snap::raw::Encoder::new();
    encoder.compress_vec(uncompressed_ssz)
        .map_err(|e| IoError::other(format!("snappy block compression fail: {e:?}")))
}

/// State machine for handling gossipsub messages over a long-lived bidirectional mesh stream.
/// Gossipsub streams multiplex many individual protobuf envelope messages back-to-back.
#[derive(Debug)]
pub enum GossipsubReadState {
    ReadingLength {
        buf: [u8; 10],
        read: usize,
    },
    ReadingBody {
        remaining: usize,
    },
}

#[derive(Debug)]
pub struct GossipsubState {
    read_state: GossipsubReadState,
    current_write: Option<(super::super::DCacheRef, usize)>,
}

impl GossipsubState {
    pub fn new() -> Self {
        Self {
            read_state: GossipsubReadState::ReadingLength { buf: [0; 10], read: 0 },
            current_write: None,
        }
    }

    /// Feeds raw QUIC bytes into the Gossipsub stream decoder.
    /// Because gossip streams transmit multiple messages sequentially,
    /// this cleanly resets to `ReadingLength` after each complete protobuf extraction.
    pub fn feed_chunk(&mut self, mut chunk: &[u8], mut out_buf: &mut [u8]) -> Result<usize, IoError> {
        let mut total_decoded = 0;

        while !chunk.is_empty() {
            match &mut self.read_state {
                GossipsubReadState::ReadingLength { buf, read } => {
                    let b = chunk[0];
                    buf[*read] = b;
                    *read += 1;
                    chunk = &chunk[1..];

                    if b & 0x80 == 0 {
                        let (length, _) = decode_varint(&buf[..*read], 0)
                            .map_err(|_| IoError::other("invalid varint"))?;
                        self.read_state = GossipsubReadState::ReadingBody { remaining: length as usize };
                    }
                }
                GossipsubReadState::ReadingBody { remaining } => {
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
                        self.read_state = GossipsubReadState::ReadingLength { buf: [0; 10], read: 0 };
                    }
                }
            }
        }
        Ok(total_decoded)
    }

    pub(crate) fn drive_write(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        outbound_queue: &mut std::collections::VecDeque<super::super::DCacheRef>,
    ) -> super::super::StreamEvent {
        let mut bytes_written = 0;
        loop {
            if self.current_write.is_none() {
                if let Some(msg) = outbound_queue.pop_front() {
                    self.current_write = Some((msg, 0));
                } else {
                    break;
                }
            }

            if let Some((msg, offset)) = self.current_write.as_mut() {
                let chunk = &msg.payload[*offset..];
                if chunk.is_empty() {
                    self.current_write = None;
                    continue;
                }

                match send.write(chunk) {
                    Ok(written) => {
                        bytes_written += written;
                        *offset += written;
                        if *offset >= msg.payload.len() {
                            self.current_write = None;
                        } else {
                            break;
                        }
                    }
                    Err(quinn_proto::WriteError::Blocked) => break,
                    Err(_) => return super::super::StreamEvent::Failed,
                }
            }
        }
        
        if bytes_written > 0 {
            super::super::StreamEvent::Sent(bytes_written)
        } else {
            super::super::StreamEvent::Pending
        }
    }
}
