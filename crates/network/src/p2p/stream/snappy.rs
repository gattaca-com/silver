use snap::raw::Decoder;

const FRAME_HDR_LEN: usize = 4;
const CHECKSUM_LEN: usize = 4;
const MAX_UNCOMPRESSED_BLOCK: usize = 65536;
/// Upper bound: 4 (header) + 4 (checksum) + max_compress_len(65536).
/// max_compress_len(n) <= 32 + n + n/6 => ~76490 for 65536.
const BUF_CAP: usize = FRAME_HDR_LEN + CHECKSUM_LEN + 76500;

const CHUNK_COMPRESSED: u8 = 0x00;
const CHUNK_UNCOMPRESSED: u8 = 0x01;
const CHUNK_STREAM_ID: u8 = 0xff;
const STREAM_ID_BODY: [u8; 6] = *b"sNaPpY";

#[derive(Debug)]
pub(crate) enum SnappyError {
    MissingStreamId,
    BadStreamId,
    Decompress,
    FrameTooLarge,
    OutputTooSmall,
}

/// Streaming snappy-frames decoder. Accumulates compressed chunks in an
/// internal buffer, decompresses complete frames via `snap::raw` directly
/// into caller-provided output. Two copies total (input -> staging,
/// staging -> decompressed output).
///
/// CRC-32C validation is skipped — QUIC/TLS already provides integrity.
pub(crate) struct SnappyDecoder {
    buf: [u8; BUF_CAP],
    buf_len: usize,
    /// Bytes required to complete current phase (header or full frame).
    need: usize,
    got_stream_id: bool,
    decoder: Decoder,
}

impl SnappyDecoder {
    pub fn new() -> Self {
        Self {
            buf: [0u8; BUF_CAP],
            buf_len: 0,
            need: FRAME_HDR_LEN,
            got_stream_id: false,
            decoder: Decoder::new(),
        }
    }

    /// Feed compressed bytes, decompress complete frames into `out`.
    /// Returns `(bytes_consumed, bytes_written)`.
    pub fn decompress(
        &mut self,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, usize), SnappyError> {
        let mut in_pos = 0;
        let mut out_pos = 0;

        while in_pos < input.len() {
            let want = self.need - self.buf_len;
            let take = want.min(input.len() - in_pos);
            self.buf[self.buf_len..self.buf_len + take]
                .copy_from_slice(&input[in_pos..in_pos + take]);
            self.buf_len += take;
            in_pos += take;

            if self.buf_len < self.need {
                break;
            }

            if self.need == FRAME_HDR_LEN {
                // Header complete — parse payload length.
                let payload_len = self.buf[1] as usize |
                    (self.buf[2] as usize) << 8 |
                    (self.buf[3] as usize) << 16;

                if FRAME_HDR_LEN + payload_len > BUF_CAP {
                    return Err(SnappyError::FrameTooLarge);
                }
                self.need = FRAME_HDR_LEN + payload_len;
                // Fall through to try filling payload from remaining input.
            } else {
                // Full frame in buf[0..self.need]. Process it.
                let written = self.process_frame(&mut out[out_pos..])?;
                out_pos += written;
                self.buf_len = 0;
                self.need = FRAME_HDR_LEN;
            }
        }

        Ok((in_pos, out_pos))
    }

    fn process_frame(&mut self, out: &mut [u8]) -> Result<usize, SnappyError> {
        let chunk_type = self.buf[0];
        let payload = &self.buf[FRAME_HDR_LEN..self.need];

        match chunk_type {
            CHUNK_STREAM_ID => {
                if payload != STREAM_ID_BODY {
                    return Err(SnappyError::BadStreamId);
                }
                self.got_stream_id = true;
                Ok(0)
            }
            CHUNK_COMPRESSED => {
                if !self.got_stream_id {
                    return Err(SnappyError::MissingStreamId);
                }
                if payload.len() <= CHECKSUM_LEN {
                    return Err(SnappyError::Decompress);
                }
                let compressed = &payload[CHECKSUM_LEN..];
                let len =
                    snap::raw::decompress_len(compressed).map_err(|_| SnappyError::Decompress)?;
                if len > MAX_UNCOMPRESSED_BLOCK || len > out.len() {
                    return Err(SnappyError::OutputTooSmall);
                }
                self.decoder
                    .decompress(compressed, &mut out[..len])
                    .map_err(|_| SnappyError::Decompress)
            }
            CHUNK_UNCOMPRESSED => {
                if !self.got_stream_id {
                    return Err(SnappyError::MissingStreamId);
                }
                if payload.len() <= CHECKSUM_LEN {
                    return Err(SnappyError::Decompress);
                }
                let data = &payload[CHECKSUM_LEN..];
                if data.len() > MAX_UNCOMPRESSED_BLOCK || data.len() > out.len() {
                    return Err(SnappyError::OutputTooSmall);
                }
                out[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            // Padding (0x02..=0x7f) and reserved skippable (0x80..=0xfe).
            _ => Ok(0),
        }
    }

    pub fn reset(&mut self) {
        self.buf_len = 0;
        self.need = FRAME_HDR_LEN;
        self.got_stream_id = false;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use rand::RngCore;
    use snap::read::FrameEncoder;

    use super::*;

    #[test]
    fn roundtrip_random_chunks() {
        let mut rng = rand::thread_rng();
        let mut raw = vec![0u8; 128 * 1024];
        rng.fill_bytes(&mut raw);

        // Compress with snap's FrameEncoder.
        let mut compressed = vec![];
        FrameEncoder::new(raw.as_slice()).read_to_end(&mut compressed).unwrap();

        let mut decoder = SnappyDecoder::new();
        let mut out = vec![0u8; raw.len()];
        let mut in_off = 0;
        let mut out_off = 0;

        // Feed in random-sized chunks.
        while in_off < compressed.len() {
            let chunk_sz = (rng.next_u32() as usize % 4096 + 1).min(compressed.len() - in_off);
            let (consumed, produced) = decoder
                .decompress(&compressed[in_off..in_off + chunk_sz], &mut out[out_off..])
                .unwrap();
            in_off += consumed;
            out_off += produced;
        }

        assert_eq!(out_off, raw.len());
        assert_eq!(raw, out);
    }
}
