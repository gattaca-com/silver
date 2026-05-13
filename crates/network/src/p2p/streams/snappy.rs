use std::{
    fmt::{self, Debug},
    io,
};

use snap::raw::{Decoder, Encoder};
use thiserror::Error;

const FRAME_HDR_LEN: usize = 4;
const CHECKSUM_LEN: usize = 4;
const MAX_UNCOMPRESSED_BLOCK: usize = 65536;
/// Upper bound: 4 (header) + 4 (checksum) + max_compress_len(65536).
/// max_compress_len(n) <= 32 + n + n/6 => ~76490 for 65536.
const BUF_CAP: usize = FRAME_HDR_LEN + CHECKSUM_LEN + 76500;
/// Worst-case compressed block size for `MAX_UNCOMPRESSED_BLOCK` input.
const MAX_COMPRESS_BLOCK: usize = 76490;

const CHUNK_COMPRESSED: u8 = 0x00;
const CHUNK_UNCOMPRESSED: u8 = 0x01;
const CHUNK_STREAM_ID: u8 = 0xff;
const STREAM_ID_BODY: [u8; 6] = *b"sNaPpY";
/// `\xff\x06\x00\x00sNaPpY` — chunk type 0xff, len 6, body "sNaPpY".
const STREAM_IDENTIFIER: [u8; 10] = [0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y'];

#[derive(Debug, Error)]
pub(crate) enum SnappyError {
    MissingStreamId,
    BadStreamId,
    Decompress,
    FrameTooLarge,
    OutputTooSmall,
}

impl fmt::Display for SnappyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Streaming snappy-frames decoder. Accumulates compressed chunks in an
/// internal buffer, decompresses complete frames via `snap::raw` directly
/// into caller-provided output. Two copies total (input -> staging,
/// staging -> decompressed output).
///
/// CRC-32C validation is skipped — QUIC/TLS already provides integrity.
#[derive(Debug)]
pub(crate) struct SnappyDecoder {
    buf: Box<[u8; BUF_CAP]>,
    buf_len: usize,
    /// Bytes required to complete current phase (header or full frame).
    need: usize,
    got_stream_id: bool,
    decoder: Decoder,
}

impl Default for SnappyDecoder {
    fn default() -> Self {
        Self {
            buf: Box::new([0u8; BUF_CAP]),
            buf_len: 0,
            need: FRAME_HDR_LEN,
            got_stream_id: false,
            decoder: Decoder::new(),
        }
    }
}

impl SnappyDecoder {
    /// Feed compressed bytes, decompress complete frames into `out`.
    /// Returns `(bytes_consumed, bytes_written)`.
    pub fn decompress(
        &mut self,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, usize), SnappyError> {
        tracing::info!(input = input.len(), output = out.len(), "decompress");
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

                // If output buffer is exactly filled, stop consuming input.
                // We've completed our payload!
                if out_pos == out.len() {
                    break;
                }
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
                    tracing::error!(len, buffer = out.len(), "decompressed len too big!");
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
                    tracing::error!(
                        len = data.len(),
                        buffer = out.len(),
                        "uncompressed len too big!"
                    );
                    return Err(SnappyError::OutputTooSmall);
                }
                out[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            // Padding (0x02..=0x7f) and reserved skippable (0x80..=0xfe).
            _ => Ok(0),
        }
    }

    /// Current buffer to fill.
    /// Retunrs buffer with currently needed bytes length.
    pub fn decompress_buffer(&mut self) -> &mut [u8] {
        &mut self.buf[self.buf_len..self.need]
    }

    /// Account for `amount` bytes the caller just wrote into the buffer
    /// returned by `decompress_buffer`, advance `buf_len`, and decode any
    /// complete frame into `out`. Returns number of decompressed bytes
    /// written to `out`.
    pub fn decompress_written(
        &mut self,
        amount: usize,
        out: &mut [u8],
    ) -> Result<usize, SnappyError> {
        self.buf_len += amount;
        let mut out_pos = 0;

        if self.buf_len < self.need {
            return Ok(0);
        }

        if self.need == FRAME_HDR_LEN {
            // Header complete — parse payload length.
            let payload_len =
                self.buf[1] as usize | (self.buf[2] as usize) << 8 | (self.buf[3] as usize) << 16;

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

        Ok(out_pos)
    }
}

/// Combined chunk-header + max-payload buffer.
const OUT_CAP: usize = FRAME_HDR_LEN + CHECKSUM_LEN + MAX_COMPRESS_BLOCK;

/// Snappy-frames encoder for non-blocking sinks.
///
/// Each `compress` call drains any frame bytes left over from the previous
/// call, then encodes successive ≤64KB blocks of `buf` into `dst` and drains
/// each before moving to the next. Returns `(input_consumed,
/// output_pending)`. When the sink can't accept more, the encoder retains
/// the partially-written frame in `dst` — re-call `compress` (with the
/// unconsumed input tail or `&[]`) until `output_pending == 0` and all
/// input is consumed.
///
/// Stream identifier is staged into `dst` on the first call and drained
/// through the same path as data frames.
pub(crate) struct SnappyEncoder {
    enc: Encoder,
    /// Header + payload pending write to the sink.
    dst: Box<[u8; OUT_CAP]>,
    /// Total bytes in `dst[..dst_len]` to be written.
    dst_len: usize,
    /// Bytes of `dst[..dst_len]` already written to the sink.
    dst_written: usize,
    wrote_stream_id: bool,
}

impl Debug for SnappyEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnappyEncoder").finish()
    }
}

impl Default for SnappyEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl SnappyEncoder {
    pub fn new() -> Self {
        Self {
            enc: Encoder::new(),
            dst: Box::new([0; OUT_CAP]),
            dst_len: 0,
            dst_written: 0,
            wrote_stream_id: false,
        }
    }

    /// Returns `(input_consumed, output_pending)`. `output_pending` is the
    /// count of bytes still buffered in `dst` awaiting drain. `input_consumed`
    /// is bytes of `buf` fully encoded into `dst` (drained or not).
    pub fn compress<W: io::Write>(
        &mut self,
        buf: &[u8],
        writer: &mut W,
    ) -> io::Result<(usize, usize)> {
        if !self.wrote_stream_id {
            debug_assert_eq!(self.dst_len, 0);
            self.dst[..STREAM_IDENTIFIER.len()].copy_from_slice(&STREAM_IDENTIFIER);
            self.dst_len = STREAM_IDENTIFIER.len();
            self.wrote_stream_id = true;
        }

        if self.drain(writer)? > 0 {
            return Ok((0, self.pending()));
        }

        let mut consumed = 0;
        while consumed < buf.len() {
            let n = (buf.len() - consumed).min(MAX_UNCOMPRESSED_BLOCK);
            self.encode_block(&buf[consumed..consumed + n])?;
            consumed += n;
            if self.drain(writer)? > 0 {
                return Ok((consumed, self.pending()));
            }
        }

        Ok((consumed, 0))
    }

    fn pending(&self) -> usize {
        self.dst_len - self.dst_written
    }

    /// Drain `dst[dst_written..dst_len]` to `writer`. Returns `0` on full
    /// drain (and resets the buffer); otherwise the bytes still pending.
    fn drain<W: io::Write>(&mut self, writer: &mut W) -> io::Result<usize> {
        while self.dst_written < self.dst_len {
            let n = writer.write(&self.dst[self.dst_written..self.dst_len])?;
            if n == 0 {
                return Ok(self.dst_len - self.dst_written);
            }
            self.dst_written += n;
        }
        self.dst_len = 0;
        self.dst_written = 0;
        Ok(0)
    }

    /// Encode a ≤64KB block into `dst` (header + crc + payload). Caller
    /// must have fully drained `dst` before invoking.
    fn encode_block(&mut self, src: &[u8]) -> io::Result<()> {
        debug_assert!(src.len() <= MAX_UNCOMPRESSED_BLOCK);
        debug_assert_eq!(self.dst_len, 0);
        debug_assert_eq!(self.dst_written, 0);

        let crc = crc32c::crc32c(src);
        let masked = crc.rotate_right(15).wrapping_add(0xa282_ead8);

        let payload_off = FRAME_HDR_LEN + CHECKSUM_LEN;
        let compressed_len = self.enc.compress(src, &mut self.dst[payload_off..])?;
        // Compression must save at least 12.5% to be worth it.
        let payload_len = if compressed_len >= src.len() - (src.len() / 8) {
            // Compression didn't pay — overwrite with raw bytes.
            self.dst[payload_off..payload_off + src.len()].copy_from_slice(src);
            self.dst[0] = CHUNK_UNCOMPRESSED;
            src.len()
        } else {
            self.dst[0] = CHUNK_COMPRESSED;
            compressed_len
        };

        let chunk_len = CHECKSUM_LEN + payload_len;
        debug_assert!(chunk_len < (1 << 24));
        self.dst[1] = (chunk_len & 0xff) as u8;
        self.dst[2] = ((chunk_len >> 8) & 0xff) as u8;
        self.dst[3] = ((chunk_len >> 16) & 0xff) as u8;
        self.dst[4..8].copy_from_slice(&masked.to_le_bytes());

        self.dst_len = payload_off + payload_len;
        Ok(())
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

        let mut decoder = SnappyDecoder::default();
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

    /// Encode with our `SnappyEncoder`, decode with the snap crate's
    /// `read::FrameDecoder`. Validates header + CRC are wire-correct.
    #[test]
    fn encoder_decoded_by_snap_crate() {
        use snap::read::FrameDecoder;

        let mut rng = rand::thread_rng();
        let mut raw = vec![0u8; 200 * 1024];
        rng.fill_bytes(&mut raw);

        let mut encoder = SnappyEncoder::new();
        let mut compressed = Vec::new();
        let (consumed, pending) = encoder.compress(&raw, &mut compressed).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(pending, 0);

        let mut out = Vec::new();
        FrameDecoder::new(compressed.as_slice()).read_to_end(&mut out).unwrap();
        assert_eq!(raw, out);
    }

    /// Round-trip through our own encoder + decoder, single block.
    #[test]
    fn encoder_decoder_roundtrip_single_block() {
        let mut rng = rand::thread_rng();
        let mut raw = vec![0u8; 32 * 1024];
        rng.fill_bytes(&mut raw);

        let mut encoder = SnappyEncoder::new();
        let mut compressed = Vec::new();
        let (consumed, pending) = encoder.compress(&raw, &mut compressed).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(pending, 0);

        let mut decoder = SnappyDecoder::default();
        let mut out = vec![0u8; raw.len()];
        let (_, produced) = decoder.decompress(&compressed, &mut out).unwrap();
        assert_eq!(produced, raw.len());
        assert_eq!(raw, out);
    }

    /// Multi-block payload, fed to decoder in randomly sized chunks.
    #[test]
    fn encoder_decoder_roundtrip_multi_block() {
        let mut rng = rand::thread_rng();
        let mut raw = vec![0u8; 256 * 1024];
        rng.fill_bytes(&mut raw);

        let mut encoder = SnappyEncoder::new();
        let mut compressed = Vec::new();
        let (consumed, pending) = encoder.compress(&raw, &mut compressed).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(pending, 0);

        let mut decoder = SnappyDecoder::default();
        let mut out = vec![0u8; raw.len()];
        let mut in_off = 0;
        let mut out_off = 0;
        while in_off < compressed.len() {
            let n = (rng.next_u32() as usize % 4096 + 1).min(compressed.len() - in_off);
            let (consumed, produced) =
                decoder.decompress(&compressed[in_off..in_off + n], &mut out[out_off..]).unwrap();
            in_off += consumed;
            out_off += produced;
        }
        assert_eq!(out_off, raw.len());
        assert_eq!(raw, out);
    }

    /// Short payload still produces a valid stream (id + one frame).
    #[test]
    fn encoder_short_payload() {
        let mut encoder = SnappyEncoder::new();
        let mut compressed = Vec::new();
        let (consumed, pending) = encoder.compress(b"hello world", &mut compressed).unwrap();
        assert_eq!(consumed, b"hello world".len());
        assert_eq!(pending, 0);
        assert!(compressed.starts_with(&STREAM_IDENTIFIER));

        let mut out = Vec::new();
        snap::read::FrameDecoder::new(compressed.as_slice()).read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello world");
    }

    /// `io::Write` adapter that returns at most `cap` bytes per `write` call.
    /// Bytes go to the inner Vec.
    struct CappedWriter<'a> {
        cap: usize,
        out: &'a mut Vec<u8>,
    }

    impl<'a> io::Write for CappedWriter<'a> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = buf.len().min(self.cap);
            self.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Sink that always returns `0` (blocked) — exercises the pending-output
    /// path in `compress`.
    struct BlockedWriter;

    impl io::Write for BlockedWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encoder_handles_partial_writes() {
        let mut rng = rand::thread_rng();
        let mut raw = vec![0u8; 200 * 1024];
        rng.fill_bytes(&mut raw);

        let mut encoder = SnappyEncoder::new();
        let mut compressed = Vec::new();
        let mut input = raw.as_slice();

        // Spin compress with a writer that only takes 7 bytes per call until
        // everything has been emitted.
        loop {
            let (consumed, pending) = {
                let mut w = CappedWriter { cap: 7, out: &mut compressed };
                encoder.compress(input, &mut w).unwrap()
            };
            input = &input[consumed..];
            if input.is_empty() && pending == 0 {
                break;
            }
        }

        let mut out = Vec::new();
        snap::read::FrameDecoder::new(compressed.as_slice()).read_to_end(&mut out).unwrap();
        assert_eq!(raw, out);
    }

    #[test]
    fn encoder_blocked_sink_returns_pending() {
        let mut encoder = SnappyEncoder::new();
        let raw = vec![0u8; 1024];
        let (consumed, pending) = encoder.compress(&raw, &mut BlockedWriter).unwrap();
        // Stream id sits in dst; nothing was drained.
        assert_eq!(consumed, 0);
        assert_eq!(pending, STREAM_IDENTIFIER.len());

        // Drain into a real sink.
        let mut compressed = Vec::new();
        let (consumed, pending) = encoder.compress(&raw, &mut compressed).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(pending, 0);

        let mut out = Vec::new();
        snap::read::FrameDecoder::new(compressed.as_slice()).read_to_end(&mut out).unwrap();
        assert_eq!(out, raw);
    }
}
