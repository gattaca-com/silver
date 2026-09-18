use std::{io, ops::Range};

// Bounds the rescan of a chunk-size or trailer line that has not arrived in
// full, and with it the bytes a peer can make us buffer without ending a line.
const MAX_LINE: usize = 1024;

// Read size while the next chunk's length is unknown: enough for a size line
// and whatever data shares its packet.
const UNKNOWN_READ_LEN: usize = 4096;

/// Strips chunk framing in place: decoded body bytes are moved down over the
/// framing that preceded them, leaving one contiguous body at `decoded()`.
pub(crate) struct ChunkedDecoder {
    state: State,
    body_start: usize,
    decoded_end: usize,
    scan: usize,
}

#[derive(Clone, Copy)]
enum State {
    Size,
    Data { remaining: usize },
    DataEnd,
    Trailer,
    Done,
}

impl ChunkedDecoder {
    /// `body_start` is the response-relative index of the first byte after the
    /// header block; every index this decoder reports is on the same origin.
    pub(crate) fn new(body_start: usize) -> Self {
        Self { state: State::Size, body_start, decoded_end: body_start, scan: body_start }
    }

    /// `response` starts at the response's first byte and ends at the last byte
    /// read so far. Decoding resumes where the previous call stopped.
    pub(crate) fn decode(&mut self, response: &mut [u8]) -> io::Result<()> {
        debug_assert!(self.scan <= response.len(), "decode called on a shrinking buffer");
        loop {
            match self.state {
                State::Size => {
                    let Some(len) = self.line_len(response, "chunk size line too long")? else {
                        return Ok(());
                    };
                    let size = parse_chunk_size(&response[self.scan..self.scan + len])?;
                    self.scan += len + 2;
                    self.state =
                        if size == 0 { State::Trailer } else { State::Data { remaining: size } };
                }
                State::Data { remaining } => {
                    let n = remaining.min(response.len() - self.scan);
                    response.copy_within(self.scan..self.scan + n, self.decoded_end);
                    self.decoded_end += n;
                    self.scan += n;
                    if n < remaining {
                        self.state = State::Data { remaining: remaining - n };
                        return Ok(());
                    }
                    self.state = State::DataEnd;
                }
                State::DataEnd => {
                    if response.len() - self.scan < 2 {
                        return Ok(());
                    }
                    if &response[self.scan..self.scan + 2] != b"\r\n" {
                        return Err(malformed("chunk data not terminated by CRLF"));
                    }
                    self.scan += 2;
                    self.state = State::Size;
                }
                State::Trailer => {
                    let Some(len) = self.line_len(response, "chunked trailer line too long")?
                    else {
                        return Ok(());
                    };
                    self.scan += len + 2;
                    if len == 0 {
                        self.state = State::Done;
                        return Ok(());
                    }
                }
                State::Done => return Ok(()),
            }
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        matches!(self.state, State::Done)
    }

    pub(crate) fn decoded(&self) -> Range<usize> {
        self.body_start..self.decoded_end
    }

    /// Response-relative end of the raw bytes the decoder has consumed; what
    /// follows belongs to the next response.
    pub(crate) fn consumed(&self) -> usize {
        self.scan
    }

    pub(crate) fn read_hint(&self) -> usize {
        match self.state {
            State::Data { remaining } => remaining + 2,
            State::Done => 0,
            State::Size | State::DataEnd | State::Trailer => UNKNOWN_READ_LEN,
        }
    }

    /// Length of the line at `scan`, excluding its CRLF, or `None` while the
    /// line is incomplete.
    fn line_len(&self, response: &[u8], too_long: &'static str) -> io::Result<Option<usize>> {
        let tail = &response[self.scan..];
        let search = &tail[..tail.len().min(MAX_LINE + 2)];
        match search.windows(2).position(|pair| pair == b"\r\n") {
            Some(i) => Ok(Some(i)),
            None if search.len() > MAX_LINE => Err(malformed(too_long)),
            None => Ok(None),
        }
    }
}

// 8 digits caps a chunk at 4 GiB and keeps the accumulator from overflowing.
fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
    let digits = match line.iter().position(|b| *b == b';') {
        Some(i) => &line[..i],
        None => line,
    };
    let digits = digits.trim_ascii();
    if digits.is_empty() || digits.len() > 8 {
        return Err(malformed("invalid chunk size"));
    }
    digits.iter().try_fold(0usize, |acc, b| {
        let digit = char::from(*b).to_digit(16).ok_or_else(|| malformed("invalid chunk size"))?;
        Ok(acc * 16 + digit as usize)
    })
}

fn malformed(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
