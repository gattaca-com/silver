use std::{
    io::Write,
    time::{Duration, Instant},
};

// Includes the response head and chunk framing, but not spare capacity or
// the discard buffer. Send progress is tracked separately from this cap.
const PENDING_MAX: usize = 64 << 10;

/// Does not emit a terminal chunk; the caller ends the stream by closing
/// the connection.
pub struct ChunkedResponse {
    pending: Vec<u8>,
    write_pos: usize,
    discard: Vec<u8>,
    /// Starts when output is queued onto an empty buffer; resets on write
    /// progress. `None` while nothing is unsent.
    waiting_since: Option<Instant>,
}

impl ChunkedResponse {
    pub(crate) fn new(head: Vec<u8>, discard: Vec<u8>, now: Instant) -> Self {
        debug_assert!(!head.is_empty(), "a stream begins with its response head");
        Self { pending: head, write_pos: 0, discard, waiting_since: Some(now) }
    }

    /// Returns `false` without changing the buffer if the framed chunk would
    /// exceed the pending send buffer limit. Nothing sent.
    #[must_use = "false means the stream is over: close the connection"]
    pub fn push(&mut self, chunk: &[u8], now: Instant) -> bool {
        assert!(!chunk.is_empty(), "an empty chunk is the terminal chunk");
        let framed = hex_digits(chunk.len()) + 2 + chunk.len() + 2;
        if self.pending_write().len() + framed > PENDING_MAX {
            return false;
        }

        if self.write_pos > 0 {
            self.pending.drain(..self.write_pos);
            self.write_pos = 0;
        }
        if self.pending.is_empty() {
            self.waiting_since = Some(now);
        }
        write!(self.pending, "{:x}\r\n", chunk.len()).unwrap();
        self.pending.extend_from_slice(chunk);
        self.pending.extend_from_slice(b"\r\n");
        true
    }

    pub fn pending_write(&self) -> &[u8] {
        &self.pending[self.write_pos..]
    }

    pub fn commit_write(&mut self, n: usize, now: Instant) {
        debug_assert!(n > 0 && self.write_pos + n <= self.pending.len());
        self.write_pos += n;
        if self.write_pos == self.pending.len() {
            self.pending.clear();
            self.write_pos = 0;
            self.waiting_since = None;
        } else {
            self.waiting_since = Some(now);
        }
    }

    /// Measures time without committed writes while output is pending;
    /// it does not observe whether the peer has read the bytes.
    pub fn stalled(&self, now: Instant, deadline: Duration) -> bool {
        self.waiting_since.is_some_and(|since| now.duration_since(since) > deadline)
    }

    /// Scratch for whatever the peer still sends: nothing on this connection
    /// is parsed again, so the bytes are read only to be dropped.
    pub fn discard_space(&mut self) -> &mut [u8] {
        &mut self.discard
    }
}

fn hex_digits(n: usize) -> usize {
    (usize::BITS - n.leading_zeros()).div_ceil(4).max(1) as usize
}

/// Announces `Connection: close` because the connection cannot be reused
/// after this response.
pub fn frame_chunked_head(out: &mut Vec<u8>, content_type: &str, headers: &[(&str, &str)]) {
    write!(out, "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n").unwrap();
    for (name, value) in headers {
        write!(out, "{name}: {value}\r\n").unwrap();
    }
    out.extend_from_slice(b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{ParsedRequest, ServerConnection, frame_response};

    const DEADLINE: Duration = Duration::from_secs(12);
    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

    fn subscribe_head(_: &ParsedRequest<'_>, out: &mut Vec<u8>) {
        frame_chunked_head(out, "text/event-stream", &[("Cache-Control", "no-cache")]);
    }

    fn feed(conn: &mut ServerConnection, bytes: &[u8]) -> *const u8 {
        let space = conn.read_space().unwrap();
        space[..bytes.len()].copy_from_slice(bytes);
        let scratch = space.as_ptr();
        conn.commit_read(bytes.len());
        scratch
    }

    fn subscribed(now: Instant) -> ChunkedResponse {
        let mut conn = ServerConnection::new();
        feed(&mut conn, b"GET /eth/v1/events?topics=block HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(conn.dispatch(&subscribe_head));
        conn.into_stream(now)
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:x}\r\n", payload.len()).into_bytes();
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\r\n");
        out
    }

    fn drain(stream: &mut ChunkedResponse, n: usize, now: Instant) -> Vec<u8> {
        let out = stream.pending_write()[..n].to_vec();
        stream.commit_write(n, now);
        out
    }

    fn drain_all(stream: &mut ChunkedResponse, now: Instant) -> Vec<u8> {
        let n = stream.pending_write().len();
        drain(stream, n, now)
    }

    fn largest_fitting_payload(stream: &ChunkedResponse) -> usize {
        let room = PENDING_MAX - stream.pending_write().len();
        (1..room).rev().find(|&n| hex_digits(n) + 4 + n <= room).unwrap()
    }

    #[test]
    fn the_head_leaves_first_ahead_of_chunks_pushed_before_the_first_drain() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        assert!(stream.push(b"event: block\ndata: {}\n\n", t0));
        assert!(stream.push(b": keep-alive\n\n", t0));

        let mut expected = HEAD.to_vec();
        expected.extend(framed(b"event: block\ndata: {}\n\n"));
        expected.extend(framed(b": keep-alive\n\n"));
        assert_eq!(drain_all(&mut stream, t0), expected);
    }

    #[test]
    fn chunks_are_framed_as_hex_length_crlf_payload_crlf() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        drain_all(&mut stream, t0);

        let payload = vec![b'p'; 300];
        assert!(stream.push(&payload, t0));
        let mut expected = b"12c\r\n".to_vec();
        expected.extend_from_slice(&payload);
        expected.extend_from_slice(b"\r\n");
        assert_eq!(stream.pending_write(), expected);
    }

    #[test]
    fn a_push_landing_exactly_on_the_cap_fits_and_the_next_byte_is_refused() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        let payload = vec![b'x'; largest_fitting_payload(&stream)];
        assert!(stream.push(&payload, t0));
        assert!(stream.pending_write().len() <= PENDING_MAX);
        let held = stream.pending_write().to_vec();

        assert!(!stream.push(b"y", t0), "one more byte would pass the cap");
        assert_eq!(
            stream.pending_write(),
            held,
            "a refused push leaves the unsent bytes as they were"
        );
    }

    #[test]
    #[should_panic(expected = "terminal chunk")]
    fn an_empty_chunk_is_refused() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        let _ = stream.push(b"", t0);
    }

    #[test]
    fn unsent_bytes_never_exceed_the_cap_across_partial_drains() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        let frame = vec![b'f'; 1000];

        for round in 0..10_000 {
            if !stream.push(&frame, t0) {
                let half = stream.pending_write().len() / 2;
                drain(&mut stream, half, t0);
                assert!(stream.push(&frame, t0), "round {round}: half a drain frees room");
            }
            assert!(stream.pending_write().len() <= PENDING_MAX, "round {round}");
            assert!(stream.pending.len() <= PENDING_MAX, "round {round}: consumed prefix retained");
        }
    }

    #[test]
    fn capacity_is_bounded_by_the_largest_burst_not_by_lifetime() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        let frame = vec![b'f'; 450];
        let burst = |stream: &mut ChunkedResponse| {
            for _ in 0..3 {
                assert!(stream.push(&frame, t0));
            }
            drain(stream, 100, t0);
            assert!(stream.push(&frame, t0));
            drain_all(stream, t0);
            assert!(stream.pending_write().is_empty());
        };

        burst(&mut stream);
        burst(&mut stream);
        let settled = stream.pending.capacity();
        for _ in 0..1000 {
            burst(&mut stream);
        }
        assert_eq!(stream.pending.capacity(), settled);
        assert!(settled <= PENDING_MAX, "{settled} bytes held for a 2 KiB burst");
    }

    #[test]
    fn the_waiting_clock_moves_only_when_bytes_leave() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);

        assert!(!stream.stalled(t0 + DEADLINE, DEADLINE), "the deadline itself is not past it");
        assert!(stream.stalled(t0 + DEADLINE + Duration::from_millis(1), DEADLINE));

        let t1 = t0 + Duration::from_secs(5);
        drain(&mut stream, 1, t1);
        assert!(!stream.stalled(t1 + DEADLINE, DEADLINE), "one byte out restarts the wait");
        assert!(stream.stalled(t1 + DEADLINE + Duration::from_millis(1), DEADLINE));

        let t2 = t1 + Duration::from_secs(5);
        assert!(stream.push(b"more", t2));
        assert!(
            stream.stalled(t1 + DEADLINE + Duration::from_millis(1), DEADLINE),
            "a push onto unsent bytes is not progress"
        );
    }

    #[test]
    fn stalled_is_false_while_nothing_is_unsent_whatever_the_clock_says() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        drain_all(&mut stream, t0);

        assert!(!stream.stalled(t0 + Duration::from_secs(3600), DEADLINE));

        let t1 = t0 + Duration::from_secs(3600);
        assert!(stream.push(b"event: block\n\n", t1));
        assert!(
            !stream.stalled(t1 + DEADLINE, DEADLINE),
            "the wait starts at the push, not the last drain"
        );
        assert!(stream.stalled(t1 + DEADLINE + Duration::from_millis(1), DEADLINE));
    }

    #[test]
    fn bytes_behind_the_subscribe_are_discarded_and_never_answered() {
        let t0 = Instant::now();
        let mut conn = ServerConnection::new();
        feed(
            &mut conn,
            b"GET /eth/v1/events HTTP/1.1\r\nHost: x\r\n\r\nGET /eth/v1/node/version HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(conn.dispatch(&subscribe_head));
        let mut stream = conn.into_stream(t0);

        assert_eq!(stream.pending_write(), HEAD, "the pipelined request got no answer");
        let scratch = stream.discard_space().len();
        for round in 0..64 {
            let space = stream.discard_space();
            assert_eq!(space.len(), scratch, "round {round} grew the scratch buffer");
            space.fill(b'b');
        }
        assert_eq!(stream.pending_write(), HEAD, "discarded bytes framed nothing");
    }

    #[test]
    fn into_stream_moves_both_buffers_without_copying() {
        let t0 = Instant::now();
        let mut conn = ServerConnection::new();
        let read_buf = feed(&mut conn, b"GET /eth/v1/events HTTP/1.1\r\nHost: x\r\n\r\n");
        let write_buf = Cell::new(std::ptr::null());
        assert!(conn.dispatch(&|req: &ParsedRequest<'_>, out: &mut Vec<u8>| {
            subscribe_head(req, out);
            write_buf.set(out.as_ptr());
        }));

        let mut stream = conn.into_stream(t0);
        assert_eq!(stream.pending_write().as_ptr(), write_buf.get());
        assert_eq!(stream.discard_space().as_ptr(), read_buf);
    }

    #[test]
    fn frame_chunked_head_declares_chunked_encoding_and_the_close() {
        let mut out = Vec::new();
        frame_chunked_head(&mut out, "application/x-ndjson", &[("X-Accel-Buffering", "no")]);
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn a_materialised_response_still_frames_as_before() {
        let mut out = Vec::new();
        frame_response(&mut out, "200 OK", None, b"ok");
        assert_eq!(out, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    }
}
