use std::{
    io::Write,
    time::{Duration, Instant},
};

// Reserve the full output allowance at construction so accepted pushes do
// not reallocate. The response head and chunk framing count against it.
const PENDING_MAX: usize = 64 << 10;
const DISCARD_LEN: usize = 4096;

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
    /// Trim inherited buffer capacity so a subscription does not retain
    /// large allocations from request handling.
    pub(crate) fn new(mut head: Vec<u8>, mut discard: Vec<u8>, now: Instant) -> Self {
        assert!(!head.is_empty(), "a stream begins with its response head");
        assert!(head.len() <= PENDING_MAX, "the stream head alone exceeds the send cap");
        head.reserve_exact(PENDING_MAX - head.len());
        head.shrink_to(PENDING_MAX);
        discard.truncate(DISCARD_LEN);
        discard.shrink_to_fit();
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

        // Delay compaction to avoid moving unsent bytes while there is room
        // to append after them.
        if self.pending.len() + framed > PENDING_MAX {
            self.pending.drain(..self.write_pos);
            self.write_pos = 0;
        }
        if self.pending_write().is_empty() {
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

    fn payload_framed_to(len: usize) -> Vec<u8> {
        let n = (len.saturating_sub(12)..len).find(|&n| hex_digits(n) + 4 + n == len).unwrap();
        vec![b'e'; n]
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
            assert_eq!(stream.pending.capacity(), PENDING_MAX, "round {round}");
        }
    }

    #[test]
    fn the_send_buffer_is_allocated_once_at_the_cap_and_never_moves() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        assert_eq!(stream.pending.capacity(), PENDING_MAX);
        let allocation = stream.pending.as_ptr();
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

        for _ in 0..1000 {
            burst(&mut stream);
        }
        let payload = vec![b'x'; largest_fitting_payload(&stream)];
        assert!(stream.push(&payload, t0), "a cap-sized burst fits the allocation as it is");
        assert_eq!(stream.pending.capacity(), PENDING_MAX);
        assert_eq!(stream.pending.as_ptr(), allocation);
    }

    #[test]
    fn consumed_bytes_stay_until_a_frame_needs_their_room() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        drain_all(&mut stream, t0);
        let first = vec![b'1'; 1000];
        let second = vec![b'2'; 1000];
        assert!(stream.push(&first, t0));
        drain(&mut stream, 500, t0);
        let allocation = stream.pending.as_ptr();

        assert!(stream.push(&second, t0));
        assert_eq!(
            stream.write_pos, 500,
            "appending within the limit preserves the consumed prefix"
        );
        let mut expected = framed(&first)[500..].to_vec();
        expected.extend(framed(&second));
        assert_eq!(stream.pending_write(), expected);

        let third = vec![b'3'; largest_fitting_payload(&stream)];
        assert!(
            stream.pending.len() + framed(&third).len() > PENDING_MAX,
            "the frame fits the unsent-byte cap but requires compaction"
        );
        assert!(stream.push(&third, t0));
        assert_eq!(stream.write_pos, 0, "the consumed prefix is dropped to make room");
        expected.extend(framed(&third));
        assert_eq!(stream.pending_write(), expected);
        assert_eq!(stream.pending.len(), expected.len());
        assert_eq!(stream.pending.capacity(), PENDING_MAX);
        assert_eq!(stream.pending.as_ptr(), allocation, "compaction happens inside the allocation");
    }

    #[test]
    fn an_exact_fit_behind_a_consumed_prefix_is_appended_without_compaction() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        drain_all(&mut stream, t0);
        assert!(stream.push(&[b'f'; 1000], t0));
        drain(&mut stream, 500, t0);
        let allocation = stream.pending.as_ptr();

        let exact = payload_framed_to(PENDING_MAX - stream.pending.len());
        assert!(stream.push(&exact, t0));
        assert_eq!(stream.write_pos, 500, "a frame ending exactly at the allocation's end fits");
        assert_eq!(stream.pending.len(), PENDING_MAX);

        assert!(stream.push(b"y", t0), "the cap still has the consumed prefix's room to give");
        assert_eq!(stream.write_pos, 0, "one byte past the allocation forces compaction");
        assert_eq!(stream.pending.capacity(), PENDING_MAX);
        assert_eq!(stream.pending.as_ptr(), allocation);
    }

    /// Moving bytes within the buffer is not progress towards the socket.
    #[test]
    fn compaction_does_not_restart_the_waiting_clock() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        drain_all(&mut stream, t0);
        assert!(stream.push(&[b'f'; 1000], t0));
        let t1 = t0 + Duration::from_secs(1);
        drain(&mut stream, 500, t1);
        assert_eq!(stream.waiting_since, Some(t1));

        let t2 = t1 + DEADLINE * 2;
        let filler = vec![b'g'; largest_fitting_payload(&stream)];
        assert!(stream.pending.len() + framed(&filler).len() > PENDING_MAX, "this push compacts");
        assert!(stream.push(&filler, t2));
        assert_eq!(stream.write_pos, 0);
        assert_eq!(stream.waiting_since, Some(t1));
        assert!(stream.stalled(t2, DEADLINE));
    }

    #[test]
    fn a_refused_push_moves_nothing_either() {
        let t0 = Instant::now();
        let mut stream = subscribed(t0);
        drain_all(&mut stream, t0);
        assert!(stream.push(&[b'f'; 1000], t0));
        drain(&mut stream, 500, t0);
        let held = stream.pending.clone();

        let room = PENDING_MAX - stream.pending_write().len();
        assert!(!stream.push(&vec![b'z'; room], t0), "framing alone takes this past the cap");
        assert_eq!(stream.write_pos, 500);
        assert_eq!(stream.pending, held);
    }

    #[test]
    #[should_panic(expected = "exceeds the send cap")]
    fn a_head_past_the_cap_is_a_bug() {
        let _ = ChunkedResponse::new(vec![b'h'; PENDING_MAX + 1], vec![0; 16], Instant::now());
    }

    #[test]
    fn a_read_buffer_grown_by_an_earlier_request_is_cut_back_to_scratch_size() {
        let t0 = Instant::now();
        let mut conn = ServerConnection::new();
        let body = vec![b'b'; 6000];
        let mut request = format!(
            "POST /eth/v1/events HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        let mut rest = request.as_slice();
        while !rest.is_empty() {
            let space = conn.read_space().unwrap();
            let n = space.len().min(rest.len());
            space[..n].copy_from_slice(&rest[..n]);
            conn.commit_read(n);
            rest = &rest[n..];
        }
        assert!(conn.dispatch(&subscribe_head));

        let mut stream = conn.into_stream(t0);
        assert_eq!(stream.discard_space().len(), DISCARD_LEN);
        assert_eq!(stream.discard.capacity(), DISCARD_LEN);
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
    fn into_stream_keeps_the_read_buffer_and_sizes_the_send_buffer_to_the_cap() {
        let t0 = Instant::now();
        let mut conn = ServerConnection::new();
        let read_buf = feed(&mut conn, b"GET /eth/v1/events HTTP/1.1\r\nHost: x\r\n\r\n");
        let head_len = Cell::new(0);
        assert!(conn.dispatch(&|req: &ParsedRequest<'_>, out: &mut Vec<u8>| {
            subscribe_head(req, out);
            head_len.set(out.len());
        }));

        let mut stream = conn.into_stream(t0);
        assert_eq!(stream.discard_space().as_ptr(), read_buf);
        assert_eq!(stream.pending_write().len(), head_len.get());
        assert_eq!(stream.pending.capacity(), PENDING_MAX);
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
