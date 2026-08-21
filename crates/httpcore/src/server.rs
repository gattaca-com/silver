use std::io::{self, Write};

// Hard cap on the read buffer. Raw SSZ, uncompressed. 16 MiB matches observed
// production maximums (21 blobs × 128 KiB plus block fields).
const READ_BUF_MAX: usize = 16 << 20;
const READ_BUF_INIT: usize = 4096;
const WRITE_BUF_INIT: usize = 4096;

pub struct ParsedRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub body: &'a [u8],
    pub accept: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub eth_consensus_version: Option<&'a str>,
    pub version: u8,
    pub keep_alive: bool,
}

/// `Incomplete` means "no verdict yet, feed me more bytes"; `Malformed` and
/// `TooLarge` mean the bytes can never become a request this connection
/// serves, so no amount of waiting helps.
enum ParseOutcome<'a> {
    Complete { consumed: usize, request: ParsedRequest<'a> },
    Incomplete,
    Malformed,
    TooLarge,
}

impl<'a> ParsedRequest<'a> {
    fn parse(buf: &'a [u8]) -> ParseOutcome<'a> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let headers_end = match req.parse(buf) {
            Ok(httparse::Status::Complete(n)) => n,
            Ok(httparse::Status::Partial) => return ParseOutcome::Incomplete,
            Err(e) => {
                tracing::warn!("unparseable request: {e}");
                return ParseOutcome::Malformed;
            }
        };
        let (Some(method), Some(raw_path), Some(version)) = (req.method, req.path, req.version)
        else {
            return ParseOutcome::Malformed;
        };
        let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
        let keep_alive = version == 1 &&
            !headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("connection") && h.value.eq_ignore_ascii_case(b"close")
            });

        let header = |name: &str| {
            headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
        };
        let content_length = match header("content-length") {
            None => 0,
            Some(value) => match trimmed_utf8(value).and_then(|v| v.parse().ok()) {
                Some(length) => length,
                None => {
                    tracing::warn!("unusable Content-Length: {:?}", String::from_utf8_lossy(value));
                    return ParseOutcome::Malformed;
                }
            },
        };
        let Some(total) = headers_end.checked_add(content_length) else {
            return ParseOutcome::Malformed;
        };
        // The declared length settles this before a body byte arrives: filling
        // the cap first would spend it and still leave nothing to answer with.
        if total > READ_BUF_MAX {
            return ParseOutcome::TooLarge;
        }
        if buf.len() < total {
            return ParseOutcome::Incomplete;
        }

        ParseOutcome::Complete {
            consumed: total,
            request: Self {
                method,
                path,
                query,
                body: &buf[headers_end..total],
                accept: header("accept").and_then(trimmed_utf8),
                content_type: header("content-type").and_then(trimmed_utf8),
                eth_consensus_version: header("eth-consensus-version").and_then(trimmed_utf8),
                version,
                keep_alive,
            },
        }
    }
}

fn trimmed_utf8(value: &[u8]) -> Option<&str> {
    std::str::from_utf8(value).ok().map(str::trim)
}

#[derive(Debug, PartialEq)]
#[must_use]
pub enum AfterResponse {
    Close,
    /// Half-close, then read and discard until the peer stops: the response
    /// was framed while inbound bytes this connection will never read were
    /// still arriving, and dropping the socket with them unread costs the peer
    /// the very response it was just sent.
    Linger,
    ResponsePending,
    AwaitRequest,
}

enum Continuation {
    KeepAlive,
    Close,
    Linger,
}

pub struct ServerConnection {
    read_buf: Vec<u8>,
    read_pos: usize,
    read_end: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    continuation: Continuation,
}

impl ServerConnection {
    pub fn new() -> Self {
        Self {
            read_buf: vec![0u8; READ_BUF_INIT],
            read_pos: 0,
            read_end: 0,
            write_buf: Vec::with_capacity(WRITE_BUF_INIT),
            write_pos: 0,
            continuation: Continuation::KeepAlive,
        }
    }

    pub fn read_space(&mut self) -> io::Result<&mut [u8]> {
        // Compact the partial tail to the front: without this, a long-lived
        // pipelined keep-alive connection whose buffer never fully drains
        // creeps read_end toward the cap and spuriously rejects small requests.
        if self.read_pos > 0 {
            self.read_buf.copy_within(self.read_pos..self.read_end, 0);
            self.read_end -= self.read_pos;
            self.read_pos = 0;
        }
        if self.read_end == READ_BUF_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
        }
        if self.read_end == self.read_buf.len() {
            self.read_buf.resize((self.read_buf.len() * 2).min(READ_BUF_MAX), 0);
        }
        Ok(&mut self.read_buf[self.read_end..])
    }

    pub fn commit_read(&mut self, n: usize) {
        debug_assert!(self.read_end + n <= self.read_buf.len());
        self.read_end += n;
    }

    /// Framing is lost — either never established, or declared past what the
    /// read buffer holds so the body bytes are unreadable — and there is
    /// nothing left to resynchronise on: answer, drop the whole buffer and
    /// linger, since whatever the peer is still sending would otherwise cost
    /// it the answer.
    fn reject(&mut self, status: &str) -> bool {
        self.continuation = Continuation::Linger;
        frame_response_with_headers(
            &mut self.write_buf,
            status,
            None,
            &[("Connection", "close")],
            b"",
        );
        self.read_pos = 0;
        self.read_end = 0;
        true
    }

    /// Scratch for a lingering connection's drain: the bytes are read only to
    /// be dropped, so the buffer is reused as it stands and never grows.
    pub fn discard_space(&mut self) -> &mut [u8] {
        debug_assert!(matches!(self.continuation, Continuation::Linger));
        &mut self.read_buf
    }

    pub fn dispatch<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(&mut self, handler: &F) -> bool {
        let (consumed, req) =
            match ParsedRequest::parse(&self.read_buf[self.read_pos..self.read_end]) {
                ParseOutcome::Complete { consumed, request } => (consumed, request),
                ParseOutcome::Incomplete => return false,
                ParseOutcome::Malformed => return self.reject("400 Bad Request"),
                ParseOutcome::TooLarge => return self.reject("413 Payload Too Large"),
            };
        if req.version != 1 {
            tracing::warn!("rejecting HTTP/1.0 request");
            self.continuation = Continuation::Close;
            frame_response(&mut self.write_buf, "505 HTTP Version Not Supported", None, b"");
        } else {
            self.continuation =
                if req.keep_alive { Continuation::KeepAlive } else { Continuation::Close };
            handler(&req, &mut self.write_buf);
        }
        self.read_pos += consumed;
        if self.read_pos == self.read_end {
            self.read_pos = 0;
            self.read_end = 0;
        }
        true
    }

    pub fn pending_write(&self) -> &[u8] {
        &self.write_buf[self.write_pos..]
    }

    pub fn commit_write(&mut self, n: usize) {
        debug_assert!(self.write_pos + n <= self.write_buf.len());
        self.write_pos += n;
    }

    pub fn after_response<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
        &mut self,
        handler: &F,
    ) -> AfterResponse {
        debug_assert!(self.write_pos == self.write_buf.len());
        match self.continuation {
            Continuation::Close => AfterResponse::Close,
            Continuation::Linger => AfterResponse::Linger,
            Continuation::KeepAlive => {
                self.write_buf.clear();
                // A keep-alive connection lives for the idle timeout, refreshed
                // by every request, so retaining the largest body it ever framed
                // would pin that much per connection for as long as a client
                // keeps polling.
                self.write_buf.shrink_to(WRITE_BUF_INIT);
                self.write_pos = 0;
                // A request pipelined behind the one just answered is already in
                // read_buf — the transport will never feed those bytes again, so
                // it must be dispatched here or it never will be.
                if self.dispatch(handler) {
                    AfterResponse::ResponsePending
                } else {
                    AfterResponse::AwaitRequest
                }
            }
        }
    }
}

impl Default for ServerConnection {
    fn default() -> Self {
        Self::new()
    }
}

pub fn frame_response(out: &mut Vec<u8>, status: &str, content_type: Option<&str>, body: &[u8]) {
    frame_response_with_headers(out, status, content_type, &[], body);
}

/// `headers` are emitted in the given order, after `Content-Type` and before
/// `Content-Length`.
pub fn frame_response_with_headers(
    out: &mut Vec<u8>,
    status: &str,
    content_type: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) {
    write!(out, "HTTP/1.1 {status}\r\n").unwrap();
    if let Some(ct) = content_type {
        write!(out, "Content-Type: {ct}\r\n").unwrap();
    }
    for (name, value) in headers {
        write!(out, "{name}: {value}\r\n").unwrap();
    }
    write!(out, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
    out.extend_from_slice(body);
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn get_req(path: &str, version: &str) -> Vec<u8> {
        format!("GET {path} {version}\r\nHost: localhost\r\n\r\n").into_bytes()
    }

    /// One header more than `parse`'s fixed slot array holds.
    fn overlong_header_req() -> Vec<u8> {
        let mut req = b"GET /metrics HTTP/1.1\r\n".to_vec();
        for i in 0..65 {
            req.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        req
    }

    fn feed(conn: &mut ServerConnection, bytes: &[u8]) {
        let space = conn.read_space().unwrap();
        space[..bytes.len()].copy_from_slice(bytes);
        conn.commit_read(bytes.len());
    }

    fn feed_all(conn: &mut ServerConnection, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let space = conn.read_space().unwrap();
            let n = space.len().min(bytes.len());
            space[..n].copy_from_slice(&bytes[..n]);
            conn.commit_read(n);
            bytes = &bytes[n..];
        }
    }

    fn fill_with_junk_until_reject(conn: &mut ServerConnection) -> io::Error {
        loop {
            match conn.read_space() {
                Ok(space) => {
                    let n = space.len();
                    space.fill(b'j');
                    conn.commit_read(n);
                }
                Err(e) => return e,
            }
            assert!(!conn.dispatch(&|_, _: &mut Vec<u8>| {
                panic!("incomplete request must not dispatch")
            }));
        }
    }

    fn drain(conn: &mut ServerConnection) -> Vec<u8> {
        let out = conn.pending_write().to_vec();
        conn.commit_write(out.len());
        out
    }

    fn echo_path(req: &ParsedRequest<'_>, out: &mut Vec<u8>) {
        frame_response(out, "200 OK", None, req.path.as_bytes());
    }

    fn parsed(buf: &[u8]) -> (usize, ParsedRequest<'_>) {
        match ParsedRequest::parse(buf) {
            ParseOutcome::Complete { consumed, request } => (consumed, request),
            ParseOutcome::Incomplete => panic!("expected a complete request, got Incomplete"),
            ParseOutcome::Malformed => panic!("expected a complete request, got Malformed"),
            ParseOutcome::TooLarge => panic!("expected a complete request, got TooLarge"),
        }
    }

    fn oversized_post(declared: usize) -> Vec<u8> {
        format!("POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: {declared}\r\n\r\n")
            .into_bytes()
    }

    fn reject_and_linger(request: &[u8], status: &str) -> ServerConnection {
        let mut conn = ServerConnection::new();
        feed(&mut conn, request);

        assert!(conn.dispatch(&|_, _: &mut Vec<u8>| {
            panic!("a rejected request must not reach the handler")
        }));
        assert_eq!(
            conn.pending_write(),
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes()
        );

        drain(&mut conn);
        assert_eq!(conn.after_response(&echo_path), AfterResponse::Linger);
        conn
    }

    #[test]
    fn parse_http11_defaults_keep_alive() {
        let req = get_req("/eth/v1/node/identity", "HTTP/1.1");
        let (_, r) = parsed(&req);
        assert_eq!(r.path, "/eth/v1/node/identity");
        assert!(r.keep_alive);
    }

    #[test]
    fn parse_http11_connection_close() {
        let req = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let (_, r) = parsed(req);
        assert_eq!(r.path, "/metrics");
        assert!(!r.keep_alive);
    }

    #[test]
    fn parse_http10_defaults_close() {
        let req = get_req("/", "HTTP/1.0");
        let (_, r) = parsed(&req);
        assert!(!r.keep_alive);
    }

    #[test]
    fn parse_partial_is_incomplete() {
        let outcome = ParsedRequest::parse(b"GET /eth/v1/node/identity HTTP/1.1\r\n");
        assert!(matches!(outcome, ParseOutcome::Incomplete));
    }

    #[test]
    fn parse_query_string_split() {
        let req = get_req("/eth/v1/beacon/states/head/validators?status=active", "HTTP/1.1");
        let (_, r) = parsed(&req);
        assert_eq!(r.path, "/eth/v1/beacon/states/head/validators");
        assert_eq!(r.query, "status=active");
    }

    #[test]
    fn parse_post_body_buffered() {
        let body = b"{\"slot\":\"1\"}";
        let req = format!(
            "POST /eth/v1/beacon/blocks HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut buf = req.into_bytes();
        assert!(matches!(ParsedRequest::parse(&buf), ParseOutcome::Incomplete), "body not arrived");
        buf.extend_from_slice(body);
        let (consumed, r) = parsed(&buf);
        assert_eq!(r.method, "POST");
        assert_eq!(r.body, body.as_ref());
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_returns_consumed_byte_count() {
        let req1 = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req2 = b"GET /eth/v1/node/identity HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let mut buf = req1.to_vec();
        buf.extend_from_slice(req2);
        let (consumed, r) = parsed(&buf);
        assert_eq!(r.path, "/metrics");
        assert_eq!(consumed, req1.len());
        let (_, r2) = parsed(&buf[consumed..]);
        assert_eq!(r2.path, "/eth/v1/node/identity");
    }

    #[test]
    fn parse_negotiation_headers() {
        let req = b"POST /eth/v2/beacon/blocks HTTP/1.1\r\nHost: x\r\nAccept: application/octet-stream;q=1.0,application/json;q=0.9\r\nContent-Type: application/octet-stream\r\nEth-Consensus-Version: fulu\r\n\r\n";
        let (_, r) = parsed(req);
        assert_eq!(r.accept, Some("application/octet-stream;q=1.0,application/json;q=0.9"));
        assert_eq!(r.content_type, Some("application/octet-stream"));
        assert_eq!(r.eth_consensus_version, Some("fulu"));
    }

    #[test]
    fn parse_negotiation_headers_absent_are_none() {
        let req = get_req("/metrics", "HTTP/1.1");
        let (_, r) = parsed(&req);
        assert_eq!(r.accept, None);
        assert_eq!(r.content_type, None);
        assert_eq!(r.eth_consensus_version, None);
    }

    #[test]
    fn parse_negotiation_header_names_are_case_insensitive() {
        let req = b"POST /p HTTP/1.1\r\nACCEPT: application/json\r\ncontent-type: application/json\r\neTh-CoNsEnSuS-vErSiOn: gloas\r\n\r\n";
        let (_, r) = parsed(req);
        assert_eq!(r.accept, Some("application/json"));
        assert_eq!(r.content_type, Some("application/json"));
        assert_eq!(r.eth_consensus_version, Some("gloas"));
    }

    #[test]
    fn parse_unparseable_request_line_is_malformed() {
        assert!(matches!(
            ParsedRequest::parse(b"NOT A VALID REQUEST\r\n\r\n"),
            ParseOutcome::Malformed
        ));
    }

    #[test]
    fn parse_more_headers_than_fit_is_malformed() {
        assert!(matches!(ParsedRequest::parse(&overlong_header_req()), ParseOutcome::Malformed));
    }

    #[test]
    fn parse_invalid_content_length_is_malformed() {
        let req = b"POST /foo HTTP/1.1\r\nHost: localhost\r\nContent-Length: abc\r\n\r\n";
        assert!(matches!(ParsedRequest::parse(req), ParseOutcome::Malformed));
    }

    #[test]
    fn parse_content_length_beyond_usize_is_malformed() {
        let req = b"POST /foo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999999999999999\r\n\r\n";
        assert!(matches!(ParsedRequest::parse(req), ParseOutcome::Malformed));
    }

    #[test]
    fn parse_content_length_past_the_read_cap_is_too_large() {
        for declared in [READ_BUF_MAX, READ_BUF_MAX + 1] {
            assert!(matches!(
                ParsedRequest::parse(&oversized_post(declared)),
                ParseOutcome::TooLarge
            ));
        }
    }

    #[test]
    fn parse_content_length_overflowing_the_header_end_is_malformed() {
        let req = format!(
            "POST /foo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            usize::MAX
        );
        assert!(matches!(ParsedRequest::parse(req.as_bytes()), ParseOutcome::Malformed));
    }

    #[test]
    fn dispatch_unparseable_request_line_writes_400_then_lingers() {
        reject_and_linger(b"NOT A VALID REQUEST\r\n\r\n", "400 Bad Request");
    }

    #[test]
    fn dispatch_more_headers_than_fit_writes_400_then_lingers() {
        reject_and_linger(&overlong_header_req(), "400 Bad Request");
    }

    #[test]
    fn dispatch_invalid_content_length_writes_400_then_lingers() {
        reject_and_linger(
            b"POST /foo HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n",
            "400 Bad Request",
        );
    }

    #[test]
    fn dispatch_content_length_beyond_usize_writes_400_then_lingers() {
        reject_and_linger(
            b"POST /foo HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n",
            "400 Bad Request",
        );
    }

    /// A validator client posting its whole registry unchunked declares the
    /// size up front, so the headers alone are enough to answer: the body
    /// bytes that would not fit never have to arrive.
    #[test]
    fn dispatch_content_length_past_the_read_cap_writes_413_then_lingers() {
        for declared in [READ_BUF_MAX, READ_BUF_MAX + 1, usize::MAX - 1024] {
            reject_and_linger(&oversized_post(declared), "413 Payload Too Large");
        }
    }

    /// The body the client is still sending is read for one reason only — to
    /// keep the answer from being lost — so it must cost nothing to read.
    #[test]
    fn a_lingering_connection_discards_without_growing() {
        let mut conn = reject_and_linger(&oversized_post(READ_BUF_MAX), "413 Payload Too Large");
        let scratch = conn.read_buf.len();

        for round in 0..64 {
            let space = conn.discard_space();
            assert_eq!(space.len(), scratch, "round {round} grew the scratch buffer");
            space.fill(b'b');
        }
        assert!(conn.pending_write().is_empty(), "the answer stays sent, not re-framed");
        assert_eq!(conn.after_response(&echo_path), AfterResponse::Linger, "nothing leaves Linger");
    }

    #[test]
    fn dispatch_partial_request_writes_nothing() {
        let mut conn = ServerConnection::new();
        feed(&mut conn, b"GET /eth/v1/node/identity HTTP/1.1\r\nHost: local");

        assert!(
            !conn.dispatch(&|_, _: &mut Vec<u8>| panic!("incomplete request must not dispatch"))
        );
        assert!(conn.pending_write().is_empty(), "an unfinished request is not a bad one");

        feed(&mut conn, b"host\r\n\r\n");
        assert!(conn.dispatch(&echo_path));
        assert_eq!(
            conn.pending_write(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n/eth/v1/node/identity"
        );
    }

    #[test]
    fn dispatch_partial_body_writes_nothing() {
        let mut conn = ServerConnection::new();
        feed(&mut conn, b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\nhalf");

        assert!(!conn.dispatch(&|_, _: &mut Vec<u8>| panic!("incomplete body must not dispatch")));
        assert!(conn.pending_write().is_empty());
    }

    #[test]
    fn pipelined_garbage_after_valid_request_answers_first_then_rejects() {
        let mut conn = ServerConnection::new();
        feed(&mut conn, b"GET /first HTTP/1.1\r\nHost: x\r\n\r\nNOT A VALID REQUEST\r\n\r\n");

        assert!(conn.dispatch(&echo_path));
        assert_eq!(drain(&mut conn), b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n/first");

        assert_eq!(conn.after_response(&echo_path), AfterResponse::ResponsePending);
        assert_eq!(
            conn.pending_write(),
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );

        drain(&mut conn);
        assert_eq!(conn.after_response(&echo_path), AfterResponse::Linger);
    }

    #[test]
    fn frame_response_without_content_type_omits_header() {
        let mut out = Vec::new();
        frame_response(&mut out, "404 Not Found", None, b"");
        assert_eq!(out, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }

    #[test]
    fn frame_response_content_length_matches_body() {
        let mut out = Vec::new();
        frame_response(&mut out, "200 OK", Some("application/json"), b"{\"data\":1}");
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"data\":1}"
        );
    }

    #[test]
    fn extra_headers_sit_between_content_type_and_content_length() {
        let mut out = Vec::new();
        frame_response_with_headers(
            &mut out,
            "200 OK",
            Some("application/octet-stream"),
            &[("Eth-Consensus-Version", "fulu")],
            b"\x01\x02",
        );
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nEth-Consensus-Version: fulu\r\nContent-Length: 2\r\n\r\n\x01\x02"
        );
    }

    #[test]
    fn extra_headers_keep_their_given_order() {
        let mut out = Vec::new();
        frame_response_with_headers(
            &mut out,
            "200 OK",
            None,
            &[("B-Header", "2"), ("A-Header", "1"), ("C-Header", "3")],
            b"",
        );
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nB-Header: 2\r\nA-Header: 1\r\nC-Header: 3\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn no_extra_headers_frames_exactly_as_frame_response() {
        let mut with_headers = Vec::new();
        frame_response_with_headers(&mut with_headers, "503 Service Unavailable", None, &[], b"x");
        let mut plain = Vec::new();
        frame_response(&mut plain, "503 Service Unavailable", None, b"x");
        assert_eq!(with_headers, plain);
    }

    #[test]
    fn dispatch_http10_writes_version_not_supported_then_closes() {
        let mut conn = ServerConnection::new();
        feed(&mut conn, b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n");

        assert!(conn.dispatch(&|_, out: &mut Vec<u8>| {
            out.extend_from_slice(b"should not appear");
        }));
        assert_eq!(
            conn.pending_write(),
            b"HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\n\r\n"
        );

        drain(&mut conn);
        assert_eq!(conn.after_response(&echo_path), AfterResponse::Close);
    }

    #[test]
    fn connection_close_request_closes_after_response() {
        let mut conn = ServerConnection::new();
        feed(&mut conn, b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

        assert!(conn.dispatch(&echo_path));
        drain(&mut conn);
        assert_eq!(conn.after_response(&echo_path), AfterResponse::Close);
    }

    #[test]
    fn request_fed_one_byte_at_a_time() {
        let mut conn = ServerConnection::new();
        let req = get_req("/metrics", "HTTP/1.1");

        for (i, byte) in req.iter().enumerate() {
            feed(&mut conn, &[*byte]);
            assert_eq!(conn.dispatch(&echo_path), i == req.len() - 1, "byte {i}");
        }
        assert_eq!(conn.pending_write(), b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n/metrics");

        drain(&mut conn);
        assert_eq!(conn.after_response(&echo_path), AfterResponse::AwaitRequest);
    }

    #[test]
    fn pipelined_requests_split_across_feeds_respond_in_order() {
        let mut conn = ServerConnection::new();

        feed(&mut conn, b"GET /first HTTP/1.1\r\nHost: x\r\n\r\nGET /sec");
        assert!(conn.dispatch(&echo_path));
        assert_eq!(drain(&mut conn), b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n/first");
        assert_eq!(conn.after_response(&echo_path), AfterResponse::AwaitRequest);

        feed(&mut conn, b"ond HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(conn.dispatch(&echo_path));
        assert_eq!(drain(&mut conn), b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n/second");
        assert_eq!(conn.after_response(&echo_path), AfterResponse::AwaitRequest);
    }

    #[test]
    fn buffered_pipelined_request_dispatched_after_drain() {
        let mut conn = ServerConnection::new();
        let calls = RefCell::new(Vec::new());
        let handler = |req: &ParsedRequest<'_>, out: &mut Vec<u8>| {
            calls.borrow_mut().push(req.path.to_string());
            echo_path(req, out);
        };

        feed(
            &mut conn,
            b"GET /first HTTP/1.1\r\nHost: x\r\n\r\nGET /second HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(conn.dispatch(&handler));
        assert_eq!(*calls.borrow(), ["/first"]);

        let mut written = Vec::new();
        while !conn.pending_write().is_empty() {
            let chunk_len = conn.pending_write().len().min(3);
            written.extend_from_slice(&conn.pending_write()[..chunk_len]);
            conn.commit_write(chunk_len);
            assert_eq!(*calls.borrow(), ["/first"], "no dispatch mid-drain");
        }
        assert_eq!(written, b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n/first");

        assert_eq!(conn.after_response(&handler), AfterResponse::ResponsePending);
        assert_eq!(*calls.borrow(), ["/first", "/second"]);
        assert_eq!(conn.pending_write(), b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n/second");
    }

    /// A request that declares nothing and never ends has no verdict to be
    /// answered with, so the cap is where the connection runs out.
    #[test]
    fn read_space_exhausted_rejects_request_too_large() {
        let mut conn = ServerConnection::new();
        let err = fill_with_junk_until_reject(&mut conn);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "request too large");
    }

    #[test]
    fn body_near_cap_dispatches() {
        let mut conn = ServerConnection::new();
        let body_len = READ_BUF_MAX - 128;
        let header =
            format!("POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: {body_len}\r\n\r\n");
        feed_all(&mut conn, header.as_bytes());
        let chunk = vec![b'b'; 1 << 16];
        let mut remaining = body_len;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            feed_all(&mut conn, &chunk[..n]);
            remaining -= n;
        }

        let seen = RefCell::new(0usize);
        assert!(conn.dispatch(&|req: &ParsedRequest<'_>, out: &mut Vec<u8>| {
            *seen.borrow_mut() = req.body.len();
            assert!(req.body.iter().all(|&b| b == b'b'));
            frame_response(out, "200 OK", None, b"");
        }));
        assert_eq!(*seen.borrow(), body_len);
    }

    #[test]
    fn pipelined_keep_alive_partial_tails_never_creep_into_cap() {
        let mut conn = ServerConnection::new();
        let mut request = b"POST /r HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n".to_vec();
        request.extend_from_slice(&vec![b'p'; 65536]);
        let split = 16;

        // Feed twice the cap in total; every dispatch leaves a partial
        // successor in the buffer, so the pre-compaction offsets would reach
        // READ_BUF_MAX about halfway through and reject with "request too
        // large".
        let rounds = 2 * READ_BUF_MAX / request.len();
        feed_all(&mut conn, &request[..split]);
        for _ in 0..rounds {
            feed_all(&mut conn, &request[split..]);
            feed_all(&mut conn, &request[..split]);
            assert!(conn.dispatch(&echo_path));
            drain(&mut conn);
            assert_eq!(conn.after_response(&echo_path), AfterResponse::AwaitRequest);
        }
    }

    #[test]
    fn a_large_response_does_not_leave_the_connection_inflated() {
        let mut conn = ServerConnection::new();
        let big = vec![b'x'; 4 << 20];
        feed(&mut conn, &get_req("/big", "HTTP/1.1"));

        assert!(conn.dispatch(&|_, out: &mut Vec<u8>| frame_response(out, "200 OK", None, &big)));
        drain(&mut conn);
        assert!(conn.write_buf.capacity() >= big.len(), "the body was framed whole");

        assert_eq!(conn.after_response(&echo_path), AfterResponse::AwaitRequest);
        assert!(
            conn.write_buf.capacity() <= WRITE_BUF_INIT,
            "{} bytes still held",
            conn.write_buf.capacity()
        );
    }

    #[test]
    fn request_split_across_growth_boundary_not_corrupted() {
        let mut conn = ServerConnection::new();
        let body: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        let mut request =
            format!("POST /grow HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len())
                .into_bytes();
        let header_len = request.len();
        request.extend_from_slice(&body);

        feed_all(&mut conn, &request[..READ_BUF_INIT]);
        assert!(
            !conn.dispatch(&|_, _: &mut Vec<u8>| panic!("incomplete request must not dispatch"))
        );
        feed_all(&mut conn, &request[READ_BUF_INIT..]);

        let seen = RefCell::new(Vec::new());
        assert!(conn.dispatch(&|req: &ParsedRequest<'_>, out: &mut Vec<u8>| {
            seen.borrow_mut().extend_from_slice(req.body);
            frame_response(out, "200 OK", None, b"");
        }));
        assert_eq!(*seen.borrow(), request[header_len..]);
    }
}
