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
    pub version: u8,
    pub keep_alive: bool,
}

impl<'a> ParsedRequest<'a> {
    fn parse(buf: &'a [u8]) -> Option<(usize, Self)> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let headers_end = match req.parse(buf) {
            Ok(httparse::Status::Complete(n)) => n,
            _ => return None,
        };
        let method = req.method?;
        let raw_path = req.path?;
        let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
        let version = req.version?;
        let keep_alive = version == 1 &&
            !headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("connection") && h.value.eq_ignore_ascii_case(b"close")
            });
        let content_length: usize =
            match headers.iter().find(|h| h.name.eq_ignore_ascii_case("content-length")) {
                None => 0,
                Some(h) => std::str::from_utf8(h.value).ok().and_then(|v| v.trim().parse().ok())?,
            };
        let total = headers_end + content_length;
        if buf.len() < total {
            return None;
        }
        Some((total, Self {
            method,
            path,
            query,
            body: &buf[headers_end..total],
            version,
            keep_alive,
        }))
    }
}

#[derive(Debug, PartialEq)]
#[must_use]
pub enum AfterResponse {
    Close,
    ResponsePending,
    AwaitRequest,
}

pub struct ServerConnection {
    read_buf: Vec<u8>,
    read_pos: usize,
    read_end: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    keep_alive: bool,
}

impl ServerConnection {
    pub fn new() -> Self {
        Self {
            read_buf: vec![0u8; READ_BUF_INIT],
            read_pos: 0,
            read_end: 0,
            write_buf: Vec::with_capacity(WRITE_BUF_INIT),
            write_pos: 0,
            keep_alive: true,
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

    pub fn dispatch<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(&mut self, handler: &F) -> bool {
        let Some((consumed, req)) =
            ParsedRequest::parse(&self.read_buf[self.read_pos..self.read_end])
        else {
            return false;
        };
        if req.version != 1 {
            tracing::warn!("rejecting HTTP/1.0 request");
            self.keep_alive = false;
            frame_response(&mut self.write_buf, "505 HTTP Version Not Supported", None, b"");
        } else {
            self.keep_alive = req.keep_alive;
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
        if !self.keep_alive {
            return AfterResponse::Close;
        }
        self.write_buf.clear();
        self.write_pos = 0;
        // A request pipelined behind the one just answered is already in
        // read_buf — the transport will never feed those bytes again, so it
        // must be dispatched here or it never will be.
        if self.dispatch(handler) {
            AfterResponse::ResponsePending
        } else {
            AfterResponse::AwaitRequest
        }
    }
}

impl Default for ServerConnection {
    fn default() -> Self {
        Self::new()
    }
}

pub fn frame_response(out: &mut Vec<u8>, status: &str, content_type: Option<&str>, body: &[u8]) {
    match content_type {
        Some(ct) => write!(
            out,
            "HTTP/1.1 {status}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ),
        None => write!(out, "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n", body.len()),
    }
    .unwrap();
    out.extend_from_slice(body);
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn get_req(path: &str, version: &str) -> Vec<u8> {
        format!("GET {path} {version}\r\nHost: localhost\r\n\r\n").into_bytes()
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

    #[test]
    fn parse_http11_defaults_keep_alive() {
        let req = get_req("/eth/v1/node/identity", "HTTP/1.1");
        let (_, r) = ParsedRequest::parse(&req).unwrap();
        assert_eq!(r.path, "/eth/v1/node/identity");
        assert!(r.keep_alive);
    }

    #[test]
    fn parse_http11_connection_close() {
        let req = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let (_, r) = ParsedRequest::parse(req).unwrap();
        assert_eq!(r.path, "/metrics");
        assert!(!r.keep_alive);
    }

    #[test]
    fn parse_http10_defaults_close() {
        let req = get_req("/", "HTTP/1.0");
        let (_, r) = ParsedRequest::parse(&req).unwrap();
        assert!(!r.keep_alive);
    }

    #[test]
    fn parse_partial_returns_none() {
        assert!(ParsedRequest::parse(b"GET /eth/v1/node/identity HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn parse_query_string_split() {
        let req = get_req("/eth/v1/beacon/states/head/validators?status=active", "HTTP/1.1");
        let (_, r) = ParsedRequest::parse(&req).unwrap();
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
        // incomplete — body not yet arrived
        assert!(ParsedRequest::parse(&buf).is_none());
        buf.extend_from_slice(body);
        let (consumed, r) = ParsedRequest::parse(&buf).unwrap();
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
        let (consumed, r) = ParsedRequest::parse(&buf).unwrap();
        assert_eq!(r.path, "/metrics");
        assert_eq!(consumed, req1.len());
        let (_, r2) = ParsedRequest::parse(&buf[consumed..]).unwrap();
        assert_eq!(r2.path, "/eth/v1/node/identity");
    }

    #[test]
    fn parse_invalid_content_length_returns_none() {
        let req = b"POST /foo HTTP/1.1\r\nHost: localhost\r\nContent-Length: abc\r\n\r\n";
        assert!(ParsedRequest::parse(req).is_none());
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

    #[test]
    fn read_space_exhausted_rejects_request_too_large() {
        let mut conn = ServerConnection::new();
        feed(
            &mut conn,
            b"POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: 33554432\r\n\r\n",
        );

        let err = fill_with_junk_until_reject(&mut conn);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "request too large");
    }

    #[test]
    fn body_just_over_cap_rejects_with_identical_error() {
        let mut conn = ServerConnection::new();
        let header = format!(
            "POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: {READ_BUF_MAX}\r\n\r\n"
        );
        feed(&mut conn, header.as_bytes());

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
