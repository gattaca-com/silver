use std::io::{self, Write};

// 4096 covers any realistic HTTP response header block; once headers are
// parsed, reads are sized to exactly the remaining Content-Length.
const HEADER_READ_LEN: usize = 4096;

pub struct ClientConnection {
    write_buf: Vec<u8>,
    write_pos: usize,
    read_buf: Vec<u8>,
    read_end: usize,
    read_offset: usize,
    response_header_end: usize,
    response_total: usize,
}

impl ClientConnection {
    pub fn with_capacity(read_capacity: usize, write_capacity: usize) -> Self {
        Self {
            write_buf: Vec::with_capacity(write_capacity),
            write_pos: 0,
            read_buf: Vec::with_capacity(read_capacity),
            read_end: 0,
            read_offset: 0,
            response_header_end: 0,
            response_total: 0,
        }
    }

    pub fn begin_request(&mut self) -> &mut Vec<u8> {
        debug_assert!(
            self.pending_write().is_empty(),
            "one request in flight per connection: previous request not fully written"
        );
        self.write_buf.clear();
        self.write_pos = 0;
        &mut self.write_buf
    }

    pub fn pending_write(&self) -> &[u8] {
        &self.write_buf[self.write_pos..]
    }

    pub fn commit_write(&mut self, n: usize) {
        debug_assert!(self.write_pos + n <= self.write_buf.len());
        self.write_pos += n;
    }

    pub fn read_space(&mut self) -> &mut [u8] {
        if self.read_offset != 0 && self.read_offset == self.read_end {
            self.read_end = 0;
            self.read_offset = 0;
        }
        let want = if self.response_total > 0 {
            self.response_total - (self.read_end - self.read_offset)
        } else {
            HEADER_READ_LEN
        };
        debug_assert!(want > 0, "complete response pending: take_response before reading more");
        if self.read_buf.len() < self.read_end + want {
            self.read_buf.resize(self.read_end + want, 0);
        }
        &mut self.read_buf[self.read_end..self.read_end + want]
    }

    pub fn commit_read(&mut self, n: usize) -> io::Result<()> {
        debug_assert!(self.read_end + n <= self.read_buf.len());
        self.read_end += n;
        if self.response_total == 0 {
            if let Some((header_end, content_length)) =
                parse_response_head(&self.read_buf[self.read_offset..self.read_end])?
            {
                self.response_header_end = header_end;
                self.response_total = header_end + content_length;
            }
        }
        Ok(())
    }

    pub fn take_response(&mut self) -> Option<&mut [u8]> {
        if self.response_total == 0 || self.read_end - self.read_offset < self.response_total {
            return None;
        }
        let start = self.read_offset + self.response_header_end;
        let end = self.read_offset + self.response_total;
        self.read_offset = end;
        self.response_header_end = 0;
        self.response_total = 0;
        Some(&mut self.read_buf[start..end])
    }

    pub fn reset(&mut self) {
        self.write_buf.clear();
        self.write_pos = 0;
        self.read_end = 0;
        self.read_offset = 0;
        self.response_header_end = 0;
        self.response_total = 0;
    }
}

// Returns (header_end, content_length) when headers are complete, None if
// partial. Content-Length framing only: a response without it is an error,
// chunked transfer encoding is unsupported.
fn parse_response_head(buf: &[u8]) -> io::Result<Option<(usize, usize)>> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let header_end = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("httparse: {e}"))),
    };
    match headers.iter().find(|h| h.name.eq_ignore_ascii_case("content-length")) {
        Some(h) if !h.value.is_empty() && h.value.iter().all(|b| b.is_ascii_digit()) => {
            let cl = h.value.iter().copied().fold(0usize, |acc, b| acc * 10 + (b - b'0') as usize);
            Ok(Some((header_end, cl)))
        }
        Some(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")),
        None => Err(io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length")),
    }
}

pub fn frame_request(
    out: &mut Vec<u8>,
    host: &str,
    body: &[u8],
    authorization: Option<&str>,
    keep_alive: bool,
) {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    match authorization {
        Some(bearer) => write!(
            out,
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {len}\r\nAuthorization: {bearer}\r\nConnection: {connection}\r\n\r\n",
            len = body.len(),
        ),
        None => write!(
            out,
            "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {len}\r\nConnection: {connection}\r\n\r\n",
            len = body.len(),
        ),
    }
    .unwrap();
    out.extend_from_slice(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = br#"{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}"#;
    const BEARER: &str = "Bearer aGVhZGVy.cGF5bG9hZA.c2ln";

    fn machine() -> ClientConnection {
        ClientConnection::with_capacity(4096, 4096)
    }

    fn make_response(body: &[u8]) -> Vec<u8> {
        let mut buf = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        buf.extend_from_slice(body);
        buf
    }

    fn feed(conn: &mut ClientConnection, bytes: &[u8]) -> io::Result<()> {
        let space = conn.read_space();
        let n = bytes.len().min(space.len());
        assert_eq!(n, bytes.len(), "test chunk exceeds offered read space");
        space[..n].copy_from_slice(bytes);
        conn.commit_read(n)
    }

    // Captured verbatim from the engine crate's `build_request_into` before the
    // extraction (2026-08-17); the framed request must stay byte-identical.
    #[test]
    fn golden_request_bytes_keep_alive() {
        let mut conn = machine();
        frame_request(conn.begin_request(), "localhost:8551", BODY, Some(BEARER), true);
        let expected: Vec<u8> = [
            b"POST / HTTP/1.1\r\nHost: localhost:8551\r\nContent-Type: application/json\r\n\
              Content-Length: 59\r\nAuthorization: Bearer aGVhZGVy.cGF5bG9hZA.c2ln\r\n\
              Connection: keep-alive\r\n\r\n"
                .as_ref(),
            BODY,
        ]
        .concat();
        assert_eq!(conn.pending_write(), expected);
    }

    #[test]
    fn golden_request_bytes_connection_close() {
        let mut conn = machine();
        frame_request(conn.begin_request(), "localhost:8551", BODY, Some(BEARER), false);
        let expected: Vec<u8> = [
            b"POST / HTTP/1.1\r\nHost: localhost:8551\r\nContent-Type: application/json\r\n\
              Content-Length: 59\r\nAuthorization: Bearer aGVhZGVy.cGF5bG9hZA.c2ln\r\n\
              Connection: close\r\n\r\n"
                .as_ref(),
            BODY,
        ]
        .concat();
        assert_eq!(conn.pending_write(), expected);
    }

    #[test]
    fn frame_request_without_authorization_omits_header() {
        let mut out = Vec::new();
        frame_request(&mut out, "localhost:8551", b"{}", None, true);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("Authorization"));
        assert!(text.contains("Content-Length: 2\r\n"));
    }

    #[test]
    fn request_drained_in_small_chunks() {
        let mut conn = machine();
        frame_request(conn.begin_request(), "localhost:8551", BODY, Some(BEARER), true);
        let expected = conn.pending_write().to_vec();

        let mut wire = Vec::new();
        while !conn.pending_write().is_empty() {
            let chunk_len = conn.pending_write().len().min(3);
            wire.extend_from_slice(&conn.pending_write()[..chunk_len]);
            conn.commit_write(chunk_len);
        }
        assert_eq!(wire, expected);
    }

    #[test]
    fn response_fed_one_byte_at_a_time() {
        let mut conn = machine();
        let body = br#"{"jsonrpc":"2.0","id":1,"result":false}"#;
        let response = make_response(body);

        for (i, byte) in response.iter().enumerate() {
            assert!(conn.take_response().is_none(), "byte {i}");
            feed(&mut conn, &[*byte]).unwrap();
        }
        assert_eq!(conn.take_response().unwrap(), body);
        assert!(conn.take_response().is_none());
    }

    #[test]
    fn headers_complete_body_incomplete_returns_none() {
        let mut conn = machine();
        let mut response = make_response(br#"{"result":1}"#);
        response.truncate(response.len() - 3);
        feed(&mut conn, &response).unwrap();
        assert!(conn.take_response().is_none());
        feed(&mut conn, br#":1}"#).unwrap();
        assert_eq!(conn.take_response().unwrap(), br#"{"result":1}"#.as_ref());
    }

    #[test]
    fn partial_headers_return_none_without_error() {
        let mut conn = machine();
        feed(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n").unwrap();
        assert!(conn.take_response().is_none());
    }

    #[test]
    fn missing_content_length_is_error() {
        let mut conn = machine();
        let err = feed(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "missing Content-Length");
    }

    #[test]
    fn invalid_content_length_is_error() {
        let mut conn = machine();
        let err = feed(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n{}").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "invalid Content-Length");
    }

    #[test]
    fn body_larger_than_header_read_arrives_in_exact_sized_reads() {
        let mut conn = machine();
        let body = vec![b'x'; 3 * HEADER_READ_LEN];
        let response = make_response(&body);

        let mut sent = 0;
        while sent < response.len() {
            assert!(conn.take_response().is_none());
            let space = conn.read_space();
            let n = space.len().min(response.len() - sent);
            space[..n].copy_from_slice(&response[sent..sent + n]);
            conn.commit_read(n).unwrap();
            sent += n;
        }
        assert_eq!(conn.take_response().unwrap(), body);
    }

    #[test]
    fn keep_alive_connection_serves_second_request() {
        let mut conn = machine();
        for body in [br#"{"id":1}"#.as_ref(), br#"{"id":2}"#.as_ref()] {
            frame_request(conn.begin_request(), "h", body, None, true);
            while !conn.pending_write().is_empty() {
                let n = conn.pending_write().len();
                conn.commit_write(n);
            }
            feed(&mut conn, &make_response(body)).unwrap();
            assert_eq!(conn.take_response().unwrap(), body);
        }
    }

    #[test]
    fn two_connections_complete_out_of_order() {
        let mut first = machine();
        let mut second = machine();
        frame_request(first.begin_request(), "h", br#"{"id":1}"#, None, true);
        frame_request(second.begin_request(), "h", br#"{"id":2}"#, None, true);

        feed(&mut second, &make_response(br#"{"id":2,"result":"b"}"#)).unwrap();
        assert!(first.take_response().is_none());
        assert_eq!(second.take_response().unwrap(), br#"{"id":2,"result":"b"}"#.as_ref());

        feed(&mut first, &make_response(br#"{"id":1,"result":"a"}"#)).unwrap();
        assert_eq!(first.take_response().unwrap(), br#"{"id":1,"result":"a"}"#.as_ref());
    }

    #[test]
    fn reset_clears_partial_state_but_keeps_capacity() {
        let mut conn = machine();
        frame_request(conn.begin_request(), "h", b"{}", None, true);
        feed(&mut conn, b"HTTP/1.1 200 OK\r\nContent-Le").unwrap();

        conn.reset();
        assert!(conn.pending_write().is_empty());
        assert!(conn.take_response().is_none());

        feed(&mut conn, &make_response(b"{}")).unwrap();
        assert_eq!(conn.take_response().unwrap(), b"{}");
    }
}
