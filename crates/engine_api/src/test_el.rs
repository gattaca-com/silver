use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
};

use simd_json::prelude::{ValueAsScalar, ValueObjectAccess};

pub const FCU_VALID_RESULT: &str = r#"{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":null}"#;

pub fn write_jwt(dir: &Path) -> PathBuf {
    let path = dir.join("jwt.hex");
    std::fs::write(&path, "0000000000000000000000000000000000000000000000000000000000000000")
        .unwrap();
    path
}

enum ElListener {
    Tcp(TcpListener),
    Uds(UnixListener),
}

enum ElStream {
    Tcp(TcpStream),
    Uds(UnixStream),
}

impl Read for ElStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Uds(s) => s.read(buf),
        }
    }
}

impl Write for ElStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Uds(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Uds(s) => s.flush(),
        }
    }
}

pub struct ElRequest {
    conn: usize,
    pub id: u64,
    pub method: String,
    pub authorization: Option<String>,
    pub body: String,
}

/// Deterministic single-threaded fake execution client: accepts connections
/// and buffers requests on `pump`, answers only when the test says so.
pub struct FakeEl {
    listener: ElListener,
    conns: Vec<Option<ElStream>>,
    read_bufs: Vec<Vec<u8>>,
    pub requests: Vec<ElRequest>,
}

impl FakeEl {
    pub fn tcp() -> (Self, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        (Self::new(ElListener::Tcp(listener)), endpoint)
    }

    pub fn uds(path: &Path) -> Self {
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self::new(ElListener::Uds(listener))
    }

    fn new(listener: ElListener) -> Self {
        Self { listener, conns: Vec::new(), read_bufs: Vec::new(), requests: Vec::new() }
    }

    pub fn pump(&mut self) {
        loop {
            let accepted = match &self.listener {
                ElListener::Tcp(l) => l.accept().map(|(s, _)| {
                    s.set_nonblocking(true).unwrap();
                    ElStream::Tcp(s)
                }),
                ElListener::Uds(l) => l.accept().map(|(s, _)| {
                    s.set_nonblocking(true).unwrap();
                    ElStream::Uds(s)
                }),
            };
            match accepted {
                Ok(stream) => {
                    self.conns.push(Some(stream));
                    self.read_bufs.push(Vec::new());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("accept: {e}"),
            }
        }

        for i in 0..self.conns.len() {
            let Some(stream) = self.conns[i].as_mut() else { continue };
            let mut chunk = [0u8; 65536];
            let mut closed = false;
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(n) => self.read_bufs[i].extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("read: {e}"),
                }
            }
            if closed {
                self.conns[i] = None;
            }
            while let Some((consumed, request)) = parse_request(i, &self.read_bufs[i]) {
                self.requests.push(request);
                self.read_bufs[i].drain(..consumed);
            }
        }
    }

    pub fn respond(&mut self, request_index: usize, result_json: &str) {
        let request = &self.requests[request_index];
        let body = format!(r#"{{"jsonrpc":"2.0","id":{},"result":{result_json}}}"#, request.id);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let stream = self.conns[request.conn].as_mut().expect("respond on closed connection");
        let mut bytes = response.as_bytes();
        while !bytes.is_empty() {
            match stream.write(bytes) {
                Ok(n) => bytes = &bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("write: {e}"),
            }
        }
    }

    pub fn close_connection_of(&mut self, request_index: usize) {
        self.conns[self.requests[request_index].conn] = None;
    }
}

fn parse_request(conn: usize, buf: &[u8]) -> Option<(usize, ElRequest)> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    let header_end = match request.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return None,
    };
    let content_length: usize = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok()?.trim().parse().ok())
        .expect("request without Content-Length");
    if buf.len() < header_end + content_length {
        return None;
    }
    let authorization = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("authorization"))
        .map(|h| String::from_utf8(h.value.to_vec()).unwrap());

    let body = String::from_utf8(buf[header_end..header_end + content_length].to_vec()).unwrap();
    let mut json = body.clone().into_bytes();
    let json = simd_json::to_borrowed_value(&mut json).expect("request body is JSON");
    let id = json.get("id").and_then(|v| v.as_u64()).expect("rpc id");
    let method = json.get("method").and_then(|v| v.as_str()).expect("rpc method").to_string();

    Some((header_end + content_length, ElRequest { conn, id, method, authorization, body }))
}
