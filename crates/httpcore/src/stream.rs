use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use mio::{
    Interest, Registry, Token,
    event::Source,
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bind {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Bind {
    pub fn parse(text: &str) -> Self {
        match text.parse() {
            Ok(addr) => Self::Tcp(addr),
            Err(_) => {
                assert!(
                    !text.contains(':'),
                    "bind {text:?}: not a valid socket address (hostnames are not resolved), \
                     and a unix socket path containing ':' is almost certainly a typo"
                );
                Self::Unix(PathBuf::from(text))
            }
        }
    }
}

pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    pub fn bind(bind: &Bind) -> io::Result<Self> {
        match bind {
            Bind::Tcp(addr) => TcpListener::bind(*addr).map(Self::Tcp),
            Bind::Unix(path) => UnixListener::bind(path).map(Self::Unix),
        }
    }

    pub fn accept(&self) -> io::Result<Stream> {
        match self {
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept()?;
                tracing::info!("accepted connection from {peer}");
                Ok(Stream::Tcp(stream))
            }
            Self::Unix(listener) => {
                let (stream, _) = listener.accept()?;
                tracing::info!("accepted connection on unix socket");
                Ok(Stream::Uds(stream))
            }
        }
    }

    /// The resolved bind: for TCP the actual listening address (a port-0 bind
    /// reports the ephemeral port the OS assigned), for Unix the socket path.
    pub fn local_addr(&self) -> Bind {
        match self {
            Self::Tcp(listener) => Bind::Tcp(listener.local_addr().expect("tcp local_addr")),
            Self::Unix(listener) => Bind::Unix(
                listener
                    .local_addr()
                    .ok()
                    .and_then(|addr| addr.as_pathname().map(Path::to_path_buf))
                    .expect("unix listener bound to a path"),
            ),
        }
    }
}

impl Source for Listener {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        match self {
            Self::Tcp(l) => l.register(registry, token, interests),
            Self::Unix(l) => l.register(registry, token, interests),
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        match self {
            Self::Tcp(l) => l.reregister(registry, token, interests),
            Self::Unix(l) => l.reregister(registry, token, interests),
        }
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        match self {
            Self::Tcp(l) => l.deregister(registry),
            Self::Unix(l) => l.deregister(registry),
        }
    }
}

pub enum Stream {
    Tcp(TcpStream),
    Uds(UnixStream),
}

impl Stream {
    pub fn connect_tcp(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self::Tcp(TcpStream::connect(addr)?))
    }

    pub fn connect_uds(path: &Path) -> io::Result<Self> {
        Ok(Self::Uds(UnixStream::connect(path)?))
    }

    /// After the writable event that ends a non-blocking connect, distinguishes
    /// success from failure: TCP has a peer address only once connected; a Unix
    /// socket reports connect failure through SO_ERROR (mio's readiness flags
    /// are not reliable for it).
    pub fn connect_complete(&self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.peer_addr().map(|_| ()),
            Self::Uds(s) => match s.take_error()? {
                Some(e) => Err(e),
                None => Ok(()),
            },
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Uds(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
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

impl Source for Stream {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.register(registry, token, interests),
            Self::Uds(s) => s.register(registry, token, interests),
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.reregister(registry, token, interests),
            Self::Uds(s) => s.reregister(registry, token, interests),
        }
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.deregister(registry),
            Self::Uds(s) => s.deregister(registry),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientConnection, frame_request};

    #[test]
    fn parse_socket_addr_is_tcp() {
        assert_eq!(Bind::parse("0.0.0.0:5051"), Bind::Tcp("0.0.0.0:5051".parse().unwrap()));
        assert_eq!(Bind::parse("127.0.0.1:0"), Bind::Tcp("127.0.0.1:0".parse().unwrap()));
        assert_eq!(Bind::parse("[::1]:5051"), Bind::Tcp("[::1]:5051".parse().unwrap()));
    }

    #[test]
    fn parse_non_addr_is_unix_path() {
        assert_eq!(Bind::parse("/run/beacon.sock"), Bind::Unix("/run/beacon.sock".into()));
        assert_eq!(Bind::parse("beacon.sock"), Bind::Unix("beacon.sock".into()));
    }

    #[test]
    #[should_panic(expected = "not a valid socket address")]
    fn parse_rejects_hostname_with_port() {
        Bind::parse("localhost:5051");
    }

    #[test]
    #[should_panic(expected = "not a valid socket address")]
    fn parse_rejects_typoed_socket_addr() {
        Bind::parse("127.0.0.1:505x");
    }

    #[test]
    fn tcp_listener_reports_ephemeral_port() {
        let listener = Listener::bind(&Bind::parse("127.0.0.1:0")).unwrap();
        let Bind::Tcp(addr) = listener.local_addr() else { panic!("tcp bind") };
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn unix_listener_reports_bound_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = Listener::bind(&Bind::Unix(path.clone())).unwrap();
        assert_eq!(listener.local_addr(), Bind::Unix(path));
    }

    #[test]
    fn uds_pair_round_trip_through_client_connection() {
        let (client_half, mut server_half) = UnixStream::pair().unwrap();
        let mut stream = Stream::Uds(client_half);
        let mut conn = ClientConnection::with_capacity(4096, 4096);

        let body = br#"{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":7}"#;
        frame_request(conn.begin_request(), "localhost", body, Some("Bearer t.t.t"), true);
        while !conn.pending_write().is_empty() {
            match stream.write(conn.pending_write()) {
                Ok(n) => conn.commit_write(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("write: {e}"),
            }
        }

        let mut request = vec![0u8; 4096];
        let n = blocking_read(&mut server_half, &mut request);
        let request = String::from_utf8(request[..n].to_vec()).unwrap();
        assert!(request.starts_with("POST / HTTP/1.1\r\n"));
        assert!(request.contains("Authorization: Bearer t.t.t\r\n"));
        assert!(request.ends_with(std::str::from_utf8(body).unwrap()));

        let response_body = br#"{"jsonrpc":"2.0","id":7,"result":false}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            std::str::from_utf8(response_body).unwrap()
        );
        blocking_write(&mut server_half, response.as_bytes());

        loop {
            if let Some(got) = conn.take_response() {
                assert_eq!(got, response_body);
                break;
            }
            match stream.read(conn.read_space()) {
                Ok(n) => conn.commit_read(n).unwrap(),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    fn blocking_read(stream: &mut UnixStream, buf: &mut [u8]) -> usize {
        use std::io::Read as _;
        loop {
            match stream.read(buf) {
                Ok(n) => return n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    fn blocking_write(stream: &mut UnixStream, mut bytes: &[u8]) {
        use std::io::Write as _;
        while !bytes.is_empty() {
            match stream.write(bytes) {
                Ok(n) => bytes = &bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("write: {e}"),
            }
        }
    }
}
