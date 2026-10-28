use std::{
    io::{self, ErrorKind, Read, Write},
    sync::{Arc, LazyLock},
};

use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};

use crate::Stream;

static WEBPKI_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    client_config(roots)
});

pub(crate) fn client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

pub(crate) struct Tls {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) server_name: ServerName<'static>,
}

impl Tls {
    pub(crate) fn webpki(server_name: &str) -> io::Result<Self> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid tls server name"))?;
        Ok(Self { config: WEBPKI_CONFIG.clone(), server_name })
    }
}

/// Non-blocking: reads and writes return `WouldBlock` as the socket does.
pub(crate) enum Transport {
    Plain(Stream),
    Tls { stream: Stream, session: Box<ClientConnection> },
}

impl Transport {
    pub(crate) fn new(stream: Stream, tls: Option<&Tls>) -> io::Result<Self> {
        let Some(tls) = tls else { return Ok(Self::Plain(stream)) };
        let mut session = ClientConnection::new(tls.config.clone(), tls.server_name.clone())
            .map_err(io::Error::other)?;
        // A request is handed over whole, even before the handshake ends.
        session.set_buffer_limit(None);
        Ok(Self::Tls { stream, session: Box::new(session) })
    }

    pub(crate) fn stream_mut(&mut self) -> &mut Stream {
        match self {
            Self::Plain(stream) | Self::Tls { stream, .. } => stream,
        }
    }

    pub(crate) fn wants_write(&self) -> bool {
        matches!(self, Self::Tls { session, .. } if session.wants_write())
    }

    /// Sends buffered records until the socket would block.
    pub(crate) fn flush_records(&mut self) -> io::Result<()> {
        let Self::Tls { stream, session } = self else { return Ok(()) };
        flush_records(stream, session)
    }
}

fn flush_records(stream: &mut Stream, session: &mut ClientConnection) -> io::Result<()> {
    while session.wants_write() {
        match session.write_tls(stream) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, session) = match self {
            Self::Plain(stream) => return stream.read(buf),
            Self::Tls { stream, session } => (stream, session),
        };
        loop {
            match session.reader().read(buf) {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                result => return result,
            }
            if session.read_tls(stream)? == 0 {
                return Ok(0);
            }
            session.process_new_packets().map_err(io::Error::other)?;
            flush_records(stream, session)?;
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (stream, session) = match self {
            Self::Plain(stream) => return stream.write(buf),
            Self::Tls { stream, session } => (stream, session),
        };
        let written = session.writer().write(buf)?;
        flush_records(stream, session)?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_records()?;
        self.stream_mut().flush()
    }
}
