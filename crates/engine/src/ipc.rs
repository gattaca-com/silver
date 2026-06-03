use std::{
    io::{self, Read, Write},
    path::PathBuf,
};

use mio::{Events, Interest, Poll, Token, net::UnixStream};

use crate::EngineError;

// Sized for the largest expected EL response: getPayload with a full
// blobsBundle (~21 blobs × 256 KB hex-encoded + execution payload
// transactions).
const READ_BUF_CAPACITY: usize = 10 * 1024 * 1024;

// Sized for the largest expected outgoing request: newPayload with a full
// block (~30M gas of transactions, hex-encoded in JSON).
const WRITE_BUF_CAPACITY: usize = 10 * 1024 * 1024;

#[derive(PartialEq)]
enum State {
    Disconnected,
    Connecting,
    Connected,
}

struct IpcTransport {
    path: PathBuf,
    token: Token,
    stream: Option<UnixStream>,
    state: State,
    pending_id: Option<u64>,
    write_buf: Vec<u8>,
    write_pos: usize,
    in_flight: Option<u64>,
    read_buf: Vec<u8>,
    read_offset: usize,
}

impl IpcTransport {
    pub(crate) fn new(path: String, token: Token) -> Self {
        Self {
            path: PathBuf::from(path),
            token,
            stream: None,
            state: State::Disconnected,
            pending_id: None,
            write_buf: Vec::with_capacity(WRITE_BUF_CAPACITY),
            write_pos: 0,
            in_flight: None,
            read_buf: Vec::with_capacity(READ_BUF_CAPACITY),
            read_offset: 0,
        }
    }
}

fn ipc_is_free(t: &IpcTransport) -> bool {
    t.in_flight.is_none() && t.pending_id.is_none()
}

fn ipc_enqueue(t: &mut IpcTransport, rpc_id: u64, body: &[u8], poll: &mut Poll) {
    t.write_buf.clear();
    t.write_buf.extend_from_slice(body);
    t.write_buf.push(b'\n');
    t.pending_id = Some(rpc_id);
    t.write_pos = 0;

    match t.state {
        State::Disconnected => ipc_connect(t, poll),
        State::Connected => ipc_set_interest(t, poll, Interest::READABLE | Interest::WRITABLE),
        State::Connecting => {}
    }
}

fn ipc_poll<F>(t: &mut IpcTransport, events: &Events, poll: &mut Poll, on_complete: &mut F)
where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    for event in events.iter() {
        if event.token() != t.token {
            continue;
        }
        match t.state {
            State::Disconnected => {}
            State::Connecting => {
                if event.is_writable() {
                    // is_error/is_write_closed flags are not reliable; use
                    // take_error() (getsockopt SO_ERROR) as the authoritative check.
                    let err = t.stream.as_ref().and_then(|s| s.take_error().ok()).flatten();
                    if let Some(e) = err {
                        ipc_on_error(t, poll, on_complete, &e.to_string());
                        break;
                    }
                    t.state = State::Connected;
                    let interest = if t.pending_id.is_none() {
                        Interest::READABLE
                    } else {
                        Interest::READABLE | Interest::WRITABLE
                    };
                    ipc_set_interest(t, poll, interest);
                }
            }
            State::Connected => {
                if event.is_error() || event.is_read_closed() {
                    ipc_on_error(t, poll, on_complete, "ipc connection lost");
                    break;
                }
                if event.is_writable() {
                    if let Err(e) = ipc_do_write(t) {
                        let msg = e.to_string();
                        ipc_on_error(t, poll, on_complete, &msg);
                        break;
                    }
                    let interest = if t.pending_id.is_none() {
                        Interest::READABLE
                    } else {
                        Interest::READABLE | Interest::WRITABLE
                    };
                    ipc_set_interest(t, poll, interest);
                }
                if event.is_readable() {
                    if let Err(e) = ipc_do_read(t, on_complete) {
                        let msg = e.to_string();
                        ipc_on_error(t, poll, on_complete, &msg);
                        break;
                    }
                }
            }
        }
    }
}

fn ipc_connect(t: &mut IpcTransport, poll: &mut Poll) {
    match UnixStream::connect(&t.path) {
        Ok(mut stream) => {
            if poll.registry().register(&mut stream, t.token, Interest::WRITABLE).is_ok() {
                t.stream = Some(stream);
                t.state = State::Connecting;
            }
        }
        Err(e) => tracing::warn!("connect error: {e}"),
    }
}

fn ipc_do_write(t: &mut IpcTransport) -> io::Result<()> {
    if t.pending_id.is_some() {
        let stream = t.stream.as_mut().unwrap();
        loop {
            match stream.write(&t.write_buf[t.write_pos..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0")),
                Ok(n) => {
                    t.write_pos += n;
                    if t.write_pos == t.write_buf.len() {
                        t.in_flight = t.pending_id.take();
                        t.write_pos = 0;
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

fn ipc_do_read<F>(t: &mut IpcTransport, on_complete: &mut F) -> io::Result<()>
where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    let stream = t.stream.as_mut().unwrap();
    loop {
        let base = t.read_buf.len();
        t.read_buf.resize(base + READ_BUF_CAPACITY, 0);
        match stream.read(&mut t.read_buf[base..]) {
            Ok(0) => {
                t.read_buf.truncate(base);
                return Err(io::Error::new(io::ErrorKind::ConnectionReset, "eof"));
            }
            Ok(n) => {
                t.read_buf.truncate(base + n);
                while let Some(rel) = t.read_buf[t.read_offset..].iter().position(|&b| b == b'\n') {
                    let offset = t.read_offset;
                    let end = offset + rel;
                    if let Some(rpc_id) = t.in_flight {
                        on_complete(rpc_id, Ok(&mut t.read_buf[offset..end]));
                    }
                    t.read_offset = end + 1;
                }
                if t.read_offset == t.read_buf.len() {
                    t.read_buf.clear();
                    t.read_offset = 0;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                t.read_buf.truncate(base);
                break;
            }
            Err(e) => {
                t.read_buf.truncate(base);
                return Err(e);
            }
        }
    }
    Ok(())
}

fn ipc_on_error<F>(t: &mut IpcTransport, poll: &mut Poll, on_complete: &mut F, msg: &str)
where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    tracing::warn!("{msg}");
    let err = msg.to_string();
    if let Some(rpc_id) = t.in_flight.take() {
        on_complete(rpc_id, Err(EngineError::Ipc(err.clone())));
    }
    if let Some(rpc_id) = t.pending_id.take() {
        on_complete(rpc_id, Err(EngineError::Ipc(err.clone())));
    }
    t.write_pos = 0;
    t.read_buf.clear();
    t.read_offset = 0;
    if let Some(mut stream) = t.stream.take() {
        let _ = poll.registry().deregister(&mut stream);
    }
    t.state = State::Disconnected;
}

fn ipc_set_interest(t: &mut IpcTransport, poll: &mut Poll, interest: Interest) {
    if let Some(stream) = t.stream.as_mut() {
        let _ = poll.registry().reregister(stream, t.token, interest);
    }
}

pub(crate) struct IpcPool {
    connections: Vec<IpcTransport>,
    path: String,
}

impl IpcPool {
    pub(crate) fn new(path: String) -> Self {
        let connections = vec![IpcTransport::new(path.clone(), Token(0))];
        Self { connections, path }
    }
}

pub(crate) fn ipc_pool_enqueue(pool: &mut IpcPool, rpc_id: u64, body: &[u8], poll: &mut Poll) {
    if let Some(conn) = pool.connections.iter_mut().find(|c| ipc_is_free(c)) {
        ipc_enqueue(conn, rpc_id, body, poll);
    } else {
        let mut new_conn = IpcTransport::new(pool.path.clone(), Token(pool.connections.len()));
        ipc_enqueue(&mut new_conn, rpc_id, body, poll);
        pool.connections.push(new_conn);
    }
}

pub(crate) fn poll_ipc_pool<F>(
    pool: &mut IpcPool,
    events: &Events,
    poll: &mut Poll,
    on_complete: &mut F,
) where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    for conn in &mut pool.connections {
        ipc_poll(conn, events, poll, on_complete);
    }
}
