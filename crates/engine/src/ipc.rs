use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    path::PathBuf,
};

use mio::{Events, Interest, Poll, Token, net::UnixStream};

use crate::EngineError;

// Sized for the largest expected EL response: getPayload with a full
// blobsBundle (~21 blobs × 256 KB hex-encoded + execution payload
// transactions).
const READ_BUF_CAPACITY: usize = 10 * 1024 * 1024;

#[derive(PartialEq)]
enum State {
    Disconnected,
    Connecting,
    Connected,
}

pub(crate) struct IpcTransport {
    path: PathBuf,
    token: Token,
    stream: Option<UnixStream>,
    state: State,
    send_queue: VecDeque<(u64, Vec<u8>)>,
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
            send_queue: VecDeque::new(),
            write_pos: 0,
            in_flight: None,
            read_buf: Vec::with_capacity(READ_BUF_CAPACITY),
            read_offset: 0,
        }
    }
}

pub(crate) fn ipc_is_free(t: &IpcTransport) -> bool {
    t.in_flight.is_none() && t.send_queue.is_empty()
}

pub(crate) fn ipc_enqueue(t: &mut IpcTransport, rpc_id: u64, body: &[u8], poll: &mut Poll) {
    let mut bytes = body.to_vec();
    bytes.push(b'\n');
    t.send_queue.push_back((rpc_id, bytes));

    match t.state {
        State::Disconnected => ipc_connect(t, poll),
        State::Connected => ipc_set_interest(t, poll, Interest::READABLE | Interest::WRITABLE),
        State::Connecting => {}
    }
}

pub(crate) fn ipc_poll<F>(
    t: &mut IpcTransport,
    events: &Events,
    poll: &mut Poll,
    on_complete: &mut F,
) where
    F: FnMut(u64, Result<Vec<u8>, EngineError>),
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
                    let interest = if t.send_queue.is_empty() {
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
                    let interest = if t.send_queue.is_empty() {
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
    while let Some((_, bytes)) = t.send_queue.front() {
        let stream = t.stream.as_mut().unwrap();
        match stream.write(&bytes[t.write_pos..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0")),
            Ok(n) => {
                t.write_pos += n;
                if t.write_pos == bytes.len() {
                    let (rpc_id, _) = t.send_queue.pop_front().unwrap();
                    t.in_flight = Some(rpc_id);
                    t.write_pos = 0;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn ipc_do_read<F>(t: &mut IpcTransport, on_complete: &mut F) -> io::Result<()>
where
    F: FnMut(u64, Result<Vec<u8>, EngineError>),
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
                    let end = t.read_offset + rel;
                    if let Some(rpc_id) = t.in_flight {
                        on_complete(rpc_id, Ok(t.read_buf[t.read_offset..end].to_vec()));
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
    F: FnMut(u64, Result<Vec<u8>, EngineError>),
{
    tracing::warn!("{msg}");
    let err = msg.to_string();
    if let Some(rpc_id) = t.in_flight.take() {
        on_complete(rpc_id, Err(EngineError::Ipc(err.clone())));
    }
    for (rpc_id, _) in t.send_queue.drain(..) {
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
    F: FnMut(u64, Result<Vec<u8>, EngineError>),
{
    for conn in &mut pool.connections {
        ipc_poll(conn, events, poll, on_complete);
    }
}
