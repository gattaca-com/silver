use std::{
    collections::HashMap,
    io::{self, Read, Write},
    time::Duration,
};

use mio::{Events, Interest, Poll, Token};
use silver_beacon_state_data::BeaconStateReader;
use silver_common::{Enr, Identify, Keypair};
use silver_httpcore::{AfterResponse, Bind, Listener, ParsedRequest, ServerConnection, Stream};

use crate::{
    router::Router,
    routes::{ApiCtx, ROUTES},
};

const LISTENER: Token = Token(0);

struct Connection {
    stream: Stream,
    http: ServerConnection,
}

pub struct BeaconApi {
    poll: Poll,
    events: Events,
    listener: Listener,
    current_token: Token,
    connections: HashMap<Token, Connection>,
    router: Router,
    ctx: ApiCtx,
}

impl BeaconApi {
    pub fn new(
        bind: &Bind,
        keypair: &Keypair,
        local_enr: Enr,
        identify: &Identify,
        state: BeaconStateReader,
    ) -> Self {
        let poll = Poll::new().unwrap();
        let mut listener =
            Listener::bind(bind).unwrap_or_else(|e| panic!("beacon api bind {bind:?}: {e}"));
        poll.registry().register(&mut listener, LISTENER, Interest::READABLE).unwrap();

        Self {
            poll,
            events: Events::with_capacity(1024),
            listener,
            current_token: Token(LISTENER.0 + 1),
            connections: HashMap::new(),
            router: Router::new(ROUTES),
            ctx: ApiCtx::new(keypair, &local_enr, identify, state),
        }
    }

    pub fn local_addr(&self) -> Bind {
        self.listener.local_addr()
    }

    pub fn pump(&mut self) -> bool {
        self.poll.poll(&mut self.events, Some(Duration::ZERO)).unwrap();

        let mut did_work = false;
        for event in &self.events {
            match event.token() {
                LISTENER => loop {
                    let mut stream = match self.listener.accept() {
                        Ok(stream) => stream,
                        Err(e) if would_block(&e) => break,
                        Err(e) => {
                            tracing::warn!("accept failed: {e}");
                            break;
                        }
                    };

                    did_work = true;
                    let token = next(&mut self.current_token);
                    self.poll.registry().register(&mut stream, token, Interest::READABLE).unwrap();
                    self.connections
                        .insert(token, Connection { stream, http: ServerConnection::new() });
                },
                token => {
                    if let Some(conn) = self.connections.get_mut(&token) {
                        did_work = true;
                        match handle_event(self.poll.registry(), conn, event, &|req, out| {
                            self.router.dispatch(req, &self.ctx, out)
                        }) {
                            Ok(true) => {
                                let _ = self.poll.registry().deregister(&mut conn.stream);
                                self.connections.remove(&token);
                            }
                            Ok(false) => {}
                            Err(e) => {
                                tracing::warn!("connection error: {e}");
                                let _ = self.poll.registry().deregister(&mut conn.stream);
                                self.connections.remove(&token);
                            }
                        };
                    }
                }
            }
        }

        did_work
    }
}

fn handle_event<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
    registry: &mio::Registry,
    conn: &mut Connection,
    event: &mio::event::Event,
    request_handler: &F,
) -> io::Result<bool> {
    if event.is_readable() {
        loop {
            let space = conn.http.read_space()?;
            match conn.stream.read(space) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => conn.http.commit_read(n),
                Err(e) if would_block(&e) => break,
                Err(e) if interrupted(&e) => continue,
                Err(e) => return Err(e),
            }
        }

        if conn.http.dispatch(request_handler) {
            registry.reregister(&mut conn.stream, event.token(), Interest::WRITABLE)?;
        }
        return Ok(false);
    }

    if event.is_writable() {
        if !conn.http.pending_write().is_empty() {
            loop {
                match conn.stream.write(conn.http.pending_write()) {
                    Ok(0) => {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"))
                    }
                    Ok(n) => {
                        conn.http.commit_write(n);
                        if conn.http.pending_write().is_empty() {
                            break;
                        }
                    }
                    Err(e) if would_block(&e) => return Ok(false),
                    Err(e) if interrupted(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
            match conn.http.after_response(request_handler) {
                AfterResponse::Close => return Ok(true),
                AfterResponse::ResponsePending => {
                    registry.reregister(&mut conn.stream, event.token(), Interest::WRITABLE)?
                }
                AfterResponse::AwaitRequest => {
                    registry.reregister(&mut conn.stream, event.token(), Interest::READABLE)?
                }
            }
        }
        return Ok(false);
    }

    Ok(false)
}

fn next(current: &mut Token) -> Token {
    let tok = Token(current.0);
    let n = current.0.wrapping_add(1);
    // Skip Token(0) == LISTENER on wrap to avoid aliasing the accept socket.
    current.0 = if n == LISTENER.0 { LISTENER.0 + 1 } else { n };
    tok
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_wrap_skips_listener() {
        let mut cur = Token(usize::MAX);
        let assigned = next(&mut cur);
        assert_ne!(assigned, LISTENER, "returned token must not alias LISTENER");
        assert_ne!(cur, LISTENER, "next token must not alias LISTENER after wrap");
        assert_eq!(cur.0, LISTENER.0 + 1);
    }
}
