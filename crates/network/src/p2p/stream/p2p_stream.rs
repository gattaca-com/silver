use quinn_proto::{Connection, StreamId};
use silver_common::{MULTISTREAM_V1, P2pStreamId, REJECT_RESPONSE, StreamProtocol};

use super::{
    protocol::{
        GossipsubState, IdentifyInboundState, IdentifyOutboundState, RpcInboundState,
        RpcOutboundState,
    },
    snappy::SnappyDecoder,
    state::{NegotiateAction, NegotiateState},
};
use crate::p2p::StreamData;

pub(crate) enum ProtocolState {
    RpcInbound(RpcInboundState, SnappyDecoder),
    RpcOutbound(RpcOutboundState, SnappyDecoder),
    IdentifyInbound(IdentifyInboundState),
    IdentifyOutbound(IdentifyOutboundState),
    Gossipsub(GossipsubState),
}

impl ProtocolState {
    pub fn new(protocol: StreamProtocol, is_inbound: bool, stream: P2pStreamId) -> Self {
        match (protocol, is_inbound) {
            (StreamProtocol::Identity, true) => Self::IdentifyInbound(IdentifyInboundState::new()),
            (StreamProtocol::Identity, false) => {
                Self::IdentifyOutbound(IdentifyOutboundState::new())
            }
            (StreamProtocol::GossipSub, _) => Self::Gossipsub(GossipsubState::new(stream)),
            (_, true) => Self::RpcInbound(RpcInboundState::new(), SnappyDecoder::new()),
            (_, false) => Self::RpcOutbound(RpcOutboundState::new(), SnappyDecoder::new()),
        }
    }

    pub(crate) fn drive_write<S: StreamData>(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        stream_id: &P2pStreamId,
        data: &mut S,
    ) -> StreamEvent {
        match self {
            Self::RpcInbound(state, _) => state.drive_write(send, stream_id, data),
            Self::RpcOutbound(state, _) => state.drive_write(send, stream_id, data),
            Self::IdentifyInbound(state) => state.drive_write(send, stream_id, data),
            Self::IdentifyOutbound(_) => StreamEvent::Pending,
            Self::Gossipsub(state) => match state.drive_write(send, data) {
                Ok(_) => StreamEvent::Pending,
                Err(e) => {
                    tracing::error!(?e, "gossip stream write failed");
                    StreamEvent::Failed
                }
            },
        }
    }
}

pub(crate) struct Stream {
    id: P2pStreamId,
    is_inbound: bool,
    state: StreamState,
    leftover: bytes::Bytes,
}

#[allow(clippy::large_enum_variant)]
enum StreamState {
    Negotiating(NegotiateState),
    Active(StreamProtocol, ProtocolState),
    Dead,
}

/// Outcome of a single drive step, returned to the Peer.
#[derive(Debug)]
pub(crate) enum StreamEvent {
    /// Negotiation complete — caller can start using this stream.
    Ready(StreamProtocol),
    /// Written application data sent to socket.
    Sent(usize),
    /// Stream negotiation failed or was rejected.
    Failed,
    /// Nothing to do right now.
    Pending,
}

impl Stream {
    pub(crate) fn new_inbound(id: P2pStreamId) -> Self {
        Self {
            id,
            is_inbound: true,
            state: StreamState::Negotiating(NegotiateState::new_inbound()),
            leftover: bytes::Bytes::new(),
        }
    }

    pub(crate) fn new_outbound(id: P2pStreamId) -> Self {
        let protocol = id.protocol();
        Self {
            id,
            is_inbound: false,
            state: StreamState::Negotiating(NegotiateState::new_outbound(protocol)),
            leftover: bytes::Bytes::new(),
        }
    }

    pub(crate) fn id(&self) -> StreamId {
        (&self.id).into()
    }

    pub(crate) fn p2p_id(&self) -> &P2pStreamId {
        &self.id
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(self.state, StreamState::Active(_, _))
    }

    /// Drive this stream forward. Reads from / writes to the quinn connection
    /// as needed by the current state.
    pub(crate) fn drive<S: StreamData>(
        &mut self,
        conn: &mut Connection,
        data: &mut S,
    ) -> StreamEvent {
        let stream_id = self.id();

        match &mut self.state {
            StreamState::Negotiating(neg) => drive_negotiate(stream_id, neg, conn),
            StreamState::Active(..) => self.drive_write(conn, data),
            StreamState::Dead => StreamEvent::Pending,
        }
    }

    /// Drive read side only (called on Readable events).
    pub(crate) fn drive_read<S: StreamData>(
        &mut self,
        conn: &mut Connection,
        data: &mut S,
    ) -> StreamEvent {
        use bytes::Buf;
        let stream_id = self.id();

        match self.state {
            StreamState::Negotiating(ref mut neg) => match drive_negotiate(stream_id, neg, conn) {
                StreamEvent::Ready(stream_protocol) => {
                    self.id.set_protocol(stream_protocol);
                    StreamEvent::Ready(stream_protocol)
                }
                event => event,
            },
            StreamState::Active(_, ref mut proto_state) => {
                let mut out_buf = [0u8]; // placeholder for IdentifyOutbound error-path buffer

                // Process leftovers first
                if !self.leftover.chunk().is_empty() {
                    let slice = &self.leftover[..];
                    let decoded_bytes =
                        feed_proto(proto_state, slice, &self.id, data, &mut out_buf);

                    match decoded_bytes {
                        Ok(n) => {
                            self.leftover.advance(n);
                            if !self.leftover.chunk().is_empty() {
                                return StreamEvent::Pending;
                            }
                        }
                        Err(_) => {
                            self.state = StreamState::Dead;
                            return StreamEvent::Failed;
                        }
                    }
                }

                // Drain from QUIC stream
                let mut recv = conn.recv_stream(stream_id);
                if let Ok(mut chunks) = recv.read(true) {
                    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
                        let mut chunk_bytes = chunk.bytes;

                        let decoded_bytes =
                            feed_proto(proto_state, &chunk_bytes[..], &self.id, data, &mut out_buf);

                        match decoded_bytes {
                            Ok(n) => {
                                chunk_bytes.advance(n);
                                if !chunk_bytes.chunk().is_empty() {
                                    self.leftover = chunk_bytes;
                                    break;
                                }
                            }
                            Err(_) => {
                                self.state = StreamState::Dead;
                                return StreamEvent::Failed;
                            }
                        }
                    }
                    let _ = chunks.finalize();
                }
                StreamEvent::Pending
            }
            StreamState::Dead => StreamEvent::Pending,
        }
    }

    /// Drive write side only (called on Writable events).
    pub(crate) fn drive_write<S: StreamData>(
        &mut self,
        conn: &mut Connection,
        data: &mut S,
    ) -> StreamEvent {
        let stream_id = self.id();
        match &mut self.state {
            StreamState::Negotiating(neg) => drive_negotiate(stream_id, neg, conn),
            StreamState::Active(_proto, state_machine) => {
                let mut send = conn.send_stream(stream_id);
                state_machine.drive_write(&mut send, &self.id, data)
            }
            StreamState::Dead => StreamEvent::Pending,
        }
    }

    /// After drive returns Ready/Failed, call this to finalize the state
    /// transition.
    pub(crate) fn apply(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::Ready(proto) => {
                self.id.set_protocol(*proto);
                let active_state = ProtocolState::new(*proto, self.is_inbound, self.id);
                self.state = StreamState::Active(*proto, active_state);
            }
            StreamEvent::Failed => self.state = StreamState::Dead,
            _ => {}
        }
    }
}

/// Dispatch input bytes to the appropriate protocol state machine, returning
/// the number of bytes consumed.
fn feed_proto<S: StreamData>(
    proto: &mut ProtocolState,
    input: &[u8],
    stream_id: &P2pStreamId,
    data: &mut S,
    out_buf: &mut [u8],
) -> Result<usize, std::io::Error> {
    match proto {
        ProtocolState::RpcInbound(state, decoder) => {
            state.feed_chunk(input, decoder, data, stream_id)
        }
        ProtocolState::RpcOutbound(state, decoder) => {
            state.feed_chunk(input, decoder, out_buf, stream_id, data)
        }
        ProtocolState::IdentifyOutbound(state) => state.feed_chunk(input, out_buf),
        ProtocolState::Gossipsub(state) => state.recv(input, data),
        ProtocolState::IdentifyInbound(state) => state.feed_chunk(input).map(|_| input.len()),
    }
}

/// Run the negotiate state machine: write pending bytes, read available
/// bytes, repeat until blocked or done.
fn drive_negotiate(id: StreamId, neg: &mut NegotiateState, conn: &mut Connection) -> StreamEvent {
    loop {
        if neg.pending_write().is_some() {
            let wrote = write_negotiate(id, neg, conn);
            if wrote == 0 {
                return StreamEvent::Pending;
            }
            match neg.advance_write(wrote) {
                NegotiateAction::Write => continue,
                NegotiateAction::Read => continue,
                NegotiateAction::Done(proto) => return StreamEvent::Ready(proto),
                NegotiateAction::Failed => return StreamEvent::Failed,
            }
        }

        let read = read_negotiate(id, neg, conn);
        if read == 0 {
            return StreamEvent::Pending;
        }
        if neg.pending_write().is_some() {
            continue;
        }
        if matches!(neg, NegotiateState::Done(..)) {
            if let NegotiateState::Done(proto) = neg {
                return StreamEvent::Ready(*proto);
            }
        }
        if matches!(neg, NegotiateState::Failed) {
            return StreamEvent::Failed;
        }
    }
}

/// Write negotiate bytes to the send_stream. Returns bytes written.
fn write_negotiate(id: StreamId, neg: &NegotiateState, conn: &mut Connection) -> usize {
    let (first, second, offset) = match neg {
        NegotiateState::OutWriting { protocol, written } => {
            (MULTISTREAM_V1, protocol.multiselect(), *written)
        }
        NegotiateState::InWriting { protocol, written } => {
            (MULTISTREAM_V1, protocol.multiselect(), *written)
        }
        NegotiateState::InWritingReject { written } => {
            return write_buf(id, conn, REJECT_RESPONSE, *written);
        }
        _ => return 0,
    };

    let first_remaining = first.len().saturating_sub(offset);
    if first_remaining > 0 {
        write_buf(id, conn, &first[offset..], 0)
    } else {
        let second_offset = offset - first.len();
        write_buf(id, conn, &second[second_offset..], 0)
    }
}

fn write_buf(id: StreamId, conn: &mut Connection, data: &[u8], offset: usize) -> usize {
    conn.send_stream(id).write(&data[offset..]).unwrap_or_default()
}

/// Read bytes from recv_stream and feed into negotiate state. Returns bytes
/// read.
fn read_negotiate(id: StreamId, neg: &mut NegotiateState, conn: &mut Connection) -> usize {
    let mut recv = conn.recv_stream(id);
    let Ok(mut chunks) = recv.read(true) else {
        return 0;
    };

    let mut total = 0;
    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
        total += chunk.bytes.len();
        neg.feed_read(&chunk.bytes);
    }
    let _ = chunks.finalize();
    total
}
