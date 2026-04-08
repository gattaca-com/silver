use quinn_proto::{Connection, StreamId};

use super::protocol::{
    GossipsubState, IdentifyInboundState, IdentifyOutboundState,
    RpcInboundState, RpcOutboundState,
};
use super::{
    MULTISTREAM_V1, REJECT_RESPONSE, StreamProtocol,
    state::{NegotiateAction, NegotiateState},
};

use super::snappy::SnappyDecoder;

pub(crate) enum ProtocolState {
    RpcInbound(RpcInboundState, SnappyDecoder),
    RpcOutbound(RpcOutboundState, SnappyDecoder),
    IdentifyInbound(IdentifyInboundState),
    IdentifyOutbound(IdentifyOutboundState),
    Gossipsub(GossipsubState),
}

impl ProtocolState {
    pub fn new(protocol: StreamProtocol, is_inbound: bool) -> Self {
        match (protocol, is_inbound) {
            (StreamProtocol::Identity, true) => {
                Self::IdentifyInbound(IdentifyInboundState::new())
            }
            (StreamProtocol::Identity, false) => {
                Self::IdentifyOutbound(IdentifyOutboundState::new())
            }
            (StreamProtocol::GossipSub, _) => {
                Self::Gossipsub(GossipsubState::new())
            }
            (_, true) => Self::RpcInbound(RpcInboundState::new(), SnappyDecoder::new()),
            (_, false) => Self::RpcOutbound(RpcOutboundState::new(), SnappyDecoder::new()),
        }
    }

    pub(crate) fn drive_write(
        &mut self,
        send: &mut quinn_proto::SendStream<'_>,
        outbound_queue: &mut std::collections::VecDeque<DCacheRef>,
    ) -> StreamEvent {
        match self {
            Self::RpcInbound(state, _) => state.drive_write(send, outbound_queue),
            Self::RpcOutbound(state, _) => state.drive_write(send, outbound_queue),
            Self::IdentifyInbound(state) => state.drive_write(send, outbound_queue),
            Self::IdentifyOutbound(state) => state.drive_write(send, outbound_queue),
            Self::Gossipsub(state) => state.drive_write(send, outbound_queue),
        }
    }
}

pub(crate) struct Stream {
    id: StreamId,
    is_inbound: bool,
    state: StreamState,
    leftover: bytes::Bytes,
}

/// Placeholder representing a slice or memory-mapped offset within the shared application ring buffer
#[derive(Debug, Clone)]
pub struct DCacheRef {
    pub payload: bytes::Bytes,
}

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
    /// Decoded application data available, specifying bytes written to out_buf.
    Data(usize),
    /// Written application data sent to socket.
    Sent(usize),
    /// Stream negotiation failed or was rejected.
    Failed,
    /// Nothing to do right now.
    Pending,
}

impl Stream {
    pub(crate) fn new_inbound(id: StreamId) -> Self {
        Self {
            id,
            is_inbound: true,
            state: StreamState::Negotiating(NegotiateState::new_inbound()),
            leftover: bytes::Bytes::new(),
        }
    }

    pub(crate) fn new_outbound(id: StreamId, protocol: StreamProtocol) -> Self {
        Self {
            id,
            is_inbound: false,
            state: StreamState::Negotiating(NegotiateState::new_outbound(protocol)),
            leftover: bytes::Bytes::new(),
        }
    }

    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    pub(crate) fn protocol(&self) -> Option<StreamProtocol> {
        match &self.state {
            StreamState::Active(p, _) => Some(*p),
            _ => None,
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(self.state, StreamState::Active(_, _))
    }

    pub(crate) fn is_dead(&self) -> bool {
        matches!(self.state, StreamState::Dead)
    }

    /// Drive this stream forward. Reads from / writes to the quinn connection
    /// as needed by the current state.
    pub(crate) fn drive(&mut self, conn: &mut Connection) -> StreamEvent {
        let StreamState::Negotiating(ref mut neg) = self.state else {
            return StreamEvent::Pending;
        };
        drive_negotiate(self.id, neg, conn)
    }

    /// Drive read side only (called on Readable events).
    pub(crate) fn drive_read(&mut self, conn: &mut Connection, mut out_buf: &mut [u8]) -> StreamEvent {
        use bytes::Buf;
        
        match self.state {
            StreamState::Negotiating(ref mut neg) => drive_negotiate(self.id, neg, conn),
            StreamState::Active(_, ref mut proto_state) => {
                let mut total_decoded = 0;

                // Process leftovers first
                if !self.leftover.is_empty() {
                    let mut slice = &self.leftover[..];
                    let decoded_bytes = match proto_state {
                        ProtocolState::RpcInbound(state, decoder) => state.feed_chunk(&mut slice, decoder, out_buf),
                        ProtocolState::RpcOutbound(state, decoder) => state.feed_chunk(&mut slice, decoder, out_buf),
                        ProtocolState::IdentifyOutbound(state) => state.feed_chunk(&mut slice, out_buf),
                        ProtocolState::Gossipsub(state) => state.feed_chunk(&mut slice, out_buf),
                        ProtocolState::IdentifyInbound(state) => state.feed_chunk(slice).map(|_| { slice = &[]; 0 }),
                    };

                    let consumed = self.leftover.len() - slice.len();
                    
                    if consumed == 0 && !out_buf.is_empty() {
                        // The state machine refused to consume bytes despite available capacity.
                        // This means it hit a terminal state (e.g. Done) and is ignoring trailing data.
                        // We must clear the unconsumed portion to prevent infinite CPU loops.
                        self.leftover.clear();
                    } else {
                        self.leftover.advance(consumed);
                    }

                    match decoded_bytes {
                        Ok(n) => {
                            total_decoded += n;
                            out_buf = &mut out_buf[n..];
                        }
                        Err(_) => {
                            self.state = StreamState::Dead;
                            return StreamEvent::Failed;
                        }
                    }
                }

                // If output buffer is full or leftover remained, stop and yield Data
                if !self.leftover.is_empty() || (out_buf.is_empty() && total_decoded > 0) {
                    return StreamEvent::Data(total_decoded);
                }

                // Drain from QUIC stream
                let mut recv = conn.recv_stream(self.id);
                if let Ok(mut chunks) = recv.read(true) {
                    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
                        let mut chunk_bytes = chunk.bytes;
                        let mut slice = &chunk_bytes[..];

                        let decoded_bytes = match proto_state {
                            ProtocolState::RpcInbound(state, decoder) => state.feed_chunk(&mut slice, decoder, out_buf),
                            ProtocolState::RpcOutbound(state, decoder) => state.feed_chunk(&mut slice, decoder, out_buf),
                            ProtocolState::IdentifyOutbound(state) => state.feed_chunk(&mut slice, out_buf),
                            ProtocolState::Gossipsub(state) => state.feed_chunk(&mut slice, out_buf),
                            ProtocolState::IdentifyInbound(state) => state.feed_chunk(slice).map(|_| { slice = &[]; 0 }),
                        };

                        let consumed = chunk_bytes.len() - slice.len();
                        
                        if consumed == 0 && !out_buf.is_empty() {
                            chunk_bytes.clear();
                        } else {
                            chunk_bytes.advance(consumed);
                        }

                        if !chunk_bytes.is_empty() {
                            self.leftover = chunk_bytes;
                        }

                        match decoded_bytes {
                            Ok(n) => {
                                total_decoded += n;
                                out_buf = &mut out_buf[n..];
                            }
                            Err(_) => {
                                self.state = StreamState::Dead;
                                return StreamEvent::Failed;
                            }
                        }

                        if !self.leftover.is_empty() || out_buf.is_empty() {
                            break;
                        }
                    }
                    let _ = chunks.finalize(); // Notify Quinn of precisely what we consumed
                }

                if total_decoded > 0 {
                    StreamEvent::Data(total_decoded)
                } else {
                    StreamEvent::Pending
                }
            }
            StreamState::Dead => StreamEvent::Pending,
        }
    }

    /// Drive write side only (called on Writable events).
    pub(crate) fn drive_write(
        &mut self,
        conn: &mut Connection,
        outbound_queue: &mut std::collections::VecDeque<DCacheRef>,
    ) -> StreamEvent {
        match &mut self.state {
            StreamState::Negotiating(neg) => drive_negotiate(self.id, neg, conn),
            StreamState::Active(_proto, state_machine) => {
                let mut send = conn.send_stream(self.id);
                state_machine.drive_write(&mut send, outbound_queue)
            }
            StreamState::Dead => StreamEvent::Pending,
        }
    }

    /// After drive returns Ready/Failed, call this to finalize the state
    /// transition.
    pub(crate) fn apply(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::Ready(proto) => {
                let active_state = ProtocolState::new(*proto, self.is_inbound);
                self.state = StreamState::Active(*proto, active_state);
            }
            StreamEvent::Failed => self.state = StreamState::Dead,
            _ => {}
        }
    }
}

/// Run the negotiate state machine: write pending bytes, read available
/// bytes, repeat until blocked or done.
fn drive_negotiate(id: StreamId, neg: &mut NegotiateState, conn: &mut Connection) -> StreamEvent {
    loop {
        // Try writes first.
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

        // Try reads.
        let read = read_negotiate(id, neg, conn);
        if read == 0 {
            return StreamEvent::Pending;
        }
        // Check if feed_read transitioned to a write or terminal state.
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
        // Still reading — loop.
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

    // Write from two concatenated slices at the given offset.
    let first_remaining = first.len().saturating_sub(offset);
    if first_remaining > 0 {
        write_buf(id, conn, &first[offset..], 0)
    } else {
        let second_offset = offset - first.len();
        write_buf(id, conn, &second[second_offset..], 0)
    }
}

fn write_buf(id: StreamId, conn: &mut Connection, data: &[u8], offset: usize) -> usize {
    match conn.send_stream(id).write(&data[offset..]) {
        Ok(n) => n,
        Err(_) => 0,
    }
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
