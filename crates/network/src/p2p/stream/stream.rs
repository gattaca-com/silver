use quinn_proto::{Connection, StreamId};

use super::{
    MULTISTREAM_V1, REJECT_RESPONSE, StreamProtocol,
    state::{NegotiateAction, NegotiateState},
};

pub(crate) struct Stream {
    id: StreamId,
    state: StreamState,
}

enum StreamState {
    Negotiating(NegotiateState),
    Active(StreamProtocol),
    Dead,
}

/// Outcome of a single drive step, returned to the Peer.
#[derive(Debug)]
pub(crate) enum StreamEvent {
    /// Negotiation complete — caller can start using this stream.
    Ready(StreamProtocol),
    /// Decoded application data available.
    Data,
    /// Stream negotiation failed or was rejected.
    Failed,
    /// Nothing to do right now.
    Pending,
}

impl Stream {
    pub(crate) fn new_inbound(id: StreamId) -> Self {
        Self { id, state: StreamState::Negotiating(NegotiateState::new_inbound()) }
    }

    pub(crate) fn new_outbound(id: StreamId, protocol: StreamProtocol) -> Self {
        Self { id, state: StreamState::Negotiating(NegotiateState::new_outbound(protocol)) }
    }

    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    pub(crate) fn protocol(&self) -> Option<StreamProtocol> {
        match &self.state {
            StreamState::Active(p) => Some(*p),
            _ => None,
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(self.state, StreamState::Active(_))
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
    pub(crate) fn drive_read(&mut self, conn: &mut Connection) -> StreamEvent {
        match self.state {
            StreamState::Negotiating(ref mut neg) => drive_negotiate(self.id, neg, conn),
            StreamState::Active(_) => {
                // TODO: read chunks → snappy decode → surface data
                StreamEvent::Pending
            }
            StreamState::Dead => StreamEvent::Pending,
        }
    }

    /// Drive write side only (called on Writable events).
    pub(crate) fn drive_write(&mut self, conn: &mut Connection) -> StreamEvent {
        let StreamState::Negotiating(ref mut neg) = self.state else {
            return StreamEvent::Pending;
        };
        drive_negotiate(self.id, neg, conn)
    }

    /// After drive returns Ready/Failed, call this to finalize the state
    /// transition.
    pub(crate) fn apply(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::Ready(proto) => self.state = StreamState::Active(*proto),
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
