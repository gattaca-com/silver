pub mod gossipsub;
pub mod identity;
pub mod rpc;

pub use gossipsub::GossipsubState;
pub use identity::{IdentifyInboundState, IdentifyOutboundState};
pub use rpc::{RpcInboundState, RpcOutboundState};
use silver_common::P2pStreamId;

use crate::StreamData;

/// Outcome of a single buffer write attempt.
pub(crate) enum WriteResult {
    /// Buffer complete. Caller should load next or transition.
    Done,
    /// Quinn send buffer full. Retry later.
    Blocked,
    /// No data available from handler.
    Empty,
    /// Fatal write error.
    Failed,
}

/// Write handler-provided bytes to a quinn send stream. If `current` is
/// `None`, polls the handler for a new message via `poll_new_send`. Writes
/// until the current message is fully drained or quinn blocks.
///
/// `current` tracks `(length, offset)` — total message length and how many
/// bytes have been written so far. Reset to `None` when the message is
/// fully sent.
///
/// Returns `(bytes_written_this_call, result)`.
pub(crate) fn drive_send<S: StreamData>(
    current: &mut Option<(usize, usize)>,
    send: &mut quinn_proto::SendStream<'_>,
    stream_id: &P2pStreamId,
    data: &mut S,
) -> (usize, WriteResult) {
    let mut total = 0;

    // Load next message if needed.
    if current.is_none() {
        if let Some(length) = data.poll_send(stream_id) {
            *current = Some((length, 0));
        } else {
            return (0, WriteResult::Empty);
        }
    }

    // Write loop for current message.
    while let Some((length, offset)) = current.as_mut() {
        if *offset >= *length {
            data.send_complete(stream_id);
            *current = None;
            return (total, WriteResult::Done);
        }

        let chunk = match data.send_data(stream_id, *offset) {
            Some(chunk) if !chunk.is_empty() => chunk,
            _ => {
                data.send_complete(stream_id);
                *current = None;
                return (total, WriteResult::Done);
            }
        };

        match send.write(chunk) {
            Ok(written) => {
                total += written;
                *offset += written;
                if written < chunk.len() {
                    return (total, WriteResult::Blocked);
                }
            }
            Err(quinn_proto::WriteError::Blocked) => return (total, WriteResult::Blocked),
            Err(_) => return (total, WriteResult::Failed),
        }
    }

    (total, WriteResult::Empty)
}

/// Write as many messages as possible to a quinn send stream. Returns a
/// `StreamEvent` with total bytes written.
pub(crate) fn drive_send_loop<S: StreamData>(
    current: &mut Option<(usize, usize)>,
    send: &mut quinn_proto::SendStream<'_>,
    stream_id: &P2pStreamId,
    data: &mut S,
) -> super::StreamEvent {
    let mut total = 0;
    loop {
        let (wrote, result) = drive_send(current, send, stream_id, data);
        total += wrote;
        match result {
            WriteResult::Done => continue,
            WriteResult::Empty | WriteResult::Blocked => break,
            WriteResult::Failed => return super::StreamEvent::Failed,
        }
    }
    if total > 0 { super::StreamEvent::Sent(total) } else { super::StreamEvent::Pending }
}
