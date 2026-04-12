pub mod gossipsub;
pub mod identity;
pub mod rpc;

pub use gossipsub::GossipsubState;
pub use identity::{IdentifyInboundState, IdentifyOutboundState};
pub use rpc::{RpcInboundState, RpcOutboundState};
use silver_common::P2pStreamId;

use crate::StreamHandler;

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

/// Write handler-provided buffers to a quinn send stream. Drains one buffer:
/// polls `poll_new_send` if `current` is None, then writes via `poll_send`
/// until the buffer is complete or quinn blocks.
///
/// Returns `(bytes_written, result)`.
pub(crate) fn drive_send<S: StreamHandler>(
    current: &mut Option<(S::BufferId, usize)>,
    send: &mut quinn_proto::SendStream<'_>,
    stream_id: &P2pStreamId,
    handler: &mut S,
) -> (usize, WriteResult) {
    let mut total = 0;

    // Load next buffer if needed.
    if current.is_none() {
        if let Some((buffer_id, _length)) = handler.poll_new_send(stream_id) {
            *current = Some((buffer_id, 0));
        } else {
            return (0, WriteResult::Empty);
        }
    }

    // Write loop for current buffer.
    while let Some((buffer_id, offset)) = current.as_mut() {
        let chunk = match handler.poll_send(buffer_id, *offset) {
            Some(chunk) if !chunk.is_empty() => chunk,
            _ => {
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

/// Write as many handler-provided buffers as possible to a quinn send stream.
/// Keeps draining buffers until the handler has none left or quinn blocks.
/// Returns a `StreamEvent` with total bytes written.
pub(crate) fn drive_send_loop<S: StreamHandler>(
    current: &mut Option<(S::BufferId, usize)>,
    send: &mut quinn_proto::SendStream<'_>,
    stream_id: &P2pStreamId,
    handler: &mut S,
) -> super::StreamEvent {
    let mut total = 0;
    loop {
        let (wrote, result) = drive_send(current, send, stream_id, handler);
        total += wrote;
        match result {
            WriteResult::Done => continue,
            WriteResult::Empty | WriteResult::Blocked => break,
            WriteResult::Failed => return super::StreamEvent::Failed,
        }
    }
    if total > 0 { super::StreamEvent::Sent(total) } else { super::StreamEvent::Pending }
}
