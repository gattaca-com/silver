use std::io::Error;

use silver_common::P2pStreamId;

mod tcache;

pub use tcache::TCacheStreamData;

use crate::RemotePeer;

/// Byte-plane stream I/O interface, called by P2p/codec internals during
/// `P2p::poll`. Keyed by `P2pStreamId`; the impl tracks per-stream buffer
/// state internally.
pub trait StreamData: Send {
    // ---- Lifecycle ----

    /// A stream has completed multistream-select negotiation and is ready
    /// for application traffic. Invoked by P2p in lockstep with
    /// `NetEvent::StreamReady`. Impl typically allocates per-stream state.
    fn new_stream(&mut self, remote_peer: &RemotePeer, stream: &P2pStreamId);

    /// Stream is gone — closed cleanly, reset, or negotiation failed.
    /// Invoked by P2p in lockstep with `NetEvent::StreamClosed`. Impl
    /// should drop any state keyed by this stream.
    fn stream_closed(&mut self, stream: &P2pStreamId);

    // ---- Receive path ----

    /// Called when a new inbound message starts. `length` is the total
    /// uncompressed payload length. The impl should allocate a receive
    /// buffer for this stream.
    fn alloc_recv(&mut self, stream: &P2pStreamId, length: usize) -> Result<(), Error>;

    /// Get a mutable receive buffer for the in-progress message on `stream`.
    /// Network writes raw (or decompressed) bytes directly here, then calls
    /// `recv_advance` to advance the write offset.
    fn recv_buf(&mut self, stream: &P2pStreamId) -> Result<&mut [u8], Error>;

    /// Notify that `written` bytes have been written into the slice
    /// returned by the previous `recv_buf`. May be called multiple times
    /// per message.
    fn recv_advance(&mut self, stream: &P2pStreamId, written: usize) -> Result<(), Error>;

    // ---- Send path ----

    /// Poll for a new outbound message on `stream`. Returns total length
    /// if available. Network will subsequently call `send_data` at various
    /// offsets until `length` bytes have been sent, then `send_complete`.
    fn poll_send(&mut self, stream: &P2pStreamId) -> Option<usize>;

    /// Get bytes of the current outbound message at `offset`.
    fn send_data(&mut self, stream: &P2pStreamId, offset: usize) -> Option<&[u8]>;

    /// Notify that the current outbound message on `stream` has been fully
    /// sent. Implementation advances to the next message.
    fn send_complete(&mut self, stream: &P2pStreamId);
}
