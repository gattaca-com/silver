use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
};

use silver_common::{
    GossipMsgOut, P2pStreamId, RpcMsgOut, StreamProtocol, TCacheRead, TProducer, TRandomAccess,
    TReservation,
};

use crate::{RemotePeer, StreamData};

const MAX_PENDING_OUTBOUND_MSGS: usize = 64;

/// Stream data handler that reads and writes messages from `TCache` buffers.
pub struct TCacheStreamData {
    /// Producer for inbound protobuf gossip messages: network -> gossip tile
    gossip_in: TProducer,
    /// Top level consumer for outbound gossip protobuf msgs.
    gossip_out: TRandomAccess,
    /// Producer for inbound RPC requests and responses.
    rpc_in: TProducer,
    /// Top level consumer for outbound RPC msgs.
    rpc_out: TRandomAccess,
    /// In-flight inbound reservation per stream (keyed by stream id).
    in_reservations: HashMap<P2pStreamId, TReservation>,
    /// Current outbound message in flight per stream.
    out_current: HashMap<P2pStreamId, TCacheRead>,
    /// Outbound streams
    gossip_out_streams: HashMap<usize, OutBuffer<MAX_PENDING_OUTBOUND_MSGS>>,
    rpc_out_streams: HashMap<P2pStreamId, OutBuffer<MAX_PENDING_OUTBOUND_MSGS>>,
}

impl TCacheStreamData {
    pub fn new(
        gossip_in: TProducer,
        gossip_out: TRandomAccess,
        rpc_in: TProducer,
        rpc_out: TRandomAccess,
    ) -> Self {
        Self {
            gossip_in,
            gossip_out,
            rpc_in,
            rpc_out,
            in_reservations: Default::default(),
            out_current: Default::default(),
            gossip_out_streams: Default::default(),
            rpc_out_streams: Default::default(),
        }
    }

    pub fn update_tail(&mut self) {
        let mut gossip_min = u64::MAX;
        for buf in self.gossip_out_streams.values() {
            gossip_min = gossip_min.min(buf.cache_tail);
        }
        self.gossip_out.set_tail(gossip_min);

        let mut rpc_min = u64::MAX;
        for buf in self.rpc_out_streams.values() {
            rpc_min = rpc_min.min(buf.cache_tail);
        }
        self.rpc_out.set_tail(rpc_min);
    }

    pub fn gossip_stream_id(&self, peer_id: usize) -> Option<&P2pStreamId> {
        self.gossip_out_streams.get(&peer_id).map(|b| &b.stream_id)
    }

    pub fn enqueue_gossip(&mut self, stream_id: &P2pStreamId, msg: GossipMsgOut) -> bool {
        let buffer = self
            .gossip_out_streams
            .entry(msg.peer_id)
            .or_insert_with(|| OutBuffer::new(*stream_id));

        if buffer.add_msg(msg.into()) {
            tracing::warn!(peer = msg.peer_id, "lagging gossip peer, message dropped");
            return false;
        }
        true
    }

    pub fn enqueue_rpc_out(&mut self, stream_id: &P2pStreamId, msg: RpcMsgOut) -> bool {
        let buffer =
            self.rpc_out_streams.entry(*stream_id).or_insert_with(|| OutBuffer::new(*stream_id));

        if buffer.add_msg(msg.into()) {
            tracing::warn!(?stream_id, "lagging rpc peer, message dropped");
            return false;
        }
        true
    }
}

impl StreamData for TCacheStreamData {
    fn new_stream(&mut self, _peer: &RemotePeer, _stream: &P2pStreamId) {
        // TODO new incoming
        // check bans?
    }

    fn stream_closed(&mut self, stream: &P2pStreamId) {
        self.in_reservations.remove(stream);
        self.out_current.remove(stream);
        match stream.protocol() {
            StreamProtocol::GossipSub => {
                self.gossip_out_streams.remove(&stream.peer());
            }
            _ => {
                self.rpc_out_streams.remove(stream);
            }
        }
    }

    fn alloc_recv(&mut self, stream: &P2pStreamId, length: usize) -> Result<(), Error> {
        let reservation = match stream.protocol() {
            StreamProtocol::GossipSub => {
                self.gossip_in.reserve(length).ok_or(ErrorKind::FileTooLarge)?
            }
            _ => self.rpc_in.reserve(length).ok_or(ErrorKind::FileTooLarge)?,
        };
        self.in_reservations.insert(*stream, reservation);
        Ok(())
    }

    fn recv_buf(&mut self, stream: &P2pStreamId) -> Result<&mut [u8], Error> {
        let reservation =
            self.in_reservations.get_mut(stream).ok_or_else(|| Error::other("no reservation"))?;

        match stream.protocol() {
            StreamProtocol::GossipSub => {
                self.gossip_in.reservation_buffer(reservation).map_err(Error::other)
            }
            _ => self.rpc_in.reservation_buffer(reservation).map_err(Error::other),
        }
    }

    fn recv_advance(&mut self, stream: &P2pStreamId, written: usize) -> Result<(), Error> {
        let reservation =
            self.in_reservations.get_mut(stream).ok_or_else(|| Error::other("no reservation"))?;
        reservation.increment_offset(written);
        // Reservation auto-commits on drop when fully written.
        Ok(())
    }

    fn poll_send(&mut self, stream: &P2pStreamId) -> Option<usize> {
        let buf = match stream.protocol() {
            StreamProtocol::GossipSub => self.gossip_out_streams.get_mut(&stream.peer())?,
            _ => self.rpc_out_streams.get_mut(stream)?,
        };

        while let Some(read) = buf.pop() {
            match read.len() {
                Ok(len) => {
                    self.out_current.insert(*stream, read);
                    return Some(len);
                }
                Err(e) => tracing::error!(?e, ?read, "failed to read from TCache"),
            }
        }
        None
    }

    fn send_data(&mut self, stream: &P2pStreamId, offset: usize) -> Option<&[u8]> {
        let current = self.out_current.get(stream)?;
        let buffer = match stream.protocol() {
            StreamProtocol::GossipSub => self.gossip_out.read_at(current.seq()).ok()?,
            _ => self.rpc_out.read_at(current.seq()).ok()?,
        };
        (offset < buffer.len()).then_some(&buffer[offset..])
    }

    fn send_complete(&mut self, stream: &P2pStreamId) {
        self.out_current.remove(stream);
    }
}

/// Buffer of outbound TCache msgs
struct OutBuffer<const N: usize> {
    stream_id: P2pStreamId,
    cache_tail: u64,
    msgs: Box<[Option<TCacheRead>]>,
    head: usize,
    tail: usize,
}

impl<const N: usize> OutBuffer<N> {
    fn new(id: P2pStreamId) -> Self {
        assert!(N.is_power_of_two());
        Self {
            stream_id: id,
            cache_tail: u64::MAX,
            msgs: vec![None; N].into_boxed_slice(),
            head: 0,
            tail: 0,
        }
    }

    fn pos(seq: usize) -> usize {
        seq & (N - 1)
    }

    /// Returns `true` if adding the new message overwrote an old message.
    fn add_msg(&mut self, msg: TCacheRead) -> bool {
        if self.cache_tail == u64::MAX {
            self.cache_tail = msg.seq();
        }

        let old_msg = self.msgs[Self::pos(self.head)].replace(msg);
        self.head += 1;
        old_msg.is_some()
    }

    /// Called when the current read is complete.
    fn pop(&mut self) -> Option<TCacheRead> {
        match self.msgs[Self::pos(self.tail)].take() {
            Some(msg) => {
                self.cache_tail = msg.seq();
                self.tail += 1;
                Some(msg)
            }
            None => {
                self.cache_tail = u64::MAX;
                None
            }
        }
    }
}
