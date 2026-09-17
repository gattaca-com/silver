use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    ptr::NonNull,
};

use fxhash::FxHashMap;
use silver_common::{GossipFrameOutcome, GossipFrameResult, P2pStreamId};

const MAX_PEER_FRAMES: usize = 16;
const MAX_PEER_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct SendReceipts {
    pending: Cell<usize>,
    peers: RefCell<FxHashMap<usize, (usize, usize)>>,
    completed: RefCell<VecDeque<GossipFrameResult>>,
    capacity: usize,
}

impl SendReceipts {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            pending: Cell::new(0),
            peers: RefCell::new(FxHashMap::with_capacity_and_hasher(capacity, Default::default())),
            completed: RefCell::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub(super) fn acquire(&self, peer: usize, frame_seq: u64, bytes: usize) -> Option<SendReceipt> {
        if self.pending.get() + self.completed.borrow().len() >= self.capacity {
            return None;
        }
        let mut peers = self.peers.borrow_mut();
        let (frames, queued_bytes) = peers.get(&peer).copied().unwrap_or_default();
        if frames >= MAX_PEER_FRAMES || bytes > MAX_PEER_BYTES.saturating_sub(queued_bytes) {
            return None;
        }
        peers.insert(peer, (frames + 1, queued_bytes + bytes));
        self.pending.set(self.pending.get() + 1);
        Some(SendReceipt {
            receipts: NonNull::from(self),
            result: GossipFrameResult {
                p2p_peer: peer,
                frame_seq,
                outcome: GossipFrameOutcome::Dropped,
            },
            bytes,
        })
    }

    pub(super) fn pop(&self) -> Option<GossipFrameResult> {
        self.completed.borrow_mut().pop_front()
    }
}

#[derive(Debug)]
pub(super) struct SendReceipt {
    receipts: NonNull<SendReceipts>,
    result: GossipFrameResult,
    bytes: usize,
}

// Receipts remain on NetworkTile; the boxed limits outlive every queued frame.
unsafe impl Send for SendReceipt {}

impl SendReceipt {
    pub(super) fn written(&mut self, stream_id: P2pStreamId) {
        self.result.outcome = GossipFrameOutcome::Written { stream_id };
    }
}

impl Drop for SendReceipt {
    fn drop(&mut self) {
        let receipts = unsafe { self.receipts.as_ref() };
        let mut peers = receipts.peers.borrow_mut();
        let (frames, bytes) = peers.get_mut(&self.result.p2p_peer).unwrap();
        *frames -= 1;
        *bytes -= self.bytes;
        if *frames == 0 {
            peers.remove(&self.result.p2p_peer);
        }
        receipts.pending.set(receipts.pending.get() - 1);
        receipts.completed.borrow_mut().push_back(self.result);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::StreamProtocol;

    use super::*;

    #[test]
    fn written_and_abandoned_frames_release_their_own_receipts() {
        let receipts = Box::new(SendReceipts::new(2));
        let mut first = receipts.acquire(1, 10, 1024).unwrap();
        let second = receipts.acquire(2, 20, 2048).unwrap();
        assert!(receipts.acquire(1, 30, 1).is_none());
        let stream_id = P2pStreamId::new(1, 4, StreamProtocol::GossipSubV13, false);
        first.written(stream_id);
        drop(first);
        assert!(receipts.acquire(1, 30, 1).is_none(), "undrained feedback reserves its capacity");
        let result = receipts.pop().unwrap();
        assert_eq!(result.frame_seq, 10);
        assert_eq!(result.outcome, GossipFrameOutcome::Written { stream_id });
        drop(second);
        let result = receipts.pop().unwrap();
        assert_eq!(result.p2p_peer, 2);
        assert_eq!(result.frame_seq, 20);
        assert_eq!(result.outcome, GossipFrameOutcome::Dropped);
        assert!(receipts.peers.borrow().is_empty());
        assert_eq!(receipts.pending.get(), 0);
    }

    #[test]
    fn peer_byte_limit_does_not_block_other_peers() {
        let receipts = Box::new(SendReceipts::new(4));
        let first = receipts.acquire(1, 1, MAX_PEER_BYTES).unwrap();
        assert!(receipts.acquire(1, 2, 1).is_none());
        let second = receipts.acquire(2, 3, 1).unwrap();
        drop(first);
        drop(second);
        assert!(receipts.peers.borrow().is_empty());
    }
}
