use std::{collections::VecDeque, ops::Range};

use flux::timing::{Duration, Instant};
use fxhash::FxHashMap;
use silver_common::{
    PeerEvent,
    RpcRequest::BlocksByRange,
    TRead,
    ssz_hash::B256,
    ssz_view::{BLOCKS_BY_RANGE_REQ_SIZE, SignedBeaconBlockView},
};

use crate::{
    store::{MAX_REQUEST_BLOCKS, PendingWrite},
    tile::BACKFILL_REQUEST_ID,
    util,
};

pub(super) struct Backfill {
    range: Range<u64>,
    // buffered blocks keyed by block root
    buffered_blocks: FxHashMap<B256, (u64, B256, TRead)>,
    next_parent: B256,
    request_id: u64,
    in_flight: Option<(Range<u64>, u64, Instant)>,
    earliest_written: u64,
}

impl Backfill {
    pub(super) fn new(range: Range<u64>, next_parent: B256) -> Self {
        Self {
            earliest_written: range.end + 1,
            range,
            buffered_blocks: FxHashMap::with_capacity_and_hasher(
                MAX_REQUEST_BLOCKS as usize,
                Default::default(),
            ),
            next_parent,
            request_id: BACKFILL_REQUEST_ID,
            in_flight: None,
        }
    }

    pub(super) fn start<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        self.range_request(emit);
    }

    pub(super) fn add_block(&mut self, ssz: TRead, write_queue: &mut VecDeque<PendingWrite>) {
        // is this the next parent block we are waiting for?
        let buffer = match ssz.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, "failed to read backfill beacon block cache buffer");
                return;
            }
        };

        let new_block_root = util::block_root(buffer);
        let slot = SignedBeaconBlockView::slot(buffer);
        let new_parent_root = *SignedBeaconBlockView::parent_root(buffer);

        self.buffered_blocks.insert(new_block_root, (slot, new_parent_root, ssz));

        while let Some((slot, parent_root, ssz)) = self.buffered_blocks.remove(&self.next_parent) {
            write_queue.push_back(PendingWrite::BackfillBlock { slot, ssz });
            self.earliest_written = self.earliest_written.min(slot);
            self.next_parent = parent_root;
        }
    }

    /// Returns `true` if backfilling is complete.
    pub(super) fn query_complete<F>(&mut self, id: u64, emit: &mut F) -> bool
    where
        F: FnMut(PeerEvent),
    {
        if self.in_flight.as_ref().map(|(_, request_id, _)| *request_id != id).unwrap_or_default() {
            return false;
        }
        if let Some((in_flight, _, _)) = self.in_flight.take() {
            if self.earliest_written < in_flight.end {
                // the previous request returned something,
                self.range.end = self.earliest_written.max(in_flight.start);
                emit(PeerEvent::EarliestSlot(self.earliest_written));
            }
        }
        if self.range.end == self.range.start {
            tracing::info!("backfill complete");
            return true;
        }
        self.buffered_blocks.clear();
        self.range_request(emit);
        false
    }

    pub(super) fn tick<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        if let Some((_, request_id, start)) = self.in_flight.as_ref() {
            if start.elapsed() > Duration::from_secs(10) {
                self.query_complete(*request_id, emit);
            }
        }
    }

    fn range_request<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let next_start_slot =
            (self.range.end.saturating_sub(MAX_REQUEST_BLOCKS)).max(self.range.start);
        let count = self.range.end - next_start_slot;
        let request_id = self.request_id;
        self.request_id += 1;

        let mut request = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        request[..8].copy_from_slice(&next_start_slot.to_le_bytes());
        request[8..16].copy_from_slice(&count.to_le_bytes());
        request[16..].copy_from_slice(&1u64.to_le_bytes());

        emit(PeerEvent::SendRpcRequest { request_id, rpc: BlocksByRange(request) });
        self.in_flight =
            Some((next_start_slot..next_start_slot + count, request_id, Instant::now()));
    }
}
