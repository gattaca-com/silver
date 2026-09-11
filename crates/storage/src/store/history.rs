use std::{sync::Arc, time::Instant};

use fxhash::FxHashMap;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    DataKind, PREFILL_SLOTS, PeerEvent, Prefill, RpcSeverity, SyncNeed, TRead, merkle::B256,
    ssz_view::MAX_PAYLOAD_SIZE,
};

use super::{
    COLUMN_SLOTS_RETAINED, Head, Payload, PendingWrite, WriteQueue,
    backfill::{self, BlockFacts, Pending, VerifiedColumns},
    coverage::{self, Block, Floors},
    finalized::Finalized,
    unfinalized::UnfinalizedBlocks,
};
use crate::tile::IoEvent;

const MAX_BUFFERED_BLOCKS: usize = 128;

/// Blocks served for backfill, buffered until the chain reaches them. Peers
/// serve a range lowest slot first; the chain links top-down.
#[derive(Default)]
struct Linker {
    buffered: FxHashMap<B256, (BlockFacts, TRead)>,
}

impl Linker {
    /// Peers serve a range bottom-up, so the block the chain reaches first is
    /// the highest buffered. A full buffer sheds the lowest, which links last.
    fn buffer(&mut self, facts: BlockFacts, ssz: TRead) {
        if self.buffered.len() >= MAX_BUFFERED_BLOCKS {
            let lowest = self
                .buffered
                .iter()
                .min_by_key(|(_, (facts, _))| facts.slot)
                .map(|(root, _)| *root)
                .expect("a full buffer is not empty");
            self.buffered.remove(&lowest);
            tracing::warn!(held = self.buffered.len(), "backfill blocks not linking; dropping one");
        }
        self.buffered.insert(facts.block_root, (facts, ssz));
    }

    fn take(&mut self, wanted: &B256) -> Option<(BlockFacts, TRead)> {
        self.buffered.remove(wanted)
    }

    fn retain_range(&mut self, start: u64, end: u64) {
        self.buffered.retain(|_, (facts, _)| (start..end).contains(&facts.slot));
    }
}

pub(super) struct History {
    spec: Arc<SpecConfig>,
    linker: Linker,
    pending: Pending,
    /// (coverage version, finalized slot, following) of the last step. Nothing
    /// a step publishes can change unless one of these did.
    walked: Option<(u64, u64, bool)>,
    /// The same coverage re-derives to the same message and says nothing.
    published: Option<Prefill>,
    claimed: Option<u64>,
    /// Reused for the block reads that seed a window. Sized for the largest
    /// block the wire allows, so no read ever grows it.
    block_scratch: Vec<u8>,
}

impl History {
    pub(super) fn new(spec: Arc<SpecConfig>) -> Self {
        Self {
            spec,
            linker: Linker::default(),
            pending: Pending::new(),
            walked: None,
            published: None,
            claimed: None,
            block_scratch: Vec::with_capacity(MAX_PAYLOAD_SIZE),
        }
    }

    fn floors(&self, finalized_slot: u64) -> Floors {
        let epoch = finalized_slot / SLOTS_PER_EPOCH;
        Floors {
            blocks: finalized_slot
                .saturating_sub(Payload::Block.slots_retained(&self.spec, epoch))
                .max(1),
            columns: finalized_slot.saturating_sub(COLUMN_SLOTS_RETAINED).max(1),
            envelopes: self.spec.gloas_fork_slot(),
        }
    }

    /// One step of the walk: the claim, then either one group read or the
    /// next window missing something, each published only when it moved.
    pub(super) fn step(
        &mut self,
        head: Head,
        following: bool,
        store_dir: &str,
        finalized: &mut Finalized,
        unfinalized: &UnfinalizedBlocks,
        emit: &mut impl FnMut(IoEvent),
    ) {
        let walk = (finalized.coverage().version(), head.finalized_slot, following);
        if self.walked == Some(walk) {
            return;
        }
        self.walked = Some(walk);

        let floors = self.floors(head.finalized_slot);
        let missing_from = floors.lowest_missing(finalized.custody());
        if let Some(claim) = self.claim(finalized, head.finalized_slot, missing_from) {
            emit(IoEvent::PeerEvent(PeerEvent::EarliestSlot(claim)));
        }
        if !following {
            return;
        }
        if finalized.coverage().unexamined_above(missing_from) {
            // One group per step, so nothing is published or claimed from the
            // index alone while a group that could need is still unread.
            let finalized_block = finalized.slot_of(&head.finalized_root).map(|slot| {
                (slot, unfinalized.child_payload_parent(head.slot, head.root, &head.finalized_root))
            });
            finalized.examine_next_group(
                floors,
                &self.spec,
                store_dir,
                finalized_block,
                &mut self.block_scratch,
            );
            return;
        }
        let Some(end) = finalized.coverage().next_window_end(floors, head.finalized_slot) else {
            return;
        };
        let start = coverage::window_start(end);
        let (prefill, needs) = finalized.describe(start, floors, head.finalized_slot);
        // A window missing nothing is one whose entry a queued truncation is
        // about to prune.
        if !needs || self.published == Some(prefill) {
            return;
        }
        if self.published.is_none_or(|last| last.start != start) {
            self.seed_window(&prefill, store_dir, finalized);
        }
        self.published = Some(prefill);
        emit(IoEvent::Need(SyncNeed::BackfillPrefill(prefill)));
    }

    /// The slot we may tell peers we serve from, when it moved. Custodying
    /// columns holds it at the column window, since every kind we serve must
    /// be there.
    fn claim(
        &mut self,
        finalized: &Finalized,
        finalized_slot: u64,
        missing_from: u64,
    ) -> Option<u64> {
        let epoch = finalized_slot / SLOTS_PER_EPOCH;
        let retained = match finalized.custody() {
            0 => Payload::Block.slots_retained(&self.spec, epoch),
            _ => COLUMN_SLOTS_RETAINED,
        };
        let floor = finalized_slot.saturating_sub(retained).max(1);
        let claim = finalized.coverage().claim(finalized_slot, floor, missing_from);
        (self.claimed != Some(claim)).then(|| {
            self.claimed = Some(claim);
            claim
        })
    }

    /// Only blocks still missing something are read, at most one window's
    /// worth, when the walk turns to it. Blocks buffered for the last
    /// window were not asked for in this one.
    fn seed_window(&mut self, prefill: &Prefill, store_dir: &str, finalized: &Finalized) {
        let end = prefill.start + PREFILL_SLOTS;
        self.linker.retain_range(prefill.start, end);
        self.pending.retain_range(prefill.start, end);

        let missing = prefill.have_block & !(prefill.columns_covered & prefill.envelopes);
        let mut block = std::mem::take(&mut self.block_scratch);
        for offset in 0..PREFILL_SLOTS {
            if missing & (1u32 << offset) == 0 {
                continue;
            }
            let slot = prefill.start + offset;
            if !coverage::read_block(store_dir, slot, &mut block) {
                tracing::error!(slot, "held block unreadable; its columns stay missing");
                continue;
            }
            self.seed_pending(slot, &block, finalized);
        }
        self.block_scratch = block;
    }
    pub(super) fn seed_pending(&mut self, slot: u64, block: &[u8], finalized: &Finalized) {
        let is_gloas = self.spec.is_gloas_at_slot(slot);
        let missing = finalized.coverage().columns_missing(slot);
        let envelope = is_gloas && finalized.coverage().envelope_missing(slot);
        self.pending.seed_block(slot, block, is_gloas, missing, envelope);
    }

    /// Every served block waits for the chain to reach it, held or not: one
    /// already on disk is re-served only when coverage fell behind the disk,
    /// and it relinks through the same write. A block outside the window was
    /// not asked for.
    pub(super) fn backfill_block(
        &mut self,
        ssz: TRead,
        head: Head,
        finalized: &Finalized,
        unfinalized: &UnfinalizedBlocks,
        write_queue: &mut WriteQueue,
    ) {
        let facts = match ssz.buffer() {
            Ok((buffer, _)) => BlockFacts::of(buffer, &self.spec),
            Err(e) => {
                tracing::error!(?e, "failed to read backfill beacon block cache buffer");
                None
            }
        };
        let Some(facts) = facts else { return };
        if let Some(window) = self.published &&
            !(window.start..window.start + PREFILL_SLOTS).contains(&facts.slot)
        {
            tracing::debug!(
                slot = facts.slot,
                window = window.start,
                "backfill block outside the window"
            );
            return;
        }
        self.linker.buffer(facts, ssz);
        self.link_buffered_blocks(head, finalized, unfinalized, write_queue);
    }

    /// Queue every held block the chain reaches from what it wants. Run on
    /// arrival and once per step: a block waiting on a write that has since
    /// landed links on the next pass.
    pub(super) fn link_buffered_blocks(
        &mut self,
        head: Head,
        finalized: &Finalized,
        unfinalized: &UnfinalizedBlocks,
        write_queue: &mut WriteQueue,
    ) {
        if write_queue.landing() != 0 || self.linker.buffered.is_empty() {
            return;
        }
        let coverage = finalized.coverage();
        let anchor = coverage.wanted_parent(head.finalized_slot).unwrap_or(head.finalized_root);
        let mut child_payload = coverage
            .child_payload(anchor)
            .or_else(|| unfinalized.child_payload_parent(head.slot, head.root, &anchor));
        let mut wanted = anchor;
        while let Some((facts, ssz)) = self.linker.take(&wanted) {
            let needs = facts.needs(&self.spec, child_payload);
            let block = Block::new(facts, needs, head.finalized_slot, head.finalized_root);
            write_queue.push_back(PendingWrite::BackfillBlock { block, ssz });
            child_payload = Some(facts.payload.parent_payload_hash);
            wanted = facts.parent_root;
        }
    }

    pub(super) fn backfill_envelope(
        &mut self,
        signed: TRead,
        finalized: &Finalized,
        write_queue: &mut WriteQueue,
        emit: &mut impl FnMut(IoEvent),
    ) {
        let Ok((buffer, _)) = signed.buffer() else {
            tracing::error!("failed to read backfill envelope cache buffer");
            return;
        };
        let Some(block_root) = backfill::envelope_block_root(buffer) else {
            tracing::warn!("badly formed backfill envelope");
            return;
        };
        let Some(slot) = finalized.slot_of(&block_root) else { return };
        if !finalized.coverage().envelope_missing(slot) {
            emit(IoEvent::Need(finalized.persisted(DataKind::Envelope, slot, None)));
            return;
        }
        if self.pending.add_envelope(buffer, slot) {
            write_queue.push_back(PendingWrite::BackfillEnvelope { slot, ssz: signed });
        }
    }

    pub(super) fn backfill_data_column(
        &mut self,
        sidecar: TRead,
        peer: usize,
        now: Instant,
        finalized: &Finalized,
        emit: &mut impl FnMut(IoEvent),
    ) -> Option<VerifiedColumns> {
        let head = match sidecar.buffer() {
            Ok((buffer, _)) => backfill::sidecar_head(buffer),
            Err(e) => {
                tracing::error!(?e, "failed to read backfill data column sidecar cache buffer");
                return None;
            }
        };
        let Some(head) = head else {
            tracing::warn!("badly formed backfill data column sidecar");
            return None;
        };
        let slot = finalized.slot_of(&head.block_root)?;
        if finalized.coverage().columns_missing(slot) == 0 {
            emit(IoEvent::Need(finalized.persisted(DataKind::Columns, slot, None)));
            return None;
        }

        let (verified, rejected) =
            self.pending.add_sidecar(sidecar, head, slot, peer, now, &self.spec);
        for bad in rejected {
            tracing::warn!(
                peer = bad.peer,
                column_index = bad.column_index,
                "backfill sidecar rejected"
            );
            emit(IoEvent::PeerEvent(PeerEvent::RpcMisbehaviour {
                p2p_peer: bad.peer,
                severity: RpcSeverity::Fatal,
            }));
        }
        verified
    }

    pub(super) fn expire(&mut self, now: Instant) {
        self.pending.expire_incomplete(now);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use silver_common::{TCache, TCacheProducer, column_util};

    use super::*;
    use crate::store::backfill::fixtures::{GLOAS_FORK_SLOT, block_bytes, spec};

    /// A gloas-era block links only if its root is computed with the gloas body
    /// layout: the wanted parent comes from the child's `parent_root` field, so
    /// a fulu-layout root here never matches and the chain stalls silently.
    #[test]
    fn gloas_block_links_by_its_gloas_root() {
        let block = block_bytes(GLOAS_FORK_SLOT, [0xCC; 32]);
        let gloas_root = column_util::block_root(&block, true);
        let fulu_root = column_util::block_root_fulu(&block);
        assert_ne!(gloas_root, fulu_root, "layouts must disagree for this to mean anything");

        let mut producer = TCache::producer("backfill_gloas_link", 1 << 20);
        let mut res = producer.reserve(block.len(), true).unwrap();
        res.write_all(&block).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        // Declared before the queue so parked reads drop first (their release
        // dereferences the consumer).
        let mut consumer =
            producer.cache_ref().random_access("backfill_gloas_link_cons", true).unwrap();

        // Nothing held, so the finalized root is the anchor the block must be.
        for (anchor, links) in [(gloas_root, true), (fulu_root, false)] {
            let mut linker = Linker::default();
            let facts = BlockFacts::of(&block, &spec()).expect("well formed");
            linker.buffer(facts, consumer.acquire(ssz));
            assert_eq!(linker.take(&anchor).is_some(), links, "taken for writing iff linked");
        }
    }
}
