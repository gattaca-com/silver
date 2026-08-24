use std::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry},
    ops::Range,
    sync::Arc,
};

use fxhash::FxHashMap;
use silver_beacon_state_data::SpecConfig;
use silver_common::{
    DataKind, SyncNeed, TRead, column_util,
    merkle::B256,
    ssz_view::{
        DataColumnSidecarFuluView, DataColumnSidecarGloasView, EXECUTION_PAYLOAD_FIXED_GLOAS,
        ExecutionPayloadBidView, ExecutionPayloadEnvelopeView, ExecutionPayloadView,
        NUMBER_OF_COLUMNS, SidecarLayout, SignedBeaconBlockView,
        SignedExecutionPayloadEnvelopeView,
    },
};

use crate::store::PendingWrite;

/// Block-history backfill **tracker**. Issuance moved to the control-tile
/// `SyncEngine`; storage reports the gap via `PeerEvent::BackfillState` and
/// here only links + writes arriving blocks and detects completion (the chain
/// has been filled down to the gap floor).
pub(super) struct Backfill {
    range: Range<u64>,
    spec: Arc<SpecConfig>,
    // buffered blocks keyed by block root
    buffered_blocks: FxHashMap<B256, (u64, B256, TRead)>,
    next_parent: B256,
    earliest_written: u64,
    blocks_complete: bool,
}

pub(super) struct AcceptedColumn {
    pub(super) block_root: B256,
    pub(super) slot: u64,
    pub(super) column_index: u64,
}

impl Backfill {
    pub(super) fn new(range: Range<u64>, next_parent: B256, spec: Arc<SpecConfig>) -> Self {
        let earliest_written = range.end;
        Self {
            range,
            spec,
            buffered_blocks: FxHashMap::default(),
            next_parent,
            earliest_written,
            blocks_complete: false,
        }
    }

    pub(super) fn floor(&self) -> u64 {
        self.range.start
    }

    pub(super) fn earliest_written(&self) -> u64 {
        self.earliest_written
    }

    /// Link an arriving backfill block to the chain and queue it for write.
    /// Blocks arrive child-first; each links to `next_parent` and drains the
    /// buffer downward. Complete once the chain reaches the gap floor.
    pub(super) fn add_block<F>(
        &mut self,
        ssz: TRead,
        write_queue: &mut VecDeque<PendingWrite>,
        emit: &mut F,
    ) where
        F: FnMut(SyncNeed),
    {
        let buffer = match ssz.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, "failed to read backfill beacon block cache buffer");
                return;
            }
        };
        if !SignedBeaconBlockView::check_size(buffer) {
            tracing::warn!(len = buffer.len(), "backfill block has invalid size");
            return;
        }

        let slot = SignedBeaconBlockView::slot(buffer);
        let new_block_root = column_util::block_root(buffer, self.spec.is_gloas_at_slot(slot));
        let new_parent_root = *SignedBeaconBlockView::parent_root(buffer);

        self.buffered_blocks.insert(new_block_root, (slot, new_parent_root, ssz));

        while let Some((slot, parent_root, ssz)) = self.buffered_blocks.remove(&self.next_parent) {
            let block_root = self.next_parent;
            write_queue.push_back(PendingWrite::BackfillBlock { block_root, slot, ssz });
            self.earliest_written = self.earliest_written.min(slot);
            self.next_parent = parent_root;
            emit(SyncNeed::Arrived { root: block_root, slot, kind: DataKind::Block });
        }

        if self.earliest_written <= self.range.start {
            self.blocks_complete = true;
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        self.blocks_complete
    }
}

/// Data-column backfill **tracker**, independent of block backfill. Seeded by
/// an on-disk scan of persisted blocks in the column-retention window (set 1)
/// and by block backfill pulling blob-carrying blocks in (set 2). Both report
/// one span — the slots still owed — which the `SyncEngine` sweeps by range.
/// Storage tracks per-block completeness (it sees the sidecars) and drops a
/// block from the span once its columns are all on disk.
pub(super) struct ColumnBackfill {
    range: Range<u64>,
    // Every block awaiting columns, keyed by block root.
    pending: FxHashMap<B256, PendingColumnBlock>,
    /// The slots `pending` covers, for the span the range walk sweeps.
    owed_slots: BTreeSet<u64>,
    scan_complete: bool,
}

struct PendingColumnBlock {
    slot: u64,
    expect: Expect,
    requested: u128,
    received: u128,
}

enum Expect {
    Fulu {
        proposer_index: u64,
        parent_root: B256,
        state_root: B256,
        body_root: B256,
        signature: [u8; 96],
    },
    Gloas {
        commitments: Box<[u8]>,
    },
}

impl Expect {
    fn layout(&self) -> SidecarLayout {
        match self {
            Self::Fulu { .. } => SidecarLayout::Fulu,
            Self::Gloas { .. } => SidecarLayout::Gloas,
        }
    }
}

impl PendingColumnBlock {
    fn accepts(&self, layout: SidecarLayout, sidecar: &[u8]) -> bool {
        match (&self.expect, layout) {
            (
                Expect::Fulu { proposer_index, parent_root, state_root, body_root, signature },
                SidecarLayout::Fulu,
            ) => {
                column_util::verify_data_column_sidecar_fulu(sidecar) &&
                    column_util::verify_data_column_sidecar_kzg_proofs_fulu(sidecar) &&
                    column_util::verify_data_column_sidecar_inclusion_proof(sidecar) &&
                    DataColumnSidecarFuluView::slot(sidecar) == self.slot &&
                    DataColumnSidecarFuluView::proposer_index(sidecar) == *proposer_index &&
                    DataColumnSidecarFuluView::parent_root(sidecar) == parent_root &&
                    DataColumnSidecarFuluView::state_root(sidecar) == state_root &&
                    DataColumnSidecarFuluView::body_root(sidecar) == body_root &&
                    DataColumnSidecarFuluView::block_signature(sidecar) == signature
            }
            (Expect::Gloas { commitments }, SidecarLayout::Gloas) => {
                column_util::verify_data_column_sidecar_gloas(sidecar, commitments) &&
                    column_util::verify_data_column_sidecar_kzg_proofs_gloas(
                        sidecar,
                        commitments,
                    ) &&
                    DataColumnSidecarGloasView::slot(sidecar) == self.slot
            }
            _ => {
                tracing::error!(
                    slot = self.slot,
                    expected = ?self.expect.layout(),
                    served = ?layout,
                    "backfill sidecar layout disagrees with the block's fork"
                );
                false
            }
        }
    }
}

impl ColumnBackfill {
    pub(super) fn new(range: Range<u64>) -> Self {
        Self {
            range,
            pending: FxHashMap::default(),
            owed_slots: BTreeSet::new(),
            scan_complete: false,
        }
    }

    /// Seed a block found by the disk scan / block backfill. `missing` is the
    /// custody columns not already on disk; reports the need to the engine.
    pub(super) fn seed_block(
        &mut self,
        block_root: B256,
        slot: u64,
        block: &[u8],
        missing: u128,
        spec: &SpecConfig,
    ) {
        if missing == 0 || !self.range.contains(&slot) || self.pending.contains_key(&block_root) {
            return;
        }

        let expect = if spec.is_gloas_at_slot(slot) {
            Expect::Gloas {
                commitments: SignedBeaconBlockView::gloas_block_commitments(block).into(),
            }
        } else {
            Expect::Fulu {
                proposer_index: SignedBeaconBlockView::proposer_index(block),
                parent_root: *SignedBeaconBlockView::parent_root(block),
                state_root: *SignedBeaconBlockView::state_root(block),
                body_root: column_util::body_root(SignedBeaconBlockView::body(block)),
                signature: *SignedBeaconBlockView::signature(block),
            }
        };
        self.pending.insert(block_root, PendingColumnBlock {
            slot,
            expect,
            requested: missing,
            received: 0,
        });
        self.owed_slots.insert(slot);
    }

    pub(super) fn servable_floor(&self) -> u64 {
        self.range.start.max(self.owed_span().1)
    }

    pub(super) fn owed_span(&self) -> (u64, u64) {
        match (self.owed_slots.first(), self.owed_slots.last()) {
            (Some(&lowest), Some(&highest)) => (lowest, highest + 1),
            _ => (0, 0),
        }
    }

    /// Validate + record a received backfill sidecar. On the block's final
    /// column, clears the need (`ColumnNeed { missing: 0 }`).
    pub(super) fn add_sidecar<F>(&mut self, sidecar: &TRead, emit: &mut F) -> Option<AcceptedColumn>
    where
        F: FnMut(SyncNeed),
    {
        let buffer = match sidecar.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, "failed to read backfill data column sidecar cache buffer");
                return None;
            }
        };

        let Some(layout) = SidecarLayout::of(buffer) else {
            tracing::warn!("backfill data column sidecar matches no known layout");
            return None;
        };

        let well_sized = match layout {
            SidecarLayout::Fulu => DataColumnSidecarFuluView::check_size(buffer),
            SidecarLayout::Gloas => DataColumnSidecarGloasView::check_size(buffer),
        };
        let column_index = match layout {
            SidecarLayout::Fulu => DataColumnSidecarFuluView::index(buffer),
            SidecarLayout::Gloas => DataColumnSidecarGloasView::index(buffer),
        };
        if !well_sized || column_index >= NUMBER_OF_COLUMNS as u64 {
            tracing::warn!(?layout, "badly formed backfill data column sidecar");
            return None;
        }

        // Fulu derives the root by hashing the header it carries; gloas states
        // it outright and is bound to the block by its KZG proofs instead.
        let block_root = match layout {
            SidecarLayout::Fulu => column_util::block_root_from_sidecar(buffer),
            SidecarLayout::Gloas => *DataColumnSidecarGloasView::beacon_block_root(buffer),
        };
        let column_bitmask = 1u128 << column_index;
        let (slot, complete) = {
            let expected = match self.pending.get_mut(&block_root) {
                Some(expected) => expected,
                None => {
                    tracing::warn!(
                        block_root = hex::encode(block_root),
                        "unrequested backfill data column sidecar"
                    );
                    return None;
                }
            };
            if expected.requested & column_bitmask == 0 {
                tracing::warn!(column_index, "backfill sidecar column was not requested");
                return None;
            }
            if expected.received & column_bitmask != 0 {
                return None;
            }
            if !expected.accepts(layout, buffer) {
                tracing::warn!(
                    block_root = hex::encode(block_root),
                    column_index,
                    ?layout,
                    "backfill sidecar does not verify against its block"
                );
                return None;
            }

            expected.received |= column_bitmask;
            let complete = expected.received & expected.requested == expected.requested;
            (expected.slot, complete)
        };

        if complete {
            self.retire(block_root, slot, emit);
        }

        Some(AcceptedColumn { block_root, slot, column_index })
    }

    fn retire<F>(&mut self, block_root: B256, slot: u64, emit: &mut F)
    where
        F: FnMut(SyncNeed),
    {
        self.pending.remove(&block_root);
        self.owed_slots.remove(&slot);
        emit(SyncNeed::Arrived { root: block_root, slot, kind: DataKind::Columns });
    }

    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(super) fn is_complete(&self) -> bool {
        self.scan_complete && self.pending.is_empty()
    }

    pub(super) fn mark_scan_complete(&mut self) {
        self.scan_complete = true;
    }
}

pub(super) struct EnvelopeBackfill {
    range: Range<u64>,
    pending: BTreeMap<u64, PendingEnvelope>,
    scan_complete: bool,
}

struct PendingEnvelope {
    block_root: B256,
    builder_index: u64,
    prev_randao: B256,
    gas_limit: u64,
    block_hash: B256,
}

impl EnvelopeBackfill {
    pub(super) fn new(range: Range<u64>) -> Self {
        Self { range, pending: BTreeMap::new(), scan_complete: false }
    }

    pub(super) fn seed_block(&mut self, block_root: B256, slot: u64, block: &[u8]) {
        if !self.range.contains(&slot) {
            return;
        }
        let Entry::Vacant(entry) = self.pending.entry(slot) else {
            return;
        };
        let Some(bid) = SignedBeaconBlockView::gloas_bid(block) else {
            return;
        };

        entry.insert(PendingEnvelope {
            block_root,
            builder_index: ExecutionPayloadBidView::builder_index(bid),
            prev_randao: *ExecutionPayloadBidView::prev_randao(bid),
            gas_limit: ExecutionPayloadBidView::gas_limit(bid),
            block_hash: *ExecutionPayloadBidView::block_hash(bid),
        });
    }

    /// The lowest slot this walk has the envelope for.
    pub(super) fn servable_floor(&self) -> u64 {
        self.range.start.max(self.owed_span().map_or(0, |(_, above)| above))
    }

    pub(super) fn owed_span(&self) -> Option<(u64, u64)> {
        let (&lowest, _) = self.pending.first_key_value()?;
        let (&highest, _) = self.pending.last_key_value()?;
        Some((lowest, highest + 1))
    }

    pub(super) fn add_envelope(
        &mut self,
        signed: &TRead,
        root_index: &FxHashMap<B256, u64>,
    ) -> Option<(B256, u64)> {
        let buffer = match signed.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, "failed to read backfill envelope cache buffer");
                return None;
            }
        };
        if !SignedExecutionPayloadEnvelopeView::check_size(buffer) {
            tracing::warn!("badly formed backfill envelope");
            return None;
        }

        let envelope = SignedExecutionPayloadEnvelopeView::message(buffer);
        if !ExecutionPayloadEnvelopeView::check_size(envelope) {
            tracing::warn!("backfill envelope message has invalid size");
            return None;
        }
        let block_root = *ExecutionPayloadEnvelopeView::beacon_block_root(envelope);
        let Some((&slot, expected)) = root_index
            .get(&block_root)
            .and_then(|slot| self.pending.get_key_value(slot))
            .filter(|(_, expected)| expected.block_root == block_root)
        else {
            tracing::warn!(block_root = hex::encode(block_root), "unrequested backfill envelope");
            return None;
        };
        if !expected.matches_bid(envelope) {
            tracing::warn!(
                block_root = hex::encode(block_root),
                "backfill envelope does not match its block's bid"
            );
            return None;
        }

        self.pending.remove(&slot);
        Some((block_root, slot))
    }

    pub(super) fn is_complete(&self) -> bool {
        self.scan_complete && self.pending.is_empty()
    }

    pub(super) fn mark_scan_complete(&mut self) {
        self.scan_complete = true;
    }
}

impl PendingEnvelope {
    fn matches_bid(&self, envelope: &[u8]) -> bool {
        let payload = ExecutionPayloadEnvelopeView::payload(envelope);
        if payload.len() < EXECUTION_PAYLOAD_FIXED_GLOAS {
            return false;
        }
        ExecutionPayloadEnvelopeView::builder_index(envelope) == self.builder_index &&
            *ExecutionPayloadView::prev_randao(payload) == self.prev_randao &&
            ExecutionPayloadView::gas_limit(payload) == self.gas_limit &&
            *ExecutionPayloadView::block_hash(payload) == self.block_hash
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use silver_beacon_state_data::SLOTS_PER_EPOCH;
    use silver_common::{TCache, TCacheProducer};

    use super::*;

    const GLOAS_FORK_EPOCH: u64 = 1;
    const GLOAS_FORK_SLOT: u64 = GLOAS_FORK_EPOCH * SLOTS_PER_EPOCH;

    fn spec() -> Arc<SpecConfig> {
        crate::store::test_spec(GLOAS_FORK_EPOCH)
    }

    /// Synthetic `SignedBeaconBlock`: message at 100, slot at [100..108),
    /// parent_root at [116..148), body at 184.
    fn block_bytes(slot: u64, parent_root: B256) -> Vec<u8> {
        let mut b = vec![0u8; 784];
        b[0..4].copy_from_slice(&100u32.to_le_bytes());
        b[100..108].copy_from_slice(&slot.to_le_bytes());
        b[116..148].copy_from_slice(&parent_root);
        b[180..184].copy_from_slice(&84u32.to_le_bytes());
        b
    }

    /// Gloas block carrying `commitments` in its bid: body offsets place a
    /// `SignedExecutionPayloadBid` (fixed 100 + bid fixed 224 + commitments)
    /// between `signed_execution_payload_bid_offset` and
    /// `payload_attestations_offset`.
    fn gloas_block_bytes(slot: u64, commitments: &[u8]) -> Vec<u8> {
        const BODY_FIXED: usize = 396;
        const BID_FIXED: usize = 224;

        let mut bid = vec![0u8; BID_FIXED];
        bid[188..192].copy_from_slice(&(BID_FIXED as u32).to_le_bytes());
        bid[64..96].copy_from_slice(&BID_BLOCK_HASH); // block_hash
        bid[96..128].copy_from_slice(&BID_PREV_RANDAO); // prev_randao
        bid[148..156].copy_from_slice(&BID_GAS_LIMIT.to_le_bytes()); // gas_limit
        bid[156..164].copy_from_slice(&BID_BUILDER_INDEX.to_le_bytes()); // builder_index
        bid.extend_from_slice(commitments);

        let mut signed_bid = vec![0u8; 100];
        signed_bid[0..4].copy_from_slice(&100u32.to_le_bytes());
        signed_bid.extend_from_slice(&bid);

        let mut body = vec![0u8; BODY_FIXED];
        let after_bid = BODY_FIXED + signed_bid.len();
        for at in [200usize, 204, 208, 212, 216, 380] {
            body[at..at + 4].copy_from_slice(&(BODY_FIXED as u32).to_le_bytes());
        }
        body[384..388].copy_from_slice(&(BODY_FIXED as u32).to_le_bytes());
        for at in [388usize, 392] {
            body[at..at + 4].copy_from_slice(&(after_bid as u32).to_le_bytes());
        }
        body.extend_from_slice(&signed_bid);

        let mut b = vec![0u8; 184];
        b[0..4].copy_from_slice(&100u32.to_le_bytes());
        b[100..108].copy_from_slice(&slot.to_le_bytes());
        b[180..184].copy_from_slice(&84u32.to_le_bytes());
        b.extend_from_slice(&body);
        b
    }

    /// A gloas-era block owes gloas sidecars, which carry no header — the bid's
    /// commitments are the only thing an arriving sidecar can be checked
    /// against, so seeding must extract them.
    #[test]
    fn gloas_seed_holds_the_bid_commitments() {
        let commitments: Vec<u8> = (0..96u8).map(|i| i.wrapping_add(1)).collect();
        let block = gloas_block_bytes(GLOAS_FORK_SLOT, &commitments);
        assert_eq!(
            SignedBeaconBlockView::gloas_block_commitments(&block),
            &commitments[..],
            "fixture must be a parseable gloas block"
        );

        let mut cb = ColumnBackfill::new(0..GLOAS_FORK_SLOT + 1);
        cb.seed_block([7u8; 32], GLOAS_FORK_SLOT, &block, 0b101, &spec());

        match &cb.pending.get(&[7u8; 32]).expect("pending").expect {
            Expect::Gloas { commitments: held } => assert_eq!(&held[..], &commitments[..]),
            Expect::Fulu { .. } => panic!("gloas-era block seeded with a fulu expectation"),
        }
        assert_eq!(
            cb.owed_span(),
            (GLOAS_FORK_SLOT, GLOAS_FORK_SLOT + 1),
            "and the block sits in the span the range walk sweeps"
        );
    }

    /// Clearing a block says one object landed, and that is all this walk
    /// reports: the span itself is published once per tick by the store, which
    /// is the only place that can see all three walks at once.
    #[test]
    fn retiring_a_block_reports_what_landed_and_shrinks_the_span() {
        let mut cb = ColumnBackfill::new(1..97);
        cb.seed_block([1u8; 32], 40, &block_bytes(40, [0; 32]), 0b1, &spec());
        cb.seed_block([2u8; 32], 50, &block_bytes(50, [0; 32]), 0b1, &spec());
        assert_eq!(cb.owed_span(), (40, 51));

        let mut arrived = Vec::new();
        let mut spans = 0;
        let mut collect = |need| match need {
            SyncNeed::Arrived { root, slot, kind } => arrived.push((root, slot, kind)),
            SyncNeed::BackfillGap { .. } => spans += 1,
            SyncNeed::Missing { .. } => {}
        };
        cb.retire([1u8; 32], 40, &mut collect);
        assert_eq!(cb.owed_span(), (50, 51), "the slot that cleared leaves the span");
        cb.retire([2u8; 32], 50, &mut collect);
        assert_eq!(cb.owed_span(), (0, 0), "and the last one empties it");

        assert_eq!(
            arrived,
            vec![([1u8; 32], 40, DataKind::Columns), ([2u8; 32], 50, DataKind::Columns),],
            "one report per block whose custody set completed"
        );
        assert_eq!(spans, 0, "the walk does not publish spans; the store does");
        assert_eq!(cb.servable_floor(), 1, "with nothing owed, the floor is the window's");
    }

    /// The two sidecar layouts are not interchangeable: the block's slot fixes
    /// which one is owed, so a mismatch is a reject rather than a fallback.
    #[test]
    fn sidecar_layout_must_match_the_pending_block() {
        let fulu = PendingColumnBlock {
            slot: 1,
            expect: Expect::Fulu {
                proposer_index: 0,
                parent_root: [0; 32],
                state_root: [0; 32],
                body_root: [0; 32],
                signature: [0; 96],
            },
            requested: 0b1,
            received: 0,
        };
        let gloas = PendingColumnBlock {
            slot: 1,
            expect: Expect::Gloas { commitments: Box::new([0u8; 48]) },
            requested: 0b1,
            received: 0,
        };

        // Contents are irrelevant: the layout arm is what refuses.
        assert!(!fulu.accepts(SidecarLayout::Gloas, &[0u8; 512]));
        assert!(!gloas.accepts(SidecarLayout::Fulu, &[0u8; 512]));
    }

    /// A gloas-era block links only if its root is computed with the gloas body
    /// layout: `next_parent` comes from the child's `parent_root` field, so a
    /// fulu-layout root here never matches and the chain stalls silently.
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

        for (anchor, links) in [(gloas_root, true), (fulu_root, false)] {
            let mut queue = VecDeque::new();
            let mut backfill = Backfill::new(GLOAS_FORK_SLOT..GLOAS_FORK_SLOT + 1, anchor, spec());
            backfill.add_block(consumer.acquire(ssz), &mut queue, &mut |_| {});

            assert_eq!(backfill.is_complete(), links, "anchored at {}", hex::encode(anchor));
            assert_eq!(queue.len(), usize::from(links), "queued for write iff linked");
            queue.clear();
        }
    }

    const BID_BLOCK_HASH: B256 = [0xB1; 32];
    const BID_PREV_RANDAO: B256 = [0xD1; 32];
    const BID_GAS_LIMIT: u64 = 30_000_000;
    const BID_BUILDER_INDEX: u64 = 77;

    /// `SignedExecutionPayloadEnvelope`: fixed 100B prefix, then the envelope —
    /// payload offset at [0..4), builder_index at [8..16), beacon_block_root at
    /// [16..48). The payload itself carries prev_randao/gas_limit/block_hash.
    fn envelope_bytes(block_root: B256, builder_index: u64, block_hash: B256) -> Vec<u8> {
        const ENVELOPE_FIXED: usize = 80;

        let mut payload = vec![0u8; EXECUTION_PAYLOAD_FIXED_GLOAS];
        payload[372..404].copy_from_slice(&BID_PREV_RANDAO);
        payload[412..420].copy_from_slice(&BID_GAS_LIMIT.to_le_bytes());
        payload[472..504].copy_from_slice(&block_hash);

        let mut envelope = vec![0u8; ENVELOPE_FIXED];
        envelope[0..4].copy_from_slice(&(ENVELOPE_FIXED as u32).to_le_bytes());
        envelope[4..8].copy_from_slice(&((ENVELOPE_FIXED + payload.len()) as u32).to_le_bytes());
        envelope[8..16].copy_from_slice(&builder_index.to_le_bytes());
        envelope[16..48].copy_from_slice(&block_root);
        envelope.extend_from_slice(&payload);

        let mut signed = vec![0u8; 100];
        signed[0..4].copy_from_slice(&100u32.to_le_bytes());
        signed.extend_from_slice(&envelope);
        signed
    }

    fn stage(producer: &mut silver_common::TProducer, bytes: &[u8]) -> silver_common::TCacheRead {
        let mut res = producer.reserve(bytes.len(), true).unwrap();
        res.write_all(bytes).unwrap();
        res.flush().unwrap();
        res.read()
    }

    /// The envelope carries no header, so its only tie to the block is the bid
    /// the block committed to. Reproducing it is what makes the payload ours.
    #[test]
    fn envelope_binds_to_its_blocks_bid() {
        const ROOT: B256 = [0x5A; 32];
        const SIBLING: B256 = [0xA5; 32];
        let block = gloas_block_bytes(GLOAS_FORK_SLOT, &[]);

        let mut producer = TCache::producer("envelope_backfill", 1 << 20);
        let good = stage(&mut producer, &envelope_bytes(ROOT, BID_BUILDER_INDEX, BID_BLOCK_HASH));
        let wrong_hash = stage(&mut producer, &envelope_bytes(ROOT, BID_BUILDER_INDEX, [0xFF; 32]));
        let wrong_builder = stage(&mut producer, &envelope_bytes(ROOT, 0, BID_BLOCK_HASH));
        let sibling =
            stage(&mut producer, &envelope_bytes(SIBLING, BID_BUILDER_INDEX, BID_BLOCK_HASH));
        let unknown =
            stage(&mut producer, &envelope_bytes([0x11; 32], BID_BUILDER_INDEX, BID_BLOCK_HASH));
        let mut consumer =
            producer.cache_ref().random_access("envelope_backfill_cons", true).unwrap();

        // Both roots resolve to the owed slot: the pending entry's own root is
        // what tells the sibling's envelope from the one we asked for.
        let root_index =
            FxHashMap::from_iter([(ROOT, GLOAS_FORK_SLOT), (SIBLING, GLOAS_FORK_SLOT)]);

        let mut eb = EnvelopeBackfill::new(0..GLOAS_FORK_SLOT + 1);
        eb.seed_block(ROOT, GLOAS_FORK_SLOT, &block);
        assert_eq!(
            eb.owed_span(),
            Some((GLOAS_FORK_SLOT, GLOAS_FORK_SLOT + 1)),
            "the block's slot is owed, as a span for the range walk"
        );
        assert!(!eb.is_complete(), "an owed envelope is not completion");

        for (envelope, why) in [
            (wrong_hash, "payload block_hash the bid did not commit to"),
            (wrong_builder, "another builder's payload"),
            (sibling, "another block persisted at the owed slot"),
            (unknown, "an envelope for a block we never asked about"),
        ] {
            assert_eq!(
                eb.add_envelope(&consumer.acquire(envelope), &root_index),
                None,
                "refuses {why}"
            );
        }
        assert!(eb.owed_span().is_some(), "a refusal leaves the slot owed");

        assert_eq!(
            eb.add_envelope(&consumer.acquire(good), &root_index),
            Some((ROOT, GLOAS_FORK_SLOT)),
            "accepted, and names what it accepted"
        );
        assert_eq!(eb.owed_span(), None, "acceptance closes the span");

        eb.mark_scan_complete();
        assert!(eb.is_complete(), "nothing left owed");
    }

    /// A pre-fork block has no bid, so nothing is owed and nothing is asked
    /// for.
    #[test]
    fn pre_fork_block_owes_no_envelope() {
        let mut eb = EnvelopeBackfill::new(0..GLOAS_FORK_SLOT + 1);
        eb.seed_block([1; 32], 1, &block_bytes(1, [0; 32]));
        assert_eq!(eb.owed_span(), None, "no bid, nothing owed");
    }
}
