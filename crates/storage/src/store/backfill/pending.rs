use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    MAX_BLOBS_PER_BLOCK, PREFILL_SLOTS, TRead,
    column_util::{self, KzgBatchEntry, KzgScratch},
    merkle::B256,
    ssz_view::{
        BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView, DataColumnSidecarGloasView,
        EXECUTION_PAYLOAD_FIXED_GLOAS, ExecutionPayloadBidView, ExecutionPayloadEnvelopeView,
        ExecutionPayloadView, NUMBER_OF_COLUMNS, SidecarLayout, SignedBeaconBlockView,
        SignedExecutionPayloadEnvelopeView,
    },
};

use crate::StorageCounters;

/// A custody set still incomplete this long after its first sidecar drops its
/// parked buffers, and every column is missing again. Shorter than the engine's
/// re-ask, so the re-ask finds them missing.
const INCOMPLETE_BLOCK_TIMEOUT: Duration = Duration::from_secs(25);

pub(in crate::store) struct VerifiedColumns {
    pub(in crate::store) slot: u64,
    pub(in crate::store) sidecars: Vec<ParkedSidecar>,
}

pub(in crate::store) struct ParkedSidecar {
    pub(in crate::store) column_index: u64,
    pub(in crate::store) ssz: TRead,
    pub(in crate::store) peer: usize,
}

/// Failed the per-sidecar fallback: the peer that served it is culpable.
pub(in crate::store) struct RejectedSidecar {
    pub(in crate::store) column_index: u64,
    pub(in crate::store) peer: usize,
}

/// What a sidecar says about itself before any check against a block.
pub(in crate::store) struct SidecarHead {
    pub(in crate::store) layout: SidecarLayout,
    pub(in crate::store) index: u64,
    pub(in crate::store) block_root: B256,
}

pub(in crate::store) fn sidecar_head(buffer: &[u8]) -> Option<SidecarHead> {
    let layout = SidecarLayout::of(buffer)?;
    let head = match layout {
        SidecarLayout::Fulu => DataColumnSidecarFuluView::check_size(buffer).then(|| SidecarHead {
            layout,
            index: DataColumnSidecarFuluView::index(buffer),
            block_root: column_util::block_root_from_sidecar(buffer),
        }),
        SidecarLayout::Gloas => {
            DataColumnSidecarGloasView::check_size(buffer).then(|| SidecarHead {
                layout,
                index: DataColumnSidecarGloasView::index(buffer),
                block_root: *DataColumnSidecarGloasView::beacon_block_root(buffer),
            })
        }
    }?;
    (head.index < NUMBER_OF_COLUMNS as u64).then_some(head)
}

pub(in crate::store) fn envelope_block_root(buffer: &[u8]) -> Option<B256> {
    if !SignedExecutionPayloadEnvelopeView::check_size(buffer) {
        return None;
    }
    let envelope = SignedExecutionPayloadEnvelopeView::message(buffer);
    ExecutionPayloadEnvelopeView::check_size(envelope)
        .then(|| *ExecutionPayloadEnvelopeView::beacon_block_root(envelope))
}

struct Commitments {
    bytes: [u8; MAX_BLOBS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT],
    len: usize,
}

impl Commitments {
    /// `None` for a list longer than any valid block carries.
    fn new(commitments: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; MAX_BLOBS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT];
        bytes.get_mut(..commitments.len())?.copy_from_slice(commitments);
        Some(Self { bytes, len: commitments.len() })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

struct Bid {
    builder_index: u64,
    prev_randao: B256,
    gas_limit: u64,
    block_hash: B256,
    commitments: Commitments,
}

impl Bid {
    fn of(block: &[u8]) -> Option<Self> {
        if !SignedBeaconBlockView::check_gloas_size(block) {
            return None;
        }
        let bid = SignedBeaconBlockView::gloas_bid(block);
        Some(Self {
            builder_index: ExecutionPayloadBidView::builder_index(bid),
            prev_randao: *ExecutionPayloadBidView::prev_randao(bid),
            gas_limit: ExecutionPayloadBidView::gas_limit(bid),
            block_hash: *ExecutionPayloadBidView::block_hash(bid),
            commitments: Commitments::new(ExecutionPayloadBidView::blob_kzg_commitments(bid))?,
        })
    }

    fn matches_envelope(&self, signed: &[u8]) -> bool {
        let envelope = SignedExecutionPayloadEnvelopeView::message(signed);
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

struct PendingBlock {
    /// Absent before gloas, where sidecars carry their own header.
    bid: Option<Bid>,
    requested: u128,
    received: u128,
    /// Sidecars that passed the per-sidecar checks, KZG deferred to the
    /// block's completion so the whole custody set is one pairing check.
    /// Holding the `TRead` keeps each buffer acquired until then.
    parked: Vec<ParkedSidecar>,
    first_parked_at: Option<Instant>,
    envelope: bool,
}

impl PendingBlock {
    fn done(&self) -> bool {
        self.requested == 0 && !self.envelope
    }

    fn accepts(&self, slot: u64, layout: SidecarLayout, sidecar: &[u8], spec: &SpecConfig) -> bool {
        let max_blobs = spec.blob_params_at(slot / SLOTS_PER_EPOCH).max_blobs_per_block as usize;
        match (&self.bid, layout) {
            (None, SidecarLayout::Fulu) => {
                column_util::verify_data_column_sidecar_fulu(sidecar, max_blobs) &&
                    column_util::verify_data_column_sidecar_inclusion_proof(sidecar) &&
                    DataColumnSidecarFuluView::slot(sidecar) == slot
            }
            (Some(bid), SidecarLayout::Gloas) => {
                column_util::verify_data_column_sidecar_gloas(
                    sidecar,
                    bid.commitments.as_slice(),
                    max_blobs,
                ) && DataColumnSidecarGloasView::slot(sidecar) == slot
            }
            _ => {
                tracing::error!(
                    slot,
                    served = ?layout,
                    "backfill sidecar layout disagrees with the block's fork"
                );
                false
            }
        }
    }

    /// `None` when the parked buffer can no longer be read: our failure, not
    /// the peer's.
    fn kzg_entry<'a>(&'a self, parked: &'a ParkedSidecar) -> Option<KzgBatchEntry<'a>> {
        let (buf, _) = parked.ssz.buffer().ok()?;
        Some(match &self.bid {
            None => KzgBatchEntry {
                column: DataColumnSidecarFuluView::column(buf),
                commitments: DataColumnSidecarFuluView::kzg_commitments(buf),
                proofs: DataColumnSidecarFuluView::kzg_proofs(buf),
                index: parked.column_index,
            },
            Some(bid) => KzgBatchEntry {
                column: DataColumnSidecarGloasView::column(buf),
                commitments: bid.commitments.as_slice(),
                proofs: DataColumnSidecarGloasView::kzg_proofs(buf),
                index: parked.column_index,
            },
        })
    }

    fn kzg_verify_single(&self, parked: &ParkedSidecar) -> bool {
        let Ok((buf, _)) = parked.ssz.buffer() else { return false };
        match &self.bid {
            None => column_util::verify_data_column_sidecar_kzg_proofs_fulu(buf),
            Some(bid) => column_util::verify_data_column_sidecar_kzg_proofs_gloas(
                buf,
                bid.commitments.as_slice(),
            ),
        }
    }
}

/// The held blocks of the window being filled, by slot.
pub(in crate::store) struct Pending {
    blocks: FxHashMap<u64, PendingBlock>,
    kzg_scratch: KzgScratch,
}

impl Pending {
    pub(in crate::store) fn new() -> Self {
        Self {
            blocks: FxHashMap::with_capacity_and_hasher(PREFILL_SLOTS as usize, Default::default()),
            kzg_scratch: KzgScratch::default(),
        }
    }

    /// Nothing is held for a gloas block whose bid cannot be read.
    pub(in crate::store) fn seed_block(
        &mut self,
        slot: u64,
        block: &[u8],
        is_gloas: bool,
        missing: u128,
        envelope: bool,
    ) {
        if (missing == 0 && !envelope) || self.blocks.contains_key(&slot) {
            return;
        }
        let bid = match is_gloas {
            false => None,
            true => match Bid::of(block) {
                Some(bid) => Some(bid),
                None => {
                    tracing::error!(slot, "gloas block bid unreadable; nothing seeded");
                    return;
                }
            },
        };
        self.blocks.insert(slot, PendingBlock {
            bid,
            requested: missing,
            received: 0,
            parked: Vec::new(),
            first_parked_at: None,
            envelope,
        });
    }

    pub(in crate::store) fn retain_range(&mut self, start: u64, end: u64) {
        self.blocks.retain(|slot, _| (start..end).contains(slot));
    }

    pub(in crate::store) fn add_sidecar(
        &mut self,
        sidecar: TRead,
        head: SidecarHead,
        slot: u64,
        peer: usize,
        now: Instant,
        spec: &SpecConfig,
    ) -> (Option<VerifiedColumns>, Vec<RejectedSidecar>) {
        let Ok((buffer, _)) = sidecar.buffer() else {
            tracing::error!("failed to read backfill data column sidecar cache buffer");
            return (None, Vec::new());
        };
        if !self.park(buffer, &head, slot, peer, now, spec) {
            return (None, Vec::new());
        }
        let block = self.blocks.get_mut(&slot).expect("parked");
        block.parked.push(ParkedSidecar { column_index: head.index, ssz: sidecar, peer });
        if block.received & block.requested != block.requested {
            return (None, Vec::new());
        }
        self.verify_complete(slot)
    }

    fn park(
        &mut self,
        buffer: &[u8],
        head: &SidecarHead,
        slot: u64,
        peer: usize,
        now: Instant,
        spec: &SpecConfig,
    ) -> bool {
        let bit = 1u128 << head.index;
        let Some(block) = self.blocks.get_mut(&slot) else { return false };
        if block.requested & bit == 0 || block.received & bit != 0 {
            return false;
        }
        if !block.accepts(slot, head.layout, buffer, spec) {
            tracing::warn!(
                slot,
                column_index = head.index,
                peer,
                layout = ?head.layout,
                "backfill sidecar does not verify against its block"
            );
            return false;
        }
        block.received |= bit;
        block.first_parked_at.get_or_insert(now);
        true
    }

    fn verify_complete(&mut self, slot: u64) -> (Option<VerifiedColumns>, Vec<RejectedSidecar>) {
        let Some(block) = self.blocks.get_mut(&slot) else { return (None, Vec::new()) };
        StorageCounters::BackfillKzgBatches.inc();
        StorageCounters::BackfillKzgBatchColumns.add(block.parked.len() as u64);

        let all_ok = column_util::kzg_verify_batch_multi(
            block.parked.iter().filter_map(|p| block.kzg_entry(p)),
            &mut self.kzg_scratch,
        );
        if all_ok {
            let sidecars = std::mem::take(&mut block.parked);
            block.requested = 0;
            block.received = 0;
            if block.done() {
                self.blocks.remove(&slot);
            }
            return (Some(VerifiedColumns { slot, sidecars }), Vec::new());
        }

        // Combined check failed: re-verify each alone so the reject lands on
        // the culpable peers only. Their columns go back to missing; the rest
        // stay parked for the re-ask to complete.
        StorageCounters::BackfillKzgBatchRejects.inc();
        let mut rejected = Vec::new();
        let mut i = 0;
        while i < block.parked.len() {
            if block.kzg_verify_single(&block.parked[i]) {
                i += 1;
                continue;
            }
            let bad = block.parked.swap_remove(i);
            block.received &= !(1u128 << bad.column_index);
            tracing::warn!(
                slot,
                column_index = bad.column_index,
                peer = bad.peer,
                "backfill sidecar kzg proof invalid"
            );
            rejected.push(RejectedSidecar { column_index: bad.column_index, peer: bad.peer });
        }
        (None, rejected)
    }

    pub(in crate::store) fn add_envelope(&mut self, signed: &[u8], slot: u64) -> bool {
        let Some(block) = self.blocks.get_mut(&slot) else { return false };
        let Some(bid) = block.bid.as_ref().filter(|_| block.envelope) else { return false };
        if !bid.matches_envelope(signed) {
            tracing::warn!(slot, "backfill envelope does not match its block's bid");
            return false;
        }
        block.envelope = false;
        if block.done() {
            self.blocks.remove(&slot);
        }
        true
    }

    /// Past the timeout every column is missing again; the block stays known so
    /// the re-ask's copies have something to check against.
    pub(in crate::store) fn expire_incomplete(&mut self, now: Instant) {
        for (slot, block) in &mut self.blocks {
            let expired = block
                .first_parked_at
                .is_some_and(|at| now.saturating_duration_since(at) >= INCOMPLETE_BLOCK_TIMEOUT);
            if !expired {
                continue;
            }
            tracing::warn!(
                slot,
                parked = block.parked.len(),
                "backfill block incomplete past timeout; dropping parked columns"
            );
            StorageCounters::BackfillIncompleteExpired.inc();
            block.parked.clear();
            block.received = 0;
            block.first_parked_at = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::fixtures::{
            BID_BLOCK_HASH, BID_BUILDER_INDEX, GLOAS_FORK_SLOT, KZG, Tc, block_bytes,
            envelope_bytes, fulu_blob_block, gloas_block_bytes, spec,
        },
        *,
    };

    /// A gloas-era block needs gloas sidecars, which carry no header: the bid's
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

        let mut pending = Pending::new();
        pending.seed_block(GLOAS_FORK_SLOT, &block, true, 0b101, false);
        let held = pending.blocks[&GLOAS_FORK_SLOT].bid.as_ref().expect("a bid");
        assert_eq!(held.commitments.as_slice(), &commitments[..]);
    }

    /// The two sidecar layouts are not interchangeable: whether the block has
    /// a bid fixes which one is missing, so a mismatch is a reject rather than
    /// a fallback.
    #[test]
    fn sidecar_layout_must_match_the_pending_block() {
        let fresh = |bid| PendingBlock {
            bid,
            requested: 0b1,
            received: 0,
            parked: Vec::new(),
            first_parked_at: None,
            envelope: false,
        };
        let fulu = fresh(None);
        let gloas = fresh(Bid::of(&gloas_block_bytes(GLOAS_FORK_SLOT, &[0u8; 48])));
        assert!(gloas.bid.is_some());

        // Contents are irrelevant: the layout arm is what refuses.
        assert!(!fulu.accepts(1, SidecarLayout::Gloas, &[0u8; 512], &spec()));
        assert!(!gloas.accepts(1, SidecarLayout::Fulu, &[0u8; 512], &spec()));
    }

    fn fulu_fixture(slot: u64) -> (Vec<u8>, Vec<Vec<u8>>) {
        let block = fulu_blob_block(slot, [0x31; 32], &KZG.commitments);
        let sidecars = (0..NUMBER_OF_COLUMNS as u64).map(|j| KZG.fulu_sidecar(&block, j)).collect();
        (block, sidecars)
    }

    fn add(
        pending: &mut Pending,
        tc: &mut Tc,
        sidecar: &[u8],
        slot: u64,
        peer: usize,
        now: Instant,
    ) -> (Option<VerifiedColumns>, Vec<RejectedSidecar>) {
        let head = sidecar_head(sidecar).expect("well formed");
        pending.add_sidecar(tc.tread(sidecar), head, slot, peer, now, &spec())
    }

    #[test]
    fn custody_set_verifies_as_one_batch_on_completion() {
        let now = Instant::now();
        let (block, sidecars) = fulu_fixture(20);
        let mut tc = Tc::new("backfill_kzg_batch", 1 << 22);
        let mut pending = Pending::new();
        let requested = 0b1011u128; // columns 0, 1, 3
        pending.seed_block(20, &block, false, requested, false);

        for &col in &[0usize, 1] {
            let (verified, rejected) = add(&mut pending, &mut tc, &sidecars[col], 20, 7, now);
            assert!(verified.is_none() && rejected.is_empty(), "col {col} parked, not verified");
        }
        assert!(pending.blocks.contains_key(&20), "still held until the set completes");

        let (verified, rejected) = add(&mut pending, &mut tc, &sidecars[3], 20, 7, now);
        assert!(rejected.is_empty());
        let verified = verified.expect("last column completes the set");
        assert_eq!(verified.slot, 20);
        let mut cols: Vec<u64> = verified.sidecars.iter().map(|p| p.column_index).collect();
        cols.sort_unstable();
        assert_eq!(cols, vec![0, 1, 3]);
        assert!(!pending.blocks.contains_key(&20), "retired");
    }

    /// The fallback blames only the forged column's peer and keeps the honest
    /// ones parked.
    #[test]
    fn forged_proof_rejects_only_its_column_and_peer() {
        let now = Instant::now();
        let (block, sidecars) = fulu_fixture(20);
        let mut tc = Tc::new("backfill_kzg_forged", 1 << 22);
        let mut pending = Pending::new();
        pending.seed_block(20, &block, false, 0b11, false);

        let mut forged = sidecars[1].clone();
        let proofs_off = column_util::data_column_sidecar_len(2) - 2 * 48;
        forged[proofs_off] ^= 0x01;

        add(&mut pending, &mut tc, &sidecars[0], 20, 7, now);
        let (verified, rejected) = add(&mut pending, &mut tc, &forged, 20, 9, now);
        assert!(verified.is_none(), "a bad column holds the set back");
        assert_eq!(rejected.len(), 1);
        assert_eq!((rejected[0].column_index, rejected[0].peer), (1, 9));

        let held = &pending.blocks[&20];
        assert_eq!(held.received, 0b01, "only the forged column is missing again");
        assert_eq!(held.parked.len(), 1, "the honest column stays parked");

        // The re-ask lands a good copy: the set completes.
        let (verified, rejected) = add(&mut pending, &mut tc, &sidecars[1], 20, 11, now);
        assert!(rejected.is_empty());
        assert_eq!(verified.expect("completes").sidecars.len(), 2);
    }

    /// The block stays known, since the re-ask's copies need something to check
    /// against.
    #[test]
    fn incomplete_set_expires_and_is_missing_again() {
        let now = Instant::now();
        let (block, sidecars) = fulu_fixture(20);
        let mut tc = Tc::new("backfill_kzg_expire", 1 << 22);
        let mut pending = Pending::new();
        pending.seed_block(20, &block, false, 0b11, false);
        add(&mut pending, &mut tc, &sidecars[0], 20, 7, now);

        pending.expire_incomplete(now + INCOMPLETE_BLOCK_TIMEOUT - Duration::from_millis(1));
        assert_eq!(pending.blocks[&20].parked.len(), 1, "inside the window it is kept");

        pending.expire_incomplete(now + INCOMPLETE_BLOCK_TIMEOUT);
        let held = &pending.blocks[&20];
        assert!(held.parked.is_empty(), "parked buffers released");
        assert_eq!(held.received, 0, "whole set missing again");
    }

    #[test]
    fn moving_on_drops_blocks_outside_the_range() {
        let mut pending = Pending::new();
        pending.seed_block(40, &block_bytes(40, [0; 32]), false, 0b1, false);
        pending.seed_block(72, &block_bytes(72, [0; 32]), false, 0b1, false);
        pending.retain_range(64, 96);
        assert!(!pending.blocks.contains_key(&40), "below the range");
        assert!(pending.blocks.contains_key(&72), "inside it");
    }

    /// The envelope carries no header, so its only tie to the block is the bid
    /// the block committed to. Reproducing it is what makes the payload ours.
    #[test]
    fn envelope_binds_to_its_blocks_bid() {
        const ROOT: B256 = [0x5A; 32];
        let block = gloas_block_bytes(GLOAS_FORK_SLOT, &[]);
        let mut pending = Pending::new();
        pending.seed_block(GLOAS_FORK_SLOT, &block, true, 0, true);
        assert!(pending.blocks.contains_key(&GLOAS_FORK_SLOT), "a gloas block carries a bid");

        let good = envelope_bytes(ROOT, BID_BUILDER_INDEX, BID_BLOCK_HASH);
        let wrong_hash = envelope_bytes(ROOT, BID_BUILDER_INDEX, [0xFF; 32]);
        let wrong_builder = envelope_bytes(ROOT, 0, BID_BLOCK_HASH);
        for (envelope, slot, why) in [
            (&wrong_hash, GLOAS_FORK_SLOT, "payload block_hash the bid did not commit to"),
            (&wrong_builder, GLOAS_FORK_SLOT, "another builder's payload"),
            (&good, GLOAS_FORK_SLOT + 1, "an envelope for a block we were not asked about"),
        ] {
            assert!(!pending.add_envelope(envelope, slot), "refuses {why}");
        }
        assert!(pending.blocks.contains_key(&GLOAS_FORK_SLOT), "a refusal leaves the block held");

        assert!(pending.add_envelope(&good, GLOAS_FORK_SLOT), "accepted");
        assert!(!pending.blocks.contains_key(&GLOAS_FORK_SLOT), "acceptance retires the block");
    }

    #[test]
    fn blocks_without_a_readable_bid_need_no_envelope() {
        let mut pending = Pending::new();
        pending.seed_block(1, &block_bytes(1, [0; 32]), false, 0, true);
        assert!(
            pending.blocks.contains_key(&1),
            "held, since the caller said an envelope is missing"
        );
        assert!(
            !pending.add_envelope(&envelope_bytes([0; 32], 0, [0; 32]), 1),
            "but no bid can match"
        );

        pending.seed_block(GLOAS_FORK_SLOT, &block_bytes(GLOAS_FORK_SLOT, [0; 32]), true, 0, true);
        assert!(!pending.blocks.contains_key(&GLOAS_FORK_SLOT), "no bid, nothing held");
    }
}
