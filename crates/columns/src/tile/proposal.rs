use std::{array, iter};

use flux::spine::SpineProducers;
use flux_profiler::timed;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, GossipDomain, IngestionTime, SilverSpineProducers, SszCache,
    TCacheProducer, TCacheRead, TProducer,
    block_contents::SignedBlockContents,
    column_util::{
        CellScratch, cell_bytes, data_column_sidecar_len, fulu_signed_block_header,
        write_data_column_sidecar_fulu,
    },
    ssz_hash::kzg_commitments_inclusion_proof,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_PROOF, BeaconBlockBodyFuluView, DATA_COLUMN_SIDECAR_MIN,
        NUMBER_OF_COLUMNS, SignedBeaconBlockView,
    },
};

use super::DataColumnsTile;
use crate::BlockRoot;

/// Contents a validator client submitted, kept until the block passes the
/// slashing-protection lock and comes back as a local gossip block.
struct Submitted {
    slot: u64,
    proposer_index: u64,
    contents: TCacheRead,
}

/// A proposed block whose custody is recorded. Its columns go out once beacon
/// state has imported the block, so an invalid one publishes none.
struct HeldBlock {
    block_root: BlockRoot,
    slot: u64,
    domain: GossipDomain,
    blob_count: usize,
    sidecars: [TCacheRead; NUMBER_OF_COLUMNS],
}

/// The columns of blocks this node proposes: all of them are published,
/// custody or not.
pub(super) struct ProposedBlocks {
    pub(super) producer: TProducer,
    cells: CellScratch,
    submitted: Vec<Submitted>,
    held: Vec<HeldBlock>,
}

impl ProposedBlocks {
    pub(super) fn new(producer: TProducer) -> Self {
        Self { producer, cells: CellScratch::default(), submitted: Vec::new(), held: Vec::new() }
    }

    pub(super) fn submit(&mut self, contents: TCacheRead, bytes: &[u8]) {
        let Some(block) = SignedBlockContents::signed_block(bytes)
            .filter(|block| SignedBeaconBlockView::check_size(block))
        else {
            return;
        };
        let slot = SignedBeaconBlockView::slot(block);
        let proposer_index = SignedBeaconBlockView::proposer_index(block);
        self.submitted.retain(|submitted| {
            submitted.slot + 1 >= slot &&
                (submitted.slot, submitted.proposer_index) != (slot, proposer_index)
        });
        self.submitted.push(Submitted { slot, proposer_index, contents });
    }

    fn take_submitted(&mut self, slot: u64, proposer_index: u64) -> Option<TCacheRead> {
        let at = self.submitted.iter().position(|submitted| {
            (submitted.slot, submitted.proposer_index) == (slot, proposer_index)
        })?;
        Some(self.submitted.swap_remove(at).contents)
    }

    #[timed]
    fn write_sidecars(
        &mut self,
        block: &[u8],
        commitments: &[u8],
        contents: &SignedBlockContents,
    ) -> Option<[TCacheRead; NUMBER_OF_COLUMNS]> {
        let slot = SignedBeaconBlockView::slot(block);
        let header = fulu_signed_block_header(block);
        let inclusion_proof = kzg_commitments_inclusion_proof(SignedBeaconBlockView::body(block));
        let blob_count = contents.blob_count();
        let len = data_column_sidecar_len(blob_count);

        let reservations: [_; NUMBER_OF_COLUMNS] =
            array::from_fn(|_| self.producer.reserve(len, true));
        if reservations.iter().any(Option::is_none) {
            silver_log::error!(slot, "proposed_columns tcache full; columns not published");
            return None;
        }
        let reservations = reservations.map(|reservation| reservation.expect("reserved"));
        let mut sidecars = reservations
            .each_ref()
            .map(|reservation| &mut reservation.buffer().expect("uncommitted")[..len]);

        for (column, sidecar) in sidecars.iter_mut().enumerate() {
            let proof_at = column * BYTES_PER_KZG_PROOF;
            write_data_column_sidecar_fulu(
                sidecar,
                column as u64,
                &header,
                &inclusion_proof,
                commitments,
                iter::empty(),
                (0..blob_count).map(|blob| {
                    contents.cell_proofs(blob)[proof_at..proof_at + BYTES_PER_KZG_PROOF]
                        .try_into()
                        .expect("48 bytes")
                }),
            );
        }

        for blob in 0..blob_count {
            let cells = match self.cells.compute(contents.blob(blob)) {
                Ok(cells) => cells,
                Err(error) => {
                    silver_log::error!(?error, slot, blob, "proposed blob has no cells");
                    return None;
                }
            };
            let cell_at = DATA_COLUMN_SIDECAR_MIN + blob * BYTES_PER_CELL;
            for (sidecar, cell) in sidecars.iter_mut().zip(cells.iter()) {
                sidecar[cell_at..cell_at + BYTES_PER_CELL].copy_from_slice(cell_bytes(cell));
            }
        }

        Some(reservations.map(|mut reservation| {
            reservation.increment_offset(len);
            reservation.read()
        }))
    }

    fn hold(&mut self, held: HeldBlock) {
        self.held.retain(|older| older.slot + 1 >= held.slot);
        self.held.push(held);
        self.retain_held();
    }

    fn take_held(&mut self, block_root: &BlockRoot) -> Option<HeldBlock> {
        let at = self.held.iter().position(|held| held.block_root == *block_root)?;
        let held = self.held.swap_remove(at);
        self.retain_held();
        Some(held)
    }

    pub(super) fn drop_held(&mut self, block_root: &BlockRoot) {
        self.take_held(block_root);
    }

    fn retain_held(&mut self) {
        let oldest = self.held.iter().map(|held| held.sidecars[0].seq()).min();
        self.producer.retain_from(oldest.unwrap_or(self.producer.next_seq()));
    }
}

impl DataColumnsTile {
    /// Records the custody of a proposed block that just passed its lock, so
    /// none of it is chased, and holds every column until the block imports.
    pub(super) fn hold_proposed_block(
        &mut self,
        block_root: BlockRoot,
        block: &[u8],
        producers: &mut SilverSpineProducers,
    ) {
        let slot = SignedBeaconBlockView::slot(block);
        let Some(submitted) =
            self.proposed.take_submitted(slot, SignedBeaconBlockView::proposer_index(block))
        else {
            return;
        };
        let Some(commitments) =
            BeaconBlockBodyFuluView::blob_kzg_commitments(SignedBeaconBlockView::body(block))
                .filter(|commitments| !commitments.is_empty())
        else {
            return;
        };
        let Some(domain) = self.validator.domain_at(slot) else { return };
        let acquired = self.reader.acquire(submitted);
        let Some(contents) = acquired
            .buffer()
            .ok()
            .and_then(|(bytes, _)| SignedBlockContents::parse(bytes))
            .filter(|contents| contents.signed_block == block)
        else {
            silver_log::error!(slot, "proposed block contents unavailable; columns not published");
            return;
        };
        let Some(sidecars) = self.proposed.write_sidecars(block, commitments, &contents) else {
            return;
        };

        let custody = self.tracker.custody_columns();
        self.tracker.record_and_notify(block_root, slot, custody, IngestionTime::now(), producers);
        let blob_count = contents.blob_count();
        self.proposed.hold(HeldBlock { block_root, slot, domain, blob_count, sidecars });
    }

    /// Custody columns are stored as well as published.
    pub(super) fn publish_proposed_columns(
        &mut self,
        block_root: &BlockRoot,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(HeldBlock { block_root, slot, domain, blob_count, sidecars }) =
            self.proposed.take_held(block_root)
        else {
            return;
        };
        for (column_index, ssz) in (0..).zip(sidecars) {
            if self.tracker.is_custody(column_index) {
                producers.produce(DataColumnsEvent::Persist {
                    ssz,
                    origin: ColumnOrigin::Assembly,
                    ssz_cache: SszCache::ProposedColumns,
                    domain: Some(domain),
                    block_root,
                    column_index,
                    slot,
                });
            } else {
                producers.produce(DataColumnsEvent::Publish { ssz, domain, column_index });
            }
        }
        silver_log::info!(slot, blobs = blob_count, "proposed block's columns published");
    }
}
