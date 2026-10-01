use std::{array, iter};

use flux::spine::SpineProducers;
use flux_profiler::timed;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, GossipDomain, IngestionTime, SilverSpineProducers, SszCache,
    TCacheProducer, TCacheRead, TProducer, TRead,
    block_contents::SignedBlockContents,
    column_util::{
        CellScratch, KzgBatchEntry, KzgScratch, cell_bytes, data_column_sidecar_len,
        fulu_header_and_inclusion_proof, kzg_verify_batch_multi, write_data_column_sidecar_fulu,
    },
    ssz_hash::hash_beacon_block_header_bytes,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_PROOF, BeaconBlockBodyFuluView, DATA_COLUMN_SIDECAR_MIN,
        DataColumnSidecarFuluView, NUMBER_OF_COLUMNS, SignedBeaconBlockView,
    },
};

use super::DataColumnsTile;
use crate::BlockRoot;

/// One own proposal a slot, for the two retained slots.
const MAX_HELD: usize = 2;

struct HeldBlock {
    block_root: BlockRoot,
    slot: u64,
    domain: GossipDomain,
    blob_count: usize,
    sidecars: [TCacheRead; NUMBER_OF_COLUMNS],
}

struct HeldBlocks([Option<HeldBlock>; MAX_HELD]);

impl HeldBlocks {
    const EMPTY: Self = Self([const { None }; MAX_HELD]);

    /// Drops blocks older than the previous slot. When full, the oldest goes.
    fn insert(&mut self, held: HeldBlock) {
        for entry in &mut self.0 {
            entry.take_if(|older| older.slot + 1 < held.slot);
        }
        let at = self.0.iter().position(Option::is_none).unwrap_or_else(|| self.oldest());
        self.0[at] = Some(held);
    }

    fn take(&mut self, block_root: &BlockRoot) -> Option<HeldBlock> {
        let entry = self
            .0
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|held| held.block_root == *block_root))?;
        entry.take()
    }

    fn oldest_seq(&self) -> Option<u64> {
        self.0.iter().flatten().map(|held| held.sidecars[0].seq()).min()
    }

    fn oldest(&self) -> usize {
        (0..MAX_HELD)
            .min_by_key(|&at| self.0[at].as_ref().map(|held| held.slot))
            .expect("MAX_HELD is not zero")
    }
}

pub(super) struct ProposedBlocks {
    pub(super) producer: TProducer,
    cells: CellScratch,
    held: HeldBlocks,
}

impl ProposedBlocks {
    pub(super) fn new(producer: TProducer) -> Self {
        Self { producer, cells: CellScratch::default(), held: HeldBlocks::EMPTY }
    }

    #[timed]
    fn write_sidecars(
        &mut self,
        slot: u64,
        header: &[u8; 208],
        inclusion_proof: &[u8; 128],
        commitments: &[u8],
        contents: &SignedBlockContents,
        kzg_scratch: &mut KzgScratch,
    ) -> Option<[TCacheRead; NUMBER_OF_COLUMNS]> {
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
                header,
                inclusion_proof,
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

        // The submitter may not be the validator client this node built for.
        let entries = sidecars.iter().zip(0..).map(|(sidecar, index)| KzgBatchEntry {
            column: DataColumnSidecarFuluView::column(sidecar),
            commitments: DataColumnSidecarFuluView::kzg_commitments(sidecar),
            proofs: DataColumnSidecarFuluView::kzg_proofs(sidecar),
            index,
        });
        if !kzg_verify_batch_multi(entries, kzg_scratch) {
            silver_log::error!(slot, "submitted blobs or proofs fail KZG; columns not published");
            return None;
        }

        Some(reservations.map(|mut reservation| {
            reservation.increment_offset(len);
            reservation.read()
        }))
    }

    fn hold(&mut self, held: HeldBlock) {
        self.held.insert(held);
        self.retain_held();
    }

    fn take_held(&mut self, block_root: &BlockRoot) -> Option<HeldBlock> {
        let held = self.held.take(block_root)?;
        self.retain_held();
        Some(held)
    }

    pub(super) fn drop_held(&mut self, block_root: &BlockRoot) {
        self.take_held(block_root);
    }

    fn retain_held(&mut self) {
        let oldest = self.held.oldest_seq();
        self.producer.retain_from(oldest.unwrap_or(self.producer.next_seq()));
    }
}

impl DataColumnsTile {
    /// Records the custody of a proposed block that just passed its lock, so
    /// none of it is chased, and holds every column until the block imports.
    #[timed]
    pub(super) fn hold_proposal_columns(
        &mut self,
        contents: TRead,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(contents) =
            contents.buffer().ok().and_then(|(bytes, _)| SignedBlockContents::parse(bytes))
        else {
            silver_log::error!("proposed block contents unavailable; columns not published");
            return;
        };
        let block = contents.signed_block;
        let slot = SignedBeaconBlockView::slot(block);
        let (header, inclusion_proof) = fulu_header_and_inclusion_proof(block);
        let block_root = hash_beacon_block_header_bytes(&header);
        // An identical resubmission passes the lock again.
        if self.tracker.custody_complete(&block_root) {
            return;
        }
        let Some(commitments) =
            BeaconBlockBodyFuluView::blob_kzg_commitments(SignedBeaconBlockView::body(block))
                .filter(|commitments| !commitments.is_empty())
        else {
            return;
        };
        let Some(domain) = self.validator.domain_at(slot) else { return };
        let Some(sidecars) = self.proposed.write_sidecars(
            slot,
            &header,
            &inclusion_proof,
            commitments,
            &contents,
            &mut self.kzg_scratch,
        ) else {
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
