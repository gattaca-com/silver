use flux::spine::SpineProducers;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, IngestionTime, SilverSpineProducers, SszCache, TCacheProducer,
    TCacheRead, TProducer,
    block_contents::SignedBlockContents,
    column_util::{
        cell_bytes, data_column_sidecar_len, fulu_signed_block_header,
        write_data_column_sidecar_fulu,
    },
    ssz_hash::kzg_commitments_inclusion_proof,
    ssz_view::{
        BYTES_PER_KZG_PROOF, BeaconBlockBodyFuluView, NUMBER_OF_COLUMNS, SignedBeaconBlockView,
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

/// The columns of blocks this node proposes: all of them are published,
/// custody or not.
pub(super) struct ProposedBlocks {
    pub(super) producer: TProducer,
    submitted: Vec<Submitted>,
}

impl ProposedBlocks {
    pub(super) fn new(producer: TProducer) -> Self {
        Self { producer, submitted: Vec::new() }
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

    fn take(&mut self, slot: u64, proposer_index: u64) -> Option<TCacheRead> {
        let at = self.submitted.iter().position(|submitted| {
            (submitted.slot, submitted.proposer_index) == (slot, proposer_index)
        })?;
        Some(self.submitted.swap_remove(at).contents)
    }
}

impl DataColumnsTile {
    /// Builds and hands out every column of a proposed block that just passed
    /// its lock. Custody columns count toward availability and are stored.
    pub(super) fn publish_proposed_block(
        &mut self,
        block_root: BlockRoot,
        block: &[u8],
        producers: &mut SilverSpineProducers,
    ) {
        let slot = SignedBeaconBlockView::slot(block);
        let Some(submitted) =
            self.proposed.take(slot, SignedBeaconBlockView::proposer_index(block))
        else {
            return;
        };
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
        let Some(domain) = self.validator.domain_at(slot) else { return };

        let settings = c_kzg::ethereum_kzg_settings(0);
        let mut cells = Vec::with_capacity(contents.blob_count());
        for index in 0..contents.blob_count() {
            match c_kzg::Blob::from_bytes(contents.blob(index))
                .and_then(|blob| settings.compute_cells(&blob))
            {
                Ok(blob_cells) => cells.push(blob_cells),
                Err(error) => {
                    silver_log::error!(?error, slot, index, "proposed blob has no cells");
                    return;
                }
            }
        }

        let body = SignedBeaconBlockView::body(block);
        let commitments = &body[BeaconBlockBodyFuluView::blob_kzg_commitments_offset(body)
            as usize..
            BeaconBlockBodyFuluView::execution_requests_offset(body) as usize];
        let header = fulu_signed_block_header(block);
        let inclusion_proof = kzg_commitments_inclusion_proof(body);
        let len = data_column_sidecar_len(cells.len());
        let mut custody = 0u128;
        for column in 0..NUMBER_OF_COLUMNS {
            let written = self.proposed.producer.write_with(len, |out| {
                let proof_at = column * BYTES_PER_KZG_PROOF;
                write_data_column_sidecar_fulu(
                    out,
                    column as u64,
                    &header,
                    &inclusion_proof,
                    commitments,
                    cells.iter().map(|blob_cells| cell_bytes(&blob_cells[column])),
                    (0..cells.len()).map(|blob| {
                        contents.cell_proofs(blob)[proof_at..proof_at + BYTES_PER_KZG_PROOF]
                            .try_into()
                            .expect("48 bytes")
                    }),
                )
            });
            let Some(ssz) = written else {
                silver_log::error!(
                    slot,
                    column,
                    "proposed_columns tcache full; columns not published"
                );
                return;
            };
            let column_index = column as u64;
            if self.tracker.is_custody(column_index) {
                custody |= 1 << column;
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
        self.tracker.record_and_notify(block_root, slot, custody, IngestionTime::now(), producers);
        silver_log::info!(slot, blobs = cells.len(), "proposed block's columns published");
    }
}
