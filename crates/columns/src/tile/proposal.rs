use std::array;

use flux::spine::SpineProducers;
use flux_profiler::timed;
use silver_common::{
    BeaconApiRequest, BeaconApiResponse, ColumnOrigin, DataColumnsEvent, ForkName, GossipDomain,
    GossipTopic, IngestionTime, LocalGossipFailure, PayloadFrame, ProposedPayload,
    SilverSpineProducers, SszCache, TCacheProducer, TCacheRead, TProducer, TRead,
    block_contents::SignedBlockContents,
    cell_store::{CommitmentContext, ContextData},
    column_util::{
        CellScratch, KzgBatchEntry, KzgScratch, fulu_header_and_inclusion_proof,
        kzg_verify_batch_multi,
    },
    envelope_contents::SignedEnvelopeContents,
    ssz_hash::hash_beacon_block_header_bytes,
    ssz_view::{
        BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_KZG_PROOF, BeaconBlockBodyFuluView,
        ExecutionPayloadEnvelopeView, ExecutionPayloadView, NUMBER_OF_COLUMNS,
        SignedBeaconBlockView, SignedExecutionPayloadEnvelopeView,
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
        context: CommitmentContext,
        data: ContextData<'_>,
        blobs: &[u8],
        proofs: &[u8],
        kzg_scratch: &mut KzgScratch,
    ) -> Result<[TCacheRead; NUMBER_OF_COLUMNS], LocalGossipFailure> {
        let slot = context.slot;
        let blob_count = context.blob_count;
        if !data.valid_for(context) ||
            blobs.len() != blob_count * BYTES_PER_BLOB ||
            proofs.len() != blob_count * NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF
        {
            return Err(LocalGossipFailure::Invalid);
        }
        let (_, cells_at) = data.column_prefix(context, 0);
        let cells_end = cells_at + blob_count * BYTES_PER_CELL;
        let commitments_len =
            if context.format == ForkName::Fulu { data.commitments().len() } else { 0 };
        let proofs_at = cells_end + commitments_len;
        let len = proofs_at + blob_count * BYTES_PER_KZG_PROOF;
        let reservations: [_; NUMBER_OF_COLUMNS] =
            array::from_fn(|_| self.producer.reserve(len, true));
        if reservations.iter().any(Option::is_none) {
            silver_log::error!(slot, "proposed_columns tcache full; columns not published");
            return Err(LocalGossipFailure::Internal);
        }
        let reservations = reservations.map(|reservation| reservation.expect("reserved"));
        let mut sidecars = reservations
            .each_ref()
            .map(|reservation| &mut reservation.buffer().expect("uncommitted")[..len]);

        for (column, sidecar) in sidecars.iter_mut().enumerate() {
            let (prefix, prefix_len) = data.column_prefix(context, column);
            sidecar[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
            if commitments_len > 0 {
                sidecar[cells_end..proofs_at].copy_from_slice(data.commitments());
            }
            for blob in 0..blob_count {
                let proof_at = (blob * NUMBER_OF_COLUMNS + column) * BYTES_PER_KZG_PROOF;
                let dest = proofs_at + blob * BYTES_PER_KZG_PROOF;
                sidecar[dest..dest + BYTES_PER_KZG_PROOF]
                    .copy_from_slice(&proofs[proof_at..proof_at + BYTES_PER_KZG_PROOF]);
            }
        }

        for (blob, bytes) in blobs.chunks_exact(BYTES_PER_BLOB).enumerate() {
            let Some(cells) = self.cells.compute(bytes.try_into().expect("one blob")) else {
                silver_log::error!(slot, blob, "proposed blob has no cells");
                return Err(LocalGossipFailure::Invalid);
            };
            let cell_at = cells_at + blob * BYTES_PER_CELL;
            for (sidecar, cell) in sidecars.iter_mut().zip(cells.iter()) {
                sidecar[cell_at..cell_at + BYTES_PER_CELL].copy_from_slice(cell);
            }
        }

        // The submitter may not be the validator client this node built for.
        let entries = sidecars.iter().zip(0..).map(|(sidecar, index)| KzgBatchEntry {
            column: &sidecar[cells_at..cells_end],
            commitments: data.commitments(),
            proofs: &sidecar[proofs_at..],
            index,
        });
        if !kzg_verify_batch_multi(entries, kzg_scratch) {
            silver_log::error!(slot, "submitted blobs or proofs fail KZG; columns not published");
            return Err(LocalGossipFailure::Invalid);
        }

        Ok(reservations.map(|mut reservation| {
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
        let context = CommitmentContext {
            block_root,
            slot,
            format: ForkName::Fulu,
            blob_count: contents.blob_count(),
        };
        let data = ContextData::Fulu {
            signed_header: &header,
            inclusion_proof: &inclusion_proof,
            commitments,
        };
        let Ok(sidecars) = self.proposed.write_sidecars(
            context,
            data,
            contents.blobs,
            contents.kzg_proofs,
            &mut self.kzg_scratch,
        ) else {
            return;
        };

        let custody = self.tracker.custody_columns();
        self.tracker.record_and_notify(block_root, slot, custody, IngestionTime::now(), producers);
        let blob_count = contents.blob_count();
        self.proposed.hold(HeldBlock { block_root, slot, domain, blob_count, sidecars });
    }

    pub(super) fn publish_payload_columns(
        &mut self,
        proposal: ProposedPayload,
        producers: &mut SilverSpineProducers,
    ) {
        if let Err(failure) = self.build_payload_columns(proposal, producers) {
            producers.produce(BeaconApiResponse::LocalGossipResponse {
                request_id: proposal.request_id,
                response: Err(failure),
            });
        }
    }

    fn build_payload_columns(
        &mut self,
        proposal: ProposedPayload,
        producers: &mut SilverSpineProducers,
    ) -> Result<(), LocalGossipFailure> {
        let signed_read = self.reader.acquire(proposal.ssz);
        let acquired = self.reader.acquire(proposal.contents);
        let bytes = acquired.buffer().map_err(|_| LocalGossipFailure::Internal)?.0;
        let payload = proposal.payload.map(|read| self.reader.acquire(read));
        let (signed, blobs, proofs) = if let Some(payload) = &payload {
            let frame =
                PayloadFrame::parse(payload.buffer().map_err(|_| LocalGossipFailure::Internal)?.0)
                    .ok_or(LocalGossipFailure::Internal)?;
            (bytes, frame.blobs, frame.cell_proofs)
        } else {
            let contents =
                SignedEnvelopeContents::parse(bytes).ok_or(LocalGossipFailure::Invalid)?;
            (contents.signed_envelope, contents.blobs, contents.kzg_proofs)
        };
        if signed_read.buffer().map_err(|_| LocalGossipFailure::Internal)?.0 != signed {
            return Err(LocalGossipFailure::Internal);
        }
        if !SignedExecutionPayloadEnvelopeView::check_canonical(signed) {
            return Err(LocalGossipFailure::Invalid);
        }
        let envelope = SignedExecutionPayloadEnvelopeView::message(signed);
        let block_root = *ExecutionPayloadEnvelopeView::beacon_block_root(envelope);
        let slot =
            ExecutionPayloadView::slot_number(ExecutionPayloadEnvelopeView::payload(envelope));
        let commitments = self.reader.acquire(proposal.commitments);
        let commitments = commitments.buffer().map_err(|_| LocalGossipFailure::Internal)?.0;
        let blob_count = commitments.len() / 48;
        let context = CommitmentContext { block_root, slot, format: ForkName::Gloas, blob_count };
        let data = ContextData::Gloas { commitments };
        let domain = self.validator.domain_at(slot).ok_or(LocalGossipFailure::Unverifiable)?;
        let sidecars =
            self.proposed.write_sidecars(context, data, blobs, proofs, &mut self.kzg_scratch)?;
        self.proposed.hold(HeldBlock { block_root, slot, domain, blob_count, sidecars });
        self.publish_proposed_columns(&block_root, producers);
        let custody = self.tracker.custody_columns();
        self.tracker.record_and_notify(block_root, slot, custody, IngestionTime::now(), producers);
        producers.produce(BeaconApiRequest::LocalGossip {
            request_id: proposal.request_id,
            topic: GossipTopic::ExecutionPayload,
            ssz: signed_read.to_read(),
        });
        Ok(())
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
