use std::{
    collections::hash_map::Entry,
    io::Write,
    time::{Duration, Instant},
};

use flux::spine::SpineProducers;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, EngineGetBlobsReq, EngineGetBlobsResp, EngineReq, ForkName,
    GossipDomain, IngestionTime, MAX_BLOBS_PER_BLOCK, SilverSpineProducers, SszCache,
    TCacheProducer, TProducer, TRandomAccess, TRead, Wheel, body_root,
    cell_store::{CommitmentContext, ContextData},
    column_util as util,
    ssz_hash::kzg_commitments_inclusion_proof,
    ssz_view::{
        BEACON_BLOCK_BODY_FIXED, BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        BeaconBlockBodyFuluView, DATA_COLUMN_SIDECAR_GLOAS_MIN, SignedBeaconBlockView,
    },
};

use crate::{
    BlockRoot, DataColumnCounters,
    availability::ColumnTracker,
    sync::SyncStatus,
    tile::cell_handler::{CellHandler, CellWriteState},
    validate::{ColumnValidator, HeaderOutcome},
};

mod response;
use response::BlobResponse;

#[cfg(test)]
mod tests;

const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_FETCHES: usize = 256;
const MAX_RESPONSES: usize = 8;
const MAX_COMMITMENTS_LEN: usize = MAX_BLOBS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT;

struct PendingBlobFetch {
    requested: bool,
    context: CommitmentContext,
    domain: GossipDomain,
    needed: u128,
    deadline: Instant,
    header: [u8; 208],
    inclusion_proof: [u8; 128],
    commitments: [u8; MAX_COMMITMENTS_LEN],
}

impl PendingBlobFetch {
    fn new(
        context: CommitmentContext,
        domain: GossipDomain,
        data: ContextData<'_>,
        needed: u128,
    ) -> Option<Self> {
        if context.blob_count == 0 ||
            context.blob_count > MAX_BLOBS_PER_BLOCK ||
            !data.valid_for(context) ||
            domain.format() != context.format
        {
            return None;
        }
        let mut fetch = Self {
            requested: false,
            context,
            domain,
            needed,
            deadline: Instant::now() + FETCH_TIMEOUT,
            header: [0; 208],
            inclusion_proof: [0; 128],
            commitments: [0; MAX_COMMITMENTS_LEN],
        };
        let commitments = data.commitments();
        fetch.commitments[..commitments.len()].copy_from_slice(commitments);
        if let ContextData::Fulu { signed_header, inclusion_proof, .. } = data {
            fetch.header = *signed_header;
            fetch.inclusion_proof = *inclusion_proof;
        }
        Some(fetch)
    }

    fn start(&mut self, producers: &SilverSpineProducers) {
        if self.requested || self.needed == 0 {
            return;
        }
        self.requested = true;
        self.deadline = Instant::now() + FETCH_TIMEOUT;
        let mut request = EngineGetBlobsReq {
            block_root: self.context.block_root,
            slot: self.context.slot,
            hash_count: self.context.blob_count as u8,
            hashes: [[0; 32]; MAX_BLOBS_PER_BLOCK],
        };
        for (hash, commitment) in request
            .hashes
            .iter_mut()
            .zip(self.data().commitments().chunks_exact(BYTES_PER_KZG_COMMITMENT))
        {
            *hash = util::kzg_commitment_to_versioned_hash(commitment);
        }
        DataColumnCounters::ElBlobsFetched.inc();
        producers.produce(EngineReq::GetBlobs(request));
    }

    fn data(&self) -> ContextData<'_> {
        let commitments = &self.commitments[..self.context.blob_count * BYTES_PER_KZG_COMMITMENT];
        match self.context.format {
            ForkName::Fulu => ContextData::Fulu {
                signed_header: &self.header,
                inclusion_proof: &self.inclusion_proof,
                commitments,
            },
            _ => ContextData::Gloas { commitments },
        }
    }
}

struct PendingResponse {
    fetch: PendingBlobFetch,
    read: TRead,
}

pub(crate) struct ElBlobFetcher {
    pending: Wheel<BlockRoot, PendingBlobFetch, 4>,
    // Deduplication outlives the payload context and includes failed lookups.
    attempted: Wheel<BlockRoot, (), 4>,
    responses: Vec<PendingResponse>,
    sidecar_buffer: Vec<u8>,
    // Deferred responses borrow bucket counters; the consumer must stay put
    // and outlive those reads.
    engine_resp_consumer: Box<TRandomAccess>,
}

impl ElBlobFetcher {
    pub(crate) fn cache_fulu_block(&mut self, bytes: &[u8], root: BlockRoot, domain: GossipDomain) {
        if domain.format() != ForkName::Fulu || self.attempted.contains(&root) {
            return;
        }
        if self.pending.len() >= MAX_FETCHES && !self.pending.contains(&root) {
            return;
        }
        let body = SignedBeaconBlockView::body(bytes);
        if body.len() < BEACON_BLOCK_BODY_FIXED {
            return;
        }
        let start = BeaconBlockBodyFuluView::blob_kzg_commitments_offset(body) as usize;
        let end = BeaconBlockBodyFuluView::execution_requests_offset(body) as usize;
        let Some(commitments) = body.get(start..end) else { return };
        let context = CommitmentContext {
            block_root: root,
            slot: SignedBeaconBlockView::slot(bytes),
            format: ForkName::Fulu,
            blob_count: commitments.len() / BYTES_PER_KZG_COMMITMENT,
        };
        if context.blob_count == 0 ||
            context.blob_count > MAX_BLOBS_PER_BLOCK ||
            !commitments.len().is_multiple_of(BYTES_PER_KZG_COMMITMENT)
        {
            return;
        }
        let mut header = [0; 208];
        header[..8].copy_from_slice(&context.slot.to_le_bytes());
        header[8..16].copy_from_slice(&SignedBeaconBlockView::proposer_index(bytes).to_le_bytes());
        header[16..48].copy_from_slice(SignedBeaconBlockView::parent_root(bytes));
        header[48..80].copy_from_slice(SignedBeaconBlockView::state_root(bytes));
        header[80..112].copy_from_slice(&body_root(body));
        header[112..].copy_from_slice(SignedBeaconBlockView::signature(bytes));
        let proof = kzg_commitments_inclusion_proof(body);
        if let Some(fetch) = PendingBlobFetch::new(
            context,
            domain,
            ContextData::Fulu { signed_header: &header, inclusion_proof: &proof, commitments },
            0,
        ) {
            match self.pending.entry(root) {
                Entry::Occupied(mut entry) => *entry.get_mut() = fetch,
                Entry::Vacant(entry) => {
                    entry.insert(fetch);
                }
            }
        }
    }

    pub(crate) fn approve_block(
        &mut self,
        root: BlockRoot,
        validator: &ColumnValidator,
        sync: &SyncStatus,
        tracker: &mut ColumnTracker,
        producers: &SilverSpineProducers,
    ) -> Option<(CommitmentContext, GossipDomain, ContextData<'_>)> {
        let fetch = self.pending.get(&root)?;
        if fetch.context.format != ForkName::Fulu {
            return None;
        }
        if !fetch.requested {
            if self.attempted.len() >= MAX_FETCHES ||
                self.attempted.contains(&root) ||
                !matches!(
                    validator.validate_fulu_context(
                        root,
                        fetch.domain,
                        fetch.data(),
                        sync,
                        tracker
                    ),
                    HeaderOutcome::Valid(_)
                )
            {
                return None;
            }
            let mut fetch = self.pending.remove(&root)?;
            fetch.needed = tracker.to_request(&root);
            fetch.start(producers);
            self.attempted.insert(root, ());
            self.pending.insert(root, fetch);
        }
        let fetch = self.pending.get(&root)?;
        Some((fetch.context, fetch.domain, fetch.data()))
    }

    pub(crate) fn new(engine_resp_consumer: TRandomAccess, epoch_duration: Duration) -> Self {
        Self {
            pending: Wheel::new(FETCH_TIMEOUT / 4),
            attempted: Wheel::new(epoch_duration),
            responses: Vec::with_capacity(MAX_RESPONSES),
            sidecar_buffer: Vec::with_capacity(8 * 1024),
            engine_resp_consumer: Box::new(engine_resp_consumer),
        }
    }

    pub(crate) fn free(&mut self) {
        self.engine_resp_consumer.free();
    }

    pub(crate) fn rotate(&mut self, now: Instant) {
        self.pending.maybe_rotate(now);
        self.attempted.maybe_rotate(now);
    }

    pub(crate) fn reject(&mut self, root: &BlockRoot) {
        if self.pending.remove(root).is_some() &&
            self.attempted.len() < MAX_FETCHES &&
            !self.attempted.contains(root)
        {
            self.attempted.insert(*root, ());
        }
        self.responses.retain(|response| &response.fetch.context.block_root != root);
    }

    pub(crate) fn try_fetch(
        &mut self,
        context: CommitmentContext,
        domain: GossipDomain,
        data: ContextData<'_>,
        needed: u128,
        producers: &SilverSpineProducers,
    ) {
        if needed == 0 ||
            self.attempted.contains(&context.block_root) ||
            self.attempted.len() >= MAX_FETCHES ||
            self.pending.len() >= MAX_FETCHES && !self.pending.contains(&context.block_root)
        {
            return;
        }
        let Some(mut fetch) = PendingBlobFetch::new(context, domain, data, needed) else { return };
        fetch.start(producers);
        self.attempted.insert(context.block_root, ());
        self.pending.remove(&context.block_root);
        self.pending.insert(context.block_root, fetch);
    }

    pub(crate) fn handle_response(&mut self, response: EngineGetBlobsResp) {
        if self
            .pending
            .get(&response.block_root)
            .is_none_or(|pending| !pending.requested || pending.context.slot != response.slot)
        {
            return;
        }
        let Some(fetch) = self.pending.remove(&response.block_root) else { return };
        if !response.ok || Instant::now() >= fetch.deadline || self.responses.len() >= MAX_RESPONSES
        {
            return;
        }
        let read = self.engine_resp_consumer.acquire(response.data);
        self.responses.push(PendingResponse { fetch, read });
    }

    pub(crate) fn process_responses(
        &mut self,
        mut cells: Option<&mut CellHandler>,
        tracker: &mut ColumnTracker,
        sync: &SyncStatus,
        producer: &mut TProducer,
        producers: &mut SilverSpineProducers,
    ) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.responses.len() {
            let pending = &self.responses[index];
            let context = pending.fetch.context;
            let needed = tracker.to_request(&context.block_root) & pending.fetch.needed;
            if now >= pending.fetch.deadline ||
                context.slot <= sync.data_availability_floor() ||
                needed == 0
            {
                self.responses.swap_remove(index);
                continue;
            }
            let target = cells.as_ref().map_or(CellWriteState::Unavailable, |cells| {
                cells.el_write_state(context, pending.fetch.domain, now)
            });
            if target == CellWriteState::Pending {
                index += 1;
                continue;
            }
            let pending = self.responses.swap_remove(index);
            // Newer responses can force this non-strict consumer past a queued
            // read. Re-acquire before borrowing bytes, even if its slot still matches.
            let Some(read) = pending.read.with_offset(0) else {
                tracing::error!(
                    block = hex::encode(context.block_root),
                    "get_blobs response buffer acquire failed"
                );
                continue;
            };
            let Some(response) = BlobResponse::parse(read.as_ref(), context.blob_count) else {
                tracing::warn!(
                    block = hex::encode(context.block_root),
                    "malformed el blobs response"
                );
                continue;
            };
            if target == CellWriteState::Ready &&
                let Some(cells) = cells.as_deref_mut()
            {
                for (row, entry) in response.present() {
                    if let Some(computed) = entry.compute_cells() {
                        cells.stage_el_row(
                            context,
                            pending.fetch.domain,
                            needed,
                            row,
                            &computed,
                            entry.proofs,
                            pending.read.seq(),
                            producers,
                        );
                    }
                }
            } else {
                let built = Self::build_columns(
                    &pending.fetch,
                    &response,
                    needed,
                    &mut self.sidecar_buffer,
                    producer,
                    producers,
                );
                if built != 0 {
                    tracker.record_and_notify(
                        context.block_root,
                        context.slot,
                        built,
                        IngestionTime::now(),
                        producers,
                    );
                }
            }
        }
    }

    fn build_columns(
        fetch: &PendingBlobFetch,
        response: &BlobResponse<'_>,
        needed: u128,
        buffer: &mut Vec<u8>,
        producer: &mut TProducer,
        producers: &SilverSpineProducers,
    ) -> u128 {
        let context = fetch.context;
        if !response.is_complete() {
            tracing::debug!(
                block = hex::encode(context.block_root),
                "el blobs incomplete; leaving columns to the p2p race"
            );
            return 0;
        }
        let mut all_cells: [Option<Box<[c_kzg::Cell; c_kzg::CELLS_PER_EXT_BLOB]>>;
            MAX_BLOBS_PER_BLOCK] = std::array::from_fn(|_| None);
        for (row, entry) in response.present() {
            let Some(computed) = entry.compute_cells() else { return 0 };
            all_cells[row] = Some(computed);
        }
        let mut built = 0;
        for column in util::columns_of(needed) {
            buffer.clear();
            match fetch.data() {
                ContextData::Fulu { signed_header, inclusion_proof, .. } => {
                    util::push_data_column_sidecar_prefix(
                        buffer,
                        column,
                        context.blob_count,
                        signed_header,
                        inclusion_proof,
                    );
                }
                ContextData::Gloas { .. } => {
                    buffer.extend_from_slice(&column.to_le_bytes());
                    buffer.extend_from_slice(&(DATA_COLUMN_SIDECAR_GLOAS_MIN as u32).to_le_bytes());
                    buffer.extend_from_slice(
                        &((DATA_COLUMN_SIDECAR_GLOAS_MIN + context.blob_count * BYTES_PER_CELL)
                            as u32)
                            .to_le_bytes(),
                    );
                    buffer.extend_from_slice(&context.slot.to_le_bytes());
                    buffer.extend_from_slice(&context.block_root);
                }
            }
            for cells in &all_cells[..context.blob_count] {
                let Some(cells) = cells else { return built };
                let cell = &cells[column as usize];
                // SAFETY: Cell is repr(C) over [u8; BYTES_PER_CELL].
                let bytes: &[u8; BYTES_PER_CELL] = unsafe { &*std::ptr::from_ref(cell).cast() };
                buffer.extend_from_slice(bytes);
            }
            if let ContextData::Fulu { commitments, .. } = fetch.data() {
                buffer.extend_from_slice(commitments);
            }
            let proof_offset = column as usize * BYTES_PER_KZG_PROOF;
            for (_, entry) in response.present() {
                buffer.extend_from_slice(
                    &entry.proofs[proof_offset..proof_offset + BYTES_PER_KZG_PROOF],
                );
            }
            let Some(mut reservation) = producer.reserve(buffer.len(), true) else {
                tracing::error!("failed to allocation cache space for el data column");
                continue;
            };
            if let Err(error) = reservation.write_all(buffer) {
                tracing::error!(?error, "failed to write el sidecar to tcache");
                continue;
            }
            tracing::info!(
                block_root = hex::encode(context.block_root),
                slot = context.slot,
                column_index = column,
                "EL data column recv"
            );
            producers.produce(DataColumnsEvent::Validated {
                block_root: context.block_root,
                column_index: column,
                slot: context.slot,
                origin: ColumnOrigin::El,
                ssz: reservation.read(),
                ssz_cache: SszCache::El,
            });
            producers.produce(DataColumnsEvent::Persist {
                ssz: reservation.read(),
                origin: ColumnOrigin::El,
                ssz_cache: SszCache::El,
                domain: Some(fetch.domain),
                block_root: context.block_root,
                column_index: column,
                slot: context.slot,
            });
            built |= 1 << column;
        }
        if built != 0 {
            DataColumnCounters::ElColumnsBuilt.inc();
        }
        built
    }
}
