//! EL-mempool blob path: fetch a block's blobs via `engine_getBlobsV2` and
//! rebuild our custody `DataColumnSidecar`s locally, racing the p2p ByRoot
//! request. Whichever fills the custody set first wins; the loser dedups via
//! `validated_columns`.

use std::{
    io::Write,
    time::{Duration, Instant},
};

use silver_common::{
    BASE_REQUEST_ID, ColumnSource, DataColumnsEvent, EngineGetBlobsReq, EngineGetBlobsResp,
    EngineReq, MAX_BLOBS_PER_BLOCK, TCacheProducer, TProducer, TRandomAccess, Wheel,
    column_util as util,
    ssz_hash::kzg_commitments_inclusion_proof,
    ssz_view::{
        BEACON_BLOCK_BODY_FIXED, BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        BeaconBlockBodyFuluView, NUMBER_OF_COLUMNS, SignedBeaconBlockView,
    },
};

use crate::{DataColumnCounters, sync::SyncStatus, tile::StorageEmit};

type BlockRoot = [u8; 32];

/// Inline size for [`PendingBlobFetch::commitments`] — avoids a per-fetch heap
/// allocation.
const MAX_COMMITMENTS_LEN: usize = MAX_BLOBS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT;

/// State carried between firing an `engine_getBlobsV2` request and receiving
/// its response — everything needed to rebuild custody sidecars from the
/// returned blobs. Keyed by engine request id.
struct PendingBlobFetch {
    block_root: BlockRoot,
    slot: u64,
    /// Custody columns still wanted at request time. Recomputed against
    /// `validated_columns` on response (the p2p race may have filled some).
    needed: u128,
    num_blobs: usize,
    header: [u8; 208],
    inclusion_proof: [u8; 128],
    commitments: [u8; MAX_COMMITMENTS_LEN],
}

pub(crate) struct ElBlobFetcher {
    engine_resp_consumer: TRandomAccess,
    next_req_id: u64,
    /// In-flight fetches, keyed by request id. 4 buckets × 500ms ⇒ entries age
    /// out after ~1.5–2s if the EL never responds.
    pending: Wheel<u64, PendingBlobFetch, 4>,
}

impl ElBlobFetcher {
    pub(crate) fn new(engine_resp_consumer: TRandomAccess) -> Self {
        Self {
            engine_resp_consumer,
            next_req_id: BASE_REQUEST_ID,
            pending: Wheel::new(Duration::from_millis(500)),
        }
    }

    pub(crate) fn free(&mut self) {
        self.engine_resp_consumer.free();
    }

    pub(crate) fn rotate(&mut self, now: Instant) {
        self.pending.maybe_rotate(now, &mut |_, _| true);
    }

    /// Fire an `engine_getBlobsV2` request for `block`'s blobs and stash the
    /// state needed to rebuild custody sidecars from the response. No-op if the
    /// block carries no commitments. Runs alongside the p2p ByRoot path.
    pub(crate) fn try_fetch<F>(
        &mut self,
        block: &[u8],
        block_root: BlockRoot,
        slot: u64,
        needed: u128,
        emit: &mut F,
    ) where
        F: FnMut(StorageEmit),
    {
        let body = SignedBeaconBlockView::body(block);
        if body.len() < BEACON_BLOCK_BODY_FIXED {
            return;
        }
        let kzg_off = BeaconBlockBodyFuluView::blob_kzg_commitments_offset(body) as usize;
        let exec_off = BeaconBlockBodyFuluView::execution_requests_offset(body) as usize;
        if kzg_off > exec_off || exec_off > body.len() {
            return;
        }
        let commitments = &body[kzg_off..exec_off];
        if commitments.is_empty() || !commitments.len().is_multiple_of(BYTES_PER_KZG_COMMITMENT) {
            return;
        }
        let num_blobs = commitments.len() / BYTES_PER_KZG_COMMITMENT;
        if num_blobs > MAX_BLOBS_PER_BLOCK {
            return;
        }

        let id = self.next_req_id;
        self.next_req_id += 1;

        let mut req = EngineGetBlobsReq {
            id,
            hash_count: num_blobs as u8,
            hashes: [[0u8; 32]; MAX_BLOBS_PER_BLOCK],
        };
        for (i, commitment) in commitments.chunks(BYTES_PER_KZG_COMMITMENT).enumerate() {
            req.hashes[i] = util::kzg_commitment_to_versioned_hash(commitment);
        }

        let mut header = [0u8; 208];
        header[0..8].copy_from_slice(&slot.to_le_bytes());
        header[8..16].copy_from_slice(&SignedBeaconBlockView::proposer_index(block).to_le_bytes());
        header[16..48].copy_from_slice(SignedBeaconBlockView::parent_root(block));
        header[48..80].copy_from_slice(SignedBeaconBlockView::state_root(block));
        header[80..112].copy_from_slice(&util::body_root(body));
        header[112..208].copy_from_slice(SignedBeaconBlockView::signature(block));

        let mut commitments_buf = [0u8; MAX_COMMITMENTS_LEN];
        commitments_buf[..commitments.len()].copy_from_slice(commitments);

        self.pending.insert(id, PendingBlobFetch {
            block_root,
            slot,
            needed,
            num_blobs,
            header,
            inclusion_proof: kzg_commitments_inclusion_proof(body),
            commitments: commitments_buf,
        });
        DataColumnCounters::ElBlobsFetched.inc();
        emit(StorageEmit::Engine(EngineReq::GetBlobs(req)));
    }

    /// Handle an `engine_getBlobsV2` response: rebuild our outstanding custody
    /// `DataColumnSidecar`s from the returned blobs and feed them through the
    /// same availability path as p2p sidecars. Bails (leaving the p2p race to
    /// fill them) on any incompleteness — `ok == false`, a missing blob, a
    /// decode/KZG error, or a now-finalized block.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle_response<F>(
        &mut self,
        resp: EngineGetBlobsResp,
        validated_columns: &mut Wheel<BlockRoot, u128, 4>,
        outstanding_requests: &mut Wheel<BlockRoot, (u128, u128, u8), 16>,
        sync_state: &SyncStatus,
        custody_group_columns: u128,
        column_producer: &mut TProducer,
        emit: &mut F,
    ) where
        F: FnMut(DataColumnsEvent),
    {
        let Some(pending) = self.pending.remove(&resp.id) else {
            return; // unknown / expired request
        };
        if !resp.ok {
            return;
        }
        if pending.slot <= sync_state.finalized_slot() {
            return; // block finalized while in flight — availability is moot
        }

        // Columns still missing (some may have arrived via the p2p race).
        let already = validated_columns.get(&pending.block_root).copied().unwrap_or(0);
        let to_build = pending.needed & !already;
        if to_build == 0 {
            return;
        }

        let read = self.engine_resp_consumer.acquire(resp.data);
        let Ok((data, _)) = read.buffer() else {
            tracing::error!(id = resp.id, "get_blobs response buffer acquire failed");
            return;
        };
        let n = pending.num_blobs;
        let mut blobs = [(EMPTY, EMPTY); MAX_BLOBS_PER_BLOCK];
        if !parse_el_blobs(data, &mut blobs[..n]) {
            tracing::debug!(
                block = hex::encode(pending.block_root),
                "el blobs incomplete; leaving columns to the p2p race"
            );
            return;
        }

        // Column j of the block is cell j of each blob. Only `compute_cells`
        // (the cheap FFT extension) — the EL's cell proofs are reused as-is.
        let settings = c_kzg::ethereum_kzg_settings(0);
        let mut all_cells: [Option<Box<[c_kzg::Cell; c_kzg::CELLS_PER_EXT_BLOB]>>;
            MAX_BLOBS_PER_BLOCK] = std::array::from_fn(|_| None);
        for (i, (blob_bytes, _)) in blobs[..n].iter().enumerate() {
            let blob = match c_kzg::Blob::from_bytes(blob_bytes) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(?e, "el blob decode failed");
                    return;
                }
            };
            match settings.compute_cells(&blob) {
                Ok(cells) => all_cells[i] = Some(cells),
                Err(e) => {
                    tracing::error!(?e, "compute_cells failed");
                    return;
                }
            }
        }

        let commitments = &pending.commitments[..n * BYTES_PER_KZG_COMMITMENT];

        let mut built = 0u128;
        for j in 0..NUMBER_OF_COLUMNS as u64 {
            let bit = 1u128 << j;
            if to_build & bit == 0 {
                continue;
            }
            let proof_lo = j as usize * BYTES_PER_KZG_PROOF;
            let proof_hi = proof_lo + BYTES_PER_KZG_PROOF;

            let mut sidecar = Vec::with_capacity(util::data_column_sidecar_len(n));
            util::push_data_column_sidecar_prefix(
                &mut sidecar,
                j,
                n,
                &pending.header,
                &pending.inclusion_proof,
            );
            // column: cell j of every blob.
            for cells in all_cells[..n].iter() {
                let cell = &cells.as_ref().unwrap()[j as usize];
                // SAFETY: `c_kzg::Cell` is `#[repr(C)]` over `[u8; BYTES_PER_CELL]`;
                // cast avoids the array copy `Cell::to_bytes()` makes.
                let bytes: &[u8; BYTES_PER_CELL] = unsafe { &*std::ptr::from_ref(cell).cast() };
                sidecar.extend_from_slice(bytes);
            }
            // kzg_commitments (shared) then kzg_proofs: proof j of every blob.
            sidecar.extend_from_slice(commitments);
            for (_, proofs) in blobs[..n].iter() {
                sidecar.extend_from_slice(&proofs[proof_lo..proof_hi]);
            }
            debug_assert_eq!(sidecar.len(), util::data_column_sidecar_len(n));

            // TODO(republish): maybe gossip these EL-reconstructed columns to peers?
            match column_producer.reserve(sidecar.len(), true) {
                Some(mut reservation) => match reservation.write(&sidecar) {
                    Ok(_) => {
                        let ssz = reservation.read();
                        emit(DataColumnsEvent::Persist {
                            ssz,
                            source: ColumnSource::El,
                            block_root: pending.block_root,
                            column_index: j,
                            slot: pending.slot,
                        });
                    }
                    Err(e) => tracing::error!(?e, "failed to write el sidecar to tcache"),
                },
                None => {
                    tracing::error!("failed to allocation cache space for el data column");
                }
            }

            // @@VE
            //store.add_unfinalized_data_column(pending.block_root, j, sidecar,
            // pending.slot);

            built |= bit;
        }

        if built == 0 {
            return;
        }
        DataColumnCounters::ElColumnsBuilt.inc();

        let validated = validated_columns.entry(pending.block_root).or_default();
        *validated |= built;
        let validated = *validated;

        // Drop satisfied bits from the p2p request wheel so it stops re-asking.
        if let Some((mut requested, full, retries)) =
            outstanding_requests.remove(&pending.block_root)
        {
            requested &= !built;
            if requested != 0 {
                outstanding_requests.insert(pending.block_root, (requested, full, retries));
            }
        }

        if validated & custody_group_columns == custody_group_columns {
            DataColumnCounters::DataColumnsAvailableEmitted.inc();
            tracing::info!(
                block = hex::encode(pending.block_root),
                slot = pending.slot,
                "DataColumnsAvailable: custody set complete (EL blobs)"
            );
            emit(DataColumnsEvent::Available {
                block_root: pending.block_root,
                slot: pending.slot,
            });
        }
    }
}

/// Placeholder for stack-initializing the parsed-blob array.
const EMPTY: &[u8] = &[];

/// Parse the `engine_getBlobsV2` tcache frame, filling `out[i]` with
/// `(blob, cell_proofs)` for blob `i`. `cell_proofs` is the flat
/// `NUMBER_OF_COLUMNS * 48` bytes of cell KZG proofs the EL supplies — reused
/// rather than recomputed (proof generation is the expensive half of the KZG
/// work). Filling a caller slice keeps the parse allocation-free.
///
/// Wire layout (from `engine::types::json_get_blobs_to_tcache`):
/// `[u32 count] ([u8 present][u8 proof_count][48B proof]* [u32
/// blob_len][blob])*`. Returns `false` unless `count == out.len()`, the frame
/// is well-formed, every blob is present, and each carries exactly
/// `NUMBER_OF_COLUMNS` cell proofs.
fn parse_el_blobs<'a>(data: &'a [u8], out: &mut [(&'a [u8], &'a [u8])]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let Ok(count_bytes) = data[0..4].try_into() else { return false };
    if u32::from_le_bytes(count_bytes) as usize != out.len() {
        return false;
    }
    let mut off = 4;
    for slot in out.iter_mut() {
        let Some(&present) = data.get(off) else { return false };
        off += 1;
        if present == 0 {
            return false;
        }
        let Some(&proof_count) = data.get(off) else { return false };
        off += 1;
        if proof_count as usize != NUMBER_OF_COLUMNS {
            return false;
        }
        let Some(proofs_end) = off.checked_add(NUMBER_OF_COLUMNS * BYTES_PER_KZG_PROOF) else {
            return false;
        };
        if proofs_end > data.len() {
            return false;
        }
        let proofs = &data[off..proofs_end];
        off = proofs_end;
        if off + 4 > data.len() {
            return false;
        }
        let Ok(len_bytes) = data[off..off + 4].try_into() else { return false };
        let blob_len = u32::from_le_bytes(len_bytes) as usize;
        off += 4;
        let Some(end) = off.checked_add(blob_len) else { return false };
        if end > data.len() {
            return false;
        }
        *slot = (&data[off..end], proofs);
        off = end;
    }
    true
}
