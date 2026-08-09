use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    BASE_REQUEST_ID, BeaconStateEvent, ColumnSource, DataColumnsEvent, EngineReq, EngineResp,
    GossipTopic, Nanos, NewGossipMsg, P2pStreamId, PeerEvent, RpcInbound, RpcSeverity, SilverSpine,
    SilverSpineProducers, StreamProtocol, SyncUpdate, SyncingStrategy, TProducer, TRandomAccess,
    TRead, Wheel, msg_is_backfill, msg_is_live_column_request, msg_is_post_gloas,
    ssz_view::{
        DataColumnSidecarFuluView, DataColumnSidecarGloasView, NUMBER_OF_COLUMNS,
        SignedBeaconBlockView, StatusView,
    },
};

use crate::{StorageCounters, el_blobs::ElBlobFetcher, sync::SyncStatus, util};
const MAX_RETRIES: u8 = 5;

/// Mainnet epoch: 32 slots × 12s. Wheel bucket width for the
/// block-level validation cache.
const EPOCH_DURATION: Duration = Duration::from_secs(32 * 12);

/// SSZ `hash_tree_root(BeaconBlockHeader)` — the same value carried as
/// `head_root` in Status RPC and `block_root` in
/// `DataColumnsByRootIdentifier`. Keys `validated_columns` so ByRoot
/// lookups and head-update integration are direct lookups.
type BlockRoot = [u8; 32];

type PendingColumn = (P2pStreamId, TRead, Option<u64>);

/// `EngineReq` is large but short-lived here, so
/// boxing it would only add an alloc on the block path.
#[allow(clippy::large_enum_variant)]
pub(crate) enum StorageEmit {
    Peer(PeerEvent),
    Engine(EngineReq),
}

enum ColumnOutcome {
    Skip,
    Reject { block_root: [u8; 32], bitmask: u128 },
    Buffer { block_root: [u8; 32] },
    AwaitParent { parent_root: [u8; 32] },
    Record { block_root: [u8; 32], column_index: u64, bitmask: u128, slot: u64 },
}

/// Only `Validated` may be forwarded / republished on gossip: `Ignored`
/// covers spec-IGNORE cases (dup, post-wall, parent pending, buffered)
/// whose sidecars must not be relayed and whose senders are not culpable.
enum ColumnDisposition {
    Validated,
    Ignored,
    Rejected { block_root: [u8; 32], bitmask: u128 },
}

pub struct DataColumnsTile {
    // bit set of our custody group columns.
    custody_group_columns: u128,
    request_id: u64,
    // Gossip and rpc are read twice: 'live' and when we receive a request from
    // beacon state to persist - this require 2 consumers.
    gossip_consumer: TRandomAccess,
    persist_gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
    persist_rpc_consumer: TRandomAccess,
    beacon_state: BeaconStateReader,

    spec: Arc<SpecConfig>,

    // keyed by block body root
    validated_columns: Wheel<BlockRoot, u128, 4>,
    // Gloas sidecars carry no commitments, so column KZG verifies against these.
    gloas_commitments: Wheel<BlockRoot, Box<[u8]>, 4>,
    // Gloas: columns whose block (hence commitments) hasn't been seen yet.
    gloas_pending_columns: Wheel<BlockRoot, Vec<PendingColumn>, 4>,
    // Fulu: columns held until their parent block validates. Keyed by the
    // sidecar's parent_root; drained on Status head advances and on block
    // arrivals (the arriving block's own parent_root).
    parent_pending_columns: Wheel<BlockRoot, Vec<PendingColumn>, 4>,
    // BLS verify memo: block_root → previously-validated 96-byte
    // proposer signature. On a subsequent sidecar with the same
    // block_root AND matching signature bytes we skip the ~1 ms BLS
    // verify; with a different signature we re-verify. block_root
    // alone is not safe to cache by — it does not cover the
    // signature, kzg_commitments, or inclusion proof, all of which
    // remain verified on every sidecar. Time-bounded: 4 buckets × 1
    // epoch ⇒ entries age out after 3–4 epochs.
    validated_blocks: Wheel<BlockRoot, [u8; 96], 4>,
    // outstanding requests - keyed by block body root
    // 16 x 500 millisecond buckets.
    outstanding_requests: Wheel<BlockRoot, (u128, u128, u8), 16>,
    // roots of peristed blocks - tracked for use in checking for seen parent blocks
    persisted_block_roots: Wheel<BlockRoot, (), 16>,

    sync_state: SyncStatus,

    /// Boot decision from control: `None` = waiting; gates `drive_replay` so we
    /// don't replay the on-disk fork tree before learning whether peers are
    /// finalized ahead (in which case we skip it and range-sync from them).
    syncing_strategy: Option<SyncingStrategy>,

    el_fetcher: ElBlobFetcher,
    el_column_producer: TProducer,
}

impl DataColumnsTile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gossip_consumer: TRandomAccess,
        persist_gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        persist_rpc_consumer: TRandomAccess,
        beacon_state: BeaconStateReader,
        custody_group_columns: u128,
        spec: Arc<SpecConfig>,
        engine_resp_consumer: TRandomAccess,
        el_column_producer: TProducer,
    ) -> Self {
        Self {
            custody_group_columns,
            request_id: BASE_REQUEST_ID,
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            beacon_state,
            spec,
            validated_columns: Wheel::new(EPOCH_DURATION),
            gloas_commitments: Wheel::new(EPOCH_DURATION),
            gloas_pending_columns: Wheel::new(EPOCH_DURATION),
            parent_pending_columns: Wheel::new(Duration::from_secs(24)),
            validated_blocks: Wheel::new(EPOCH_DURATION),
            persisted_block_roots: Wheel::new(EPOCH_DURATION),
            outstanding_requests: Wheel::new(Duration::from_millis(100)),
            sync_state: SyncStatus::default(),
            syncing_strategy: None,
            el_fetcher: ElBlobFetcher::new(engine_resp_consumer),
            el_column_producer,
        }
    }

    fn column_request(&mut self, block_root: [u8; 32], columns: u128) -> PeerEvent {
        let id = self.request_id;
        self.request_id += 1;
        PeerEvent::SendDataColumnsByRootRequest { request_id: id, columns, block_root }
    }

    #[timed]
    fn beacon_block<F>(
        &mut self,
        stream_id: P2pStreamId,
        block: TRead,
        emit: &mut F,
    ) -> Option<(B256, bool)>
    where
        F: FnMut(StorageEmit),
    {
        let buffer = match block.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read beacon block cache buffer");
                return None;
            }
        };

        let slot = SignedBeaconBlockView::slot(buffer);
        let is_gloas = self.spec.is_gloas_at_slot(slot);
        let has_columns = SignedBeaconBlockView::has_data_columns(buffer, is_gloas);

        tracing::info!(slot, has_columns, "beacon block recv");

        if !has_columns {
            return None;
        }

        if slot <= self.sync_state.finalized_slot() {
            return None;
        }

        let block_root = util::block_root(buffer, is_gloas);

        if is_gloas {
            self.cache_gloas_commitments(block_root, buffer);
        }

        if self.outstanding_requests.contains(&block_root) {
            return Some((block_root, is_gloas));
        }

        // Custody columns only — silver floors cgc at SAMPLES_PER_SLOT, so the
        // custody set IS the sample set; no beyond-custody sampling needed.
        // These by-root requests race gossip and serve as the fallback when a
        // sidecar isn't delivered on the subscribed subnet.
        let to_request = self.columns_to_request(&block_root);
        if to_request == 0 {
            return Some((block_root, is_gloas));
        }

        self.outstanding_requests.insert(block_root, (to_request, to_request, MAX_RETRIES));

        tracing::trace!(
            block = hex::encode(block_root),
            ?stream_id,
            "data columns by root request: {to_request:b}"
        );

        // EL blob reconstruction parses the Fulu body layout; gloas blobs are
        // fetched from peers by root/range instead.
        if !is_gloas {
            let slot = SignedBeaconBlockView::slot(buffer);
            self.el_fetcher.try_fetch(buffer, block_root, slot, to_request, emit);
        }

        if stream_id.protocol() != StreamProtocol::GossipSub {
            emit(StorageEmit::Peer(self.column_request(block_root, to_request)));
        }
        Some((block_root, is_gloas))
    }

    fn columns_to_request(&self, root: &BlockRoot) -> u128 {
        let validated = self.validated_columns.get(root).copied().unwrap_or(0);
        self.custody_group_columns & !validated
    }

    #[timed]
    fn data_columns<F>(
        &mut self,
        stream_id: P2pStreamId,
        sidecar: TRead,
        is_gloas: bool,
        gossip_subnet: Option<u64>,
        recv_ts: Option<Nanos>,
        emit: &mut F,
    ) -> ColumnDisposition
    where
        F: FnMut(DataColumnsEvent),
    {
        let outcome = match sidecar.buffer() {
            Ok((buf, _)) => {
                if is_gloas {
                    self.validate_gloas_column(stream_id, buf, gossip_subnet)
                } else {
                    self.validate_fulu_column(stream_id, buf, gossip_subnet, recv_ts)
                }
            }
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read data column sidecar buffer");
                return ColumnDisposition::Ignored;
            }
        };
        self.handle_column(outcome, stream_id, sidecar, gossip_subnet, emit)
    }

    fn handle_column<F>(
        &mut self,
        outcome: ColumnOutcome,
        stream_id: P2pStreamId,
        sidecar: TRead,
        gossip_subnet: Option<u64>,
        emit: &mut F,
    ) -> ColumnDisposition
    where
        F: FnMut(DataColumnsEvent),
    {
        match outcome {
            ColumnOutcome::Skip => ColumnDisposition::Ignored,
            ColumnOutcome::Reject { block_root, bitmask } => {
                ColumnDisposition::Rejected { block_root, bitmask }
            }
            ColumnOutcome::Buffer { block_root } => {
                let pending = self.gloas_pending_columns.entry(block_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::debug!(?stream_id, "gloas column before block — buffering");
                    pending.push((stream_id, sidecar, gossip_subnet));
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::AwaitParent { parent_root } => {
                let pending = self.parent_pending_columns.entry(parent_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::info!(?stream_id, "column parent pending — buffering");
                    pending.push((stream_id, sidecar, gossip_subnet));
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::Record { block_root, column_index, bitmask, slot } => {
                self.record_validated_column(
                    block_root,
                    column_index,
                    bitmask,
                    slot,
                    sidecar,
                    stream_id.protocol() == StreamProtocol::GossipSub,
                    emit,
                );
                ColumnDisposition::Validated
            }
        }
    }

    #[timed]
    fn validate_fulu_column(
        &mut self,
        stream_id: P2pStreamId,
        buffer: &[u8],
        gossip_subnet: Option<u64>,
        recv_ts: Option<Nanos>,
    ) -> ColumnOutcome {
        let block_root = util::block_root_from_sidecar(buffer);
        let parent_root = DataColumnSidecarFuluView::parent_root(buffer);
        let slot = DataColumnSidecarFuluView::slot(buffer);

        if slot < self.sync_state.head_slot() {
            tracing::info!(block_root = hex::encode(block_root), slot, "skip old data column");
            return ColumnOutcome::Skip;
        }

        if gossip_subnet.is_some() {
            let elapsed_ms = recv_ts.map(|r| r.elapsed().as_millis_u64());
            tracing::info!(
                slot,
                block_root = hex::encode(block_root),
                parent_root = hex::encode(parent_root),
                ?gossip_subnet,
                ?elapsed_ms,
                "data column recv"
            );
        }

        if self.sync_state.is_synced() && slot > self.sync_state.wall_slot().saturating_add(1) {
            tracing::debug!(
                ?stream_id,
                slot,
                wall_slot = self.sync_state.wall_slot(),
                "post-wall sidecar"
            );
            return ColumnOutcome::Skip;
        }

        let column_index = DataColumnSidecarFuluView::index(buffer);
        let column_bitmask = 1u128 << column_index;

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        let do_parent_checks = stream_id.protocol() == StreamProtocol::GossipSub;

        if self
            .validated_columns
            .get(&block_root)
            .map(|c| c & column_bitmask != 0)
            .unwrap_or_default()
        {
            return ColumnOutcome::Skip;
        }

        if !util::verify_data_column_sidecar_fulu(buffer) {
            tracing::warn!(?stream_id, "badly formed data column sidecar");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }
        if !util::verify_data_column_sidecar_kzg_proofs_fulu(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar kzg proof");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        // Inclusion proof binds the sidecar's `kzg_commitments` to the
        // block's `body_root` — neither input is pinned by block_root, so
        // it must run on every sidecar.
        if !util::verify_data_column_sidecar_inclusion_proof(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar inclusion proof");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        // State-driven validations: pull every input in one seqlock pass.
        // BLS verify runs OUTSIDE the closure (slow; would hold the
        // notional read lock too long otherwise).
        let block_slot = DataColumnSidecarFuluView::slot(buffer);
        let claimed_proposer_index = DataColumnSidecarFuluView::proposer_index(buffer);
        let checks = self.beacon_state.read(&|v| {
            let state_epoch = v.slot.current_epoch();

            let (proposer_matches, parent_validated, is_above_finalized) = if do_parent_checks {
                // proposer_lookahead is anchored to `state_epoch` and covers
                // current+next epochs (PROPOSER_LOOKAHEAD_SIZE = 64). Slots
                // outside that window we cannot resolve here.
                let lookahead_idx = block_slot.wrapping_sub(state_epoch * SLOTS_PER_EPOCH) as usize;
                let expected_proposer = v.epoch.proposer_at(lookahead_idx);
                let parent_validated = util::parent_validated(
                    buffer,
                    v.slot.finalized_block_roots(),
                    v.slot.delta_block_roots(),
                    self.sync_state.head_root(),
                );
                let is_above_finalized =
                    util::is_above_finalized(buffer, v.epoch.state().finalized_checkpoint.epoch);
                (
                    expected_proposer == Some(claimed_proposer_index),
                    parent_validated,
                    is_above_finalized,
                )
            } else {
                // Sync / RPC blocks cannot validate proposer shuffling.
                (true, true, true)
            };

            let idx = claimed_proposer_index as usize;
            let pubkey =
                (idx < v.validators.count()).then(|| *v.validators.pubkey_decompressed(idx));

            (
                is_above_finalized,
                parent_validated,
                proposer_matches,
                pubkey,
                v.epoch.fork().current_version, // TODO for backfill
                v.imm.genesis_validators_root,
            )
        });
        // No snapshot yet (pre-bootstrap): nothing can be validated.
        let Some((above_finalized, parent_validated, proposer_matches, pubkey, fork_version, gvr)) =
            checks
        else {
            tracing::warn!(?stream_id, "sidecar before first beacon state snapshot");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        };

        if !above_finalized {
            tracing::warn!(?stream_id, "sidecar slot at or below finalized — ignoring");
            return ColumnOutcome::Skip;
        }
        // The state view sees only the head fork's chain; the store holds
        // every BS-accepted block (all forks, incl. validated children of the
        // head that aren't head yet).
        let parent_validated = parent_validated || self.persisted_block_roots.contains(parent_root);
        if !parent_validated {
            tracing::warn!(
                ?stream_id,
                block_slot,
                parent_root = hex::encode(parent_root),
                "sidecar parent_root not yet validated — ignoring (not penalized)"
            );
            return ColumnOutcome::AwaitParent { parent_root: *parent_root };
        }
        if !proposer_matches {
            tracing::warn!(?stream_id, "sidecar proposer_index mismatch");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        // BLS verify cache: skip the ~1 ms verify iff the sidecar's
        // signature bytes match a previously-validated signature for
        // this block_root. block_root does not pin the signature, so
        // bytes-equality is required.
        let sig_bytes = *DataColumnSidecarFuluView::block_signature(buffer);
        if self.validated_blocks.get(&block_root) != Some(&sig_bytes) {
            let Some(pubkey) = pubkey else {
                tracing::warn!(?stream_id, "sidecar proposer_index out of range");
                return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
            };
            if !util::verify_proposer_signature(buffer, &pubkey, fork_version, &gvr) {
                tracing::warn!(?stream_id, "sidecar proposer signature invalid");
                return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
            }
            self.validated_blocks.insert(block_root, sig_bytes);
        }

        ColumnOutcome::Record { block_root, column_index, bitmask: column_bitmask, slot }
    }

    fn cache_gloas_commitments(&mut self, block_root: [u8; 32], buffer: &[u8]) {
        if self.gloas_commitments.contains(&block_root) {
            return;
        }
        let commitments = SignedBeaconBlockView::gloas_block_commitments(buffer);
        if !commitments.is_empty() {
            self.gloas_commitments.insert(block_root, commitments.to_vec().into_boxed_slice());
        }
    }

    fn drain_pending_gloas_columns<F>(&mut self, block_root: [u8; 32], emit: &mut F)
    where
        F: FnMut(DataColumnsEvent),
    {
        let pending = self.gloas_pending_columns.remove(&block_root);
        self.drain_entries(pending, true, emit);
    }

    #[timed]
    fn drain_parent_pending_columns<F>(&mut self, parent_root: [u8; 32], emit: &mut F)
    where
        F: FnMut(DataColumnsEvent),
    {
        let pending = self.parent_pending_columns.remove(&parent_root);
        if pending.is_some() {
            tracing::info!(
                root = hex::encode(parent_root),
                "draining data columns for parent root"
            );
        }
        self.drain_entries(pending, false, emit);
    }

    fn drain_entries<F>(
        &mut self,
        pending: Option<Vec<PendingColumn>>,
        is_gloas: bool,
        emit: &mut F,
    ) where
        F: FnMut(DataColumnsEvent),
    {
        let Some(pending) = pending else {
            return;
        };
        for (stream_id, sidecar, gossip_subnet) in pending {
            let outcome = match sidecar.buffer() {
                Ok((buf, _)) => {
                    if is_gloas {
                        self.validate_gloas_column(stream_id, buf, gossip_subnet)
                    } else {
                        self.validate_fulu_column(stream_id, buf, gossip_subnet, None)
                    }
                }
                Err(e) => {
                    tracing::error!(?e, ?stream_id, "failed to read buffered column");
                    continue;
                }
            };
            self.handle_column(outcome, stream_id, sidecar, gossip_subnet, emit);
        }
    }

    #[timed]
    fn validate_gloas_column(
        &mut self,
        stream_id: P2pStreamId,
        buffer: &[u8],
        gossip_subnet: Option<u64>,
    ) -> ColumnOutcome {
        let block_root = *DataColumnSidecarGloasView::beacon_block_root(buffer);
        let slot = DataColumnSidecarGloasView::slot(buffer);

        if self.sync_state.is_synced() && slot > self.sync_state.wall_slot().saturating_add(1) {
            tracing::debug!(
                ?stream_id,
                slot,
                wall_slot = self.sync_state.wall_slot(),
                "post-wall sidecar"
            );
            return ColumnOutcome::Skip;
        }
        if slot <= self.sync_state.finalized_slot() {
            return ColumnOutcome::Skip;
        }

        let column_index = DataColumnSidecarGloasView::index(buffer);
        let column_bitmask = 1u128 << column_index;

        if let Some(subnet) = gossip_subnet &&
            subnet != column_index
        {
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        if self
            .validated_columns
            .get(&block_root)
            .map(|c| c & column_bitmask != 0)
            .unwrap_or_default()
        {
            return ColumnOutcome::Skip;
        }

        let Some(commitments) = self.gloas_commitments.get(&block_root) else {
            return ColumnOutcome::Buffer { block_root };
        };

        if !util::verify_data_column_sidecar_gloas(buffer, commitments) {
            tracing::warn!(?stream_id, "badly formed gloas data column sidecar");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }
        if !util::verify_data_column_sidecar_kzg_proofs_gloas(buffer, commitments) {
            tracing::warn!(?stream_id, "failed to verify gloas sidecar kzg proof");
            return ColumnOutcome::Reject { block_root, bitmask: column_bitmask };
        }

        ColumnOutcome::Record { block_root, column_index, bitmask: column_bitmask, slot }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_validated_column<F>(
        &mut self,
        block_root: [u8; 32],
        column_index: u64,
        column_bitmask: u128,
        slot: u64,
        sidecar: TRead,
        is_gossip: bool,
        emit: &mut F,
    ) where
        F: FnMut(DataColumnsEvent),
    {
        let mut completion_check = self.custody_group_columns;

        if let Some((mut requested, full_set, retries)) =
            self.outstanding_requests.remove(&block_root)
        {
            requested &= !column_bitmask;
            completion_check = full_set;
            if requested != 0 {
                // more column responses pending
                self.outstanding_requests.insert(block_root, (requested, full_set, retries));
            }
        }

        let validated = self.validated_columns.entry(block_root).or_default();
        *validated |= column_bitmask;
        let validated = *validated;

        if validated & completion_check == completion_check {
            // have all validated data columns for the block.
            StorageCounters::DataColumnsAvailableEmitted.inc();
            tracing::info!(
                block = hex::encode(block_root),
                slot,
                "DataColumnsAvailable: custody set complete"
            );
            emit(DataColumnsEvent::Available { block_root, slot })
        }

        if column_bitmask & self.custody_group_columns != 0 {
            // emit persist msg
            let source = if is_gossip { ColumnSource::Gossip } else { ColumnSource::Rpc };
            emit(DataColumnsEvent::Persist {
                ssz: sidecar.read,
                source,
                block_root,
                column_index,
                slot,
            })
        }
    }

    #[timed]
    fn handle_beacon_block(
        &mut self,
        t_read: TRead,
        stream_id: P2pStreamId,
        producers: &mut SilverSpineProducers,
    ) {
        let parent_root = t_read
            .buffer()
            .ok()
            .filter(|(buf, _)| SignedBeaconBlockView::check_size(buf))
            .map(|(buf, _)| *SignedBeaconBlockView::parent_root(buf));

        let root = self.beacon_block(stream_id, t_read, &mut |emit| match emit {
            StorageEmit::Peer(evt) => {
                producers.peer_events.produce(&evt.into());
            }
            StorageEmit::Engine(req) => {
                producers.engine_reqs.produce(&req.into());
            }
        });

        if let Some((block_root, is_gloas)) = root &&
            is_gloas
        {
            self.drain_pending_gloas_columns(block_root, &mut |msg| {
                producers.data_columns.produce(&msg.into());
            });
        }
        if let Some(parent_root) = parent_root {
            self.drain_parent_pending_columns(parent_root, &mut |msg| {
                producers.data_columns.produce(&msg.into());
            });
        }
    }

    #[timed]
    fn handle_data_column_sidecar(
        &mut self,
        t_read: TRead,
        stream_id: P2pStreamId,
        is_gloas: bool,
        gossip_subnet: Option<u64>,
        recv_ts: Option<Nanos>,
        producers: &mut SilverSpineProducers,
    ) -> bool {
        let emit_da = &mut |msg: DataColumnsEvent| {
            producers.data_columns.produce(&msg.into());
        };

        match self.data_columns(stream_id, t_read, is_gloas, gossip_subnet, recv_ts, emit_da) {
            ColumnDisposition::Validated => true,
            ColumnDisposition::Ignored => false,
            ColumnDisposition::Rejected { block_root, bitmask } => {
                // Score down the peer and retransmit.
                producers.peer_events.produce(
                    &PeerEvent::RpcMisbehaviour {
                        p2p_peer: stream_id.peer(),
                        severity: RpcSeverity::Fatal,
                    }
                    .into(),
                );
                producers.peer_events.produce(&self.column_request(block_root, bitmask).into());
                false
            }
        }
    }
}

impl DataColumnsTile {
    #[timed]
    fn handle_beacon_state_event(
        &mut self,
        event: BeaconStateEvent,
        producers: &mut SilverSpineProducers,
    ) -> Option<([u8; 92], u64)> {
        let mut latest_status_event: Option<([u8; 92], u64)> = None;
        match event {
            BeaconStateEvent::Status { ssz, wall_slot, .. } => {
                // Per-event (not latest-only): BS emits one Status per accepted
                // block, and each newly validated root may unblock buffered
                // children.
                self.drain_parent_pending_columns(*StatusView::head_root(&ssz), &mut |msg| {
                    producers.data_columns.produce(&msg.into());
                });
                latest_status_event = Some((ssz, wall_slot));
            }
            BeaconStateEvent::PersistBlock { ssz, source } => {
                let t_read = match source {
                    silver_common::BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    silver_common::BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        let block_root = util::block_root_fulu(buf);

                        // record persisted block roots for use in parent check
                        self.persisted_block_roots.insert(block_root, ());

                        // This block just got BS-accepted: it may be the
                        // missing parent of buffered columns.
                        self.drain_parent_pending_columns(block_root, &mut |msg| {
                            producers.data_columns.produce(&msg.into());
                        });
                    }
                    Err(e) => {
                        tracing::error!(?e, seq=t_read.seq(), consumer=?self.persist_gossip_consumer, "persist consumer buffer acquire failed");
                    }
                }
            }
            _ => {}
        }
        latest_status_event
    }
}

impl Tile<SilverSpine> for DataColumnsTile {
    fn try_init(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        util::warm_kzg_settings();
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|d: SyncingStrategy, _| self.syncing_strategy = Some(d));

        self.gossip_consumer.free();
        self.rpc_consumer.free();
        self.persist_gossip_consumer.free();
        self.persist_rpc_consumer.free();

        // Check for data columns and incoming blocks with data columns via gossip.
        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock if self.sync_state.is_synced() => {
                let t_read: TRead = self.gossip_consumer.acquire(gossip.ssz);
                self.handle_beacon_block(t_read, gossip.stream_id, producers);
            }
            silver_common::GossipTopic::DataColumnSidecar(custody_group)
                if self.sync_state.is_synced() =>
            {
                tracing::debug!(custody_group, "data column sidecar over gossip");

                let t_read = self.gossip_consumer.acquire(gossip.ssz);

                let is_gloas = self.spec.is_gloas_at_slot(self.sync_state.head_slot() + 1);
                if self.handle_data_column_sidecar(
                    t_read,
                    gossip.stream_id,
                    is_gloas,
                    Some(custody_group),
                    Some(gossip.recv_ts),
                    producers,
                ) {
                    producers.peer_events.produce(
                        &PeerEvent::SendGossip {
                            originator_stream_id: gossip.stream_id,
                            topic: gossip.topic,
                            msg_hash: gossip.msg_hash,
                            recv_ts: gossip.recv_ts,
                            protobuf: gossip.protobuf,
                        }
                        .into(),
                    );
                }
            }
            _ => {}
        });

        // Check for data columns and incoming blocks via RPC.
        adapter.consume(|rpc: RpcInbound, producers| match rpc {
            RpcInbound::Request(_) => {}
            RpcInbound::Response(rsp) => match rsp.response {
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz }
                    if self.sync_state.is_synced() && !msg_is_backfill(rsp.application_id) =>
                {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.handle_beacon_block(t_read, rsp.stream_id, producers);
                }
                // Forward-sync (not synced): cache each gloas block's bid
                // commitments so its data columns can be KZG-verified as they
                // range-sync, then drain any columns that arrived before it.
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz } if !msg_is_backfill(rsp.application_id) => {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    if let Ok((buf, _)) = t_read.buffer() &&
                        SignedBeaconBlockView::check_size(buf)
                    {
                        let is_gloas = self.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(buf));
                        let parent_root = *SignedBeaconBlockView::parent_root(buf);
                        if is_gloas {
                            let block_root = util::block_root(buf, is_gloas);
                            self.cache_gloas_commitments(block_root, buf);
                            self.drain_pending_gloas_columns(block_root, &mut |msg| {
                                producers.data_columns.produce(&msg.into());
                            });
                        }
                        self.drain_parent_pending_columns(parent_root, &mut |msg| {
                            producers.data_columns.produce(&msg.into());
                        });
                    }
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if msg_is_live_column_request(rsp.application_id) => {
                    // TODO validate that originating peer has data column index in custody groups
                    tracing::debug!("data column sidecar over rpc");
                    let t_read = self.rpc_consumer.acquire(ssz);
                    let is_gloas = msg_is_post_gloas(rsp.application_id);

                    let Ok((buffer, _)) = t_read.buffer() else {
                        return;
                    };
                    let column_index = if is_gloas {
                        DataColumnSidecarGloasView::index(buffer)
                    } else {
                        DataColumnSidecarFuluView::index(buffer)
                    };

                    if self.handle_data_column_sidecar(t_read, rsp.stream_id, is_gloas, None, None, producers) {
                        if self.sync_state.is_synced() {
                            // Publish to gossip
                            producers.peer_events.produce(&PeerEvent::PublishDataColumn {
                                originator: rsp.stream_id,
                                topic: GossipTopic::DataColumnSidecar(column_index),
                                ssz,
                            }.into());
                        }
                    }
                }
                silver_common::RpcResponse::Error { error, msg, len } if msg_is_live_column_request(rsp.application_id) => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "rpc error response");
                }
                other => {
                    tracing::trace!(?other, app_id=rsp.application_id, id=?rsp.stream_id, "ignoring rpc response");
                }
            },
        });

        adapter.consume(|beacon_event: BeaconStateEvent, producers| {
            if let Some((ssz, wall_slot)) = self.handle_beacon_state_event(beacon_event, producers)
            {
                self.sync_state.update(ssz, wall_slot);
            }
        });

        adapter.consume(|sync_update: SyncUpdate, _| match sync_update {
            SyncUpdate::Following => self.sync_state.update_synced(true),
            _ => self.sync_state.update_synced(false),
        });

        // EL-mempool blob responses (engine_getBlobsV2). Broadcast queue — we
        // only act on GetBlobs; the rest are the beacon-state tile's.
        adapter.consume(|resp: EngineResp, producers| {
            if let EngineResp::GetBlobs(r) = resp {
                self.el_fetcher.handle_response(
                    r,
                    &mut self.validated_columns,
                    &mut self.outstanding_requests,
                    &self.sync_state,
                    self.custody_group_columns,
                    &mut self.el_column_producer,
                    &mut |msg| {
                        producers.data_columns.produce(&msg.into());
                    },
                );
            }
        });
        self.el_fetcher.free();

        let now = Instant::now();

        // Age out per-block validation memo.
        self.validated_blocks.maybe_rotate(now, &mut |_, _| true);
        // Age out validated columns.
        self.validated_columns.maybe_rotate(now, &mut |_, _| true);
        // Age out cached columns and commitments
        self.parent_pending_columns.maybe_rotate(now, &mut |_, _| true);
        self.gloas_pending_columns.maybe_rotate(now, &mut |_, _| true);
        self.gloas_commitments.maybe_rotate(now, &mut |_, _| true);
        self.persisted_block_roots.maybe_rotate(now, &mut |_, _| true);

        // Age out EL blob fetches the engine never answered (the p2p race
        // covers those columns); answered ones are removed on response.
        self.el_fetcher.rotate(now);

        // Timeout any pending requests and re-issue
        let mut request_id = self.request_id;
        let mut wheel_resent = 0usize;
        self.outstanding_requests.maybe_rotate(now, &mut |block_root, (columns, _, retries)| {
            if *retries == 0 {
                return true; // remove
            }
            request_id += 1;
            wheel_resent += 1;
            tracing::info!(
                block_root = hex::encode(block_root),
                "resending outstanding data column request: {columns:b}"
            );
            adapter.produce(PeerEvent::SendDataColumnsByRootRequest {
                request_id,
                columns: *columns,
                block_root: *block_root,
            });

            *retries -= 1;
            false
        });

        self.request_id = request_id;
        // by-root wheel re-request volume per rotation (a large sustained
        // number is the ds_incoming_rpc flood source).
        if wheel_resent > 0 {
            tracing::debug!(wheel_resent, "by-root column wheel re-sent");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use silver_beacon_state_data::BeaconStateOwner;
    use silver_common::{P2pStreamId, StreamProtocol, TCache, TCacheProducer};

    use super::*;

    #[test]
    fn test_beacon_block_rpc_requests_custody_columns() {
        let store_dir = format!("/tmp/test_storage_tile_gossip_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_dir);

        let custody_columns = (1u128 << 3) | (1u128 << 7);

        let gossip_tc = TCache::producer("gossip_blocks", 1024 * 1024);
        let gossip_consumer = gossip_tc.cache_ref().random_access("gossip_cons", true).unwrap();

        let persist_gossip_tc = TCache::producer("persist_gossip_blocks", 1024 * 1024);
        let persist_gossip_consumer =
            persist_gossip_tc.cache_ref().random_access("persist_gossip_cons", true).unwrap();

        let rpc_tc = TCache::producer("rpc_blocks", 1024 * 1024);
        let rpc_consumer = rpc_tc.cache_ref().random_access("rpc_cons", true).unwrap();

        let persist_rpc_tc = TCache::producer("persist_rpc_blocks", 1024 * 1024);
        let persist_rpc_consumer =
            persist_rpc_tc.cache_ref().random_access("persist_rpc_cons", true).unwrap();

        let el_columns_tc = TCache::producer("el_columns", 1024 * 1024);

        // Unused here (no EL path exercised); only satisfies the constructor.
        let engine_resp_tc = TCache::producer("engine_resp", 1024 * 1024);
        let engine_resp_consumer =
            engine_resp_tc.cache_ref().random_access("engine_resp_cons", true).unwrap();

        let beacon_state = BeaconStateOwner::empty_test(0).reader();

        let mut tile = DataColumnsTile::new(
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            beacon_state,
            custody_columns,
            Arc::new(SpecConfig::mainnet()),
            engine_resp_consumer,
            el_columns_tc,
        );

        let mut block_bytes = vec![0u8; 784];
        // Set message offset to 100
        block_bytes[0..4].copy_from_slice(&100u32.to_le_bytes());
        // Set slot to 42 at [100..108)
        block_bytes[100..108].copy_from_slice(&42u64.to_le_bytes());
        // Body offset at [180..184) relative to 100: let's make it 84
        block_bytes[180..184].copy_from_slice(&84u32.to_le_bytes());

        // Inside body (starts at 184):
        // blob_kzg_commitments_offset at body[388..392]
        block_bytes[184 + 388..184 + 392].copy_from_slice(&400u32.to_le_bytes());
        // execution_requests_offset at body[392..396]
        block_bytes[184 + 392..184 + 396].copy_from_slice(&500u32.to_le_bytes());

        let mut producer = TCache::producer("test_block_prod", 1024 * 1024);
        let mut res = producer.reserve(block_bytes.len(), true).unwrap();
        res.write_all(&block_bytes).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut blocks_consumer =
            producer.cache_ref().random_access("test_block_cons", true).unwrap();
        let read = blocks_consumer.acquire(ssz);

        let block_root = util::block_root_fulu(&block_bytes);
        let rpc_stream = P2pStreamId::new(2, 2, StreamProtocol::BeaconBlocksByRange, true);

        // Once synced, an RPC block requests its custody columns by root.
        tile.sync_state.update_synced(true);
        let mut rpc_events = Vec::new();
        tile.beacon_block(rpc_stream, read.clone(), &mut |emit| {
            if let StorageEmit::Peer(evt) = emit {
                rpc_events.push(evt);
            }
        });
        assert_eq!(rpc_events.len(), 1);
        if let PeerEvent::SendDataColumnsByRootRequest { columns, block_root: req_root, .. } =
            rpc_events[0]
        {
            assert_eq!(columns, custody_columns);
            assert_eq!(req_root, block_root);
        } else {
            panic!("expected SendDataColumnsByRootRequest");
        }

        // Clean up outstanding request to allow requesting the same block root again
        tile.outstanding_requests.remove(&block_root);

        let _ = std::fs::remove_dir_all(&store_dir);
    }
}
