use std::{
    collections::VecDeque,
    fs::File,
    io::Read,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    BASE_REQUEST_ID, BeaconStateEvent, DataColumnsAvailable, EngineReq, EngineResp, NewGossipMsg,
    P2pSend, P2pStreamId, PeerControl, PeerEvent, ReplayBlock, RpcInbound, RpcSeverity,
    SilverSpine, SilverSpineProducers, StreamProtocol, SyncUpdate, SyncingStrategy, TCacheProducer,
    TMultiProducer, TProducer, TRandomAccess, TRead, Wheel, msg_is_backfill,
    msg_is_column_backfill, msg_is_live_column_request, msg_is_post_gloas,
    ssz_view::{
        DataColumnSidecarFuluView, DataColumnSidecarGloasView, NUMBER_OF_COLUMNS,
        SignedBeaconBlockView, StatusView,
    },
};

use crate::{StorageCounters, el_blobs::ElBlobFetcher, store::Store, util};
const MAX_RETRIES: u8 = 5;

/// Fallback: if control's replay-vs-sync decision is never received, default
/// `drive_replay` to replaying the on-disk chain after this long.
const SYNCING_STRATEGY_FALLBACK: Duration = Duration::from_secs(45);

const MAX_REPLAY_BLOCKS_PER_LOOP: usize = 16;

/// Persist a finalized-state checkpoint only when within this many slots of
/// the wall-clock head (i.e. not fast-syncing) — avoids stalling the writer
/// and re-encoding every intermediate finalized epoch while catching up.
const CAUGHT_UP_SLACK_SLOTS: u64 = 2 * SLOTS_PER_EPOCH;

/// Mainnet epoch: 32 slots × 12s. Wheel bucket width for the
/// block-level validation cache.
const EPOCH_DURATION: Duration = Duration::from_secs(32 * 12);

/// SSZ `hash_tree_root(BeaconBlockHeader)` — the same value carried as
/// `head_root` in Status RPC and `block_root` in
/// `DataColumnsByRootIdentifier`. Keys `validated_columns` so ByRoot
/// lookups and head-update integration are direct lookups.
type BlockRoot = [u8; 32];

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
    Record { block_root: [u8; 32], column_index: u64, bitmask: u128, slot: u64 },
}

pub struct StorageTile {
    // bit set of our custody group columns.
    custody_group_columns: u128,
    request_id: u64,
    // Gossip and rpc are read twice: 'live' and when we receive a request from
    // beacon state to persist - this require 2 consumers.
    gossip_consumer: TRandomAccess,
    persist_gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
    persist_rpc_consumer: TRandomAccess,
    rpc_producer: TMultiProducer,
    beacon_state: BeaconStateReader,
    store: Store,
    fork_digest: [u8; 4], // fork digest

    spec: Arc<SpecConfig>,

    // keyed by block body root
    validated_columns: Wheel<BlockRoot, u128, 4>,
    // Gloas sidecars carry no commitments, so column KZG verifies against these.
    gloas_commitments: Wheel<BlockRoot, Box<[u8]>, 4>,
    // Gloas: columns whose block (hence commitments) hasn't been seen yet.
    gloas_pending_columns: Wheel<BlockRoot, Vec<(P2pStreamId, TRead)>, 4>,
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

    // Highest Status finalized epoch we've scheduled a checkpoint for; dedups
    // the trigger so we encode at most once per finalized-epoch advance.
    // Advanced when a persist is queued; re-derived from disk on restart.
    checkpointed_epoch: u64,
    // Set by a Status when finality advanced past the last persisted epoch and
    // we are caught up to head; consumed when a persist is started (the
    // in-flight checkpoint then lives on the `Store`, driven by `file_io`).
    persist_pending: bool,

    replay_blocks: VecDeque<(PathBuf, bool)>,
    replay_producer: TProducer,
    replay_done: bool,
    /// Boot decision from control: `None` = waiting; gates `drive_replay` so we
    /// don't replay the on-disk fork tree before learning whether peers are
    /// finalized ahead (in which case we skip it and range-sync from them).
    syncing_strategy: Option<SyncingStrategy>,
    /// Tile construction time; bounds how long `drive_replay` waits on the
    /// decision before defaulting to replay (control signal lost).
    created_at: Instant,
    peers_loaded: bool,

    el_fetcher: ElBlobFetcher,
}

impl StorageTile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gossip_consumer: TRandomAccess,
        persist_gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        persist_rpc_consumer: TRandomAccess,
        rpc_producer: TMultiProducer,
        replay_producer: TProducer,
        beacon_state: BeaconStateReader,
        custody_group_columns: u128,
        fork_digest: [u8; 4],
        spec: Arc<SpecConfig>,
        data_store_dir: String,
        replay_from_disk: bool,
        engine_resp_consumer: TRandomAccess,
    ) -> Self {
        let store = Store::load(data_store_dir).expect("failed to load storage store");
        let checkpointed_epoch = store.last_persisted_finalized_slot() / SLOTS_PER_EPOCH;
        let replay_blocks = if replay_from_disk {
            let mut paths = store.replay_block_paths(custody_group_columns);
            paths.sort_unstable_by_key(|(slot, _, _)| *slot);
            paths.into_iter().map(|(_, path, cols)| (path, cols)).collect()
        } else {
            VecDeque::new()
        };
        tracing::info!("have {} replay block paths", replay_blocks.len());

        Self {
            custody_group_columns,
            request_id: BASE_REQUEST_ID,
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            rpc_producer,
            beacon_state,
            store,
            fork_digest,
            spec,
            validated_columns: Wheel::new(EPOCH_DURATION),
            gloas_commitments: Wheel::new(EPOCH_DURATION),
            gloas_pending_columns: Wheel::new(EPOCH_DURATION),
            validated_blocks: Wheel::new(EPOCH_DURATION),
            outstanding_requests: Wheel::new(Duration::from_millis(100)),
            checkpointed_epoch,
            persist_pending: false,
            replay_blocks,
            replay_producer,
            replay_done: !replay_from_disk,
            syncing_strategy: None,
            created_at: Instant::now(),
            peers_loaded: false,
            el_fetcher: ElBlobFetcher::new(engine_resp_consumer),
        }
    }

    fn drive_replay(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.replay_done {
            return;
        }

        let strategy = match self.syncing_strategy {
            Some(d) => d,
            None if self.created_at.elapsed() >= SYNCING_STRATEGY_FALLBACK => {
                SyncingStrategy::ReplayDisk
            }
            None => return,
        };
        if matches!(strategy, SyncingStrategy::SyncFromPeers) {
            tracing::info!(
                staged = self.replay_blocks.len(),
                "skipping on-disk replay; peers finalized ahead — syncing from peers"
            );
            self.replay_blocks.clear();
            adapter.produce(ReplayBlock::Done);
            self.replay_done = true;
            return;
        }

        let mut sent = 0;
        while sent < MAX_REPLAY_BLOCKS_PER_LOOP {
            let Some(&(ref path, cols_on_disk)) = self.replay_blocks.front() else {
                break;
            };

            let (mut file, len) = match File::open(path).and_then(|f| {
                let len = f.metadata()?.len() as usize;
                Ok((f, len))
            }) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(?e, ?path, "replay block open failed; skipping");
                    self.replay_blocks.pop_front();
                    continue;
                }
            };

            let Some(mut reservation) = self.replay_producer.reserve(len, true) else {
                return; // tcache full — retry next loop
            };
            let buf = match reservation.buffer() {
                Ok(buf) => buf,
                Err(e) => {
                    tracing::error!(?e, "replay reservation buffer failed; skipping");
                    self.replay_blocks.pop_front();
                    continue;
                }
            };
            if let Err(e) = file.read_exact(&mut buf[..len]) {
                tracing::error!(?e, ?path, "replay block read failed; skipping");
                self.replay_blocks.pop_front();
                continue;
            }

            // TODO: request the missing columns instead of dropping?
            let block = &buf[..len];
            if !cols_on_disk &&
                SignedBeaconBlockView::check_size(block) &&
                SignedBeaconBlockView::has_data_columns_fulu(block)
            {
                tracing::warn!(?path, "replay skip: custody columns missing on disk");
                self.replay_blocks.pop_front();
                continue;
            }

            reservation.increment_offset(len);
            adapter.produce(ReplayBlock::Block { ssz: reservation.read() });
            self.replay_blocks.pop_front();
            sent += 1;
        }

        if self.replay_blocks.is_empty() {
            adapter.produce(ReplayBlock::Done);
            self.replay_done = true;
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
    ) -> Option<B256>
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

        let is_gloas = self.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(buffer));

        let has_columns = SignedBeaconBlockView::has_data_columns(buffer, is_gloas);
        if !has_columns {
            return None;
        }

        if SignedBeaconBlockView::slot(buffer) <= self.store.finalized_slot() {
            return None;
        }

        let block_root = util::block_root(buffer, is_gloas);

        if is_gloas {
            self.cache_gloas_commitments(block_root, buffer);
        }
        // idk
        let gloas_root = is_gloas.then_some(block_root);

        if self.outstanding_requests.contains(&block_root) {
            return gloas_root;
        }

        // Custody columns only — silver floors cgc at SAMPLES_PER_SLOT, so the
        // custody set IS the sample set; no beyond-custody sampling needed.
        // These by-root requests race gossip and serve as the fallback when a
        // sidecar isn't delivered on the subscribed subnet.
        let mut to_request = self.custody_group_columns;
        let validated = self.validated_columns.get(&block_root).copied().unwrap_or(0);
        to_request &= !validated;

        if to_request == 0 {
            return gloas_root;
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
        gloas_root
    }

    #[inline]
    fn data_columns<F>(
        &mut self,
        stream_id: P2pStreamId,
        sidecar: TRead,
        is_gloas: bool,
        emit: &mut F,
    ) -> Option<([u8; 32], u128)>
    where
        F: FnMut(DataColumnsAvailable),
    {
        let outcome = match sidecar.buffer() {
            Ok((buf, _)) => {
                if is_gloas {
                    self.validate_gloas_column(stream_id, buf)
                } else {
                    self.validate_fulu_column(stream_id, buf)
                }
            }
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read data column sidecar buffer");
                return None;
            }
        };
        self.handle_column(outcome, stream_id, sidecar, emit)
    }

    fn handle_column<F>(
        &mut self,
        outcome: ColumnOutcome,
        stream_id: P2pStreamId,
        sidecar: TRead,
        emit: &mut F,
    ) -> Option<([u8; 32], u128)>
    where
        F: FnMut(DataColumnsAvailable),
    {
        match outcome {
            ColumnOutcome::Skip => None,
            ColumnOutcome::Reject { block_root, bitmask } => Some((block_root, bitmask)),
            ColumnOutcome::Buffer { block_root } => {
                let pending = self.gloas_pending_columns.entry(block_root).or_default();
                if pending.len() >= NUMBER_OF_COLUMNS {
                    return None;
                }
                tracing::debug!(?stream_id, "gloas column before block — buffering");
                pending.push((stream_id, sidecar));
                None
            }
            ColumnOutcome::Record { block_root, column_index, bitmask, slot } => {
                self.record_validated_column(block_root, column_index, bitmask, slot, sidecar, emit)
            }
        }
    }

    #[timed]
    fn validate_fulu_column(&mut self, stream_id: P2pStreamId, buffer: &[u8]) -> ColumnOutcome {
        let block_root = util::block_root_from_sidecar(buffer);
        let parent_root = DataColumnSidecarFuluView::parent_root(buffer);
        let slot = DataColumnSidecarFuluView::slot(buffer);

        if self.store.is_synced() && slot > self.store.head_slot() + 1 {
            // received data columns with parent ahead of current head
            // data column request will be retried
            return ColumnOutcome::Skip;
        }

        let column_index = DataColumnSidecarFuluView::index(buffer);
        let column_bitmask = 1u128 << column_index;

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
                    self.store.head_root(),
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
            tracing::debug!(?stream_id, "sidecar slot at or below finalized — ignoring");
            return ColumnOutcome::Skip;
        }
        if !parent_validated {
            tracing::debug!(
                ?stream_id,
                block_slot,
                parent_root = hex::encode(parent_root),
                "sidecar parent_root not yet validated — ignoring (not penalized)"
            );
            return ColumnOutcome::Skip;
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
        F: FnMut(DataColumnsAvailable),
    {
        if let Some(pending) = self.gloas_pending_columns.remove(&block_root) {
            for (stream_id, sidecar) in pending {
                let outcome = match sidecar.buffer() {
                    Ok((buf, _)) => self.validate_gloas_column(stream_id, buf),
                    Err(e) => {
                        tracing::error!(?e, ?stream_id, "failed to read buffered gloas column");
                        continue;
                    }
                };
                self.handle_column(outcome, stream_id, sidecar, emit);
            }
        }
    }

    #[timed]
    fn validate_gloas_column(&mut self, stream_id: P2pStreamId, buffer: &[u8]) -> ColumnOutcome {
        let block_root = *DataColumnSidecarGloasView::beacon_block_root(buffer);
        let slot = DataColumnSidecarGloasView::slot(buffer);

        if self.store.is_synced() && slot > self.store.head_slot() + 1 {
            return ColumnOutcome::Skip;
        }
        if slot <= self.store.finalized_slot() {
            return ColumnOutcome::Skip;
        }

        let column_index = DataColumnSidecarGloasView::index(buffer);
        let column_bitmask = 1u128 << column_index;

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

    fn record_validated_column<F>(
        &mut self,
        block_root: [u8; 32],
        column_index: u64,
        column_bitmask: u128,
        slot: u64,
        sidecar: TRead,
        emit: &mut F,
    ) -> Option<([u8; 32], u128)>
    where
        F: FnMut(DataColumnsAvailable),
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
            emit(DataColumnsAvailable { block_root, slot })
        }

        if column_bitmask & self.custody_group_columns != 0 {
            // Add to store. Keyed by block_root while unfinalized; the store
            // routes to the flat finalized layout once slot <= finalized.
            self.store.add_data_column(block_root, column_index, sidecar, slot);
        }

        None
    }

    fn handle_beacon_block(
        &mut self,
        t_read: TRead,
        stream_id: P2pStreamId,
        producers: &mut SilverSpineProducers,
    ) {
        let gloas_root = self.beacon_block(stream_id, t_read, &mut |emit| match emit {
            StorageEmit::Peer(evt) => {
                producers.peer_events.produce(&evt.into());
            }
            StorageEmit::Engine(req) => {
                producers.engine_reqs.produce(&req.into());
            }
        });

        if let Some(block_root) = gloas_root {
            self.drain_pending_gloas_columns(block_root, &mut |msg| {
                producers.data_columns.produce(&msg.into());
            });
        }
    }

    fn handle_data_column_sidecar(
        &mut self,
        t_read: TRead,
        stream_id: P2pStreamId,
        is_gloas: bool,
        producers: &mut SilverSpineProducers,
    ) {
        let emit_da = &mut |msg: DataColumnsAvailable| {
            producers.data_columns.produce(&msg.into());
        };

        let Some((block_root, columns)) = self.data_columns(stream_id, t_read, is_gloas, emit_da)
        else {
            return;
        };

        // Validation failed - score down the peer and retransmit
        producers.peer_events.produce(
            &PeerEvent::RpcMisbehaviour {
                p2p_peer: stream_id.peer(),
                severity: RpcSeverity::Fatal,
            }
            .into(),
        );
        producers.peer_events.produce(&self.column_request(block_root, columns).into());
    }
}

impl Tile<SilverSpine> for StorageTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|d: SyncingStrategy, _| self.syncing_strategy = Some(d));
        self.drive_replay(adapter);

        self.gossip_consumer.free();
        self.rpc_consumer.free();
        self.persist_gossip_consumer.free();
        self.persist_rpc_consumer.free();

        // Check for data columns and incoming blocks with data columns via gossip.
        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock if self.store.is_synced() => {
                let t_read: TRead = self.gossip_consumer.acquire(gossip.ssz);
                self.handle_beacon_block(t_read, gossip.stream_id, producers);
            }
            silver_common::GossipTopic::DataColumnSidecar(_custody_group)
                if self.store.is_synced() =>
            {
                // TODO validate that topic group matches sidecar column index
                tracing::debug!(_custody_group, "data column sidecar over gossip");

                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                // Gossip is `is_synced`-gated, so head ≈ wall selects the layout.
                let is_gloas = self.spec.is_gloas_at_slot(self.store.head_slot() + 1);
                self.handle_data_column_sidecar(t_read, gossip.stream_id, is_gloas, producers);
            }
            _ => {}
        });

        // Check for data columns and incoming blocks via RPC.
        adapter.consume(|rpc: RpcInbound, producers| match rpc {
            RpcInbound::Request(req) => {
                self.store.rpc_request(&mut self.rpc_consumer, req);
            }
            RpcInbound::Response(rsp) => match rsp.response {
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz }
                    if msg_is_backfill(rsp.application_id) =>
                {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.store.backfill_block(t_read);
                }
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz }
                    if self.store.is_synced() =>
                {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.handle_beacon_block(t_read, rsp.stream_id, producers);
                }
                // Forward-sync (not synced): cache each gloas block's bid
                // commitments so its data columns can be KZG-verified as they
                // range-sync, then drain any columns that arrived before it.
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz } => {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    if let Ok((buf, _)) = t_read.buffer() &&
                        self.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(buf)) &&
                        SignedBeaconBlockView::check_size(buf)
                    {
                        let block_root = util::block_root_gloas(buf);
                        self.cache_gloas_commitments(block_root, buf);
                        self.drain_pending_gloas_columns(block_root, &mut |msg| {
                            producers.data_columns.produce(&msg.into());
                        });
                    }
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if msg_is_column_backfill(rsp.application_id) => {
                    tracing::debug!("backfill data column sidecar over rpc");
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.store.backfill_data_column(t_read, &mut |evt| {
                        producers.peer_events.produce(&evt.into());
                    });
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => {
                    // TODO validate that originating peer has data column index in custody groups
                    tracing::debug!("data column sidecar over rpc");
                    let t_read = self.rpc_consumer.acquire(ssz);
                    let is_gloas = msg_is_post_gloas(rsp.application_id);
                    self.handle_data_column_sidecar(t_read, rsp.stream_id, is_gloas, producers);
                }
                silver_common::RpcResponse::Error { error, msg, len } if msg_is_column_backfill(rsp.application_id)=> {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "column backfill rpc error response");
                }
                silver_common::RpcResponse::Error { error, msg, len } if msg_is_backfill(rsp.application_id)=> {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "backfill rpc error response");
                }
                silver_common::RpcResponse::Error { error, msg, len } if msg_is_live_column_request(rsp.application_id) => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "rpc error response");
                }
                // Backfill block/column stream terminators: completion is the
                // SyncEngine's (it owns the request lifecycle); storage just
                // writes payloads + tracks per-block column completeness.
                silver_common::RpcResponse::Complete
                    if msg_is_backfill(rsp.application_id) || msg_is_backfill(rsp.application_id) => {}
                other => {
                    tracing::trace!(?other, app_id=rsp.application_id, id=?rsp.stream_id, "ignoring rpc response");
                }
            },
        });

        let mut latest_status_event = None;

        adapter.consume(|beacon_event: BeaconStateEvent, _| match beacon_event {
            BeaconStateEvent::Status { ssz, wall_slot, .. } => {
                latest_status_event = Some((ssz, wall_slot));
            }
            BeaconStateEvent::PersistBlock {
                ssz,
                source,
            } => {
                let t_read = match source {
                    silver_common::BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    silver_common::BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        use silver_common::ssz_view::SignedBeaconBlockView;
                        let slot = SignedBeaconBlockView::slot(buf);
                        let parent_root = *SignedBeaconBlockView::parent_root(buf);
                        let block_root = util::block_root_fulu(buf);
                        self.store.add_block(block_root, t_read, slot, parent_root);
                    }
                    Err(e) => {
                        tracing::error!(?e, seq=t_read.seq(), consumer=?self.persist_gossip_consumer, "persist consumer buffer acquire failed");
                    }
                }
            }
            _ => {}
        });

        if let Some((ssz, wall_slot)) = latest_status_event {
            let head_slot = StatusView::head_slot(&ssz);
            let head_root = *StatusView::head_root(&ssz);
            let finalized_epoch = StatusView::finalized_epoch(&ssz);
            let finalized_root = *StatusView::finalized_root(&ssz);
            self.fork_digest = *StatusView::fork_digest(&ssz);
            self.store.update_head(
                head_slot,
                head_root,
                finalized_epoch * SLOTS_PER_EPOCH,
                finalized_root,
            );

            if finalized_epoch > self.checkpointed_epoch &&
                head_slot + CAUGHT_UP_SLACK_SLOTS >= wall_slot
            {
                self.checkpointed_epoch = finalized_epoch;
                self.persist_pending = true;
            }
        }

        adapter.consume(|sync_update: SyncUpdate, _| self.store.sync_update(sync_update));

        adapter.consume(|peer_control: PeerControl, _| {
            if let PeerControl::PersistPeer { enr } = peer_control {
                self.store.persist_peer(enr);
            }
        });

        if !self.peers_loaded {
            self.peers_loaded = true;
            self.store.load_peers();
        }

        // EL-mempool blob responses (engine_getBlobsV2). Broadcast queue — we
        // only act on GetBlobs; the rest are the beacon-state tile's.
        adapter.consume(|resp: EngineResp, producers| {
            if let EngineResp::GetBlobs(r) = resp {
                self.el_fetcher.handle_response(
                    r,
                    &mut self.store,
                    &mut self.validated_columns,
                    &mut self.outstanding_requests,
                    self.custody_group_columns,
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
            tracing::trace!(
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

        // Start a checkpoint persist when one is pending and none is in flight;
        // `file_io` then streams it one section per turn and commits at the end.
        if self.persist_pending && !self.store.checkpoint_in_flight() {
            self.persist_pending = false;
            self.store.begin_checkpoint(self.beacon_state.clone());
        }

        // Run store file i/o (also advances any in-flight checkpoint persist).
        if let Err(e) = self.store.file_io(
            &self.fork_digest,
            self.custody_group_columns,
            &mut self.rpc_producer,
            &mut |io| match io {
                IoEvent::P2pSend(p2p_send) => adapter.produce(p2p_send),
                IoEvent::PeerEvent(peer_event) => adapter.produce(peer_event),
            },
        ) {
            tracing::error!(
                ?e,
                store_dir = self.store.store_dir(),
                "storage store file i/o failed"
            );
        }
    }
}

pub(crate) enum IoEvent {
    P2pSend(P2pSend),
    PeerEvent(PeerEvent),
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

        let rpc_producer = TCache::multi_producer("rpc_out", 1024 * 1024);
        let replay_producer = TCache::producer("replay_out", 1024 * 1024);

        // Unused here (no EL path exercised); only satisfies the constructor.
        let engine_resp_tc = TCache::producer("engine_resp", 1024 * 1024);
        let engine_resp_consumer =
            engine_resp_tc.cache_ref().random_access("engine_resp_cons", true).unwrap();

        let beacon_state = BeaconStateOwner::empty_test(0).reader();

        let mut tile = StorageTile::new(
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            rpc_producer,
            replay_producer,
            beacon_state,
            custody_columns,
            [1, 2, 3, 4],
            Arc::new(SpecConfig::mainnet()),
            store_dir.clone(),
            false,
            engine_resp_consumer,
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
        tile.store.sync_update(SyncUpdate::Following);
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

    /// Synthetic SignedBeaconBlock: message at 100, slot at [100..108), body
    /// at 184. `has_data_columns` is `blob_kzg_commitments_offset <
    /// execution_requests_offset`, so equal offsets ⇒ no columns.
    fn make_block(slot: u64, with_data_columns: bool) -> Vec<u8> {
        let mut b = vec![0u8; 784];
        b[0..4].copy_from_slice(&100u32.to_le_bytes());
        b[100..108].copy_from_slice(&slot.to_le_bytes());
        b[180..184].copy_from_slice(&84u32.to_le_bytes());
        let (blob_off, exec_off): (u32, u32) =
            if with_data_columns { (400, 500) } else { (500, 500) };
        b[184 + 388..184 + 392].copy_from_slice(&blob_off.to_le_bytes());
        b[184 + 392..184 + 396].copy_from_slice(&exec_off.to_le_bytes());
        b
    }

    #[test]
    fn replay_skips_blocks_missing_custody_columns() {
        // Checkpoint at slot 32 plus three unfinalized blocks above it. Custody
        // set = {3, 7}. Needs-columns comes from the block bytes, presence
        // from the disk bitmask:
        //   slot 33 — has columns, full custody set on disk   ⇒ replayed
        //   slot 34 — has columns, only column 3 on disk      ⇒ skipped
        //   slot 35 — columnless block, nothing on disk       ⇒ replayed
        // Only the unavailable block is dropped; replay continues past it and
        // ends with Done so the peer manager resyncs the gap.
        let custody = (1u128 << 3) | (1u128 << 7);
        let store_dir = format!("/tmp/test_storage_replay_da_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_dir);

        // Committed-checkpoint marker → last_persisted_finalized_slot = 32.
        let ckpt = format!("{store_dir}/finalized_checkpoints/32");
        std::fs::create_dir_all(&ckpt).unwrap();
        std::fs::write(format!("{ckpt}/32.ssz"), b"x").unwrap();

        // Unfinalized blocks: `<slot>_<parent>_<root>.ssz`. The root in the
        // name keys the column bitmask; needs-columns is parsed from the bytes.
        let unfin = format!("{store_dir}/unfinalized");
        std::fs::create_dir_all(&unfin).unwrap();
        let (root_a, root_b, root_c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        for (slot, root, dc) in [(33, &root_a, true), (34, &root_b, true), (35, &root_c, false)] {
            std::fs::write(
                format!("{unfin}/{slot}_{}_{}.ssz", "0".repeat(64), root),
                make_block(slot, dc),
            )
            .unwrap();
        }

        // Custody columns on disk: `<slot>_<root>_<column>.ssz`.
        let cols = format!("{store_dir}/unfinalized_columns");
        std::fs::create_dir_all(&cols).unwrap();
        for col in [3, 7] {
            std::fs::write(format!("{cols}/33_{root_a}_{col}.ssz"), b"c").unwrap();
        }
        std::fs::write(format!("{cols}/34_{root_b}_3.ssz"), b"c").unwrap(); // partial

        let gossip_tc = TCache::producer("g", 1 << 20);
        let pg_tc = TCache::producer("pg", 1 << 20);
        let rpc_tc = TCache::producer("r", 1 << 20);
        let pr_tc = TCache::producer("pr", 1 << 20);
        let engine_resp_tc = TCache::producer("engine_resp", 1 << 20);
        let mut tile = StorageTile::new(
            gossip_tc.cache_ref().random_access("g", true).unwrap(),
            pg_tc.cache_ref().random_access("pg", true).unwrap(),
            rpc_tc.cache_ref().random_access("r", true).unwrap(),
            pr_tc.cache_ref().random_access("pr", true).unwrap(),
            TCache::multi_producer("rpc_out", 1 << 20),
            TCache::producer("replay_out", 1 << 20),
            BeaconStateOwner::empty_test(0).reader(),
            custody,
            [1, 2, 3, 4],
            Arc::new(SpecConfig::mainnet()),
            store_dir.clone(),
            true,
            engine_resp_tc.cache_ref().random_access("engine_resp", true).unwrap(),
        );
        assert_eq!(tile.replay_blocks.len(), 3, "skip decided at replay, not load");

        // Spine + injector: the tile produces, the injector drains.
        let base = std::env::temp_dir().join(format!("silver-replay-da-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&base).unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(&base, None));
        let mut tile_adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        let inj = Injector;
        let mut inj_adapter = SpineAdapter::connect_tile(&inj, &mut spine);
        // Prime injector cursors while queues are empty.
        inj_adapter.consume(|_: DataColumnsAvailable, _| {});
        inj_adapter.consume(|_: ReplayBlock, _| {});

        tile.syncing_strategy = Some(SyncingStrategy::ReplayDisk);
        tile.drive_replay(&mut tile_adapter);

        let mut das = 0;
        inj_adapter.consume(|_: DataColumnsAvailable, _| das += 1);
        let (mut blocks, mut done) = (0, 0);
        inj_adapter.consume(|m: ReplayBlock, _| match m {
            ReplayBlock::Block { .. } => blocks += 1,
            ReplayBlock::Done => done += 1,
        });

        assert_eq!(das, 0, "replay emits no separate DataColumnsAvailable event");
        assert_eq!(blocks, 2, "slots 33 and 35 replayed; 34 skipped");
        assert_eq!(done, 1, "replay terminated with Done");
        assert!(tile.replay_done);

        let _ = std::fs::remove_dir_all(&store_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    struct Injector;

    impl Tile<SilverSpine> for Injector {
        fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
    }
}
