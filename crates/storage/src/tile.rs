use std::{collections::VecDeque, fs::File, io::Read, path::PathBuf, sync::Arc, time::Instant};

use flux::{spine::SpineAdapter, tile::Tile};
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    BeaconStateEvent, BlockSource, ColumnSource, DataColumnsEvent, DataKind, Origin, P2pSend,
    PeerControl, PeerEvent, ReplayBlock, RequestId, RpcInbound, SilverSpine, SyncNeed, SyncUpdate,
    SyncingStrategy, TCacheProducer, TMultiProducer, TProducer, TRandomAccess, column_util,
    ssz_view::{SignedBeaconBlockView, SignedExecutionPayloadEnvelopeView, StatusView},
};

use crate::{StorageCounters, store::Store};

const MAX_REPLAY_BLOCKS_PER_LOOP: usize = 16;

enum ReplayStep {
    Block { path: PathBuf, columns_on_disk: bool },
    Envelope { path: PathBuf },
}

impl ReplayStep {
    fn path(&self) -> &PathBuf {
        match self {
            Self::Block { path, .. } | Self::Envelope { path } => path,
        }
    }
}

/// Persist a finalized-state checkpoint only when within this many slots of
/// the wall-clock head (i.e. not fast-syncing) — avoids stalling the writer
/// and re-encoding every intermediate finalized epoch while catching up.
const CAUGHT_UP_SLACK_SLOTS: u64 = 2 * SLOTS_PER_EPOCH;

pub struct StorageTile {
    // bit set of our custody group columns.
    custody_group_columns: u128,
    persist_gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
    persist_rpc_consumer: TRandomAccess,
    el_column_consumer: TRandomAccess,
    rpc_producer: TMultiProducer,
    beacon_state: BeaconStateReader,
    store: Store,
    genesis_validators_root: Option<B256>,

    spec: Arc<SpecConfig>,

    // Highest Status finalized epoch we've scheduled a checkpoint for; dedups
    // the trigger so we encode at most once per finalized-epoch advance.
    // Advanced when a persist is queued; re-derived from disk on restart.
    checkpointed_epoch: u64,
    wall_slot: u64,
    // Set by a Status when finality advanced past the last persisted epoch and
    // we are caught up to head; consumed when a persist is started (the
    // in-flight checkpoint then lives on the `Store`, driven by `file_io`).
    persist_pending: bool,

    /// Flattened replay stream: each block is immediately followed by its
    /// envelope, so a gloas child's precheck sees the parent payload verified.
    replay_steps: VecDeque<ReplayStep>,
    replay_producer: TProducer,
    replay_done: bool,
    /// Boot decision from control: `None` = waiting; gates `drive_replay` so we
    /// don't replay the on-disk fork tree before learning whether peers are
    /// finalized ahead (in which case we skip it and sync from them).
    syncing_strategy: Option<SyncingStrategy>,
    peers_loaded: bool,
}

impl StorageTile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        persist_gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        persist_rpc_consumer: TRandomAccess,
        el_column_consumer: TRandomAccess,
        rpc_producer: TMultiProducer,
        replay_producer: TProducer,
        beacon_state: BeaconStateReader,
        custody_group_columns: u128,
        spec: Arc<SpecConfig>,
        data_store_dir: String,
        replay_from_disk: bool,
    ) -> Self {
        let store =
            Store::load(data_store_dir, spec.clone()).expect("failed to load storage store");
        let checkpointed_epoch = store.last_persisted_finalized_slot() / SLOTS_PER_EPOCH;
        let replay_steps = if replay_from_disk {
            let mut entries = store.replay_entries(custody_group_columns);
            entries.sort_unstable_by_key(|e| e.slot);
            entries
                .into_iter()
                .flat_map(|e| {
                    [Some(ReplayStep::Block { path: e.block, columns_on_disk: e.columns_on_disk })]
                        .into_iter()
                        .chain([e.envelope.map(|path| ReplayStep::Envelope { path })])
                        .flatten()
                })
                .collect()
        } else {
            VecDeque::new()
        };
        tracing::info!("have {} replay steps", replay_steps.len());

        Self {
            custody_group_columns,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            el_column_consumer,
            rpc_producer,
            beacon_state,
            store,
            genesis_validators_root: None,
            spec,
            checkpointed_epoch,
            wall_slot: u64::MAX,
            persist_pending: false,
            replay_steps,
            replay_producer,
            replay_done: !replay_from_disk,
            syncing_strategy: None,
            peers_loaded: false,
        }
    }

    fn drive_replay(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.replay_done {
            return;
        }

        let Some(strategy) = self.syncing_strategy else { return };
        if matches!(strategy, SyncingStrategy::SyncFromPeers) {
            tracing::info!(
                staged = self.replay_steps.len(),
                "skipping on-disk replay; peers finalized ahead — syncing from peers"
            );
            self.replay_steps.clear();
            adapter.produce(ReplayBlock::Done);
            self.replay_done = true;
            return;
        }

        let mut sent = 0;
        while sent < MAX_REPLAY_BLOCKS_PER_LOOP {
            let Some(step) = self.replay_steps.front() else {
                break;
            };
            let path = step.path();

            let (mut file, len) = match File::open(path).and_then(|f| {
                let len = f.metadata()?.len() as usize;
                Ok((f, len))
            }) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(?e, ?path, "replay data file open failed; skipping");
                    self.replay_steps.pop_front();
                    continue;
                }
            };

            let Some(mut reservation) = self.replay_producer.reserve(len, true) else {
                return; // tcache full — retry next loop
            };
            let buf = match reservation.buffer() {
                Ok(buf) => buf,
                Err(e) => {
                    tracing::error!(?e, ?path, "replay reservation buffer failed; skipping");
                    self.replay_steps.pop_front();
                    continue;
                }
            };
            if let Err(e) = file.read_exact(&mut buf[..len]) {
                tracing::error!(?e, ?path, "replay read failed; skipping");
                self.replay_steps.pop_front();
                continue;
            }

            // TODO: request the missing columns instead of dropping?
            let ssz = &buf[..len];
            if let ReplayStep::Block { columns_on_disk: false, .. } = step &&
                SignedBeaconBlockView::check_size(ssz) &&
                SignedBeaconBlockView::has_data_columns(
                    ssz,
                    self.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(ssz)),
                )
            {
                tracing::warn!(?path, "replay skip: custody columns missing on disk");
                self.replay_steps.pop_front();
                continue;
            }

            reservation.increment_offset(len);
            let ssz = reservation.read();
            adapter.produce(match step {
                ReplayStep::Block { .. } => ReplayBlock::Block { ssz },
                ReplayStep::Envelope { .. } => ReplayBlock::Envelope { ssz },
            });
            self.replay_steps.pop_front();
            sent += 1;
        }

        if self.replay_steps.is_empty() {
            adapter.produce(ReplayBlock::Done);
            self.replay_done = true;
        }
    }
}

impl StorageTile {
    #[timed]
    fn handle_beacon_state_event(
        &mut self,
        event: BeaconStateEvent,
        needs: &mut impl FnMut(SyncNeed),
    ) -> Option<([u8; 92], u64)> {
        let mut latest_status_event: Option<([u8; 92], u64)> = None;
        match event {
            BeaconStateEvent::Status { ssz, wall_slot, .. } => {
                latest_status_event = Some((ssz, wall_slot));
            }
            BeaconStateEvent::PersistBlock { ssz, source, slot, block_root } => {
                let t_read = match source {
                    BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        let slot = SignedBeaconBlockView::slot(buf);
                        let parent_root = *SignedBeaconBlockView::parent_root(buf);
                        let block_root =
                            column_util::block_root(buf, self.spec.is_gloas_at_slot(slot));
                        self.store.add_block(block_root, t_read, slot, parent_root);
                    }
                    Err(e) => {
                        tracing::error!(
                            ?e,
                            seq = t_read.seq(),
                            ?source,
                            slot,
                            "persist block buffer acquire failed"
                        );
                        StorageCounters::PersistAcquireFailed.inc();
                        needs(SyncNeed::Missing {
                            root: block_root,
                            slot,
                            kind: DataKind::Block,
                            columns: 0,
                            origin: Origin::Live,
                        });
                    }
                }
            }
            BeaconStateEvent::EnvelopeAvailable { ssz, source, slot, block_root } => {
                if !self.store.is_envelope_owed(&block_root, slot) {
                    return None;
                }
                let t_read = match source {
                    BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };
                match t_read.buffer() {
                    Ok((buf, _)) if SignedExecutionPayloadEnvelopeView::check_size(buf) => {
                        self.store.add_envelope(block_root, t_read);
                    }
                    Ok(_) => tracing::error!(slot, "envelope available: bad ssz size"),
                    Err(e) => {
                        tracing::error!(
                            ?e,
                            seq = t_read.seq(),
                            ?source,
                            slot,
                            "envelope buffer acquire failed"
                        );
                        StorageCounters::PersistAcquireFailed.inc();
                        needs(SyncNeed::Missing {
                            root: block_root,
                            slot,
                            kind: DataKind::Envelope,
                            columns: 0,
                            origin: Origin::Live,
                        });
                    }
                }
            }
            _ => {}
        }
        latest_status_event
    }
}

impl Tile<SilverSpine> for StorageTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|d: SyncingStrategy, _| self.syncing_strategy = Some(d));
        self.drive_replay(adapter);

        self.rpc_consumer.free();
        self.persist_gossip_consumer.free();
        self.persist_rpc_consumer.free();
        self.el_column_consumer.free();

        // Check for data columns and incoming blocks via RPC.
        adapter.consume(|rpc: RpcInbound, producers| match rpc {
            RpcInbound::Request(req) => {
                self.store.rpc_request(&mut self.rpc_consumer, req);
            }
            RpcInbound::Response(rsp) => {
                let id = RequestId::from(rsp.application_id);
                match rsp.response {
                    silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz }
                        if id.is(DataKind::Block, Origin::Backfill) =>
                    {
                        let t_read = self.rpc_consumer.acquire(ssz);
                        self.store.backfill_block(t_read);
                    }
                    silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz }
                        if id.is(DataKind::Columns, Origin::Backfill) =>
                    {
                        tracing::debug!("backfill data column sidecar over rpc");
                        let t_read = self.rpc_consumer.acquire(ssz);
                        self.store.backfill_data_column(
                            t_read,
                            rsp.stream_id.peer(),
                            Instant::now(),
                            &mut |event| {
                                producers.peer_events.produce(&event.into());
                            },
                        );
                    }
                    silver_common::RpcResponse::ExecutionPayloadEnvelope {
                        fork_digest: _,
                        ssz,
                    } if id.is(DataKind::Envelope, Origin::Backfill) => {
                        let t_read = self.rpc_consumer.acquire(ssz);
                        self.store.backfill_envelope(t_read, &mut |need| {
                            producers.sync_needs.produce(&need.into());
                        });
                    }
                    silver_common::RpcResponse::Error { error, msg, len }
                        if id.origin == Origin::Backfill =>
                    {
                        let err_msg = String::from_utf8_lossy(&msg[..len]);
                        tracing::error!(error, %err_msg, "backfill rpc error response");
                    }
                    _ => {}
                }
            }
        });

        let mut latest_status_event: Option<([u8; 92], u64)> = None;

        adapter.consume(|beacon_event: BeaconStateEvent, producers| {
            let mut needs = |need: SyncNeed| {
                producers.sync_needs.produce(&need.into());
            };
            if let Some(latest) = self.handle_beacon_state_event(beacon_event, &mut needs) {
                latest_status_event.replace(latest);
            }
        });

        adapter.consume(|dc_event: DataColumnsEvent, producers| {
            if let DataColumnsEvent::Persist { ssz, source, block_root, column_index, slot } =
                dc_event
            {
                let sidecar_ssz = match source {
                    ColumnSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    ColumnSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                    ColumnSource::El => self.el_column_consumer.acquire(ssz),
                };
                match sidecar_ssz.buffer() {
                    Ok(_) => self.store.add_data_column(
                        block_root,
                        column_index,
                        sidecar_ssz,
                        slot,
                        false,
                    ),
                    Err(e) => {
                        tracing::error!(
                            ?e,
                            seq = sidecar_ssz.seq(),
                            ?source,
                            slot,
                            column_index,
                            "persist data column buffer acquire failed"
                        );
                        StorageCounters::PersistAcquireFailed.inc();
                        producers.sync_needs.produce(
                            &SyncNeed::Missing {
                                root: block_root,
                                slot,
                                kind: DataKind::Columns,
                                columns: 1u128 << column_index,
                                origin: Origin::Live,
                            }
                            .into(),
                        );
                    }
                }
            }
        });

        if let Some((ssz, wall_slot)) = latest_status_event {
            self.wall_slot = wall_slot;
            let head_slot = StatusView::head_slot(&ssz);
            let head_root = *StatusView::head_root(&ssz);
            let finalized_epoch = StatusView::finalized_epoch(&ssz);
            let finalized_root = *StatusView::finalized_root(&ssz);
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

        // Start a checkpoint persist when one is pending and none is in flight;
        // `file_io` then streams it one section per turn and commits at the end.
        if self.persist_pending && !self.store.checkpoint_in_flight() {
            self.persist_pending = false;
            self.store.begin_checkpoint(self.beacon_state.clone());
        }

        // Genesis validators root is constant post-genesis; latch it once the
        // reader has a published state. Feeds the per-slot served fork-digest.
        if self.genesis_validators_root.is_none() {
            self.genesis_validators_root =
                self.beacon_state.read(&|v| v.imm.genesis_validators_root);
        }

        // Run store file i/o (also advances any in-flight checkpoint persist).
        let spec = &*self.spec;
        let gvr = self.genesis_validators_root;
        let fork_digest_at = move |slot: u64| match gvr {
            Some(gvr) => spec.fork_digest_at(slot / SLOTS_PER_EPOCH, &gvr),
            None => [0u8; 4],
        };
        if let Err(e) = self.store.file_io(
            fork_digest_at,
            self.custody_group_columns,
            &mut self.rpc_producer,
            &mut |io| match io {
                IoEvent::P2pSend(p2p_send) => adapter.produce(p2p_send),
                IoEvent::PeerEvent(peer_event) => adapter.produce(peer_event),
                IoEvent::Need(need) => adapter.produce(need),
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

#[allow(clippy::large_enum_variant)]
pub(crate) enum IoEvent {
    P2pSend(P2pSend),
    PeerEvent(PeerEvent),
    Need(SyncNeed),
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::BeaconStateOwner;
    use silver_common::{DataColumnsEvent, TCache, TCacheProducer};

    use super::*;

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

        let pg_tc = TCache::producer("pg", 1 << 20);
        let rpc_tc = TCache::producer("r", 1 << 20);
        let pr_tc = TCache::producer("pr", 1 << 20);
        let el_tc = TCache::producer("pr", 1 << 20);

        let mut tile = StorageTile::new(
            pg_tc.cache_ref().random_access("pg", true).unwrap(),
            rpc_tc.cache_ref().random_access("r", true).unwrap(),
            pr_tc.cache_ref().random_access("pr", true).unwrap(),
            el_tc.cache_ref().random_access("el_column_consumer", true).unwrap(),
            TCache::multi_producer("rpc_out", 1 << 20),
            TCache::producer("replay_out", 1 << 20),
            BeaconStateOwner::empty_test(0).reader(),
            custody,
            Arc::new(SpecConfig::mainnet()),
            store_dir.clone(),
            true,
        );
        assert_eq!(tile.replay_steps.len(), 3, "skip decided at replay, not load");

        // Spine + injector: the tile produces, the injector drains.
        let base = std::env::temp_dir().join(format!("silver-replay-da-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&base).unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(&base, None));
        let mut tile_adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        let inj = Injector;
        let mut inj_adapter = SpineAdapter::connect_tile(&inj, &mut spine);
        // Prime injector cursors while queues are empty.
        inj_adapter.consume(|_: DataColumnsEvent, _| {});
        inj_adapter.consume(|_: ReplayBlock, _| {});

        tile.syncing_strategy = Some(SyncingStrategy::ReplayDisk);
        tile.drive_replay(&mut tile_adapter);

        let mut das = 0;
        inj_adapter.consume(|_: DataColumnsEvent, _| das += 1);
        let (mut blocks, mut done) = (0, 0);
        inj_adapter.consume(|m: ReplayBlock, _| match m {
            ReplayBlock::Block { .. } => blocks += 1,
            ReplayBlock::Envelope { .. } => {}
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
