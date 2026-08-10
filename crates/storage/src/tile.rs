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
    BeaconStateEvent, ColumnSource, DataColumnsEvent, P2pSend, PeerControl, PeerEvent, ReplayBlock,
    RpcInbound, SilverSpine, SyncUpdate, SyncingStrategy, TCacheProducer, TMultiProducer,
    TProducer, TRandomAccess, column_util, msg_is_backfill, msg_is_column_backfill,
    ssz_view::{
        ExecutionPayloadEnvelopeView, SignedBeaconBlockView, SignedExecutionPayloadEnvelopeView,
        StatusView,
    },
};

use crate::store::Store;

/// Fallback: if control's replay-vs-sync decision is never received, default
/// `drive_replay` to replaying the on-disk chain after this long.
const SYNCING_STRATEGY_FALLBACK: Duration = Duration::from_secs(45);

const MAX_REPLAY_BLOCKS_PER_LOOP: usize = 16;

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
            replay_blocks,
            replay_producer,
            replay_done: !replay_from_disk,
            syncing_strategy: None,
            created_at: Instant::now(),
            peers_loaded: false,
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
}

impl StorageTile {
    #[timed]
    fn handle_beacon_state_event(&mut self, event: BeaconStateEvent) -> Option<([u8; 92], u64)> {
        let mut latest_status_event: Option<([u8; 92], u64)> = None;
        match event {
            BeaconStateEvent::Status { ssz, wall_slot, .. } => {
                latest_status_event = Some((ssz, wall_slot));
            }
            BeaconStateEvent::PersistBlock { ssz, source } => {
                let t_read = match source {
                    silver_common::BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    silver_common::BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        let slot = SignedBeaconBlockView::slot(buf);
                        let parent_root = *SignedBeaconBlockView::parent_root(buf);
                        let block_root = column_util::block_root_fulu(buf);
                        self.store.add_block(block_root, t_read, slot, parent_root);
                    }
                    Err(e) => {
                        tracing::error!(?e, seq=t_read.seq(), consumer=?self.persist_gossip_consumer, "persist consumer buffer acquire failed");
                    }
                }
            }
            BeaconStateEvent::PersistEnvelope { ssz, source } => {
                let t_read = match source {
                    silver_common::BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    silver_common::BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };
                match t_read.buffer() {
                    Ok((buf, _)) if SignedExecutionPayloadEnvelopeView::check_size(buf) => {
                        let msg = SignedExecutionPayloadEnvelopeView::message(buf);
                        let block_root = *ExecutionPayloadEnvelopeView::beacon_block_root(msg);
                        self.store.add_envelope(block_root, t_read);
                    }
                    Ok(_) => tracing::error!("persist envelope: bad ssz size"),
                    Err(e) => {
                        tracing::error!(?e, "persist envelope consumer buffer acquire failed");
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
            RpcInbound::Response(rsp) => match rsp.response {
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz }
                    if msg_is_backfill(rsp.application_id) =>
                {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.store.backfill_block(t_read);
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if msg_is_column_backfill(rsp.application_id) => {
                    tracing::debug!("backfill data column sidecar over rpc");
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.store.backfill_data_column(t_read, &mut |evt| {
                        producers.peer_events.produce(&evt.into());
                    });
                }
                silver_common::RpcResponse::Error { error, msg, len } if msg_is_column_backfill(rsp.application_id)=> {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "column backfill rpc error response");
                }
                silver_common::RpcResponse::Error { error, msg, len } if msg_is_backfill(rsp.application_id)=> {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "backfill rpc error response");
                }
                other => {
                    tracing::trace!(?other, app_id=rsp.application_id, id=?rsp.stream_id, "ignoring rpc response");
                }
            },
        });

        let mut latest_status_event: Option<([u8; 92], u64)> = None;

        adapter.consume(|beacon_event: BeaconStateEvent, _producers| {
            if let Some(latest) = self.handle_beacon_state_event(beacon_event) {
                latest_status_event.replace(latest);
            }
        });

        adapter.consume(|dc_event: DataColumnsEvent, _producers| {
            if let DataColumnsEvent::Persist { ssz, source, block_root, column_index, slot } =
                dc_event
            {
                let sidecar_ssz = match source {
                    ColumnSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    ColumnSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                    ColumnSource::El => self.el_column_consumer.acquire(ssz),
                };
                self.store.add_data_column(block_root, column_index, sidecar_ssz, slot);
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
        let spec = self.spec.clone();
        let gvr = self.genesis_validators_root;
        let fork_digest_at = move |slot: u64| match gvr {
            Some(gvr) => column_util::fork_digest_at(&spec, slot, &gvr),
            None => [0u8; 4],
        };
        if let Err(e) = self.store.file_io(
            fork_digest_at,
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
        assert_eq!(tile.replay_blocks.len(), 3, "skip decided at replay, not load");

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
