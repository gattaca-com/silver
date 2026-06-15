use std::{
    collections::VecDeque,
    fs::File,
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_state_data::{BeaconStateReader, SLOTS_PER_EPOCH};
use silver_common::{
    BASE_REQUEST_ID, BeaconStateEvent, DataColumnsAvailable, NewGossipMsg, P2pSend, P2pStreamId,
    PeerEvent, ReplayBlock, RpcInbound, RpcSeverity, SilverSpine, StreamProtocol, SyncUpdate,
    SyncingStrategy, TCacheProducer, TMultiProducer, TProducer, TRandomAccess, TRead, Wheel,
    ssz_view::{DataColumnSidecarView, SignedBeaconBlockView, StatusView},
};
use silver_metrics::timed;

use crate::{StorageCounters, store::Store, util};
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

    // keyed by block body root
    validated_columns: Wheel<BlockRoot, u128, 4>,
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
            validated_columns: Wheel::new(EPOCH_DURATION),
            validated_blocks: Wheel::new(EPOCH_DURATION),
            outstanding_requests: Wheel::new(Duration::from_millis(100)),
            checkpointed_epoch,
            persist_pending: false,
            replay_blocks,
            replay_producer,
            replay_done: !replay_from_disk,
            syncing_strategy: None,
            created_at: Instant::now(),
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
                SignedBeaconBlockView::has_data_columns(block)
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
    fn beacon_block<F>(&mut self, stream_id: P2pStreamId, block: TRead, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let buffer = match block.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read beacon block cache buffer");
                return;
            }
        };

        if !SignedBeaconBlockView::has_data_columns(buffer) {
            return;
        }

        if SignedBeaconBlockView::slot(buffer) <= self.store.finalized_slot() {
            return;
        }

        let block_root = util::block_root(buffer);

        if self.outstanding_requests.contains(&block_root) {
            return;
        }

        // Custody columns only — silver floors cgc at SAMPLES_PER_SLOT, so the
        // custody set IS the sample set; no beyond-custody sampling needed.
        // These by-root requests race gossip and serve as the fallback when a
        // sidecar isn't delivered on the subscribed subnet.
        let mut to_request = self.custody_group_columns;
        let validated = self.validated_columns.get(&block_root).copied().unwrap_or(0);
        to_request &= !validated;

        if to_request == 0 {
            return;
        }

        self.outstanding_requests.insert(block_root, (to_request, to_request, MAX_RETRIES));

        tracing::trace!(
            block = hex::encode(block_root),
            ?stream_id,
            "data columns by root request: {to_request:b}"
        );

        if stream_id.protocol() != StreamProtocol::GossipSub {
            emit(self.column_request(block_root, to_request));
        }
    }

    #[timed]
    fn data_columns<F>(
        &mut self,
        stream_id: P2pStreamId,
        sidecar: TRead,
        emit: &mut F,
    ) -> Option<([u8; 32], u128)>
    where
        F: FnMut(DataColumnsAvailable),
    {
        let buffer = match sidecar.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read data column sidecar cache buffer");
                return None;
            }
        };

        let block_root = util::block_root_from_sidecar(buffer);
        let parent_root = DataColumnSidecarView::parent_root(buffer);
        let slot = DataColumnSidecarView::slot(buffer);

        if self.store.is_synced() && slot > self.store.head_slot() + 1 {
            // received data columns with parent ahead of current head
            // data column request will be retried
            return None;
        }

        let column_index = DataColumnSidecarView::index(buffer);
        let column_bitmask = 1u128 << column_index;
        let requested = self.outstanding_requests.remove(&block_root);

        let do_parent_checks = stream_id.protocol() == StreamProtocol::GossipSub;

        if self
            .validated_columns
            .get(&block_root)
            .map(|c| c & column_bitmask != 0)
            .unwrap_or_default()
        {
            return None;
        }

        if !util::verify_data_column_sidecar(buffer) {
            tracing::warn!(?stream_id, "badly formed data column sidecar");
            return Some((block_root, column_bitmask));
        }
        if !util::verify_data_column_sidecar_kzg_proofs(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar kzg proof");
            return Some((block_root, column_bitmask));
        }

        // Inclusion proof binds the sidecar's `kzg_commitments` to the
        // block's `body_root` — neither input is pinned by block_root, so
        // it must run on every sidecar.
        if !util::verify_data_column_sidecar_inclusion_proof(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar inclusion proof");
            return Some((block_root, column_bitmask));
        }

        // State-driven validations: pull every input in one seqlock pass.
        // BLS verify runs OUTSIDE the closure (slow; would hold the
        // notional read lock too long otherwise).
        let block_slot = DataColumnSidecarView::slot(buffer);
        let claimed_proposer_index = DataColumnSidecarView::proposer_index(buffer);
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
                v.imm.fork.current_version, // TODO for backfill
                v.imm.genesis_validators_root,
            )
        });
        // No snapshot yet (pre-bootstrap): nothing can be validated.
        let Some((above_finalized, parent_validated, proposer_matches, pubkey, fork_version, gvr)) =
            checks
        else {
            tracing::warn!(?stream_id, "sidecar before first beacon state snapshot");
            return Some((block_root, column_bitmask));
        };

        if !above_finalized {
            tracing::debug!(?stream_id, "sidecar slot at or below finalized — ignoring");
            return None;
        }
        if !parent_validated {
            tracing::debug!(
                ?stream_id,
                block_slot,
                parent_root = hex::encode(parent_root),
                "sidecar parent_root not yet validated — ignoring (not penalized)"
            );
            return None;
        }
        if !proposer_matches {
            tracing::warn!(?stream_id, "sidecar proposer_index mismatch");
            return Some((block_root, column_bitmask));
        }

        // BLS verify cache: skip the ~1 ms verify iff the sidecar's
        // signature bytes match a previously-validated signature for
        // this block_root. block_root does not pin the signature, so
        // bytes-equality is required.
        let sig_bytes = *DataColumnSidecarView::block_signature(buffer);
        if self.validated_blocks.get(&block_root) != Some(&sig_bytes) {
            let Some(pubkey) = pubkey else {
                tracing::warn!(?stream_id, "sidecar proposer_index out of range");
                return Some((block_root, column_bitmask));
            };
            if !util::verify_proposer_signature(buffer, &pubkey, fork_version, &gvr) {
                tracing::warn!(?stream_id, "sidecar proposer signature invalid");
                return Some((block_root, column_bitmask));
            }
            self.validated_blocks.insert(block_root, sig_bytes);
        }

        let mut completion_check = self.custody_group_columns;

        if let Some((mut requested, full_set, retries)) = requested {
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
                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                self.beacon_block(gossip.stream_id, t_read, &mut |evt| {
                    producers.peer_events.produce(&evt.into());
                });
            }
            silver_common::GossipTopic::DataColumnSidecar(_custody_group)
                if self.store.is_synced() =>
            {
                // TODO validate that topic group matches sidecar column index
                tracing::debug!(_custody_group, "data column sidecar over gossip");

                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                if let Some((block_root, columns)) =
                    self.data_columns(gossip.stream_id, t_read, &mut |msg| {
                        producers.data_columns.produce(&msg.into());
                    })
                {
                    // Validation failed - score down the peer and retransmit
                    producers.peer_events.produce(
                        &PeerEvent::P2pGossipInvalidMsg {
                            p2p_peer: gossip.stream_id.peer(),
                            topic: gossip.topic,
                            hash: gossip.msg_hash,
                        }
                        .into(),
                    );
                    producers.peer_events.produce(&self.column_request(block_root, columns).into());
                }
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
                    if rsp.is_backfill() =>
                {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.store.backfill_block(t_read);
                }
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz } if self.store.is_synced() => {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.beacon_block(rsp.stream_id, t_read, &mut |evt| {
                        producers.peer_events.produce(&evt.into());
                    });
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if rsp.is_column_backfill() => {
                    tracing::debug!("backfill data column sidecar over rpc");
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.store.backfill_data_column(t_read, &mut |event| {
                        producers.peer_events.produce(&event.into());
                    });
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => {
                    // TODO validate that originating peer has data column index in custody groups
                    tracing::debug!("data column sidecar over rpc");
                    let t_read = self.rpc_consumer.acquire(ssz);
                    if let Some((block_root, columns)) =
                        self.data_columns(rsp.stream_id, t_read, &mut |msg| {
                            producers.data_columns.produce(&msg.into());
                        })
                    {
                        // Validation failed - score down the peer and retransmit
                        producers.peer_events.produce(
                            &PeerEvent::RpcMisbehaviour {
                                p2p_peer: rsp.stream_id.peer(),
                                severity: RpcSeverity::Fatal,
                            }
                            .into(),
                        );
                        producers
                            .peer_events
                            .produce(&self.column_request(block_root, columns).into());
                    }
                }
                silver_common::RpcResponse::Error { error, msg, len } if rsp.is_column_backfill() => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "column backfill rpc error response");
                }
                silver_common::RpcResponse::Error { error, msg, len } if rsp.is_backfill() => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "backfill rpc error response");
                    self.store.backfill_request_complete(rsp.application_id, &mut |event| {
                        producers.peer_events.produce(&event.into());
                    });
                }
                silver_common::RpcResponse::Error { error, msg, len } if rsp.is_live_column_request() => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "rpc error response");
                }
                silver_common::RpcResponse::Complete if rsp.is_column_backfill() => {}
                silver_common::RpcResponse::Complete if rsp.is_backfill() => {
                    self.store.backfill_request_complete(rsp.application_id, &mut |event| {
                        producers.peer_events.produce(&event.into());
                    });
                }
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
                        let block_root = util::block_root(buf);
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

        let now = Instant::now();

        // Age out per-block validation memo.
        self.validated_blocks.maybe_rotate(now, &mut |_, _| true);
        // Age out validated columns.
        self.validated_columns.maybe_rotate(now, &mut |_, _| true);

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
            tracing::error!(?e, "storage store file i/o failed");
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

        let beacon_state = BeaconStateOwner::pre_bootstrap().reader();

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
            store_dir.clone(),
            false,
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

        let block_root = util::block_root(&block_bytes);
        let rpc_stream = P2pStreamId::new(2, 2, StreamProtocol::BeaconBlocksByRange, true);

        // Once synced, an RPC block requests its custody columns by root.
        tile.store.sync_update(SyncUpdate::Following);
        let mut rpc_events = Vec::new();
        tile.beacon_block(rpc_stream, read.clone(), &mut |evt| rpc_events.push(evt));
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
        let mut tile = StorageTile::new(
            gossip_tc.cache_ref().random_access("g", true).unwrap(),
            pg_tc.cache_ref().random_access("pg", true).unwrap(),
            rpc_tc.cache_ref().random_access("r", true).unwrap(),
            pr_tc.cache_ref().random_access("pr", true).unwrap(),
            TCache::multi_producer("rpc_out", 1 << 20),
            TCache::producer("replay_out", 1 << 20),
            BeaconStateOwner::pre_bootstrap().reader(),
            custody,
            [1, 2, 3, 4],
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
