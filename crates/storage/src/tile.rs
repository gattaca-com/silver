use std::time::{Duration, Instant};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_state_data::{BeaconStateReader, SLOTS_PER_EPOCH};
use silver_common::{
    BeaconStateEvent, DataColumnsAvailable, NewGossipMsg, P2pSend, P2pStreamId, PeerEvent,
    RpcInbound, RpcResponseInbound, RpcSeverity, SilverSpine, StreamProtocol, SyncUpdate,
    TMultiProducer, TRandomAccess, TRead, Wheel,
    ssz_view::{DataColumnSidecarView, StatusView},
};
use silver_metrics::timed;

use crate::{store::Store, util};

const REQUEST_ID_PREFIX_MASK: u64 = 0xffff_ffff_0000_0000;
const BASE_REQUEST_ID: u64 = 0x00da_5da5 << 32; // DAS prefix.
pub(crate) const BACKFILL_REQUEST_ID: u64 = 0xbacc_f111 << 32;
pub(crate) const COLUMN_BACKFILL_REQUEST_ID: u64 = 0xc01b_accf << 32;
const MAX_RETRIES: u8 = 5;

/// Persist a finalized-state checkpoint only when within this many slots of
/// the wall-clock head (i.e. not fast-syncing) — avoids stalling the writer
/// and re-encoding every intermediate finalized epoch while catching up.
const CAUGHT_UP_SLACK_SLOTS: u64 = 2 * SLOTS_PER_EPOCH;

/// Initial capacity for the reused checkpoint encode buffer. A mainnet
/// finalized state is ~312 MiB, we allocate 400 MiB.
const CHECKPOINT_BUF_CAPACITY: usize = 400 * 1024 * 1024;

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
    outstanding_requests: Wheel<BlockRoot, (u128, u8), 16>,

    // Highest Status finalized epoch we've scheduled a checkpoint for; dedups
    // the trigger so we encode at most once per finalized-epoch advance.
    // Advanced when a persist is queued; re-derived from disk on restart.
    checkpointed_epoch: u64,
    // Reused buffer for the finalized-state checkpoint SSZ (phase 1: whole
    // state encoded in one batch, then written + atomically renamed).
    checkpoint_buf: Vec<u8>,
    // Set by a Status when finality advanced past the last persisted epoch and
    // we are caught up to head; consumed (and cleared) in `loop_body`.
    persist_pending: bool,
}

impl StorageTile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gossip_consumer: TRandomAccess,
        persist_gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        persist_rpc_consumer: TRandomAccess,
        rpc_producer: TMultiProducer,
        beacon_state: BeaconStateReader,
        custody_group_columns: u128,
        fork_digest: [u8; 4],
        data_store_dir: String,
    ) -> Self {
        let store = Store::load(data_store_dir).expect("failed to load storage store");
        let checkpointed_epoch = store.last_persisted_finalized_slot() / SLOTS_PER_EPOCH;
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
            outstanding_requests: Wheel::new(Duration::from_millis(500)),
            checkpointed_epoch,
            checkpoint_buf: Vec::with_capacity(CHECKPOINT_BUF_CAPACITY),
            persist_pending: false,
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

        if !util::has_data_columns(buffer) {
            return;
        }

        let block_root = util::block_root(buffer);

        if self.outstanding_requests.contains(&block_root) {
            return;
        }

        let mut to_request = self.custody_group_columns;
        if let Some(validated) = self.validated_columns.get(&block_root) {
            to_request &= !validated;
            if to_request == 0 {
                // already have all custody group columns
                return;
            }
        }
        self.outstanding_requests.insert(block_root, (to_request, MAX_RETRIES));
        emit(self.column_request(block_root, to_request));
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
        let checks = self.beacon_state.read(&mut |v| {
            let epoch_state = v.epoch_state();
            let state_epoch = v.epoch();

            let (proposer_matches, parent_validated, is_above_finalized) = if do_parent_checks {
                // proposer_lookahead is anchored to `state_epoch` and covers
                // current+next epochs (PROPOSER_LOOKAHEAD_SIZE = 64). Slots
                // outside that window we cannot resolve here.
                let lookahead_idx = block_slot.wrapping_sub(state_epoch * SLOTS_PER_EPOCH) as usize;
                let expected_proposer = epoch_state.proposer_lookahead.get(lookahead_idx).copied();
                let parent_validated = util::parent_validated(
                    buffer,
                    v.finalized_block_roots(),
                    v.delta_block_roots(),
                );
                let is_above_finalized =
                    util::is_above_finalized(buffer, epoch_state.finalized_checkpoint.epoch);
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
                (idx < v.validators_count()).then(|| *v.validator_pubkey_decompressed(idx));

            (
                is_above_finalized,
                parent_validated,
                proposer_matches,
                pubkey,
                v.fork_current_version(), // TODO for backfill
                v.genesis_validators_root(),
            )
        });
        let (above_finalized, parent_validated, proposer_matches, pubkey, fork_version, gvr) =
            checks;

        if !above_finalized {
            tracing::warn!(?stream_id, "sidecar slot at or below finalized");
            return Some((block_root, column_bitmask));
        }
        if !parent_validated {
            tracing::warn!(
                ?stream_id,
                block_slot,
                parent_root = hex::encode(parent_root),
                "sidecar parent_root not in validated set"
            );
            return Some((block_root, column_bitmask));
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

        if let Some((mut requested, retries)) = requested {
            requested &= !column_bitmask;
            if requested != 0 {
                // more column responses pending
                self.outstanding_requests.insert(block_root, (requested, retries));
            }
        }

        let validated = self.validated_columns.entry(block_root).or_default();
        *validated |= column_bitmask;

        if *validated & self.custody_group_columns == self.custody_group_columns {
            // have all validated data columns for the block.
            emit(DataColumnsAvailable {
                slot: DataColumnSidecarView::slot(buffer),
                proposer_index: DataColumnSidecarView::proposer_index(buffer),
                parent_root: *DataColumnSidecarView::parent_root(buffer),
                state_root: *DataColumnSidecarView::state_root(buffer),
                body_root: *DataColumnSidecarView::body_root(buffer),
                signature: *DataColumnSidecarView::block_signature(buffer),
            })
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
        self.gossip_consumer.free();
        self.rpc_consumer.free();
        self.persist_gossip_consumer.free();
        self.persist_rpc_consumer.free();

        // Check for data columns and incoming blocks with data columns via gossip.
        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock => {
                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                self.beacon_block(gossip.stream_id, t_read, &mut |evt| {
                    producers.peer_events.produce(&evt.into());
                });
            }
            silver_common::GossipTopic::DataColumnSidecar(_custody_group) => {
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
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz } if is_backfill(&rsp) => {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.store.backfill_block(t_read);
                }
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz } => {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.beacon_block(rsp.stream_id, t_read, &mut |evt| {
                        producers.peer_events.produce(&evt.into());
                    });
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if is_column_backfill(&rsp) => {
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
                silver_common::RpcResponse::Error { error, msg, len } if is_column_backfill(&rsp) => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "column backfill rpc error response");
                }
                silver_common::RpcResponse::Error { error, msg, len } if is_backfill(&rsp) => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "backfill rpc error response");
                    self.store.backfill_request_complete(rsp.application_id, &mut |event| {
                        producers.peer_events.produce(&event.into());
                    });
                }
                silver_common::RpcResponse::Error { error, msg, len } if is_live_column_request(&rsp) => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "rpc error response");
                }
                silver_common::RpcResponse::Complete if is_column_backfill(&rsp) => {}
                silver_common::RpcResponse::Complete if is_backfill(&rsp) => {
                    self.store.backfill_request_complete(rsp.application_id, &mut |event| {
                        producers.peer_events.produce(&event.into());
                    });
                }
                other => {
                    tracing::trace!(?other, app_id=rsp.application_id, id=?rsp.stream_id, "ignoring rpc response");
                }
            },
        });

        adapter.consume(|beacon_event: BeaconStateEvent, _| match beacon_event {
            BeaconStateEvent::Status { ssz, wall_slot, .. } => {
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
            BeaconStateEvent::PersistBlock {
                ssz,
                source,
            } => {
                let t_read = match source {
                    silver_common::BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    silver_common::BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };

                tracing::info!(seq=t_read.seq(), "persist block");
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

        adapter.consume(|sync_update: SyncUpdate, _| self.store.sync_update(sync_update));

        let now = Instant::now();

        // Age out per-block validation memo.
        self.validated_blocks.maybe_rotate(now, &mut |_, _| true);
        // Age out validated columns.
        self.validated_columns.maybe_rotate(now, &mut |_, _| true);

        // Timeout any pending requests and re-issue
        let mut request_id = self.request_id;
        self.outstanding_requests.maybe_rotate(now, &mut |block_root, (columns, retries)| {
            if *retries == 0 {
                return true; // remove
            }
            request_id += 1;
            tracing::trace!(
                columns,
                block_root = hex::encode(block_root),
                "resending outstanding data column request"
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

        // Run store file i/o
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

        if self.persist_pending {
            self.persist_pending = false;
            let buf = &mut self.checkpoint_buf;
            let slot = self.beacon_state.read(&mut |v| v.encode_finalized(buf));
            match self.store.persist_finalized_checkpoint(slot, &self.checkpoint_buf) {
                Ok(()) => tracing::info!(
                    slot,
                    bytes = self.checkpoint_buf.len(),
                    "persisted finalized checkpoint"
                ),
                Err(e) => tracing::error!(?e, slot, "failed to persist finalized checkpoint"),
            }
        }
    }
}

pub(crate) enum IoEvent {
    P2pSend(P2pSend),
    PeerEvent(PeerEvent),
}

fn is_backfill(rsp: &RpcResponseInbound) -> bool {
    rsp.application_id & REQUEST_ID_PREFIX_MASK == BACKFILL_REQUEST_ID
}

fn is_column_backfill(rsp: &RpcResponseInbound) -> bool {
    rsp.application_id & REQUEST_ID_PREFIX_MASK == COLUMN_BACKFILL_REQUEST_ID
}

fn is_live_column_request(rsp: &RpcResponseInbound) -> bool {
    rsp.application_id & REQUEST_ID_PREFIX_MASK == BASE_REQUEST_ID
}
