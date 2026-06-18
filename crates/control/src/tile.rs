use std::{
    io::{self, ErrorKind, Write},
    time::{Duration, Instant},
};

use flux::tile::Tile;
use silver_common::{
    BeaconStateEvent, P2pSend, PeerControl, PeerEvent, RpcInbound, RpcOutbound, RpcRequestOutbound,
    SilverSpine, SilverSpineProducers, TCacheProducer, TCacheRead, TMultiProducer,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE},
};
use silver_peer::PeerManager;

const OUTBOUND_DRAIN_INTERVAL: Duration = Duration::from_secs(5);
const PEER_PERSIST_INTERVAL: Duration = Duration::from_secs(300);

pub struct Controller {
    peer_manager: PeerManager,
    rpc_producer: TMultiProducer,
    last_tick: Instant,
    last_ping: Instant,
    last_status: Instant,
    last_drain: Instant,
    last_peer_persist: Instant,

    /// When false, the 17000ms heartbeat skips the per-peer Ping fan-out.
    /// Tests use this to keep the peer-state machine ticking without
    /// generating background Ping traffic that would interfere with
    /// targeted RPC assertions.
    auto_ping: bool,
}

impl Controller {
    /// Build a Controller. `status` and `metadata` start empty — callers
    /// update them via `set_status` / `set_metadata` once chain state is
    /// available.
    pub fn new(peer_manager: PeerManager, rpc_producer: TMultiProducer) -> Self {
        Self {
            peer_manager,
            rpc_producer,
            last_tick: Instant::now(),
            last_ping: Instant::now(),
            last_status: Instant::now(),
            last_drain: Instant::now(),
            last_peer_persist: Instant::now(),
            auto_ping: true,
        }
    }

    pub fn set_status(&mut self, status: [u8; STATUS_V2_SIZE]) {
        self.peer_manager.set_status(status);
    }

    pub fn set_metadata(&mut self, metadata: [u8; METADATA_SIZE]) {
        self.peer_manager.set_metadata(metadata);
    }

    /// Toggle the heartbeat-driven outbound Ping fan-out. Default is on.
    pub fn set_auto_ping(&mut self, enabled: bool) {
        self.auto_ping = enabled;
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }
}

impl Tile<SilverSpine> for Controller {
    fn loop_body(&mut self, adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        let now = Instant::now();

        let mut handle_peer_control =
            |pc: PeerControl, producers: &mut SilverSpineProducers| match pc {
                PeerControl::P2pSend(send) => {
                    producers.p2p_send.produce(&send.into());
                }
                PeerControl::P2pBlockByRootRequest { app_id, peer, block_root } => {
                    match allocate_blocks_by_root(&mut self.rpc_producer, &block_root) {
                        Ok(read) => {
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                                    application_id: app_id,
                                    peer,
                                    request: silver_common::RpcRequest::BlockByRoot(read),
                                }))
                                .into(),
                            );
                        }
                        Err(e) => {
                            tracing::error!(?e, "failed to allocate blocks by root request");
                        }
                    }
                }
                PeerControl::P2pDataColumnsRequest { app_id, peer, block_root, columns } => {
                    tracing::debug!(peer, columns, "emit data columns P2pSend");
                    match allocate_data_columns_by_root(
                        &mut self.rpc_producer,
                        &block_root,
                        columns,
                    ) {
                        Ok(tcache) => {
                            producers.p2p_send.produce(
                                &P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
                                    application_id: app_id,
                                    peer,
                                    request: silver_common::RpcRequest::DataColumnsByRoot(tcache),
                                }))
                                .into(),
                            );
                        }
                        Err(e) => {
                            tracing::error!(?e, "failed to allocate data columns request");
                        }
                    };
                }
                other => {
                    producers.peer_control.produce(&other.into());
                }
            };

        adapter.consume(|event: PeerEvent, producers| {
            self.peer_manager
                .handle_event(event, now, &mut |evt| handle_peer_control(evt, producers));
        });

        adapter.consume(|rpc: RpcInbound, producers| {
            self.peer_manager
                .on_rpc_inbound(rpc, now, &mut |evt| handle_peer_control(evt, producers));
        });

        let mut latest_status_event = None;

        adapter.consume(|beacon_event: BeaconStateEvent, _producers| match beacon_event {
            BeaconStateEvent::Status { ssz, latest_block_slot, wall_slot } => {
                latest_status_event = Some((ssz, latest_block_slot, wall_slot));
            }
            BeaconStateEvent::BlockRejected { block_root, source } => {
                self.peer_manager.record_block_rejected(block_root, source);
            }
            BeaconStateEvent::ReplayComplete => {
                self.peer_manager.on_local_replay_complete();
            }
            BeaconStateEvent::BacktrackStall => {
                self.peer_manager.request_resync();
            }
            _ => {}
        });

        if let Some((ssz, latest_block_slot, wall_slot)) = latest_status_event {
            tracing::debug!(wall_slot, latest_block_slot, "new status set");
            self.peer_manager.set_status(ssz);
            self.peer_manager.set_local_head_imported(latest_block_slot);
            self.peer_manager.set_wall_slot(wall_slot);
        }

        if let Some(target) = self.peer_manager.maybe_emit_sync_target() {
            adapter.produce(target);
        }

        if let Some(strategy) = self.peer_manager.maybe_choose_syncing_strategy(now) {
            adapter.produce(strategy);
        }

        // Catchup → Following edge: blast a one-shot Status to every peer
        // so they reciprocate with their fresh head — primes the head-sync
        // set — and announce our topic subscriptions so peers connected
        // during catch-up start gossiping to us. Subsequent Status fan-outs
        // run on the periodic 300s heartbeat.
        if self.peer_manager.take_just_synced() {
            self.last_status = now;
            self.peer_manager
                .fan_out_status(now, &mut |evt| handle_peer_control(evt, &mut adapter.producers));
            self.peer_manager
                .fan_out_subscriptions(&mut |evt| handle_peer_control(evt, &mut adapter.producers));
        }

        self.peer_manager.maybe_issue_syncreq(now, &mut |pc| {
            match pc {
                PeerControl::P2pSend(send) => adapter.produce(send),
                other => adapter.produce(other),
            };
        });

        if self.last_drain.elapsed() > OUTBOUND_DRAIN_INTERVAL {
            self.last_drain = now;
            self.peer_manager.drain_pending_outbound(now, &mut |evt| {
                handle_peer_control(evt, &mut adapter.producers)
            });
        }

        if self.last_tick.elapsed() > Duration::from_millis(700) {
            self.last_tick = now;
            self.peer_manager
                .tick(now, &mut |evt| handle_peer_control(evt, &mut adapter.producers));

            if self.auto_ping && self.last_ping.elapsed() > Duration::from_secs(17) {
                self.last_ping = now;
                self.peer_manager
                    .fan_out_ping(now, &mut |evt| handle_peer_control(evt, &mut adapter.producers));
            }
        }

        if self.last_peer_persist.elapsed() > PEER_PERSIST_INTERVAL {
            self.last_peer_persist = now;
            for peer in self.peer_manager.live_peers_with_status() {
                if let Some(enr) = peer.enr.as_ref() {
                    handle_peer_control(
                        PeerControl::PersistPeer { enr: *enr },
                        &mut adapter.producers,
                    );
                }
            }
        }

        // Off-schedule Status fan-out on a silent fall-behind. Tight 1 s
        // backoff: if we suddenly look behind wall_slot, peers either know
        // a newer head or we need to learn we're stranded — either way,
        // refresh sooner rather than waiting on the 5 min keepalive.
        let fell_behind =
            self.peer_manager.fell_behind() && self.last_status.elapsed() > Duration::from_secs(1);
        if fell_behind || self.last_status.elapsed() > Duration::from_secs(30) {
            self.last_status = now;
            self.peer_manager
                .fan_out_status(now, &mut |evt| handle_peer_control(evt, &mut adapter.producers));
        }
    }
}

fn allocate_data_columns_by_root(
    producer: &mut TMultiProducer,
    root: &[u8; 32],
    columns: u128,
) -> Result<TCacheRead, io::Error> {
    // the data columns by root request is a list of `DataColumnsByRootIdentifier`.
    // Each of those is the block root followed by the list of column
    // indices. So the layout is: N x 4 byte offsets of list entries (little
    // endian) (so first offset / 4 is list length) Then N times:
    //   32 bytes block root
    //   4  bytes columns data offset (always = 36, little endian)
    //   8 bytes column index for each column, little endian
    let number_of_columns = columns.count_ones() as usize;
    let length = 4 + 32 + 4 + (8 * number_of_columns);
    let Some(mut reservation) = producer.reserve(length, true) else {
        tracing::warn!("Failed to allocate TCache buffer for data columns request");
        return Err(ErrorKind::StorageFull.into());
    };
    reservation.write_all(&4u32.to_le_bytes())?;
    reservation.write_all(root)?;
    reservation.write_all(&36u32.to_le_bytes())?;
    for i in 0..128 {
        if columns & (1 << i) != 0 {
            reservation.write_all(&(i as u64).to_le_bytes())?;
        }
    }
    reservation.flush()?;
    Ok(reservation.read())
}

fn allocate_blocks_by_root(
    producer: &mut TMultiProducer,
    root: &[u8; 32],
) -> Result<TCacheRead, io::Error> {
    let Some(mut reservation) = producer.reserve(32, true) else {
        tracing::warn!("Failed to allocate TCache buffer for blocks request");
        return Err(ErrorKind::StorageFull.into());
    };
    reservation.write_all(root)?;
    reservation.flush()?;
    Ok(reservation.read())
}
