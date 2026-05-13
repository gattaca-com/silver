use std::time::{Duration, Instant};

use flux::tile::Tile;
use silver_common::{
    BeaconStateEvent, PeerControl, PeerEvent, RpcInbound, SilverSpine,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE},
};
use silver_peer::PeerManager;

pub struct Controller {
    peer_manager: PeerManager,
    last_tick: Instant,
    last_ping: Instant,
    last_status: Instant,

    /// When false, the 17000ms heartbeat skips the per-peer Ping fan-out.
    /// Tests use this to keep the peer-state machine ticking without
    /// generating background Ping traffic that would interfere with
    /// targeted RPC assertions.
    auto_ping: bool,
}

impl Controller {
    /// Build a Controller with a fresh `PeerManager`. `status` and
    /// `metadata` start empty — callers update them via `set_status` /
    /// `set_metadata` once chain state is available.
    pub fn new(peer_manager: PeerManager) -> Self {
        Self {
            peer_manager,
            last_tick: Instant::now(),
            last_ping: Instant::now(),
            last_status: Instant::now(),
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
        adapter.consume(|event: PeerEvent, producers| {
            self.peer_manager.handle_event(event, now, &mut |pc| {
                match pc {
                    PeerControl::P2pSend(send) => producers.p2p_send.produce(&send.into()),
                    other => producers.peer_control.produce(&other.into()),
                };
            });
        });
        adapter.consume(|rpc: RpcInbound, producers| {
            self.peer_manager.on_rpc_inbound(rpc, now, &mut |pc| {
                match pc {
                    PeerControl::P2pSend(send) => producers.p2p_send.produce(&send.into()),
                    other => producers.peer_control.produce(&other.into()),
                };
            });
        });

        adapter.consume(|beacon_event: BeaconStateEvent, producers| {
            match beacon_event {
                BeaconStateEvent::Synced(status) => {
                    // TODO trigger gossip subscriptions
                    self.peer_manager.set_synced(true);
                    self.peer_manager.set_status(status);
                }
                BeaconStateEvent::Status(status) => {
                    self.peer_manager.set_status(status);
                }
                BeaconStateEvent::RequestBlocksByRange { request_id, ssz } => {
                    self.peer_manager.on_request_blocks_by_range(request_id, ssz, &mut |pc| {
                        match pc {
                            PeerControl::P2pSend(send) => producers.p2p_send.produce(&send.into()),
                            other => producers.peer_control.produce(&other.into()),
                        };
                    });
                }
                _ => {}
            }
        });

        self.peer_manager.drain_pending_outbound(&mut |pc| {
            match pc {
                PeerControl::P2pSend(send) => adapter.produce(send),
                other => adapter.produce(other),
            };
        });

        if self.last_tick.elapsed() > Duration::from_millis(700) {
            self.last_tick = now;
            self.peer_manager.tick(now, &mut |event| {
                match event {
                    PeerControl::P2pSend(send) => adapter.produce(send),
                    other => adapter.produce(other),
                };
            });

            if self.auto_ping && self.last_ping.elapsed() > Duration::from_secs(17) {
                self.last_ping = now;
                self.peer_manager.fan_out_ping(&mut |pc| {
                    match pc {
                        PeerControl::P2pSend(send) => adapter.produce(send),
                        other => adapter.produce(other),
                    };
                });
            }
        }

        if self.last_status.elapsed() > Duration::from_secs(300) {
            self.last_status = Instant::now();
            self.peer_manager.fan_out_status(&mut |pc| {
                match pc {
                    PeerControl::P2pSend(send) => adapter.produce(send),
                    other => adapter.produce(other),
                };
            });
        }
    }
}
