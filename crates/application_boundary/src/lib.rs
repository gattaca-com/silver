use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_api::{BeaconApi, PeerCounts, SlotStatus};
use silver_common::{BeaconStateEvent, SilverSpine, SyncUpdate};
use silver_engine_api::EngineApi;
use silver_peer::PeerCounters;

pub struct ApplicationBoundaryTile {
    pub beacon: BeaconApi,
    pub engine: EngineApi,
}

impl Tile<SilverSpine> for ApplicationBoundaryTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.engine.intake(adapter);
        self.engine.spin(adapter);
        self.refresh_node_status(adapter);
        if self.beacon.pump() {
            adapter.mark_work();
        }
    }
}

impl ApplicationBoundaryTile {
    fn refresh_node_status(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let status = self.beacon.node_status_mut();

        // Consumed every iteration, and never behind the engine's capacity
        // gate: a consumer's first `consume` jumps its cursor to the
        // producer's write head, so a queue left unread while the pool is
        // saturated loses everything published in the meantime.
        adapter.consume(|event: BeaconStateEvent, _| {
            if let BeaconStateEvent::Status {
                latest_block_slot, wall_slot, head_optimistic, ..
            } = event
            {
                status.slots =
                    Some(SlotStatus { head_slot: latest_block_slot, wall_slot, head_optimistic });
            }
        });
        adapter.consume(|update: SyncUpdate, _| {
            status.syncing = !matches!(update, SyncUpdate::Following);
        });

        status.el = self.engine.sync_status();
        status.peers = PeerCounts {
            connected: PeerCounters::PeersConnected.get(),
            connecting: PeerCounters::PeersConnecting.get(),
        };
    }
}
