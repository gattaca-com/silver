use flux::{spine::SpineAdapter, tile::Tile};
use silver_beacon_api::BeaconApi;
use silver_common::SilverSpine;
use silver_engine_api::EngineApi;

pub struct ClientServerTile {
    pub beacon: BeaconApi,
    pub engine: EngineApi,
}

impl Tile<SilverSpine> for ClientServerTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.engine.intake(adapter);
        self.engine.spin(adapter);
        if self.beacon.pump() {
            adapter.mark_work();
        }
    }
}
