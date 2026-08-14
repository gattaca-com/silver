use flux::tile::{TileConfig, attach_tile};
use silver_beacon_api::BeaconApiTile;
use silver_common::{Enr, Identify, Keypair, SilverSpine};

fn main() {
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let local_enr = Enr::empty(keypair.secret_key()).unwrap();
    let identify = Identify::default();
    let spine = SilverSpine::new(None);
    spine.start(None, None, |scoped_spine| {
        attach_tile(
            BeaconApiTile::new(&keypair, local_enr, &identify),
            scoped_spine,
            TileConfig::new(1, None),
        );
    });
}
