use std::time::Duration;

use silver_beacon_api::BeaconApi;
use silver_beacon_state_data::BeaconStateOwner;
use silver_common::{Enr, Identify, Keypair};
use silver_httpcore::Bind;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:5051".into());
    let binds = arg.split(',').map(Bind::parse).collect::<Vec<_>>();
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let local_enr = Enr::empty(keypair.secret_key()).unwrap();
    // Never-published reader: state endpoints answer 503, as pre-bootstrap.
    let state = BeaconStateOwner::empty_test(0).reader();

    let mut api = BeaconApi::new(
        &binds,
        64,
        Duration::from_secs(75),
        &keypair,
        local_enr,
        &Identify::default(),
        state,
    );
    println!("serving on {:?}", api.local_addrs());
    loop {
        api.pump();
        std::thread::sleep(Duration::from_millis(1));
    }
}
