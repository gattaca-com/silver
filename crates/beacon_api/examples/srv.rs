use std::time::Duration;

use silver_beacon_api::{ApiConsumers, BeaconApi};
use silver_beacon_state_data::{BeaconStateOwner, SpecConfig};
use silver_common::{Enr, Identify, Keypair, TCache, TCacheProducer};
use silver_httpcore::{Bind, Readiness, TokenRange};

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:5051".into());
    let binds = arg.split(',').map(Bind::parse).collect::<Vec<_>>();
    let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
    let local_enr = Enr::empty(keypair.secret_key()).unwrap();
    let state = BeaconStateOwner::published_empty_test(0).reader();

    let cache = TCache::producer("srv", 1 << 12);
    let consumer = || cache.cache_ref().random_access("srv", true).unwrap();

    let mut readiness = Readiness::new(1024);
    let mut api = BeaconApi::new(
        readiness.registry(),
        TokenRange::whole(),
        &binds,
        64,
        Duration::from_secs(75),
        &keypair,
        local_enr,
        &Identify::default(),
        &SpecConfig::mainnet(),
        state,
        ApiConsumers { gossip: consumer(), rpc: consumer() },
    );
    println!("serving on {:?}", api.local_addrs());
    loop {
        readiness.wait(Duration::ZERO);
        api.pump(readiness.events());
        std::thread::sleep(Duration::from_millis(1));
    }
}
