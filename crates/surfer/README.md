## Silver Surfer - metrics console

<img src="surfer.png" width=400 />

Invoke with args: `silver_surfer <shared memory base dir> <app_name>`

Consumes metrics from shared memory:
- spine queue timings
- flux timers
- shared memory counters

### Timing functions and methods

The `#[timed]` attribute macro (from `silver_common`) can be used to create timers for functions and methods. 

### Counters

Counters are defined using the `declare_counters!` macro from `silver_common`. For example:

```
silver_common::declare_counters! {
    pub NetworkCounters => "network" {
        DiscBytesRecv,
        DiscBytesSent,
        P2pBytesRecv,
        P2pBytesSent,
        P2pConnections,
    }
}
```

The `lookup` function `schema.rs` file in `silver_surfer` crate must all be updated:
```
/// Map from file suffix (the `{name}` in `counters-{name}`) to the
/// variant name array. Add lines here as silver crates declare counter
/// enums via `silver_common::declare_counters!`.
pub fn lookup(file_name: &str) -> Option<&'static [&'static str]> {
    match file_name {
        "storage" => Some(storage::StorageCounters::NAMES),
        "network" => Some(silver_network::NetworkCounters::NAMES),
        _ => None,
    }
}
```

Use the `dec()` method of counters with caution - this will overflow if called on a counter with a zero value. For gauge like use of counters `set()` may be a better option. 