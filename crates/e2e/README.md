# E2e testing

This crate contains a test harness that runs 2 stacks in a single thread. For testing end to end. 

## Example

Run standalone e2e example:
```
// silver -> silver
cargo run -p silver_e2e --example gossip_oneway -- --duration 2 --rate 300 --payload-size 512 --dup-pct 20
// silver -> libp2p
cargo run -p silver_e2e --features lh-client --example gossip_oneway_lh -- --duration 2 --rate 300 --payload-size 512
// libp2p -> silver
cargo run -p silver_e2e --features lh-client --example gossip_oneway_lh_b -- --duration 2 --rate 300 --payload-size 512
// libp2p -> libp2p
cargo run -p silver_e2e --features lh-client --example gossip_oneway_lh_c -- --duration 2 --rate 300 --payload-size 512
```
Sends dummy gossip payloads on a single channel from one stack to another.

## Integration tests
```
cargo test -p silver_e2e --tests
```

## Lighthouse tests
```
cargo test -p silver_e2e --features lh-client
```