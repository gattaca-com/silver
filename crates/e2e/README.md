# E2e testing

This crate contains a test harness that runs 2 stacks in a single thread. For testing end to end. 

## Example

Run standalone e2e example:
```
cargo run -p silver_e2e --example gossip_oneway -- --duration 2 --rate 300 --payload-size 512 --dup-pct 20
```
Sends dummy gossip payloads on a single channel from one stack to another.

## Integration tests
```
cargo test -p silver_e2e --tests
```