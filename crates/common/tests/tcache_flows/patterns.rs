//! One test per production flow; see the pattern catalog in
//! `docs/tcache-tail-watermarks.md`. `Expect::Known` marks what the
//! sliding guard cannot do today and flips to `Holds` with floors.

use silver_common::{TCache, TCacheId, TCacheTable, TReadMode};

use crate::model::{
    Action, CAPACITY, Drain, Driver, Expect, NONE, Node, Then, World, Writer, check, consume,
    consume_one, produce, wraps,
};

const SEEDS: [u64; 4] = [1, 7, 42, 1234];
const CACHE: TCacheId = TCacheId::IncomingGossip;
const OTHER: TCacheId = TCacheId::IncomingRpc;

fn producer(name: &'static str, id: TCacheId) -> (Node, Writer) {
    let writer = Writer::Single(World::cache(id));
    let table = World::table(&[&writer]);
    (Node::new(name, table), writer)
}

/// Producer node on `CACHE`, plus a table for its consumers.
fn source() -> (Node, TCacheTable) {
    let (node, writer) = producer("producer", CACHE);
    let table = World::table(&[&writer]);
    (node.with_writer(writer), table)
}

fn broadcast(tag: u8, links: &'static [usize], n: usize) -> impl Iterator<Item = Action> {
    std::iter::repeat_n(Action::Broadcast { writer: 0, tag, links }, n)
}

fn consumer(name: &'static str, table: TCacheTable, action: Action) -> Node {
    Node::new(name, table).open(CACHE, TReadMode::Sliding).script([action])
}

#[test]
fn producer_to_one_consumer_in_order() {
    for driver in [Driver::Sequential, Driver::Random { seed: SEEDS[0] }] {
        let (p, table) = source();
        let n = wraps(3);
        let mut world = World::new(
            vec![
                p.script(produce(0, 0x11, 0, n)),
                consumer("consumer", table, consume(0, Then::Acquire, n)),
            ],
            1,
        );
        world.run(driver);
        check(&world, Expect::Holds);
    }
}

#[test]
fn producer_to_n_consumers_different_speeds() {
    for seed in SEEDS {
        let (p, table) = source();
        let n = wraps(2);
        let mut world = World::new(
            vec![
                p.script(broadcast(0x22, &[0, 1, 2], n)),
                consumer("fast", table, consume(0, Then::Acquire, n)),
                consumer("medium", table, consume(1, Then::Acquire, n)),
                // One message per turn, so it trails the producer.
                consumer("slow", table, consume_one(2, Then::Acquire, n)),
            ],
            3,
        );
        world.run(Driver::Random { seed });
        check(&world, Expect::Holds);
    }
}

#[test]
fn interleaved_open_reservations_later_completes_first() {
    for driver in [Driver::Sequential, Driver::Random { seed: SEEDS[1] }] {
        let (p, table) = source();
        let pairs = wraps(2) / 2;
        let mut world = World::new(
            vec![
                p.script(
                    std::iter::repeat_n(
                        [
                            Action::Reserve { writer: 0, tag: 0x31 },
                            Action::Reserve { writer: 0, tag: 0x32 },
                            Action::EmitNewest { link: 0 },
                            Action::Emit { link: 0 },
                        ],
                        pairs,
                    )
                    .flatten(),
                ),
                consumer("consumer", table, consume(0, Then::Acquire, pairs * 2)),
            ],
            1,
        );
        world.run(driver);
        check(&world, Expect::Holds);
    }
}

#[test]
fn forward_while_pinned_one_hop() {
    for seed in SEEDS {
        let (p, table) = source();
        let n = wraps(3);
        let mut world = World::new(
            vec![
                p.script(produce(0, 0x41, 0, n)),
                consumer("forwarder", table, consume(0, Then::ForwardPinned { link: 1 }, n)),
                consumer("receiver", table, consume(1, Then::Acquire, n)),
            ],
            2,
        );
        world.run(Driver::Random { seed });
        check(&world, Expect::Holds);
    }
}

/// Two forwarders feed one receiver from the same cache. The second pins each
/// read on arrival and forwards it `lag` messages later, as columns does
/// across a KZG batch. Past the guard window the receiver's acquire is below
/// its tail and uncounted; it holds reads in batches, as storage does across
/// I/O, so the uncounted pin shows up as reclaimed bytes at release.
fn two_queues_into_one_consumer(lag: usize, expect: Expect) {
    let (p, table) = source();
    let n = wraps(2);
    let mut world = World::new(
        vec![
            p.script(broadcast(0x51, &[0, 1], n)),
            consumer("prompt", table, consume(0, Then::ForwardPinned { link: 2 }, n)),
            Node::new("lagging", table).open(CACHE, TReadMode::Sliding).script(
                [consume_one(1, Then::Delay { link: 3, depth: lag }, n)]
                    .into_iter()
                    .chain(std::iter::repeat_n(Action::ForwardOldestHeld { link: 3 }, lag)),
            ),
            Node::new("receiver", table).open(CACHE, TReadMode::Sliding).script(
                std::iter::repeat_n(
                    [
                        Action::Consume {
                            links: [2, 3],
                            drain: Drain::All,
                            then: Then::Hold,
                            count: 16,
                        },
                        Action::ReleaseAll,
                        Action::Free,
                    ],
                    2 * n / 16,
                )
                .flatten(),
            ),
        ],
        4,
    );
    world.run(Driver::Sequential);
    check(&world, expect);
}

#[test]
fn forward_with_delay_within_the_guard() {
    two_queues_into_one_consumer(2, Expect::Holds);
}

#[test]
fn forward_with_delay_beyond_the_guard() {
    two_queues_into_one_consumer(
        wraps(1) / 2,
        Expect::Known(
            "a forward from beyond the guard window is acquired below the tail, uncounted",
        ),
    );
}

#[test]
fn forward_two_hops() {
    for seed in SEEDS {
        let (p, table) = source();
        let n = wraps(3);
        let mut world = World::new(
            vec![
                p.script(produce(0, 0x61, 0, n)),
                consumer("hop1", table, consume(0, Then::ForwardPinned { link: 1 }, n)),
                consumer("hop2", table, consume(1, Then::ForwardPinned { link: 2 }, n)),
                consumer("receiver", table, consume(2, Then::Acquire, n)),
            ],
            3,
        );
        world.run(Driver::Random { seed });
        check(&world, Expect::Holds);
    }
}

#[test]
fn two_producer_clones_one_queue() {
    for seed in SEEDS {
        let shared = TCache::multi_producer(OTHER, CAPACITY);
        let a = Writer::Multi(shared.clone());
        let b = Writer::Multi(shared);
        let table = World::table(&[&a]);
        let n = wraps(2);
        let mut world = World::new(
            vec![
                Node::new("control", table).with_writer(a).script(produce(0, 0x71, 0, n)),
                Node::new("storage", table).with_writer(b).script(produce(0, 0x72, 0, n)),
                Node::new("network", table).open(OTHER, TReadMode::Sliding).script([consume(
                    0,
                    Then::Acquire,
                    2 * n,
                )]),
            ],
            1,
        );
        world.run(Driver::Random { seed });
        check(&world, Expect::Holds);
    }
}

#[test]
fn broadcast_to_receivers_on_different_caches() {
    for seed in SEEDS {
        let (pa, wa) = producer("gossip", CACHE);
        let (pb, wb) = producer("rpc", OTHER);
        let table = World::table(&[&wa, &wb]);
        let n = wraps(2);
        let both = |name, link| {
            Node::new(name, table)
                .open(CACHE, TReadMode::Sliding)
                .open(OTHER, TReadMode::Sliding)
                .script([consume(link, Then::Acquire, 2 * n)])
        };
        let mut world = World::new(
            vec![
                pa.with_writer(wa).script(broadcast(0x81, &[0, 1], n)),
                pb.with_writer(wb).script(broadcast(0x82, &[0, 1], n)),
                both("control", 0),
                both("api", 1),
            ],
            2,
        );
        world.run(Driver::Random { seed });
        check(&world, Expect::Holds);
    }
}

/// `StagedBlock.ssz` / `GossipSidecarFrame.protobuf`: a descriptor held
/// unpinned across a ring wrap and forwarded later. The receiver also follows
/// the live stream so its tail keeps moving and does not shield the holder.
#[test]
fn hold_bare_forward_later() {
    let (p, table) = source();
    let n = wraps(2);
    let mut world = World::new(
        vec![
            p.script(broadcast(0x91, &[0, 1], n)),
            Node::new("holder", table).open(CACHE, TReadMode::Sliding).script([
                consume_one(0, Then::HoldBare, 1),
                consume(0, Then::Acquire, n - 1),
                Action::ForwardHeldBare { link: 2 },
            ]),
            Node::new("receiver", table)
                .open(CACHE, TReadMode::Sliding)
                .script([consume(1, Then::Acquire, n), consume(2, Then::Acquire, 1)]),
        ],
        3,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Known("a bare descriptor is not pinned across the wrap"));
}

/// A consumer that is open but has nothing addressed to it holds its tail at
/// seq 0 while the producer fills: the freeze the snapshot design removes.
#[test]
fn idle_consumer_freezes_the_producer() {
    let (p, table) = source();
    let n = wraps(2);
    let mut world = World::new(
        vec![
            p.script(produce(0, 0x92, 0, n)),
            consumer("active", table, consume(0, Then::Acquire, n)),
            Node::new("idle", table).open(CACHE, TReadMode::Sliding).script([Action::Free]),
        ],
        1,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Known("an idle consumer's tail at seq 0 blocks the producer"));
}

/// mcache: one protobuf pinned while later reads flow past a ring's worth of
/// production; the producer must block on the pin, never lose it.
#[test]
fn long_lived_pin() {
    let (p, table) = source();
    let before = wraps(1) - 2;
    let after = wraps(2);
    let mut world = World::new(
        vec![
            p.script(produce(0, 0xa1, 0, before + after)),
            Node::new("mcache", table).open(CACHE, TReadMode::Sliding).script([
                consume_one(0, Then::Hold, 1),
                consume(0, Then::Acquire, before - 1),
                Action::ReleaseAll,
                Action::Free,
                consume(0, Then::Acquire, after),
            ]),
        ],
        1,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Holds);
}

/// Storage's `reader` and `persist_reader`: two consumers of one cache in one
/// tile, one holding reads for the duration of I/O.
#[test]
fn two_readers_in_one_node_on_one_cache() {
    for seed in SEEDS {
        let (p, table) = source();
        let n = wraps(2);
        let mut world = World::new(
            vec![
                p.script(broadcast(0xb1, &[0, 1], n)),
                consumer("storage_reader", table, consume(0, Then::Acquire, n)),
                Node::new("storage_persist", table).open(CACHE, TReadMode::Sliding).script(
                    std::iter::repeat_n(
                        [consume(1, Then::Hold, 4), Action::ReleaseAll, Action::Free],
                        n / 4,
                    )
                    .flatten(),
                ),
            ],
            2,
        );
        world.run(Driver::Random { seed });
        check(&world, Expect::Holds);
    }
}

/// Columns with no sidecars while gossip blocks flow: the forwarder consumes
/// but emits nothing, and must not freeze the receiver's tail.
#[test]
fn silent_forwarder_while_producer_runs() {
    let (p, table) = source();
    let n = wraps(3);
    let mut world = World::new(
        vec![
            p.script(broadcast(0xc1, &[0, 1], n)),
            consumer("columns", table, consume(0, Then::Acquire, n)),
            consumer("storage", table, consume(1, Then::Acquire, n)),
        ],
        2,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Holds);
}

/// A receiver that opens after the producer has wrapped once reads what was
/// produced after it opened; its claimed tail briefly blocks the producer.
#[test]
fn late_opener() {
    let (p, table) = source();
    let before = wraps(1) + 4;
    let after = wraps(1);
    let mut world = World::new(
        vec![
            p.script(produce(0, 0xd1, 0, before).chain(produce(0, 0xd2, 1, after))),
            Node::new("late", table).script(std::iter::repeat_n(Action::Skip, before).chain([
                Action::Consume {
                    links: [0, NONE],
                    drain: Drain::All,
                    then: Then::Drop,
                    count: before,
                },
                Action::Open { cache: CACHE, name: "late", mode: TReadMode::Sliding },
                consume(1, Then::Acquire, after),
            ])),
        ],
        2,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Holds);
}

/// Network `consume_one` under send backpressure: the queue is never fully
/// drained, yet every queued read must stay readable.
#[test]
fn consume_one_and_stop_queue_not_drained() {
    let (p, table) = source();
    let n = wraps(2);
    let mut world = World::new(
        vec![
            p.script(produce(0, 0xe1, 0, n)),
            consumer("network", table, consume_one(0, Then::Acquire, n)),
        ],
        1,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Holds);
}

/// Cells cache: fixed boundary moved by `advance_retention`; the producer
/// blocks on the boundary and resumes when it moves.
#[test]
fn retained_cache() {
    let (p, writer) = producer("allocator", TCacheId::DataColumns);
    let table = World::table(&[&writer]);
    let batch = wraps(1) / 2;
    let advance = Action::AdvanceRetentionToConsumed { cache: TCacheId::DataColumns };
    let mut world = World::new(
        vec![
            p.with_writer(writer).script(produce(0, 0xf1, 0, 3 * batch)),
            Node::new("cells", table).open(TCacheId::DataColumns, TReadMode::Retained).script([
                consume(0, Then::Acquire, batch),
                advance,
                consume(0, Then::Acquire, batch),
                advance,
                consume(0, Then::Acquire, batch),
            ]),
        ],
        1,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Holds);
}

/// A forwarder re-emitting a received descriptor unpinned. Needs the
/// produce-time `CarriesReads` check (migration step 7) to be detectable.
#[test]
#[ignore = "copy-through check lands with CarriesReads"]
fn copy_through_is_detected() {}

/// A tile calling `sync()` after its consume pass. Needs the snapshot
/// (migration step 6).
#[test]
#[ignore = "snapshot ordering lands with sync()"]
fn snapshot_taken_after_consume_must_fail() {}

/// One pin held while the producer fills past the 90% lag threshold and
/// wraps: the producer should block on the pin, never reclaim under it.
#[test]
fn pin_held_past_the_lag_threshold() {
    let (p, table) = source();
    let n = wraps(2);
    let mut world = World::new(
        vec![
            p.script(produce(0, 0xa2, 0, n)),
            Node::new("mcache", table).open(CACHE, TReadMode::Sliding).script([
                consume_one(0, Then::Hold, 1),
                consume(0, Then::Acquire, n - 1),
                Action::ReleaseAll,
            ]),
        ],
        1,
    );
    world.run(Driver::Sequential);
    check(&world, Expect::Known("lag eviction at 90% of capacity drops a held pin"));
}
