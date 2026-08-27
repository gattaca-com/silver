//! Replays a prod capture of one slot's column gossip, at the arrival offsets
//! the recording node saw, through a real `DataColumnsTile`: gossip in, custody
//! set out, `recv -> proc max` and the `#[timed]` call tree, like
//! `just perf-local`.
//!
//!   just da-local [--slots N] [--columns N]
//!
//! Collect the capture with `just da-fixtures`. Entering where the tile enters
//! is the point — a bench calling the validator directly drifts from the tile's
//! own call sequence. `--columns` custodies a subset of the capture, which is
//! how a supernode capture also measures the 8-column boxes.
//!
//! The beacon tile is deliberately absent: it would pull in Following mode,
//! whose head-state ticking forces the replay to pace itself against a wall
//! clock. The DA gate and the apply it guards are `da_wait` in the
//! `block_events` telemetry, measured on the node rather than here.

use std::{
    env,
    process::{ExitCode, exit},
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use mimalloc::MiMalloc;
use silver_beacon_state_data::{BeaconState, BeaconStateOwner, SpecConfig};
use silver_columns::tile::{ColumnConsumers, DataColumnsTile};
#[cfg(feature = "alloc-profile")]
use silver_common::metrics::CountingAllocator;
use silver_common::{
    BeaconStateEvent, DataColumnsEvent, EngineReq, GossipTopic, MessageId, Nanos, NewGossipMsg,
    P2pStreamId, PeerEvent, SilverSpine, StreamProtocol, SyncUpdate, TCache, TCacheProducer,
    TProducer,
    profiler::InProcessReader,
    ssz_view::{DataColumnSidecarFuluView, NUMBER_OF_COLUMNS, STATUS_V2_SIZE},
};
use silver_e2e::{
    da_capture::{ColumnFixtures, SlotCapture, order_index},
    utils::{Injector, tcache_write},
};
use silver_metrics::{
    fold_stats,
    table::{Column, Table},
};
use tempfile::TempDir;

#[cfg(not(feature = "alloc-profile"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[cfg(feature = "alloc-profile")]
#[global_allocator]
static GLOBAL: CountingAllocator<MiMalloc> = CountingAllocator(MiMalloc);

/// A slot that never completes its custody set must not hang the run.
const SLOT_BUDGET: Duration = Duration::from_secs(5);
const DEFAULT_SLOTS: usize = 9;
const USAGE: &str = "usage: da_replay [--slots N] [--columns N]";

/// Indices are spread across the range so a small custody set still samples the
/// whole arrival curve instead of one corner of it.
fn custody_mask(columns: usize) -> u128 {
    assert!(
        (1..=NUMBER_OF_COLUMNS).contains(&columns),
        "custody is 1..={NUMBER_OF_COLUMNS} columns"
    );
    (0..columns).map(|i| 1u128 << (i * NUMBER_OF_COLUMNS / columns)).fold(0, |mask, bit| mask | bit)
}

/// Declaration order is drop order: adapters and the tile before the spine, and
/// before the producers backing their caches.
struct Node {
    inj: SpineAdapter<SilverSpine>,
    conn: SpineAdapter<SilverSpine>,
    tile: DataColumnsTile,
    gossip_p: TProducer,
    _state: BeaconStateOwner,
    _spine: Box<SilverSpine>,
    _base: TempDir,
}

#[derive(Default)]
struct ReplayCost {
    columns: usize,
    cpu: Duration,
    recv_to_proc_max: f64,
}

impl ReplayCost {
    fn merge(&mut self, slot: &ReplayCost) {
        self.columns += slot.columns;
        self.cpu += slot.cpu;
        self.recv_to_proc_max = self.recv_to_proc_max.max(slot.recv_to_proc_max);
    }
}

impl Node {
    fn boot(state_ssz: &[u8], custody: u128) -> Self {
        let base = TempDir::new().expect("tempdir");
        let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
        let spec = Arc::new(SpecConfig::mainnet());

        let state =
            BeaconState::from_checkpoint(state_ssz, &spec, &[]).expect("decompose anchor state");
        let mut owner = BeaconStateOwner::new(state);
        // Readers see nothing until a state id is published.
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);

        // One gossip cache sized for a slot's 128 sidecars so it never wraps
        // mid-slot; the rest only satisfy the constructor.
        let gossip_p = TCache::producer("gossip_in", 1 << 26);
        let rpc_p = TCache::producer("rpc_in", 1 << 20);
        let engine_p = TCache::producer("engine_resp", 1 << 20);
        let ra = |p: &TProducer, name: &'static str| {
            p.cache_ref().random_access(name, true).expect("random access")
        };
        let mut tile = DataColumnsTile::new(
            ColumnConsumers {
                gossip: ra(&gossip_p, "dc_gossip"),
                persist_gossip: ra(&gossip_p, "dc_gossip_persist"),
                rpc: ra(&rpc_p, "dc_rpc"),
                persist_rpc: ra(&rpc_p, "dc_rpc_persist"),
            },
            owner.reader(),
            custody,
            spec,
            ra(&engine_p, "dc_engine"),
            TCache::producer("el_columns", 1 << 22),
        );

        let mut conn = SpineAdapter::connect_tile(&tile, &mut spine);
        let mut inj = SpineAdapter::connect_tile(&Injector, &mut spine);
        tile.try_init(&mut conn);
        // Cursors snap on their first consume, so give the tile a turn before
        // anything it must see is produced.
        tile.loop_body(&mut conn);
        inj.consume(|_: DataColumnsEvent, _| {});
        inj.produce(SyncUpdate::Following);

        Self { inj, conn, tile, gossip_p, _state: owner, _spine: spine, _base: base }
    }

    /// The tile takes head and wall slot from the beacon tile's Status; naming
    /// the slot's own parent as head is what lets its sidecars pass the parent
    /// check with no chain to replay.
    fn follow(&mut self, slot: u64, parent_root: &[u8; 32]) {
        let mut ssz = [0u8; STATUS_V2_SIZE];
        ssz[44..76].copy_from_slice(parent_root);
        ssz[76..84].copy_from_slice(&(slot - 1).to_le_bytes());
        self.inj.produce(BeaconStateEvent::Status {
            ssz,
            latest_block_slot: slot - 1,
            wall_slot: slot,
            enr_fork_id: [0u8; 16],
        });
        self.turn();
    }

    fn gossip_sidecar(&mut self, index: u64, ssz_bytes: &[u8]) {
        let ssz = tcache_write(&mut self.gossip_p, ssz_bytes);
        let mut id = [0u8; 20];
        id.copy_from_slice(&ssz_bytes[..20]);
        self.inj.produce(NewGossipMsg {
            stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
            topic: GossipTopic::DataColumnSidecar(index),
            msg_hash: MessageId { id },
            recv_ts: Nanos::now(),
            ssz,
            // Relay republishes this; the replay has no peers, so the
            // decompressed bytes stand in for the wire form.
            protobuf: ssz,
        });
    }

    fn turn(&mut self) {
        self.tile.loop_body(&mut self.conn);
    }

    /// Validated columns as a bitmask — a count would double-count a queue that
    /// wrapped between drains — and whether the custody set completed.
    fn drain(&mut self) -> (u128, bool) {
        let (mut validated, mut available) = (0u128, false);
        self.inj.consume(|ev: DataColumnsEvent, _| match ev {
            DataColumnsEvent::Persist { column_index, .. } => validated |= 1u128 << column_index,
            DataColumnsEvent::Available { .. } => available = true,
        });
        // Stands in for the Controller and StorageTile: both carry tcache
        // handles, and a handle nobody consumes pins the gossip ring.
        self.inj.consume(|_: PeerEvent, _| {});
        self.inj.consume(|_: EngineReq, _| {});
        (validated, available)
    }

    /// Feeds one slot at its recorded offsets and returns its row once the
    /// custody set is complete, plus the tile cpu and worst per-column
    /// recv→proc gap.
    fn replay_slot(&mut self, slot: u64, cap: &SlotCapture, table: &mut Table) -> ReplayCost {
        let first_sidecar = cap.sidecars.values().next().expect("slot has sidecars");
        self.follow(slot, DataColumnSidecarFuluView::parent_root(first_sidecar));

        let columns = cap.sidecars.len();
        // Offsets are into the slot, so the replay starts its clock at the first
        // arrival rather than idling out the seconds before it.
        let recv_first_us = cap.arrivals.first().map_or(0, |a| a.at_us);
        let ms = |us: u64| us as f64 / 1e3;
        // Both curves on one clock: validations are timed from the first feed, the
        // arrivals from slot start.
        let slot_offset = ms(recv_first_us);
        let mut arrived_ms = [0.0; NUMBER_OF_COLUMNS];
        for arrival in &cap.arrivals {
            arrived_ms[arrival.index as usize] = ms(arrival.at_us);
        }
        let t0 = Instant::now();
        let mut next = 0;
        let mut fed = 0;
        let mut seen = 0u128;
        let mut available_ms = None;
        let mut cpu = Duration::ZERO;
        let mut recv_to_proc_max = 0.0f64;
        let mut validated_ms = Vec::with_capacity(columns);
        while t0.elapsed() < SLOT_BUDGET {
            let elapsed_us = t0.elapsed().as_micros() as u64;
            while let Some(arrival) =
                cap.arrivals.get(next).filter(|a| a.at_us - recv_first_us <= elapsed_us)
            {
                let index = arrival.index;
                self.gossip_sidecar(index, &cap.sidecars[&index]);
                next += 1;
            }

            // Only the turns handed a sidecar are charged: the rest are the replay
            // spinning out the arrival curve, which is input, not tile cost.
            let turn = Instant::now();
            self.turn();
            if next > fed {
                cpu += turn.elapsed();
                fed = next;
            }
            let (validated, available) = self.drain();
            let now_ms = t0.elapsed().as_secs_f64() * 1e3;
            let mut fresh = validated & !seen;
            while fresh != 0 {
                let index = fresh.trailing_zeros() as usize;
                fresh &= fresh - 1;
                validated_ms.push(now_ms);
                recv_to_proc_max = recv_to_proc_max.max(slot_offset + now_ms - arrived_ms[index]);
            }
            seen |= validated;
            if available_ms.is_none() && available {
                available_ms = Some(now_ms);
            }
            if next == cap.arrivals.len() && available_ms.is_some() {
                break;
            }
        }

        assert_eq!(
            seen.count_ones() as usize,
            columns,
            "slot {slot}: {} of {columns} sidecars never validated — the replay is broken, not the \
             node (a `proposer_index mismatch` warning means the capture's anchor is further behind \
             its window than the proposer lookahead reaches)",
            columns - seen.count_ones() as usize
        );
        // The arrival curve is replayed input; what this rig measures is when the
        // tile validated each column, and the cpu it spent.
        let recv = |fraction| cap.arrival_percentile(fraction).map_or(0.0, ms);
        let proc = |fraction| {
            order_index(validated_ms.len(), fraction).map_or(0.0, |i| slot_offset + validated_ms[i])
        };
        let recv_last = ms(cap.arrivals.last().map_or(0, |a| a.at_us));
        let done = slot_offset + available_ms.expect("custody set never completed");
        table.row(vec![
            format!("{slot}{}", if cap.is_backfill() { "*" } else { "" }),
            columns.to_string(),
            format!("{slot_offset:.0}ms"),
            format!("{:.0}ms", recv(0.5)),
            format!("{:.0}ms", proc(0.5)),
            format!("{:.0}ms", recv(0.9)),
            format!("{:.0}ms", proc(0.9)),
            format!("{recv_last:.0}ms"),
            format!("{done:.0}ms"),
            format!("{recv_to_proc_max:.1}ms"),
            format!("{:.1}ms", cpu.as_secs_f64() * 1e3),
        ]);
        ReplayCost { columns, cpu, recv_to_proc_max }
    }
}

/// Both knobs take `--flag N` or `--flag=N`; anything else is a usage error.
fn parse_args() -> (usize, usize) {
    let argv: Vec<String> = env::args().skip(1).collect();
    let mut words: Vec<&str> = Vec::new();
    for arg in &argv {
        match arg.split_once('=') {
            Some((flag, value)) => words.extend([flag, value]),
            None => words.push(arg),
        }
    }
    let (mut slots, mut columns) = (DEFAULT_SLOTS, NUMBER_OF_COLUMNS);
    for pair in words.chunks(2) {
        let [flag, value] = pair else { fail(USAGE) };
        let Ok(n) = value.parse() else { fail(&format!("{flag} takes a number, got {value}")) };
        match *flag {
            "--slots" => slots = n,
            "--columns" => columns = n,
            _ => fail(USAGE),
        }
    }
    (slots, columns)
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    exit(2)
}

fn main() -> ExitCode {
    // `RUST_LOG=silver_columns=warn` names the check a sidecar failed.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    let (limit, custody_columns) = parse_args();
    let custody = custody_mask(custody_columns);

    let mut cap = ColumnFixtures::da().load();
    cap.retain_custody(custody);
    let window: Vec<_> = cap.slots.keys().copied().take(limit).collect();
    assert!(!window.is_empty(), "no captured slot holds a column in the custody set");

    let mut node = Node::boot(&cap.state, custody);
    let recorder = InProcessReader::start();
    // ms into the slot, as prod telemetry reports arrivals. `recv_p50` is when
    // half the custody set was in — what a gate that reconstructs instead of
    // waiting for all of it would have waited for.
    let mut table = Table::new(vec![
        Column::right("slot"),
        Column::right("columns"),
        Column::right("recv_first"),
        Column::right("recv_p50"),
        Column::right("proc_p50"),
        Column::right("recv_p90"),
        Column::right("proc_p90"),
        Column::right("recv_last"),
        Column::right("proc_last"),
        Column::right("recv -> proc max"),
        Column::right("cpu"),
    ]);
    let mut total = ReplayCost::default();
    for slot in &window {
        total.merge(&node.replay_slot(*slot, &cap.slots[slot], &mut table));
    }
    // The one number the tile owns: the worst gap it added between a column
    // arriving and that column being validated.
    table.row(vec![
        format!("{} slots", window.len()),
        total.columns.to_string(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        format!("{:.1}ms", total.recv_to_proc_max),
        format!("{:.1}ms", total.cpu.as_secs_f64() * 1e3),
    ]);
    print!("{}", table.render());
    if window.iter().any(|slot| cap.slots[slot].is_backfill()) {
        println!("* served over RPC after its slot ended — not a gossip arrival curve");
    }
    eprint!("{}", fold_stats(&recorder.collect()).call_tree());
    ExitCode::SUCCESS
}
