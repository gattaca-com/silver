use std::{
    collections::{HashMap, VecDeque},
    io::Write,
};

use silver_common::{
    TCache, TCacheId, TCacheProducer, TCacheRead, TCacheReader, TCacheRef, TCacheTable,
    TMultiProducer, TProducer, TRead, TReadMode, TReservation,
};

pub const CAPACITY: usize = 256 * 1024;
pub const MSG: usize = 8 * 1024;
/// Pads the `links` array of `Action::Consume`.
pub const NONE: usize = usize::MAX;

#[derive(Clone, Copy, Debug)]
pub struct Msg {
    pub read: TCacheRead,
    pub tag: u8,
}

/// One spine queue between two nodes.
#[derive(Default)]
pub struct Link(VecDeque<Msg>);

pub enum Writer {
    Single(TProducer),
    Multi(TMultiProducer),
}

impl Writer {
    fn producer(&mut self) -> &mut dyn TCacheProducer {
        match self {
            Self::Single(p) => p,
            Self::Multi(p) => p,
        }
    }

    pub fn cache_ref(&self) -> TCacheRef {
        match self {
            Self::Single(p) => p.cache_ref(),
            Self::Multi(p) => p.cache_ref(),
        }
    }
}

struct Open {
    reservation: TReservation,
    tag: u8,
}

pub struct Node {
    pub name: &'static str,
    // Boxed: acquired reads point into it and nodes live in a Vec.
    pub reader: Box<TCacheReader>,
    pub writers: Vec<Writer>,
    held: Vec<(TRead, Msg)>,
    consumed: HashMap<TCacheId, u64>,
    bare: Vec<Msg>,
    open: Vec<Open>,
    script: VecDeque<Action>,
    // A retained consumer pins by boundary; its producer blocking is not a stall.
    retains: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum Then {
    /// Acquire, verify, release.
    Acquire,
    /// Acquire, verify, keep pinned in `held`.
    Hold,
    /// Keep the bare descriptor in `bare`.
    HoldBare,
    /// Acquire, verify, emit the same read on `link`, release.
    ForwardPinned {
        link: usize,
    },
    /// Acquire and hold; once more than `depth` reads are held, emit the
    /// oldest on `link` and release it. A forwarder with a fixed delay.
    Delay {
        link: usize,
        depth: usize,
    },
    Drop,
}

#[derive(Clone, Copy, Debug)]
pub enum Drain {
    All,
    One,
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    /// Reserve without committing; `writer` indexes `Node::writers`.
    Reserve {
        writer: usize,
        tag: u8,
    },
    /// Commit and emit the oldest open reservation.
    Emit {
        link: usize,
    },
    /// Commit and emit the newest open reservation: a later stream completing
    /// first.
    EmitNewest {
        link: usize,
    },
    /// Reserve, commit and emit in one step.
    Produce {
        writer: usize,
        tag: u8,
        link: usize,
    },
    /// One reservation, the same read on every link: a spine broadcast.
    Broadcast {
        writer: usize,
        tag: u8,
        links: &'static [usize],
    },
    /// Consume `count` messages from `links` (`NONE` pads), `drain` per step,
    /// freeing the reader after each step. Blocks while every link is empty.
    Consume {
        links: [usize; 2],
        drain: Drain,
        then: Then,
        count: usize,
    },
    /// Acquire the oldest bare descriptor, verify, emit it on `link`.
    ForwardHeldBare {
        link: usize,
    },
    /// Emit the oldest pinned read on `link`, then release it: a forwarder
    /// that pins on arrival and forwards after a delay.
    ForwardOldestHeld {
        link: usize,
    },
    ReleaseAll,
    Free,
    Open {
        cache: TCacheId,
        name: &'static str,
        mode: TReadMode,
    },
    /// Advance the fixed retention boundary to the last seq this node acquired
    /// on `cache`: everything older is done with.
    AdvanceRetentionToConsumed {
        cache: TCacheId,
    },
    /// No-op turn, to delay a node relative to the others.
    Skip,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    /// An emitted read was acquired but its bytes were gone or wrong.
    Stale { node: &'static str, seq: u64, detail: String },
    /// An emitted read was acquired below the consumer's tail: intact, but
    /// the pin is not counted and the producer may reclaim it while held.
    BelowTail { node: &'static str, seq: u64 },
    /// A producer could not reserve while nothing anywhere protects the ring.
    Stall { node: &'static str },
    /// Scripts remain but no node can make progress.
    Deadlock,
}

impl Node {
    pub fn new(name: &'static str, tcaches: TCacheTable) -> Self {
        Self {
            name,
            reader: Box::new(TCacheReader::new(tcaches)),
            writers: Vec::new(),
            held: Vec::new(),
            consumed: HashMap::new(),
            bare: Vec::new(),
            open: Vec::new(),
            script: VecDeque::new(),
            retains: false,
        }
    }

    pub fn with_writer(mut self, writer: Writer) -> Self {
        self.writers.push(writer);
        self
    }

    pub fn open(mut self, cache: TCacheId, mode: TReadMode) -> Self {
        self.reader.open(cache, self.name, mode).unwrap();
        self.retains |= matches!(mode, TReadMode::Retained);
        self
    }

    pub fn script(mut self, actions: impl IntoIterator<Item = Action>) -> Self {
        self.script.extend(actions);
        self
    }
}

pub struct World {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
    pub violations: Vec<Violation>,
    pub steps: usize,
}

impl World {
    /// Consecutive repeats (a stalled producer retrying) collapse to one.
    fn violate(&mut self, violation: Violation) {
        if self.violations.last() != Some(&violation) {
            self.violations.push(violation);
        }
    }
}

enum Progress {
    /// The action completed.
    Advanced,
    /// The action did work but stays at the front of the script.
    Partial,
    Blocked,
}

impl World {
    pub fn new(nodes: Vec<Node>, links: usize) -> Self {
        Self {
            nodes,
            links: (0..links).map(|_| Link::default()).collect(),
            violations: Vec::new(),
            steps: 0,
        }
    }

    pub fn cache(id: TCacheId) -> TProducer {
        TCache::producer(id, CAPACITY)
    }

    pub fn table(writers: &[&Writer]) -> TCacheTable {
        TCacheTable::from_iter(writers.iter().map(|w| w.cache_ref()))
    }

    /// Run every node's script to completion in the given interleaving.
    pub fn run(&mut self, driver: Driver) -> &[Violation] {
        let mut rng = Xorshift(match driver {
            Driver::Sequential => 0,
            Driver::Random { seed } => seed,
        });
        loop {
            let pending: Vec<usize> =
                (0..self.nodes.len()).filter(|&n| !self.nodes[n].script.is_empty()).collect();
            if pending.is_empty() {
                break;
            }
            // Sequential: every node takes one step per round, in order.
            // Random: one node per round, chosen by the seed; blocked nodes
            // pass the turn on.
            let mut advanced = false;
            match driver {
                Driver::Sequential => {
                    for node in pending {
                        advanced |= !matches!(self.step(node), Progress::Blocked);
                    }
                }
                Driver::Random { .. } => {
                    let start = rng.next() as usize % pending.len();
                    for node in pending.iter().cycle().skip(start).take(pending.len()) {
                        if !matches!(self.step(*node), Progress::Blocked) {
                            advanced = true;
                            break;
                        }
                    }
                }
            }
            if !advanced {
                self.violations.push(Violation::Deadlock);
                break;
            }
            self.steps += 1;
            assert!(self.steps < 100_000, "runaway schedule");
        }
        &self.violations
    }

    fn step(&mut self, n: usize) -> Progress {
        let Some(&action) = self.nodes[n].script.front() else { return Progress::Blocked };
        let progress = match action {
            Action::Reserve { writer, tag } => self.reserve(n, writer, tag),
            Action::Emit { link } => self.emit(n, 0, &[link]),
            Action::EmitNewest { link } => {
                let newest = self.nodes[n].open.len().saturating_sub(1);
                self.emit(n, newest, &[link])
            }
            Action::Produce { writer, tag, link } => self.produce(n, writer, tag, &[link]),
            Action::Broadcast { writer, tag, links } => self.produce(n, writer, tag, links),
            Action::Consume { links, drain, then, count } => {
                let mut taken = 0;
                for link in links.into_iter().filter(|&l| l != NONE) {
                    let available = self.links[link].0.len().min(count - taken);
                    let step = match drain {
                        Drain::All => available,
                        Drain::One if taken == 0 => available.min(1),
                        Drain::One => 0,
                    };
                    for _ in 0..step {
                        let msg = self.links[link].0.pop_front().unwrap();
                        self.receive(n, msg, then);
                        taken += 1;
                    }
                }
                if taken == 0 {
                    return Progress::Blocked;
                }
                self.nodes[n].reader.free();
                if count > taken {
                    *self.nodes[n].script.front_mut().unwrap() =
                        Action::Consume { links, drain, then, count: count - taken };
                    return Progress::Partial;
                }
                Progress::Advanced
            }
            Action::ForwardHeldBare { link } => {
                let node = &mut self.nodes[n];
                if node.bare.is_empty() {
                    return Progress::Blocked;
                }
                let msg = node.bare.remove(0);
                self.receive(n, msg, Then::ForwardPinned { link });
                Progress::Advanced
            }
            Action::ForwardOldestHeld { link } => {
                let node = &mut self.nodes[n];
                if node.held.is_empty() {
                    return Progress::Blocked;
                }
                let (read, msg) = node.held.remove(0);
                if let Err(detail) = intact(&read, msg.tag) {
                    let seq = msg.read.seq();
                    self.violations.push(Violation::Stale { node: node.name, seq, detail });
                }
                self.links[link].0.push_back(msg);
                drop(read);
                Progress::Advanced
            }
            Action::ReleaseAll => {
                // A pin that was not counted (acquired below the tail) may have
                // been reclaimed underneath; the bytes tell.
                let node = &mut self.nodes[n];
                for (read, msg) in node.held.drain(..) {
                    if let Err(detail) = intact(&read, msg.tag) {
                        let seq = read.seq();
                        self.violations.push(Violation::Stale { node: node.name, seq, detail });
                    }
                }
                Progress::Advanced
            }
            Action::Free => {
                self.nodes[n].reader.free();
                Progress::Advanced
            }
            Action::Open { cache, name, mode } => {
                self.nodes[n].reader.open(cache, name, mode).unwrap();
                self.nodes[n].retains |= matches!(mode, TReadMode::Retained);
                Progress::Advanced
            }
            Action::AdvanceRetentionToConsumed { cache } => {
                let Some(&seq) = self.nodes[n].consumed.get(&cache) else {
                    return Progress::Blocked;
                };
                self.nodes[n].reader.advance_retention(cache, seq);
                Progress::Advanced
            }
            Action::Skip => Progress::Advanced,
        };
        if let Progress::Advanced = progress {
            self.nodes[n].script.pop_front();
        }
        progress
    }

    fn produce(&mut self, n: usize, writer: usize, tag: u8, links: &[usize]) -> Progress {
        match self.reserve(n, writer, tag) {
            Progress::Advanced => {
                let newest = self.nodes[n].open.len() - 1;
                self.emit(n, newest, links)
            }
            other => other,
        }
    }

    fn emit(&mut self, n: usize, index: usize, links: &[usize]) -> Progress {
        let node = &mut self.nodes[n];
        if node.open.is_empty() {
            return Progress::Blocked;
        }
        let Open { mut reservation, tag } = node.open.remove(index);
        reservation.flush().unwrap();
        let read = reservation.read();
        for &link in links {
            self.links[link].0.push_back(Msg { read, tag });
        }
        Progress::Advanced
    }

    fn reserve(&mut self, n: usize, writer: usize, tag: u8) -> Progress {
        let node = &mut self.nodes[n];
        match node.writers[writer].producer().reserve(MSG, false) {
            Some(mut reservation) => {
                reservation.buffer().unwrap().fill(tag);
                reservation.increment_offset(MSG);
                node.open.push(Open { reservation, tag });
                Progress::Advanced
            }
            None => {
                if node.open.is_empty() && self.nothing_protects() {
                    self.violate(Violation::Stall { node: self.nodes[n].name });
                    // Unblock the schedule: the failure is recorded.
                    self.nodes[n].script.pop_front();
                    return Progress::Partial;
                }
                Progress::Blocked
            }
        }
    }

    fn nothing_protects(&self) -> bool {
        self.nodes.iter().all(|node| !node.retains && node.held.is_empty() && node.bare.is_empty()) &&
            self.links.iter().all(|link| link.0.is_empty())
    }

    fn receive(&mut self, n: usize, msg: Msg, then: Then) {
        match then {
            Then::Drop => {}
            Then::HoldBare => self.nodes[n].bare.push(msg),
            Then::Acquire | Then::Hold | Then::ForwardPinned { .. } | Then::Delay { .. } => {
                let node = &mut self.nodes[n];
                let seq = msg.read.seq();
                // Strict first: `None` means below the tail or already overwritten.
                let acquired = match node.reader.acquire_strict(msg.read) {
                    Some(acquired) => acquired,
                    None => {
                        let acquired = node.reader.acquire(msg.read);
                        if intact(&acquired, msg.tag).is_ok() {
                            self.violations.push(Violation::BelowTail { node: node.name, seq });
                        }
                        acquired
                    }
                };
                if let Err(detail) = intact(&acquired, msg.tag) {
                    self.violations.push(Violation::Stale { node: node.name, seq, detail });
                }
                node.consumed.insert(msg.read.id(), msg.read.seq());
                match then {
                    Then::Hold => node.held.push((acquired, msg)),
                    Then::Delay { link, depth } => {
                        node.held.push((acquired, msg));
                        if node.held.len() > depth {
                            let (oldest, msg) = node.held.remove(0);
                            self.links[link].0.push_back(msg);
                            drop(oldest);
                        }
                    }
                    Then::ForwardPinned { link } => {
                        self.links[link].0.push_back(msg);
                        drop(acquired);
                    }
                    _ => drop(acquired),
                }
            }
        }
    }
}

fn intact(read: &TRead, tag: u8) -> Result<(), String> {
    let (bytes, _) = read.buffer().map_err(|e| format!("{e:?}"))?;
    if bytes.len() != MSG {
        return Err(format!("len {}", bytes.len()));
    }
    match bytes.iter().find(|b| **b != tag) {
        Some(other) => Err(format!("tag {other:#x} != {tag:#x}")),
        None => Ok(()),
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Driver {
    /// Nodes advance in declaration order, one action each per round.
    Sequential,
    /// Random interleaving, reproducible from `seed`.
    Random { seed: u64 },
}

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// `n` messages of `tag` from `writer` onto `link`.
pub fn produce(writer: usize, tag: u8, link: usize, n: usize) -> impl Iterator<Item = Action> {
    std::iter::repeat_n(Action::Produce { writer, tag, link }, n)
}

/// Consume `n` messages from `link`, draining all available each step.
pub fn consume(link: usize, then: Then, n: usize) -> Action {
    Action::Consume { links: [link, NONE], drain: Drain::All, then, count: n }
}

/// As `consume`, one message per step.
pub fn consume_one(link: usize, then: Then, n: usize) -> Action {
    Action::Consume { links: [link, NONE], drain: Drain::One, then, count: n }
}

/// Enough messages to wrap the ring `times` over.
pub fn wraps(times: usize) -> usize {
    times * CAPACITY / MSG
}

/// What the current implementation is known to do on a pattern.
#[derive(Clone, Copy, Debug)]
pub enum Expect {
    Holds,
    /// Fails today for the stated reason; flips to `Holds` when that is fixed.
    Known(&'static str),
}

pub fn check(world: &World, expect: Expect) {
    match expect {
        Expect::Holds => assert!(
            world.violations.is_empty(),
            "violations after {} steps: {:?}",
            world.steps,
            world.violations
        ),
        Expect::Known(reason) => {
            eprintln!("known limitation ({reason}) reproduced: {:?}", world.violations);
            assert!(
                !world.violations.is_empty(),
                "known limitation ({reason}) no longer reproduces after {} steps; flip to Holds",
                world.steps
            );
        }
    }
}
