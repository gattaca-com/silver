import { BlockTrace, SlotClock } from './trace.js';
import { Kind, SourceClass, Stage, TimingChannel } from './wire.js';

/** Datagram silence after which an instance renders as stale. */
const STALE_MS = 5000;
/** Peer rows and topic memberships not refreshed within this are dropped;
 *  covers a full round-robin sweep of a large peer set. */
const PEER_TTL_NS = 10e9;
/** 1 s buckets × 240 = 4 minutes, as surfer keeps. */
const HISTORY_LEN = 240;
/** 4 minutes of the exporter's 50 ms `fast:` samples, with slack. */
const SAMPLE_HISTORY_LEN = 5000;
const FAST_PREFIX = 'fast:';
/** Per instance; the oldest trace is dropped past this. */
const TRACES_CAP = 64;

/** Per-slot value and rate over consecutive completed buckets, columns
 *  aligned with `ts` (unix seconds). A slot first seen late is null-padded
 *  back. */
export class CounterHistory {
  constructor() {
    this.ts = [];
    this.values = [];
    this.rates = [];
  }

  /** The u64::MAX sentinel (null) on either side records a 0 rate, as
   *  surfer does; the value keeps the null. */
  push(cur, prev) {
    if (this.ts.length === HISTORY_LEN) {
      this.ts.shift();
      for (const v of this.values) v?.shift();
      for (const r of this.rates) r?.shift();
    }
    this.ts.push(cur.tsNs / 1e9);
    const secs = (cur.tsNs - prev.tsNs) / 1e9;
    for (let i = 0; i < cur.values.length; i++) {
      const a = cur.values[i];
      const b = prev.values[i];
      this.values[i] ??= new Array(this.ts.length - 1).fill(null);
      this.rates[i] ??= new Array(this.ts.length - 1).fill(null);
      this.values[i].push(a ?? null);
      this.rates[i].push(a === null || a === undefined || b === null || b === undefined ? 0 : (a - b) / secs);
    }
  }
}

const TIMING_FIELDS = ['count', 'p50', 'p99'];

/** Completed timing buckets of one source, both channels, columns aligned
 *  with `ts` (unix seconds). A bucket's two channels may arrive in separate
 *  datagrams; they share the header timestamp. */
export class TimingHistory {
  constructor() {
    this.ts = [];
    this.channels = [TimingChannel.Latency, TimingChannel.Processing].map(() => ({
      count: [],
      p50: [],
      p99: [],
    }));
  }

  /** An empty bucket records its zero count and null quantiles, so lines
   *  break over idle seconds rather than dropping to zero. */
  push(tsNs, t) {
    const ts = tsNs / 1e9;
    if (this.ts.at(-1) !== ts) {
      if (this.ts.length === HISTORY_LEN) {
        this.ts.shift();
        for (const c of this.channels) for (const f of TIMING_FIELDS) c[f].shift();
      }
      this.ts.push(ts);
      for (const c of this.channels) for (const f of TIMING_FIELDS) c[f].push(null);
    }
    const c = this.channels[t.channel];
    const i = this.ts.length - 1;
    c.count[i] = t.count;
    c.p50[i] = t.count ? t.p50Ns : null;
    c.p99[i] = t.count ? t.p99Ns : null;
  }
}

/** Raw values of a `fast:` counter source per sample, columns aligned with
 *  `ts` (unix seconds). */
export class SampleHistory {
  constructor() {
    this.ts = [];
    this.values = [];
  }

  /** A sample split across datagrams shares one timestamp. */
  push(tsNs, firstSlot, values) {
    const ts = tsNs / 1e9;
    if (this.ts.at(-1) !== ts) {
      if (this.ts.length === SAMPLE_HISTORY_LEN) {
        this.ts.shift();
        for (const v of this.values) v?.shift();
      }
      this.ts.push(ts);
      for (const v of this.values) v?.push(null);
    }
    const k = this.ts.length - 1;
    values.forEach((v, i) => {
      this.values[firstSlot + i] ??= new Array(this.ts.length).fill(null);
      this.values[firstSlot + i][k] = v;
    });
  }
}

export function tcacheMinTail(values) {
  const capacity = values[0] ?? 0;
  const head = values[1] ?? 0;
  const tails = values.slice(2);
  if (tails.every((t) => t === null)) return Math.max(0, head - capacity);
  return Math.min(...tails.map((t) => t ?? head));
}

export function tcacheLength(values) {
  return Math.max(0, (values[1] ?? 0) - tcacheMinTail(values));
}

/** One exporter's view. A `bootId` change invalidates every source id and
 *  every connection, so both reset with it; block traces survive. */
export class Instance {
  constructor(key) {
    this.key = key;
    this.label = key;
    this.buildInfo = '';
    this.clock = null;
    this.bootId = null;
    this.nextSeq = 0n;
    this.lost = 0;
    this.lastRecv = 0;
    this.nowNs = 0;
    /** Oldest first. */
    this.traces = [];
    this.resetBoot();
  }

  resetBoot() {
    this.sources = new Map();
    this.slotNames = new Map();
    this.counters = new Map();
    this.prevCounters = new Map();
    this.tcacheMaxLength = new Map();
    /** Per-slot value and rate history of every counter source, by id. */
    this.counterHistory = new Map();
    /** Per `fast:` source id; kept apart from the 1 s bucket history. */
    this.sampleHistory = new Map();
    /** Latest completed bucket per source id. */
    this.tileUtils = new Map();
    this.timings = new Map();
    this.timingHistory = new Map();
    this.peers = new Map();
  }

  stale(now) {
    return now - this.lastRecv > STALE_MS;
  }

  sourcesOf(cls) {
    return [...this.sources].filter(([, s]) => s.cls === cls).map(([id, s]) => ({ id, ...s }));
  }

  /** Samples and slot names of the `fast:{name}` source, or null. */
  samples(name) {
    const id = this.sourceNamed(FAST_PREFIX + name);
    const history = id === null ? null : this.sampleHistory.get(id);
    return history ? { history, names: this.slotNames.get(id) ?? [] } : null;
  }

  sourceNamed(name) {
    for (const [id, s] of this.sources) if (s.name === name) return id;
    return null;
  }

  /** Names come from the `gossip_topics` counter source, whose slot names
   *  are `{topic}_sent` at `4 * topicSlot`. */
  topicName(topicSlot) {
    const id = this.sourceNamed('gossip_topics');
    const name = id === null ? null : this.slotNames.get(id)?.[topicSlot * 4];
    return name ? name.replace(/_sent$/, '') : `topic_${topicSlot}`;
  }


  /** Drops peer rows and memberships older than the TTL, relative to this
   *  node's latest datagram so a replay ages rows by their own timestamps. */
  livePeers() {
    const floor = this.nowNs - PEER_TTL_NS;
    for (const [id, p] of this.peers) {
      if (p.seenNs < floor) {
        this.peers.delete(id);
        continue;
      }
      for (const [slot, t] of p.topics) if (t.seenNs < floor) p.topics.delete(slot);
      if (p.scores && p.scoresNs < floor) p.scores = null;
    }
    return this.peers;
  }

  peer(id, tsNs) {
    let p = this.peers.get(id);
    if (!p) this.peers.set(id, (p = { p2p: null, scores: null, scoresNs: 0, topics: new Map() }));
    p.seenNs = tsNs;
    return p;
  }

  apply(d) {
    this.lastRecv = performance.now();
    const tsNs = Number(d.tsNs);
    this.nowNs = Math.max(this.nowNs, tsNs);
    if (d.bootId !== this.bootId) {
      this.bootId = d.bootId;
      this.nextSeq = d.seq;
      this.resetBoot();
    }
    if (d.seq > this.nextSeq) this.lost += Number(d.seq - this.nextSeq);
    if (d.seq >= this.nextSeq) this.nextSeq = d.seq + 1n;

    switch (d.kind) {
      case Kind.Instance:
        this.label = d.text;
        break;
      case Kind.BuildInfo:
        this.buildInfo = d.text;
        break;
      case Kind.Chain:
        this.clock = new SlotClock(d.genesisUnixSecs, d.slotMs);
        break;
      case Kind.Sources:
        for (const s of d.sources) this.sources.set(s.id, { cls: s.cls, name: s.name });
        break;
      case Kind.SlotNames:
        splice(this.slotNames, d.sourceId, d.firstSlot, d.names);
        break;
      case Kind.CounterValues:
        this.applyCounters(d, tsNs);
        break;
      case Kind.TileUtils:
        for (const u of d.utils) this.tileUtils.set(u.sourceId, u);
        break;
      case Kind.Timings:
        for (const t of d.timings) {
          let entry = this.timings.get(t.sourceId);
          if (!entry) this.timings.set(t.sourceId, (entry = {}));
          entry[t.channel === TimingChannel.Latency ? 'latency' : 'processing'] = t;
          let history = this.timingHistory.get(t.sourceId);
          if (!history) this.timingHistory.set(t.sourceId, (history = new TimingHistory()));
          history.push(tsNs, t);
        }
        break;
      case Kind.PeerP2p:
        for (const e of d.entries) this.peer(e.peer, tsNs).p2p = e;
        break;
      case Kind.PeerScores:
        for (const e of d.entries) {
          const p = this.peer(e.peer, tsNs);
          p.scores = e;
          p.scoresNs = tsNs;
        }
        break;
      case Kind.PeerTopic:
        for (const e of d.entries) this.peer(e.peer, tsNs).topics.set(e.topicSlot, { ...e, seenNs: tsNs });
        break;
      case Kind.Stages:
        for (const e of d.entries) this.applyStage(e);
        break;
    }
  }

  /** One bucket spans several datagrams sharing a timestamp; the previous
   *  bucket is snapshotted when a newer one starts, for rates. */
  applyCounters(d, tsNs) {
    // Samples before the first Sources descriptor of a replay land in the
    // bucket path below and are not kept.
    if (this.sources.get(d.sourceId)?.name.startsWith(FAST_PREFIX)) {
      let history = this.sampleHistory.get(d.sourceId);
      if (!history) this.sampleHistory.set(d.sourceId, (history = new SampleHistory()));
      history.push(tsNs, d.firstSlot, d.values);
      return;
    }
    const cur = this.counters.get(d.sourceId);
    const tcache = this.sources.get(d.sourceId)?.cls === SourceClass.TCache;
    if (cur && cur.tsNs !== tsNs) {
      // `cur` is complete once a newer bucket starts.
      const prev = this.prevCounters.get(d.sourceId);
      if (prev) {
        let history = this.counterHistory.get(d.sourceId);
        if (!history) this.counterHistory.set(d.sourceId, (history = new CounterHistory()));
        history.push(cur, prev);
      }
      this.prevCounters.set(d.sourceId, { tsNs: cur.tsNs, values: cur.values.slice() });
    }
    const entry = cur ?? { tsNs, values: [] };
    entry.tsNs = tsNs;
    for (let i = 0; i < d.values.length; i++) entry.values[d.firstSlot + i] = d.values[i];
    this.counters.set(d.sourceId, entry);

    // Datagrams preceding the first Sources descriptor of a replay carry no
    // class yet and do not count towards the maximum.
    if (tcache) {
      const prev = this.tcacheMaxLength.get(d.sourceId) ?? 0;
      this.tcacheMaxLength.set(d.sourceId, Math.max(prev, tcacheLength(entry.values)));
    }
  }

  /** Per-second rate of slot `i` over the last completed bucket. */
  rate(sourceId, i) {
    const cur = this.counters.get(sourceId);
    const prev = this.prevCounters.get(sourceId);
    if (!cur || !prev || cur.tsNs <= prev.tsNs) return null;
    const delta = (cur.values[i] ?? 0) - (prev.values[i] ?? 0);
    return delta / ((cur.tsNs - prev.tsNs) / 1e9);
  }

  /** An announcement always opens a trace; other events only while live,
   *  so early columns land but replayed historical slots cannot churn it. */
  applyStage(e) {
    let trace = this.traces.findLast((t) => t.root === e.root);
    if (!trace) {
      if (e.slot === null) return;
      const live = e.stage === Stage.Received || this.clock?.offsetInSlot(e.ts, e.slot) != null;
      if (!live) return;
      if (this.traces.length === TRACES_CAP) this.traces.shift();
      const base = this.clock ? this.clock.slotStart(e.slot) : e.ts;
      this.traces.push((trace = new BlockTrace(e.slot, e.root, base)));
    }
    trace.apply(e);
  }
}

function splice(map, id, first, items) {
  let arr = map.get(id);
  if (!arr) map.set(id, (arr = []));
  for (let i = 0; i < items.length; i++) arr[first + i] = items[i];
  return arr;
}

export class Fleet {
  constructor() {
    this.instances = new Map();
  }

  apply(d) {
    const key = d.instanceId.toString(16);
    let inst = this.instances.get(key);
    if (!inst) this.instances.set(key, (inst = new Instance(key)));
    inst.apply(d);
  }

  sorted() {
    return [...this.instances.values()].sort((a, b) => a.label.localeCompare(b.label));
  }
}
