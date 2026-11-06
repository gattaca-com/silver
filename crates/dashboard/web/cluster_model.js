// What the Cluster tab reads per clustered instance: its `cluster` counters,
// cluster timing sources, Raft peer records and resolved commit samples,
// reduced to per-second and per-slot views.

import { SERIES_MAX } from './chart.js';
import { TimingChannel } from './wire.js';

const SOURCE = 'cluster';
/** Mainnet's slot, until an instance has described its chain. */
const DEFAULT_SLOT_NS = 12e9;

export const ROLES = ['follower', 'candidate', 'leader'];

export function mean(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
}

export function fmtUs(us) {
  if (us === null || us === undefined) return '·';
  if (us < 1000) return `${Math.round(us)}µs`;
  if (us < 1e6) return `${(us / 1000).toFixed(us < 1e4 ? 1 : 0)}ms`;
  return `${(us / 1e6).toFixed(2)}s`;
}

export function colourOf(index) {
  return index < SERIES_MAX ? `var(--series-${index + 1})` : 'var(--fg)';
}

/** One clustered instance. `index` is its fleet position, which picks its
 *  colour everywhere. */
export class ClusterNode {
  constructor(inst, index) {
    this.inst = inst;
    this.index = index;
    this.colour = colourOf(index);
    this.label = inst.label;
    this.id = inst.sourceNamed(SOURCE);
    this.names = this.id === null ? [] : (inst.slotNames.get(this.id) ?? []);
    this.history = this.id === null ? null : inst.counterHistory.get(this.id);
    this.nodeId = null;
  }

  get present() {
    return this.id !== null && this.inst.counters.has(this.id);
  }

  get slotNs() {
    return this.inst.clock?.slotNs ?? DEFAULT_SLOT_NS;
  }

  slotAt(unixS) {
    const clock = this.inst.clock;
    if (!clock) return null;
    return Math.floor((unixS * 1e9 - Number(clock.genesisNs)) / clock.slotNs);
  }

  slotStartS(slot) {
    const clock = this.inst.clock;
    return clock ? Number(clock.slotStart(slot)) / 1e9 : null;
  }

  value(name) {
    const i = this.names.indexOf(name);
    return i < 0 ? null : (this.inst.counters.get(this.id)?.values[i] ?? null);
  }

  /** Raw values of `name` per completed second, `{ ts, ys }`. */
  series(name) {
    const ys = this.history?.values[this.names.indexOf(name)];
    return this.history && ys ? { ts: this.history.ts, ys } : { ts: [], ys: [] };
  }

  /** Growth of an event counter per second, `{ ts, ys }`. */
  deltas(name) {
    const { ts, ys } = this.series(name);
    const out = ts.map((_, k) => {
      const a = ys[k];
      const b = ys[k - 1];
      return k === 0 || a === null || b === null || b === undefined || a < b ? null : a - b;
    });
    return { ts, ys: out };
  }

  /** Per slot of the retained seconds, `fold` over each name's per-second
   *  values: growth for event counters, the maximum for gauges. */
  perSlot(names, fold = 'delta') {
    const slots = [];
    const columns = names.map(() => []);
    if (!this.inst.clock || !this.history) return { slots, columns };
    const series = names.map((n) => (fold === 'delta' ? this.deltas(n) : this.series(n)).ys);
    this.history.ts.forEach((t, k) => {
      const slot = this.slotAt(t);
      if (slots.at(-1) !== slot) {
        slots.push(slot);
        for (const c of columns) c.push(null);
      }
      series.forEach((ys, i) => {
        const v = ys[k];
        if (v === null || v === undefined) return;
        const col = columns[i];
        const last = col.length - 1;
        col[last] = fold === 'delta' ? (col[last] ?? 0) + v : Math.max(col[last] ?? 0, v);
      });
    });
    return { slots, columns };
  }

  windowTotal(name) {
    return this.deltas(name).ys.reduce((a, b) => a + (b ?? 0), 0);
  }

  /** Latency channel of a timing source: `{ ts, count, p50, p99 }` in ns,
   *  or null before it reports. */
  timing(name) {
    const id = this.inst.sourceNamed(name);
    const history = id === null ? null : this.inst.timingHistory.get(id);
    if (!history) return null;
    return { ts: history.ts, ...history.channels[TimingChannel.Latency] };
  }

  peers() {
    return [...this.inst.liveClusterPeers().values()].sort((a, b) => a.nodeId - b.nodeId);
  }

  peerHistory(nodeId) {
    return this.inst.clusterPeerHistory.get(nodeId) ?? [];
  }

  /** Growth per slot of a cumulative peer field, from consecutive records;
   *  a node restart (a falling count) breaks the delta. */
  peerPerSlot(nodeId, field) {
    const records = this.peerHistory(nodeId);
    const bySlot = new Map();
    for (let k = 1; k < records.length; k++) {
      const a = records[k][field];
      const b = records[k - 1][field];
      if (a === null || b === null || a < b) continue;
      const slot = this.slotAt(records[k].seenNs / 1e9);
      if (slot === null) continue;
      bySlot.set(slot, (bySlot.get(slot) ?? 0) + a - b);
    }
    return bySlot;
  }

  commits() {
    return this.inst.clusterCommits;
  }

  commitsBySlot() {
    const bySlot = new Map();
    for (const c of this.commits()) {
      let list = bySlot.get(c.slot);
      if (!list) bySlot.set(c.slot, (list = []));
      list.push(c);
    }
    return bySlot;
  }
}

/** Instances exporting the `cluster` counters, in fleet order, each tagged
 *  with its own Raft node id: the one voter id its peer records leave out. */
export function clusterNodes(fleet) {
  const nodes = fleet
    .sorted()
    .map((inst, index) => new ClusterNode(inst, index))
    .filter((node) => node.present && node.value('Clustered') === 1);
  const voters = new Set(nodes.flatMap((node) => node.peers().map((p) => p.nodeId)));
  for (const node of nodes) {
    const peers = new Set(node.peers().map((p) => p.nodeId));
    const own = [...voters].filter((id) => !peers.has(id));
    node.nodeId = own.length === 1 ? own[0] : null;
  }
  return nodes;
}

/** The slots shown in per-slot panels: the last `count` slots any node has
 *  data for. */
export function windowSlots(nodes, count) {
  let last = null;
  for (const node of nodes) {
    const { slots } = node.perSlot(['ProposalsSubmitted']);
    const commitSlot = node.commits().at(-1)?.slot;
    for (const s of [slots.at(-1), commitSlot]) if (s !== undefined && s !== null) last = Math.max(last ?? s, s);
  }
  if (last === null) return [];
  return Array.from({ length: count }, (_, i) => last - count + 1 + i);
}

/** Series sampled at different instants, on one x axis of whole seconds. */
export function align(series) {
  const xs = [...new Set(series.flatMap((s) => s.ts.map(Math.round)))].sort((a, b) => a - b);
  const at = new Map(xs.map((x, i) => [x, i]));
  const data = series.map((s) => {
    const ys = new Array(xs.length).fill(null);
    s.ts.forEach((t, k) => (ys[at.get(Math.round(t))] = s.ys[k] ?? null));
    return ys;
  });
  return [xs, ...data];
}
