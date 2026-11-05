// uPlot line-chart specs for the Cluster tab, over the retained seconds or
// per slot.

import { SERIES_MAX } from './chart.js';
import { align } from './cluster_model.js';
import { fmtNanos } from './events.js';

const HEIGHT = 180;
const fmtCount = (v) => String(Math.round(v));
const lineSpec = (labels, data, colourOf, fmt, extra = {}) => ({
  labels,
  data,
  colourOf,
  fmt,
  height: HEIGHT,
  spanGaps: true,
  ...extra,
});

/** Per-slot maps of several series on one x axis of slot start times. */
function alignSlots(nodes, maps) {
  const clockNode = nodes.find((n) => n.inst.clock);
  const slots = [...new Set(maps.flatMap((m) => [...m.keys()]))].sort((a, b) => a - b);
  const xs = slots.map((s) => clockNode?.slotStartS(s) ?? s);
  return [xs, ...maps.map((m) => slots.map((s) => m.get(s) ?? null))];
}

function slotMap(node, names, fold) {
  const { slots, columns } = node.perSlot(names, fold);
  return columns.map((col) => new Map(slots.map((s, i) => [s, col[i]])));
}

/** Per second, the larger p99 of several timing sources. */
function maxTiming(node, names) {
  const parts = names.map((name) => node.timing(name)).filter(Boolean);
  const bySecond = new Map();
  for (const t of parts) {
    t.ts.forEach((ts, k) => {
      const v = t.p99[k];
      if (v === null || v === undefined) return;
      const second = Math.round(ts);
      bySecond.set(second, Math.max(bySecond.get(second) ?? 0, v));
    });
  }
  const ts = [...bySecond.keys()].sort((x, y) => x - y);
  return { ts, ys: ts.map((t) => bySecond.get(t)) };
}

/** Per node, signed duty received → lock released. Attestations and blocks
 *  take the same Raft path, so one line takes whichever p99 is larger. */
export function latency(nodes) {
  const lines = nodes.map((node) => ({
    label: node.label,
    ...maxTiming(node, ['cluster_duty_attestation', 'cluster_duty_block']),
  }));
  const [xs, ...ys] = align(lines);
  return lineSpec(lines.map((l) => l.label), [xs, ...ys], nodes.map((n) => n.index), fmtNanos);
}

/** Each node's second peer is drawn dashed, so both links of a node share
 *  its colour and stay apart. */
function edges(nodes) {
  return nodes.flatMap((node) => node.peers().map((p, k) => ({ node, peer: p.nodeId, dashed: k > 0 })));
}

const dashedEdges = (list) => list.flatMap(({ dashed }, i) => (dashed ? [i] : []));

export function messages(nodes) {
  const list = edges(nodes);
  const maps = list.map(({ node, peer }) => node.peerPerSlot(peer, 'messagesOut'));
  return lineSpec(
    list.map(({ node, peer }) => `${node.label} → ${peer}`),
    alignSlots(nodes, maps),
    list.map(({ node }) => node.index),
    fmtCount,
    { stepped: true, dashed: dashedEdges(list) },
  );
}

const REFUSALS = [
  [['AttestationLockConflicting'], 'att conflicting', SERIES_MAX - 1, null],
  [['AttestationLockSurrounding'], 'att surrounding', SERIES_MAX - 1, 'dashed'],
  [['BlockLockConflicting'], 'block conflicting', SERIES_MAX - 2, null],
  [['AttestationLockTooOld', 'BlockLockTooOld'], 'too old', SERIES_MAX - 2, 'dashed'],
];

function summed(nodes, names) {
  const sum = new Map();
  for (const node of nodes) {
    for (const map of slotMap(node, names)) {
      for (const [slot, v] of map) if (v !== null) sum.set(slot, (sum.get(slot) ?? 0) + v);
    }
  }
  return sum;
}

/** Left axis: proposals stacked by the node the VC sent them to (series `i`
 *  is the sum of nodes `i..`, so each band is one node's share), and the
 *  locks they took. Right axis: refusals, which must stay at 0 with a single
 *  signer. */
export function locks(nodes) {
  const proposalMaps = nodes.map((n) => slotMap(n, ['ProposalsSubmitted'])[0]);
  const taken = summed(nodes, ['AttestationLockAccepted', 'BlockLockAccepted']);
  const refused = REFUSALS.map(([names]) => summed(nodes, names));
  const [xs, ...ys] = alignSlots(nodes, [...proposalMaps, taken, ...refused]);
  const proposals = ys.slice(0, nodes.length);
  const stacked = proposals.map((_, i) => xs.map((_, k) => proposals.slice(i).reduce((sum, col) => sum + (col[k] ?? 0), 0)));
  const rest = ys.slice(nodes.length);
  const labels = [...nodes.map((n) => `${n.label} proposals`), 'locks taken', ...REFUSALS.map(([, label]) => label)];
  const first = nodes.length + 1;
  return lineSpec(labels, [xs, ...stacked, ...rest], [...nodes.map((n) => n.index), SERIES_MAX - 3, ...REFUSALS.map(([, , colour]) => colour)], fmtCount, {
    stepped: true,
    fill: nodes.map((_, i) => i),
    right: REFUSALS.map((_, i) => first + i),
    fmtRight: fmtCount,
    dashed: REFUSALS.flatMap(([, , , style], i) => (style === 'dashed' ? [first + i] : [])),
  });
}
