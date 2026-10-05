// Charts at the top of the Slots pane: each client's attestations processed
// and p2p bytes received per 100 ms of the current slot, from the 50 ms
// `fast:` counter samples.

import { fmtBytes } from './view.js';

const BIN_S = 0.1;
const HEIGHT = 160;
/** x axis until a client has described its chain: mainnet's slot. */
const DEFAULT_SLOT_S = 12;
/** Every attestation-data root lookup: single attestations past the
 *  committee checks, plus aggregates. */
const ATTESTATIONS = { source: 'beacon_state', counters: ['AttestationRootMemoHit', 'AttestationRootMemoMiss'] };
const P2P_RECV = { source: 'network', counters: ['P2pBytesRecv'] };

function slotAt(clock, unixS) {
  return Math.floor((unixS * 1e9 - Number(clock.genesisNs)) / clock.slotNs);
}

/** Per bin of the slot starting at `startS`, the summed counters' growth: each
 *  sample's delta lands in the bin holding its timestamp. A bin with no sample
 *  is null; a counter reset breaks the delta. A client without samples keeps
 *  an all-null line, so the chart stays up. */
function binnedSeries(inst, { source, counters }, slot, startS, bins) {
  const ys = new Array(bins).fill(null);
  const block = inst.traces.find((t) => t.slot === slot && t.receivedAt !== null);
  const blockX = block ? (Number(block.base) + block.receivedAt) / 1e9 - startS : null;
  const s = inst.samples(source);
  const cols = s ? counters.map((n) => s.history.values[s.names.indexOf(n)]) : [];
  if (!s || cols.some((c) => !c)) return { label: inst.label, ys, blockX };
  let prevTotal = null;
  s.history.ts.forEach((x, k) => {
    const parts = cols.map((c) => c[k]);
    const total = parts.some((v) => v === null || v === undefined) ? null : parts.reduce((a, b) => a + b, 0);
    const bin = Math.floor((x - startS) / BIN_S);
    if (bin >= 0 && bin < bins && total !== null && prevTotal !== null && total >= prevTotal) {
      ys[bin] = (ys[bin] ?? 0) + total - prevTotal;
    }
    prevTotal = total;
  });
  return { label: inst.label, ys, blockX };
}

/** One line per client over a fixed x axis: the seconds of the current slot.
 *  The bins run to now, so the lines grow across the slot and restart at the
 *  next one. A dashed line marks when each client received a block this slot;
 *  the top-right totals sum each client's bins so far. */
function slotSpec(instances, nowS, counter, fmt) {
  const clock = instances.find((i) => i.clock)?.clock;
  const slotS = clock ? clock.slotNs / 1e9 : DEFAULT_SLOT_S;
  const slot = clock ? slotAt(clock, nowS) : null;
  const startS = clock ? Number(clock.slotStart(slot)) / 1e9 : nowS;
  const bins = clock ? Math.min(Math.floor((nowS - startS) / BIN_S) + 1, Math.round(slotS / BIN_S)) : 0;
  const series = instances.map((inst) => binnedSeries(inst, counter, slot, startS, bins));
  const xs = Array.from({ length: bins }, (_, i) => Math.round(i * BIN_S * 10) / 10);
  const spec = {
    labels: series.map((s) => s.label),
    data: [xs, ...series.map((s) => s.ys)],
    fmt,
    height: HEIGHT,
    xSeconds: true,
    xRange: [0, slotS],
    spanGaps: true,
    markers: series.flatMap((s, i) => (s.blockX === null ? [] : [{ x: s.blockX, series: i }])),
    cornerLabels: series.map((s) => fmt(s.ys.reduce((sum, v) => sum + (v ?? 0), 0))),
  };
  return { spec, slot, startS };
}

function card(key, title) {
  return `<div><p class="meta">${title}</p><div class="chart" data-chart="${key}"></div></div>`;
}

/** Chart placeholders, with their specs added to `specs`. Both are always
 *  drawn, empty until data arrives. */
export function slotCharts(fleet, specs) {
  const nowS = Date.now() / 1000;
  const instances = fleet.sorted();
  const charts = [
    { key: 'slots-p2p', what: 'p2p bytes received', counter: P2P_RECV, fmt: (v) => fmtBytes(Math.round(v)) },
    { key: 'slots-att', what: 'attestations', counter: ATTESTATIONS, fmt: (v) => String(Math.round(v)) },
  ];
  const cards = charts.map(({ key, what, counter, fmt }) => {
    const built = slotSpec(instances, nowS, counter, fmt);
    specs.set(key, built.spec);
    if (built.slot === null) return card(key, `${what} per 100 ms`);
    const start = new Date(built.startS * 1000).toISOString().slice(11, 23);
    return card(key, `${what} per 100 ms, slot ${built.slot} from ${start} UTC`);
  });
  return `<div class="slot-charts">${cards.join('')}</div>`;
}
