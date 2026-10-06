// Charts at the top of the Slots pane: each client's bytes received and sent
// (gossip solid, rpc dashed) and attestations processed, per 100 ms of the
// current slot, from the 50 ms `fast:` counter samples.

import { escape, fmtBytes } from './view.js';

const BIN_S = 0.1;
const HEIGHT = 160;
/** `.slot-charts` row gap and `.meta` height + margin in index.html. */
const SLOT_ROW_GAP = 8;
const SLOT_TITLE_H = 16;
/** The right chart spans both left rows: their two plots, one more title and
 *  the gap between them. */
const RIGHT_HEIGHT = 2 * HEIGHT + SLOT_TITLE_H + SLOT_ROW_GAP;
/** x axis until a client has described its chain: mainnet's slot. */
const DEFAULT_SLOT_S = 12;
/** Every attestation-data root lookup: single attestations past the
 *  committee checks, plus aggregates. */
const ATTESTATIONS = { source: 'beacon_state', counters: ['AttestationRootMemoHit', 'AttestationRootMemoMiss'] };
const network = (counter) => ({ source: 'network', counters: [counter] });
const BYTES_RECV = [
  { name: 'gossip', counter: network('P2pGossipBytesRecv') },
  { name: 'rpc', counter: network('P2pRpcBytesRecv'), dashed: true },
];
const BYTES_SENT = [
  { name: 'gossip', counter: network('P2pGossipBytesSent') },
  { name: 'rpc', counter: network('P2pRpcBytesSent'), dashed: true },
];

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

/** Per client, one line per entry of `lines`, in the client's colour, over a
 *  fixed x axis: the seconds of the current slot. The bins run to now, so the
 *  lines grow across the slot and restart at the next one. A dashed vertical
 *  marks when each client received a block this slot; the top-right totals
 *  sum each client's bins so far across all its lines. */
function slotSpec(instances, nowS, lines, fmt, height) {
  const clock = instances.find((i) => i.clock)?.clock;
  const slotS = clock ? clock.slotNs / 1e9 : DEFAULT_SLOT_S;
  const slot = clock ? slotAt(clock, nowS) : null;
  const startS = clock ? Number(clock.slotStart(slot)) / 1e9 : nowS;
  const bins = clock ? Math.min(Math.floor((nowS - startS) / BIN_S) + 1, Math.round(slotS / BIN_S)) : 0;
  // Line-major: series `l * clients + i` is line `l` of client `i`, so the
  // first line's series index is the client's, as markers and corner labels
  // expect.
  const perLine = lines.map(({ counter }) => instances.map((inst) => binnedSeries(inst, counter, slot, startS, bins)));
  const series = perLine[0];
  const xs = Array.from({ length: bins }, (_, i) => Math.round(i * BIN_S * 10) / 10);
  const sum = (ys) => ys.reduce((total, v) => total + (v ?? 0), 0);
  const spec = {
    labels: perLine.flatMap((line, l) => line.map((s) => (lines[l].name ? `${s.label} ${lines[l].name}` : s.label))),
    data: [xs, ...perLine.flatMap((line) => line.map((s) => s.ys))],
    colourOf: perLine.flatMap((line) => line.map((_, i) => i)),
    dashed: lines.flatMap((line, l) => (line.dashed ? instances.map((_, i) => l * instances.length + i) : [])),
    fmt,
    height,
    legend: false,
    xSeconds: true,
    xRange: [0, slotS],
    spanGaps: true,
    markers: series.flatMap((s, i) => (s.blockX === null ? [] : [{ x: s.blockX, series: i }])),
    cornerLabels: series.map((_, i) => fmt(perLine.reduce((total, line) => total + sum(line[i].ys), 0))),
  };
  return { spec, slot, startS };
}

function card(key, place, title) {
  return `<div class="${place}"><p class="meta" title="${title}">${title}</p><div class="chart" data-chart="${key}"></div></div>`;
}

/** Client colours, shared by all charts, and the gossip/rpc line styles. */
function legend(instances) {
  const clients = instances.map(
    (inst, i) => `<span><i style="border-top-color: var(--series-${i + 1})"></i>${escape(inst.label)}</span>`,
  );
  const styles = ['<span><i></i>gossip</span>', '<span><i class="dashed"></i>rpc</span>'];
  return `<div class="slot-legend">${[...clients, ...styles].join('')}</div>`;
}

/** Chart placeholders, with their specs added to `specs`. All are always
 *  drawn, empty until data arrives. */
export function slotCharts(fleet, specs) {
  const nowS = Date.now() / 1000;
  const instances = fleet.sorted();
  const bytes = (v) => fmtBytes(Math.round(v));
  const charts = [
    { key: 'slots-recv', place: 'left-1', what: 'bytes received', lines: BYTES_RECV, fmt: bytes, height: HEIGHT },
    { key: 'slots-sent', place: 'left-2', what: 'bytes sent', lines: BYTES_SENT, fmt: bytes, height: HEIGHT },
    {
      key: 'slots-att',
      place: 'right',
      what: 'attestations',
      lines: [{ counter: ATTESTATIONS }],
      fmt: (v) => String(Math.round(v)),
      height: RIGHT_HEIGHT,
    },
  ];
  const cards = charts.map(({ key, place, what, lines, fmt, height }) => {
    const built = slotSpec(instances, nowS, lines, fmt, height);
    specs.set(key, built.spec);
    if (built.slot === null) return card(key, place, `${what} per 100 ms`);
    const start = new Date(built.startS * 1000).toISOString().slice(11, 23);
    return card(key, place, `${what} per 100 ms, slot ${built.slot} from ${start} UTC`);
  });
  return `<div class="slot-charts">${cards.join('')}${legend(instances)}</div>`;
}
