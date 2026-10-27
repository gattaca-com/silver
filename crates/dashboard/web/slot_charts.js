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

/** The current slot and its 100 ms bins so far, on a fixed x axis of the slot's
 *  seconds. Without a clock, no slot and no bins. */
export function slotWindow(clock, nowS) {
  const slotS = clock ? clock.slotNs / 1e9 : DEFAULT_SLOT_S;
  const slot = clock ? slotAt(clock, nowS) : null;
  const startS = clock ? Number(clock.slotStart(slot)) / 1e9 : nowS;
  const bins = clock ? Math.min(Math.floor((nowS - startS) / BIN_S) + 1, Math.round(slotS / BIN_S)) : 0;
  const xs = Array.from({ length: bins }, (_, i) => Math.round(i * BIN_S * 10) / 10);
  return { slot, slotS, startS, bins, xs };
}

/** Per bin of the slot starting at `startS`, the summed counters' growth: each
 *  sample's delta lands in the bin holding its timestamp. A bin with no sample
 *  is null; a counter reset breaks the delta. A client without samples keeps
 *  an all-null line, so the chart stays up. */
export function binnedSeries(inst, { source, counters }, slot, startS, bins) {
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

const clientKey = (inst) => `client:${inst.key}`;
const lineKey = (line) => `line:${line.name}`;

/** Per client, one line per entry of `lines`, in the client's colour, over a
 *  fixed x axis: the seconds of the current slot. The bins run to now, so the
 *  lines grow across the slot and restart at the next one. A dashed vertical
 *  marks when each client received a block this slot; the top-right totals
 *  sum each client's bins so far across all its lines. A client or line in
 *  `hidden` keeps its series, all null, so the plot is not rebuilt. */
function slotSpec(instances, nowS, lines, fmt, height, hidden) {
  const { slot, slotS, startS, bins, xs } = slotWindow(instances.find((i) => i.clock)?.clock, nowS);
  const shown = (line, inst) => !hidden.has(clientKey(inst)) && !(line.name && hidden.has(lineKey(line)));
  // Line-major: series `l * clients + i` is line `l` of client `i`, so the
  // first line's series index is the client's, as markers and corner labels
  // expect.
  const perLine = lines.map((line) =>
    instances.map((inst) => {
      const s = binnedSeries(inst, line.counter, slot, startS, bins);
      return shown(line, inst) ? s : { ...s, ys: new Array(bins).fill(null) };
    }),
  );
  const series = perLine[0];
  const sum = (ys) => ys.reduce((total, v) => total + (v ?? 0), 0);
  const clientShown = instances.map((inst) => !hidden.has(clientKey(inst)));
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
    markers: series.flatMap((s, i) => (s.blockX === null || !clientShown[i] ? [] : [{ x: s.blockX, series: i }])),
    cornerLabels: series.map((_, i) =>
      clientShown[i] ? fmt(perLine.reduce((total, line) => total + sum(line[i].ys), 0)) : '',
    ),
  };
  return { spec, slot, startS };
}

const fmtCount = (v) => String(Math.round(v));

/** The attestations chart alone, every client shown; returns its title. */
export function attestationsChart(fleet, specs, key, height) {
  const built = slotSpec(fleet.sorted(), Date.now() / 1000, [{ counter: ATTESTATIONS }], fmtCount, height, new Set());
  specs.set(key, built.spec);
  return built.slot === null ? 'attestations per 100 ms' : `attestations per 100 ms, slot ${built.slot}`;
}

function card(key, place, title) {
  return `<div class="${place}"><p class="meta" title="${title}">${title}</p><div class="chart" data-chart="${key}"></div></div>`;
}

/** Client colours, shared by all charts, and the gossip/rpc line styles; each
 *  entry toggles its lines. */
function legend(instances, hidden) {
  const entry = (key, mark, label) =>
    `<span data-slot-legend="${escape(key)}"${hidden.has(key) ? ' class="off"' : ''}>${mark}${label}</span>`;
  const clients = instances.map((inst, i) =>
    entry(clientKey(inst), `<i style="border-top-color: var(--series-${i + 1})"></i>`, escape(inst.label)),
  );
  const styles = BYTES_RECV.map((line) =>
    entry(lineKey(line), `<i${line.dashed ? ' class="dashed"' : ''}></i>`, line.name),
  );
  return `<div class="slot-legend">${[...clients, ...styles].join('')}</div>`;
}

/** True when the click toggled a legend entry in `hidden`. */
export function legendClick(target, hidden) {
  const key = target.closest('[data-slot-legend]')?.dataset.slotLegend;
  if (!key) return false;
  if (!hidden.delete(key)) hidden.add(key);
  return true;
}

/** Chart placeholders, with their specs added to `specs`. All are always
 *  drawn, empty until data arrives; `hidden` holds the legend entries
 *  toggled off. */
export function slotCharts(fleet, specs, hidden) {
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
      fmt: fmtCount,
      height: RIGHT_HEIGHT,
    },
  ];
  const cards = charts.map(({ key, place, what, lines, fmt, height }) => {
    const built = slotSpec(instances, nowS, lines, fmt, height, hidden);
    specs.set(key, built.spec);
    if (built.slot === null) return card(key, place, `${what} per 100 ms`);
    const start = new Date(built.startS * 1000).toISOString().slice(11, 23);
    return card(key, place, `${what} per 100 ms, slot ${built.slot} from ${start} UTC`);
  });
  return `<div class="slot-charts">${cards.join('')}${legend(instances, hidden)}</div>`;
}
