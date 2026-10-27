// Gossip pane, traffic view: gossip bytes per topic over the current slot,
// binned per 100 ms and stacked, from the exporter's `fast:gossip_bytes_*`.

import { SERIES_MAX } from './chart.js';
import { binnedSeries, slotWindow } from './slot_charts.js';
import { escape, fmtBytes } from './view.js';

const SOURCES = { recv: 'gossip_bytes_recv', sent: 'gossip_bytes_sent' };
const CONTROL = 'control';
const OTHER = 'other';
/** Control and the unpicked rest take two of the colour slots. */
const MAX_PICKED = SERIES_MAX - 2;
const OTHER_COLOUR = SERIES_MAX - 1;
/** Room left for the pane's tabs and switches above the chart. */
const CHROME_PX = 240;
const MIN_HEIGHT = 320;

/** Subnet topics listed, stacked and picked as one entry per kind. */
const SUBNET_GROUP = /^(beacon_attestation|data_column_sidecar|sync_committee)_\d+$/;

export function entryOf(topic) {
  const subnet = SUBNET_GROUP.exec(topic);
  return subnet ? `${subnet[1]}_*` : topic;
}

/** Bytes `column` grew since `startS`: its latest sample less the last one
 *  before the slot. */
function slotBytes(history, column, startS) {
  if (!column) return 0;
  let last = null;
  for (let k = history.ts.length - 1; k >= 0; k--) {
    const v = column[k];
    if (v === null || v === undefined) continue;
    last ??= v;
    if (history.ts[k] < startS) return Math.max(0, last - v);
  }
  return 0;
}

function dirSwitch(dir) {
  const buttons = Object.keys(SOURCES)
    .map((d) => `<button class="${d === dir ? 'active' : ''}" data-dir="${d}">${d}</button>`)
    .join('');
  return `<div class="subtabs">${buttons}</div>`;
}

/** Sums of the layers below and including each, so a layer's top edge sits
 *  on the one beneath. A bin no layer has a sample for stays null. */
function stack(layers) {
  let below = null;
  return layers.map(({ ys }) => {
    const top = ys.map((v, b) => {
      const under = below?.[b] ?? null;
      return v === null && under === null ? null : (v ?? 0) + (under ?? 0);
    });
    below = top;
    return top;
  });
}

function listRow(name, bytes, colour, picked) {
  const swatch = colour === null ? '<i class="swatch"></i>' : `<i class="swatch" style="background: var(--series-${colour + 1})"></i>`;
  const attr = picked === null ? '' : ` data-traffic-topic="${escape(name)}"`;
  return `<tr class="${picked ? 'picked' : ''}"${attr}>
    <td>${swatch}${escape(name)}</td><td class="num">${fmtBytes(bytes)}</td></tr>`;
}

/** The stacked chart over `dir`'s samples, with the entries the topic list
 *  shows; null before samples arrive. `ui` holds the picks and toggles. */
export function trafficChart(inst, ui, dir, nowS) {
  const source = SOURCES[dir];
  const samples = inst.samples(source);
  if (!samples) return null;

  const { history, names } = samples;
  const w = slotWindow(inst.clock, nowS);
  const column = (name) => history.values[names.indexOf(name)];
  const totals = new Map(names.map((n) => [n, slotBytes(history, column(n), w.startS)]));
  // Entry → its topics, with the slot's bytes over all of them.
  const entries = new Map();
  for (const topic of names.filter((n) => n !== CONTROL && !n.startsWith('slot_'))) {
    const key = entryOf(topic);
    const entry = entries.get(key) ?? { topics: [], bytes: 0 };
    entry.topics.push(topic);
    entry.bytes += totals.get(topic);
    entries.set(key, entry);
  }
  const bytesOf = (key) => entries.get(key).bytes;
  const ranked = [...entries.keys()].filter((k) => bytesOf(k) > 0).sort((a, b) => bytesOf(b) - bytesOf(a));
  // Until an entry is picked by hand, the busiest ones are.
  ui.autoPicked = ranked.slice(0, MAX_PICKED);
  const picked = (ui.picked ?? ui.autoPicked).filter((k) => entries.has(k));
  const rest = [...entries.keys()].filter((k) => !picked.includes(k));

  const layers = [
    ...(ui.hideControl ? [] : [{ label: CONTROL, counters: [CONTROL], colour: 0 }]),
    ...picked.map((k, i) => ({ label: k, counters: entries.get(k).topics, colour: i + 1 })),
    ...(ui.hideOther ? [] : [{ label: OTHER, counters: rest.flatMap((k) => entries.get(k).topics), colour: OTHER_COLOUR }]),
  ].map((layer) => {
    const { ys, blockX } = binnedSeries(inst, { source, counters: layer.counters }, w.slot, w.startS, w.bins);
    return { ...layer, ys, blockX };
  });
  const tops = stack(layers);
  // Largest first, so each lower layer is drawn over the one above it.
  const order = layers.map((_, i) => i).reverse();
  const sum = (ys) => ys.reduce((total, v) => total + (v ?? 0), 0);
  const blockX = layers[0]?.blockX ?? null;
  const spec = {
    labels: order.map((i) => layers[i].label),
    data: [w.xs, ...order.map((i) => tops[i])],
    colourOf: order.map((i) => layers[i].colour),
    fill: true,
    fmt: (v) => fmtBytes(Math.round(v)),
    height: Math.max(MIN_HEIGHT, window.innerHeight - CHROME_PX),
    legend: false,
    xSeconds: true,
    xRange: [0, w.slotS],
    spanGaps: true,
    markers: blockX === null ? [] : [{ x: blockX, series: 0 }],
    cornerLabels: order.map((i) => `${layers[i].label} ${fmtBytes(sum(layers[i].ys))}`),
  };
  return { spec, slot: w.slot, totals, entries, ranked, picked, rest };
}

/** The view's HTML, with its chart spec added to `specs`. */
export function render(inst, ui, nowS, specs) {
  ui.dir ??= 'recv';
  const chart = trafficChart(inst, ui, ui.dir, nowS);
  if (!chart) return `${dirSwitch(ui.dir)}<p class="empty">no ${ui.dir} traffic samples yet</p>`;
  const { spec, slot, totals, entries, ranked, picked, rest } = chart;
  specs.set('gossip-traffic', spec);
  const bytesOf = (key) => entries.get(key).bytes;
  const colourOf = new Map(picked.map((n, i) => [n, i + 1]));
  const listed = [...new Set([...picked, ...ranked])];
  const rows = [
    listRow(CONTROL, totals.get(CONTROL) ?? 0, ui.hideControl ? null : 0, !ui.hideControl),
    listRow(OTHER, rest.reduce((t, k) => t + bytesOf(k), 0), ui.hideOther ? null : OTHER_COLOUR, !ui.hideOther),
    ...listed.map((k) => listRow(k, bytesOf(k), colourOf.get(k) ?? null, colourOf.has(k))),
  ].join('');
  const title = slot === null ? 'bytes per 100 ms' : `bytes per 100 ms, slot ${slot}`;
  return `${dirSwitch(ui.dir)}
    <div class="gossip-traffic">
      <section><table class="dense">
        <thead><tr><th>topic (${picked.length}/${MAX_PICKED} picked)</th><th class="num">slot</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></section>
      <div><p class="meta">${title}</p><div class="chart" data-chart="gossip-traffic"></div></div>
    </div>`;
}

/** True when the click was the view's. */
export function click(target, ui) {
  const dir = target.closest('[data-dir]')?.dataset.dir;
  if (dir && SOURCES[dir]) {
    ui.dir = dir;
    return true;
  }
  const topic = target.closest('[data-traffic-topic]')?.dataset.trafficTopic;
  if (!topic) return false;
  if (topic === OTHER) {
    ui.hideOther = !ui.hideOther;
    return true;
  }
  if (topic === CONTROL) {
    ui.hideControl = !ui.hideControl;
    return true;
  }
  const picked = ui.picked ?? [...(ui.autoPicked ?? [])];
  const at = picked.indexOf(topic);
  if (at >= 0) picked.splice(at, 1);
  else if (picked.length < MAX_PICKED) picked.push(topic);
  ui.picked = picked;
  return true;
}
