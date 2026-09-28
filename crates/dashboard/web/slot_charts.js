// Charts at the top of the Slots pane: each client's slot over time, from
// its block `Received` events, and each client's attestations processed per
// 50 ms sample of the `fast:beacon_state` source, over the last 30 s.

import { alignSeries } from './chart.js';

const WINDOW_S = 240;
const ATTESTATION_WINDOW_S = 30;
const HEIGHT = 160;
/** Every attestation-data root lookup: single attestations past the
 *  committee checks, plus aggregates. */
const ATTESTATION_SLOTS = ['AttestationRootMemoHit', 'AttestationRootMemoMiss'];

function slotAt(clock, unixS) {
  return Math.floor((unixS * 1e9 - Number(clock.genesisNs)) / clock.slotNs);
}

/** Received time (unix s) and slot of each traced block, oldest first. */
function slotPoints(inst) {
  return inst.traces
    .filter((t) => t.receivedAt !== null)
    .map((t) => ({ x: (Number(t.base) + t.receivedAt) / 1e9, slot: t.slot }))
    .sort((a, b) => a.x - b.x);
}

/** y spans the wall-clock slots of the window or the spread of the clients'
 *  latest slots, whichever reaches further, so a lagging client stays in
 *  view. */
function slotSpec(instances, nowS) {
  const points = instances.map((inst) => ({ inst, points: slotPoints(inst) })).filter((p) => p.points.length);
  if (!points.length) return null;
  const latest = points.map((p) => p.points.at(-1).slot);
  let lo = Math.min(...latest);
  let hi = Math.max(...latest);
  const clock = instances.find((i) => i.clock)?.clock;
  if (clock) {
    lo = Math.min(lo, slotAt(clock, nowS - WINDOW_S));
    hi = Math.max(hi, slotAt(clock, nowS));
  }
  const series = points.map(({ points: pts }) => {
    const inWindow = pts.filter((p) => p.x >= nowS - WINDOW_S);
    return { xs: inWindow.map((p) => p.x), ys: inWindow.map((p) => p.slot) };
  });
  return {
    labels: points.map((p) => p.inst.label),
    data: alignSeries(series),
    fmt: (v) => String(Math.round(v)),
    height: HEIGHT,
    xRange: [nowS - WINDOW_S, nowS],
    yRange: [lo - 0.5, hi + 0.5],
    stepped: true,
    spanGaps: true,
    endLabel: (_i, v) => String(v),
  };
}

/** Attestations per 50 ms sample: the delta of the summed counters. A
 *  counter reset breaks the delta. */
function attestationSeries(inst, nowS) {
  const s = inst.samples('beacon_state');
  if (!s) return null;
  const cols = ATTESTATION_SLOTS.map((n) => s.history.values[s.names.indexOf(n)]);
  if (cols.some((c) => !c)) return null;
  const xs = [];
  const ys = [];
  let prevTotal = null;
  s.history.ts.forEach((x, k) => {
    const parts = cols.map((c) => c[k]);
    const total = parts.some((v) => v === null || v === undefined) ? null : parts.reduce((a, b) => a + b, 0);
    if (x >= nowS - ATTESTATION_WINDOW_S) {
      xs.push(x);
      ys.push(total === null || prevTotal === null || total < prevTotal ? null : total - prevTotal);
    }
    prevTotal = total;
  });
  return xs.length ? { label: inst.label, xs, ys } : null;
}

/** One line per client. Clients sample on their own clocks, so the aligned
 *  series interleave with nulls and the lines span them. */
function attestationSpec(instances, nowS) {
  const series = instances.map((inst) => attestationSeries(inst, nowS)).filter(Boolean);
  if (!series.length) return null;
  return {
    labels: series.map((s) => s.label),
    data: alignSeries(series),
    fmt: (v) => String(Math.round(v)),
    height: HEIGHT,
    xRange: [nowS - ATTESTATION_WINDOW_S, nowS],
    spanGaps: true,
  };
}

function card(key, title) {
  return `<div><p class="meta">${title}</p><div class="chart" data-chart="${key}"></div></div>`;
}

/** Chart placeholders, with their specs added to `specs`. */
export function slotCharts(fleet, specs) {
  const nowS = Date.now() / 1000;
  const instances = fleet.sorted();
  const cards = [];
  const slots = slotSpec(instances, nowS);
  if (slots) {
    specs.set('slots-slot', slots);
    cards.push(card('slots-slot', 'slot by client (block received)'));
  }
  const attestations = attestationSpec(instances, nowS);
  if (attestations) {
    specs.set('slots-att', attestations);
    cards.push(card('slots-att', 'attestations per 50 ms'));
  }
  return cards.length ? `<div class="slot-charts">${cards.join('')}</div>` : '';
}
