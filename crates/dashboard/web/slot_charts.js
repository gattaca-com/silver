// Charts at the top of the Slots pane: each client's slot over time, from
// its block `Received` events, and each client's attestations processed per
// 100 ms of the current slot, from the 50 ms `fast:beacon_state` samples.

import { alignSeries } from './chart.js';

const WINDOW_S = 240;
const BIN_S = 0.1;
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

/** Attestations per bin of the slot starting at `startS`: each sample's
 *  delta of the summed counters lands in the bin holding its timestamp. A bin
 *  with no sample is null; a counter reset breaks the delta. */
function attestationSeries(inst, startS, bins) {
  const s = inst.samples('beacon_state');
  if (!s) return null;
  const cols = ATTESTATION_SLOTS.map((n) => s.history.values[s.names.indexOf(n)]);
  if (cols.some((c) => !c)) return null;
  const ys = new Array(bins).fill(null);
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
  return ys.some((v) => v !== null) ? { label: inst.label, ys } : null;
}

/** One line per client over a fixed x axis: the seconds of the current slot.
 *  The bins run to now, so the lines grow across the slot and restart at the
 *  next one. */
function attestationSpec(instances, nowS) {
  const clock = instances.find((i) => i.clock)?.clock;
  if (!clock) return null;
  const slotS = clock.slotNs / 1e9;
  const startS = Number(clock.slotStart(slotAt(clock, nowS))) / 1e9;
  const bins = Math.min(Math.floor((nowS - startS) / BIN_S) + 1, Math.round(slotS / BIN_S));
  const series = instances.map((inst) => attestationSeries(inst, startS, bins)).filter(Boolean);
  if (!series.length) return null;
  const xs = Array.from({ length: bins }, (_, i) => Math.round(i * BIN_S * 10) / 10);
  return {
    labels: series.map((s) => s.label),
    data: [xs, ...series.map((s) => s.ys)],
    fmt: (v) => String(Math.round(v)),
    height: HEIGHT,
    xSeconds: true,
    xRange: [0, slotS],
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
    cards.push(card('slots-att', 'attestations per 100 ms, current slot'));
  }
  return cards.length ? `<div class="slot-charts">${cards.join('')}</div>` : '';
}
