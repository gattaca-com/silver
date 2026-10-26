// Landing pane: percentile strips, one panel per block pipeline component and
// per gossip topic entry, one row per instance. Pipeline durations come from
// the retained traces of blocks that reached attestable; gossip bytes from
// completed slots, grouped as in the traffic view.

import { SERIES_MAX } from './chart.js';
import { fmtNanos } from './events.js';
import { entryOf } from './gossip_traffic.js';
import { escape, fmtBytes } from './view.js';

const PERCENTILES = [50, 90, 99];
const TRAFFIC = { recv: 'gossip_bytes_recv', sent: 'gossip_bytes_sent' };

// [label, span, counts]. A blobless block's `da` is an instant, not a wait;
// `daWait` only exists on parked imports.
const always = () => true;
const COMPONENTS = [
  ['data available', 'da', (t) => t.columns.length > 0],
  ['el', 'el', always],
  ['validate', 'validate', always],
  ['apply', 'apply', always],
  ['da wait', 'daWait', (t) => t.parked()],
];

/** Nearest rank on ascending `sorted`. */
function percentile(sorted, p) {
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)];
}

/** `{ p, n }` with `p` per PERCENTILES, or null when empty. */
function stats(values) {
  if (!values?.length) return null;
  const sorted = values.slice().sort((a, b) => a - b);
  return { p: PERCENTILES.map((p) => percentile(sorted, p)), n: sorted.length };
}

function pipelineStats(inst) {
  const done = inst.traces.filter((t) => t.attestable !== null);
  return COMPONENTS.map(([, span, counts]) => {
    const durations = [];
    for (const trace of done) {
      const interval = counts(trace) ? trace.interval(span) : null;
      if (interval) durations.push(interval.end - interval.start);
    }
    return stats(durations);
  });
}

/** Entry → stats of its bytes per completed slot. */
function trafficStats(totals) {
  const entries = new Map();
  if (!totals) return entries;
  totals.names.forEach((name, c) => {
    if (name.startsWith('slot_')) return;
    const key = entryOf(name);
    let bytes = entries.get(key);
    if (!bytes) entries.set(key, (bytes = new Array(totals.slots.length).fill(0)));
    totals.slots.forEach((slot, k) => (bytes[k] += slot.bytes[c] ?? 0));
  });
  return new Map([...entries].map(([key, bytes]) => [key, stats(bytes)]));
}

function strip(s, max) {
  if (!s) return '<div class="strip"></div>';
  const [p50, p90, p99] = s.p.map((v) => (max > 0 ? (v / max) * 100 : 0));
  return `<div class="strip"><s style="width:${p99}%"></s><u style="left:${p50}%;width:${p90 - p50}%"></u>
    <i class="m50" style="left:${p50}%"></i><i class="m90" style="left:${p90}%"></i><i class="m99" style="left:${p99}%"></i></div>`;
}

/** `rows`: `{ inst, s }`; a row's colour follows its instance. */
function stripRows(rows, max, fmt, colourOf) {
  return rows
    .map(({ inst, s }) => {
      const title = s
        ? `${inst.label}: ${PERCENTILES.map((p, i) => `p${p} ${fmt(s.p[i])}`).join(' · ')} · ${s.n} slots`
        : `${inst.label}: no data`;
      return `<div class="strip-row" style="--c:${colourOf(inst)}" title="${escape(title)}">
        <span class="strip-label">${escape(inst.label)}</span>${strip(s, max)}
        <span class="num">${s ? fmt(s.p[0]) : '·'}</span></div>`;
    })
    .join('');
}

function maxP99(rows) {
  return Math.max(0, ...rows.map(({ s }) => s?.p[2] ?? 0));
}

function panel(title, max, fmt, body) {
  const scale = max > 0 ? `0 – ${fmt(max)}` : '';
  return `<div class="strip-panel"><h3>${escape(title)}<span class="meta">${scale}</span></h3>${body}</div>`;
}

function pipelinePanels(insts, colourOf) {
  const perInst = insts.map((inst) => ({ inst, all: pipelineStats(inst) }));
  return COMPONENTS.map(([label], c) => {
    const rows = perInst.map(({ inst, all }) => ({ inst, s: all[c] }));
    const max = maxP99(rows);
    return panel(label, max, fmtNanos, stripRows(rows, max, fmtNanos, colourOf));
  }).join('');
}

/** Busiest received first; entries no shown instance moved bytes on are left
 *  out. */
function trafficPanels(insts, colourOf) {
  const perInst = insts.map((inst) => ({
    inst,
    recv: trafficStats(inst.slotTotalsOf(TRAFFIC.recv)),
    sent: trafficStats(inst.slotTotalsOf(TRAFFIC.sent)),
  }));
  const keys = new Set(perInst.flatMap(({ recv, sent }) => [...recv.keys(), ...sent.keys()]));
  const panels = [...keys].map((key) => {
    const recv = perInst.map(({ inst, recv }) => ({ inst, s: recv.get(key) ?? null }));
    const sent = perInst.map(({ inst, sent }) => ({ inst, s: sent.get(key) ?? null }));
    const max = Math.max(maxP99(recv), maxP99(sent));
    const order = Math.max(0, ...recv.map(({ s }) => s?.p[0] ?? 0));
    const body = `<h4>recv</h4>${stripRows(recv, max, fmtBytes, colourOf)}
      <h4>sent</h4>${stripRows(sent, max, fmtBytes, colourOf)}`;
    return { max, order, html: panel(key, max, fmtBytes, body) };
  });
  return panels
    .filter((p) => p.max > 0)
    .sort((a, b) => b.order - a.order)
    .map((p) => p.html)
    .join('');
}

function legend(all, hidden, colourOf) {
  const insts = all
    .map((inst) => {
      const off = hidden.has(inst.key) ? ' off' : '';
      const title = inst.buildInfo ? ` title="${escape(inst.buildInfo.trim())}"` : '';
      return `<span class="strip-inst${off}" data-home-instance="${inst.key}" style="--c:${colourOf(inst)}"${title}>
        <i class="swatch"></i>${escape(inst.label)}</span>`;
    })
    .join('');
  const marker = (cls, label) => `<span><span class="strip key"><i class="${cls}" style="left:50%"></i></span>${label}</span>`;
  return `<div class="strip-legend">${insts}
    <span class="strip-markers">${marker('m50', 'p50')}${marker('m90', 'p90')}${marker('m99', 'p99')}</span></div>`;
}

export function render(fleet, root, _now, ui) {
  ui.hidden ??= new Set();
  const all = fleet.sorted();
  if (!all.length) {
    root.innerHTML = '<p class="empty">no instances connected</p>';
    return;
  }
  // Colour follows the instance's place in the whole fleet, so hiding one
  // does not repaint the rest. Past the categorical palette, muted.
  const index = new Map(all.map((inst, i) => [inst.key, i]));
  const colourOf = (inst) => {
    const i = index.get(inst.key);
    return i < SERIES_MAX ? `var(--series-${i + 1})` : 'var(--muted)';
  };
  const shown = all.filter((inst) => !ui.hidden.has(inst.key));
  const traffic = trafficPanels(shown, colourOf);
  root.innerHTML = `${legend(all, ui.hidden, colourOf)}
    <h2>block pipeline <span class="meta">per block reaching attestable</span></h2>
    <div class="strips">${pipelinePanels(shown, colourOf)}</div>
    <h2>gossip bytes <span class="meta">per completed slot</span></h2>
    ${traffic ? `<div class="strips">${traffic}</div>` : '<p class="empty">no completed slots of gossip traffic yet</p>'}`;
}

export function click(target, ui) {
  const key = target.closest('[data-home-instance]')?.dataset.homeInstance;
  if (key && !ui.hidden.delete(key)) ui.hidden.add(key);
}
