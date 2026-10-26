// Landing pane: per instance, percentiles of each block pipeline component
// over the retained traces of blocks that reached attestable, and of gossip
// bytes per completed slot, grouped as in the traffic view.

import { fmtNanos } from './events.js';
import { entryOf } from './gossip_traffic.js';
import { escape, fmtBytes, instanceHeading } from './view.js';

const PERCENTILES = [50, 90, 99];
const TRAFFIC = { recv: 'gossip_bytes_recv', sent: 'gossip_bytes_sent' };

// [label, span, colour class, counts]. A blobless block's `da` is an instant,
// not a wait; `daWait` only exists on parked imports.
const always = () => true;
const COMPONENTS = [
  ['data available', 'da', 'c-da', (t) => t.columns.length > 0],
  ['el', 'el', '', always],
  ['validate', 'validate', 'c-validate', always],
  ['apply', 'apply', 'c-apply', always],
  ['da wait', 'daWait', 'c-dawait', (t) => t.parked()],
];

/** Nearest rank on ascending `sorted`. */
function percentile(sorted, p) {
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)];
}

function row([label, span, cls, counts], done) {
  const durations = [];
  for (const trace of done) {
    const interval = counts(trace) ? trace.interval(span) : null;
    if (interval) durations.push(interval.end - interval.start);
  }
  durations.sort((a, b) => a - b);
  const cells = PERCENTILES.map((p) => (durations.length ? fmtNanos(percentile(durations, p)) : '·'));
  return `<tr><td class="${cls}">${label}</td>${cells.map((c) => `<td class="num">${c}</td>`).join('')}
    <td class="num">${durations.length}</td></tr>`;
}

/** Entry → its bytes per completed slot, ascending. */
function entrySlotBytes(totals) {
  const entries = new Map();
  if (!totals) return entries;
  totals.names.forEach((name, c) => {
    if (name.startsWith('slot_')) return;
    const key = entryOf(name);
    let bytes = entries.get(key);
    if (!bytes) entries.set(key, (bytes = new Array(totals.slots.length).fill(0)));
    totals.slots.forEach((slot, k) => (bytes[k] += slot.bytes[c] ?? 0));
  });
  for (const bytes of entries.values()) bytes.sort((a, b) => a - b);
  return entries;
}

function bytesCells(sorted) {
  return PERCENTILES.map((p) => `<td class="num">${sorted?.length ? fmtBytes(percentile(sorted, p)) : '·'}</td>`).join('');
}

function trafficTable(inst) {
  const recvTotals = inst.slotTotalsOf(TRAFFIC.recv);
  const sentTotals = inst.slotTotalsOf(TRAFFIC.sent);
  const recv = entrySlotBytes(recvTotals);
  const sent = entrySlotBytes(sentTotals);
  const p50 = (bytes) => (bytes?.length ? percentile(bytes, 50) : 0);
  const keys = [...new Set([...recv.keys(), ...sent.keys()])]
    .filter((k) => recv.get(k)?.at(-1) || sent.get(k)?.at(-1))
    .sort((a, b) => p50(recv.get(b)) - p50(recv.get(a)) || p50(sent.get(b)) - p50(sent.get(a)));
  if (!keys.length) return '<p class="empty">no completed slots of gossip traffic yet</p>';

  const recvSlots = recvTotals?.slots.length ?? 0;
  const sentSlots = sentTotals?.slots.length ?? 0;
  const slots = recvSlots === sentSlots ? `${recvSlots} slots` : `${recvSlots} recv / ${sentSlots} sent slots`;
  const head = ['recv', 'sent'].flatMap((dir) => PERCENTILES.map((p) => `<th class="num">${dir} p${p}</th>`)).join('');
  const rows = keys
    .map((k) => `<tr><td>${escape(k)}</td>${bytesCells(recv.get(k))}${bytesCells(sent.get(k))}</tr>`)
    .join('');
  return `<p class="meta">gossip bytes per slot, ${slots}</p>
    <section><table class="dense"><thead><tr><th>topic</th>${head}</tr></thead><tbody>${rows}</tbody></table></section>`;
}

export function render(fleet, root, now) {
  const instances = fleet.sorted();
  if (!instances.length) {
    root.innerHTML = '<p class="empty">no instances connected</p>';
    return;
  }
  const head = `<thead><tr><th>component</th>${PERCENTILES.map((p) => `<th class="num">p${p}</th>`).join('')}
    <th class="num">slots</th></tr></thead>`;
  root.innerHTML = instances
    .map((inst) => {
      const done = inst.traces.filter((t) => t.attestable !== null);
      return `${instanceHeading(inst, now)}<section><table class="dense">${head}
        <tbody>${COMPONENTS.map((c) => row(c, done)).join('')}</tbody></table></section>
        ${trafficTable(inst)}`;
    })
    .join('');
}
