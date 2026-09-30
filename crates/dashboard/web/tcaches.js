// TCache table for one instance: occupancy, head, tails, and a chart of head
// and tail rates under the focused row.

import { SERIES_MAX } from './chart.js';
import { SourceClass } from './wire.js';
import { tcacheLength, tcacheMinTail } from './state.js';
import { escape, fmtBytes } from './view.js';

const HEAD_SLOT = 1;
const FIXED_SLOTS = 2;
const COLUMNS = 7;

/** Filled spans of the ring as [start, end) fractions of capacity. */
function occupied(capacity, head, minTail) {
  const length = head - minTail;
  if (length >= capacity) return [[0, 1]];
  if (length <= 0) return [];
  const h = (head % capacity) / capacity;
  const t = (minTail % capacity) / capacity;
  return h >= t ? [[t, h]] : [[t, 1], [0, h]];
}

function bar(capacity, head, minTail) {
  if (!capacity) return '';
  const spans = occupied(capacity, head, minTail)
    .map(([a, b]) => `<i style="left:${a * 100}%;width:${(b - a) * 100}%"></i>`)
    .join('');
  const mark = `<b style="left:${((head % capacity) / capacity) * 100}%"></b>`;
  return `<div class="ring">${spans}${mark}</div>`;
}

/** Head plus the published tails in `slots` (all when null), as surfer
 *  charts them; slot 0 (capacity) is constant and skipped. Unused tails hold
 *  the u64::MAX sentinel. */
function chartSpec(inst, id, values, slots) {
  const history = inst.counterHistory.get(id);
  if (!history || !history.ts.length) return null;
  const names = inst.slotNames.get(id) ?? [];
  const labels = ['head'];
  const data = [history.ts, history.rates[HEAD_SLOT]];
  for (let slot = FIXED_SLOTS; slot < values.length && labels.length < SERIES_MAX; slot++) {
    if (values[slot] === null || !history.rates[slot]) continue;
    if (slots && !slots.has(slot)) continue;
    labels.push(names[slot] || `tail_${slot - FIXED_SLOTS}`);
    data.push(history.rates[slot]);
  }
  return { labels, data, fmt: (v) => `${fmtBytes(Math.max(0, Math.round(v)))}/s` };
}

/** `focus`: `{ name, slots }`, the source name of the row to mark and expand
 *  and the tail slots its chart keeps (all when null); null for none. Rows
 *  carry `data-tcache`, the tcache's name, for selection. */
export function tcacheTable(inst, specs, focus) {
  const rows = inst
    .sourcesOf(SourceClass.TCache)
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(({ id, name }) => {
      const v = inst.counters.get(id)?.values;
      if (!v || v.length < 2) return '';
      const [capacity, head] = [v[0] ?? 0, v[1] ?? 0];
      const minTail = tcacheMinTail(v);
      const key = `tc-row:${inst.key}:${id}`;
      const focused = focus?.name === name;
      const cache = name.replace(/^tcache-/, '');
      const display = escape(cache);
      let chart = '';
      if (focused) {
        const spec = chartSpec(inst, id, v, focus.slots);
        if (spec) specs.set(key, spec);
        chart = `<tr class="open chart-row focus"><td colspan="${COLUMNS}">
          <div class="meta">${display} — 1s deltas (bytes/s)</div>
          ${spec ? `<div class="chart" data-chart="${key}"></div>` : '<p class="empty">no completed buckets yet</p>'}
        </td></tr>`;
      }
      return `<tr class="row${focused ? ' open focus' : ''}" data-tcache="${escape(cache)}">
        <td>${display}</td>
        <td class="bar">${bar(capacity, head, minTail)}</td>
        <td class="num">${fmtBytes(head)}</td>
        <td class="num">${fmtBytes(minTail)}</td>
        <td class="num">${fmtBytes(capacity)}</td>
        <td class="num">${fmtBytes(tcacheLength(v))}</td>
        <td class="num">${fmtBytes(inst.tcacheMaxLength.get(id) ?? 0)}</td>
      </tr>${chart}`;
    })
    .join('');
  return `<table class="tcache-table">
    <thead><tr>
      <th>name</th><th>occupancy</th><th>head</th><th>min_tail</th>
      <th>capacity</th><th>length</th><th>max_length</th>
    </tr></thead>
    <tbody>${rows || `<tr><td colspan="${COLUMNS}" class="empty">no tcaches described yet</td></tr>`}</tbody>
  </table>`;
}
