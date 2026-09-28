// The Events tab, after surfer's: each block's pipeline on a shared
// ms-into-slot axis. One strip per (slot, root, instance); its bar spans
// arrival → attestable. Opening a strip unfolds the three components that
// join at attestable (`data available → cols`, `stf → validate/apply`, `el`).

import { LineCharts } from './chart.js';
import { slotCharts } from './slot_charts.js';
import { BLOCK_SOURCE, EL_VERDICT } from './wire.js';
import { Origin, Verdict, colsOrigin, colsSpan } from './trace.js';
import { escape } from './view.js';

const TITLE = 'block pipeline: arrival → attestable';
const SLOTS_PER_EPOCH = 32;
const NUMBER_OF_COLUMNS = 128;
const FOLD = { leaf: '  ', closed: '▸ ', open: '▾ ' };

const GROUP_CHILDREN = {
  block: ['da', 'custody', 'stf', 'el'],
  da: [Origin.Gossip, Origin.El, Origin.Rpc, Origin.Assembly].map(colsSpan),
  stf: ['validate', 'apply', 'daWait'],
};
const SPAN_LABEL = {
  strip: '',
  da: 'data available',
  custody: 'custody',
  stf: 'stf',
  validate: 'validate',
  apply: 'apply',
  daWait: 'da wait',
  el: 'el',
  [colsSpan(Origin.Gossip)]: 'gossip cols',
  [colsSpan(Origin.Rpc)]: 'rpc cols',
  [colsSpan(Origin.El)]: 'el cols',
  [colsSpan(Origin.Assembly)]: 'cells',
};
const SPAN_OPENS = { strip: 'block', da: 'da', custody: 'da', stf: 'stf' };
const GROUP_OPENER = { block: 'strip', da: 'da', stf: 'stf' };

const isCols = (span) => span.startsWith('cols:');

function spanOpens(span) {
  return isCols(span) ? span : (SPAN_OPENS[span] ?? null);
}

/** Both data rows open the column list; it unfolds under the lower one. */
function unfoldingAfter(span) {
  return span === 'da' ? null : spanOpens(span);
}

function spanParent(span) {
  return Object.keys(GROUP_CHILDREN).find((g) => GROUP_CHILDREN[g].includes(span)) ?? null;
}

function hidden(span, trace) {
  if (isCols(span)) return !trace.hasOrigin(colsOrigin(span));
  if (span === 'custody') return !trace.columns.length;
  if (span === 'daWait') return !trace.parked();
  return false;
}

// Nodes: { span } | { origin, batch } | { index, rank }.
function nodeKey(node) {
  if (node.span) return node.span;
  if (node.batch !== undefined) return `batch:${node.origin}:${node.batch}`;
  return `col:${node.index}`;
}

function nodeOpens(node) {
  if (node.span) return spanOpens(node.span);
  if (node.batch !== undefined) return `batch:${node.origin}:${node.batch}`;
  return null;
}

/** The group this row is listed under, so selecting a child folds it. */
function nodeParent(node, trace) {
  if (node.span) return spanParent(node.span);
  if (node.batch !== undefined) return colsSpan(node.origin);
  const origin = trace.columns[node.index].origin;
  const batches = trace.batches(origin);
  const b = batches.findIndex((batch) => batch.some((c) => c.index === node.index));
  return b >= 0 && batches[b].length > 1 ? `batch:${origin}:${b}` : colsSpan(origin);
}

function groupOpener(group) {
  if (group.startsWith('batch:')) return group;
  return GROUP_OPENER[group] ?? group;
}

function nodeBatch(node, trace) {
  return trace.batches(node.origin)[node.batch];
}

function nodeInterval(node, trace) {
  if (node.span) return trace.interval(node.span);
  if (node.batch !== undefined) return trace.batchInterval(nodeBatch(node, trace));
  const c = trace.columns[node.index];
  return { start: c.receivedAt, end: c.validatedAt ?? c.receivedAt };
}

/** A batch the gate waited on, or a column of one. */
function countedForGate(node, trace) {
  const batch = node.batch !== undefined ? nodeBatch(node, trace) : trace.batchOf(node.index);
  return !batch || trace.countedForGate(batch);
}

function openKey(inst, trace, group) {
  return `${inst.key}|${trace.root}|${group}`;
}

/** Newest slot first; within a (slot, root), one strip per instance. Each
 *  strip is a preorder walk through its open groups. */
function displayRows(fleet, expanded) {
  const blocks = new Map();
  for (const inst of fleet.sorted()) {
    if (!inst.clock) continue;
    for (const trace of inst.traces) {
      const key = `${trace.slot}|${trace.root}`;
      if (!blocks.has(key)) blocks.set(key, { slot: trace.slot, root: trace.root, seen: [] });
      blocks.get(key).seen.push([inst, trace]);
    }
  }
  const out = [];
  const ordered = [...blocks.values()].sort((a, b) => b.slot - a.slot || a.root.localeCompare(b.root));
  for (const block of ordered) {
    for (const [inst, trace] of block.seen) walkSpan(out, inst, trace, expanded, 'strip', 0);
  }
  return out;
}

function walkSpan(out, inst, trace, expanded, span, depth) {
  const opens = spanOpens(span);
  const fold = opens === null ? 'leaf' : expanded.has(openKey(inst, trace, opens)) ? 'open' : 'closed';
  out.push({ inst, trace, node: { span }, depth, fold });

  const group = unfoldingAfter(span);
  if (group === null || !expanded.has(openKey(inst, trace, group))) return;
  for (const child of GROUP_CHILDREN[group] ?? []) {
    if (!hidden(child, trace)) walkSpan(out, inst, trace, expanded, child, depth + 1);
  }
  if (isCols(group)) walkColumns(out, inst, trace, expanded, colsOrigin(group), depth + 1);
}

/** One row per batch in validation order; a batch of one is its column. */
function walkColumns(out, inst, trace, expanded, origin, depth) {
  trace.batches(origin).forEach((columns, batch) => {
    let colDepth = depth;
    if (columns.length > 1) {
      const node = { origin, batch };
      const open = expanded.has(openKey(inst, trace, nodeKey(node)));
      out.push({ inst, trace, node, depth, fold: open ? 'open' : 'closed' });
      if (!open) return;
      colDepth = depth + 1;
    }
    for (const c of columns) {
      out.push({ inst, trace, node: { index: c.index, rank: c.rank }, depth: colDepth, fold: 'leaf' });
    }
  });
}

function rowKey(row) {
  return `${row.inst.key}|${row.trace.root}|${nodeKey(row.node)}`;
}

/** Same units as flux `Nanos` Display; zero renders as "0". */
export function fmtNanos(ns) {
  ns = Math.round(ns);
  if (ns === 0) return '0';
  if (ns < 1e3) return `${ns}ns`;
  if (ns < 1e6) return `${ns / 1e3}μs`;
  if (ns < 1e9) return `${Math.floor(ns / 1e3) / 1e3}ms`;
  const s = `${Math.floor(ns / 1e6) / 1e3}`;
  return `${s.padStart(2, '0')}s`;
}

function wallTime(trace, t) {
  return new Date(Math.floor(trace.wallMs(t))).toISOString().slice(11, 23);
}

/** `showSlot` false blanks a block row's slot under the slot's first row. */
function label(row, showSlot) {
  const { trace, node, depth, fold } = row;
  let text;
  if (node.span === 'strip') text = showSlot ? String(trace.slot) : '';
  else if (node.span) text = SPAN_LABEL[node.span];
  else if (node.batch !== undefined) {
    const batch = nodeBatch(node, trace);
    text = `#${batch[0].rank}..#${batch[batch.length - 1].rank}`;
  } else text = `#${node.rank} col ${trace.columns[node.index].index}`;
  return `${'  '.repeat(depth)}${FOLD[fold]}${text}`;
}

function attributes(node, trace) {
  if (node.span === 'da' && !trace.columns.length && trace.available !== null) return 'no blobs';
  // The custody size is not on the wire; a supernode's is every column.
  if (node.span === 'custody') return `${trace.columns.length}/${NUMBER_OF_COLUMNS} cols`;
  if (node.span && isCols(node.span)) return `${trace.ofOrigin(colsOrigin(node.span)).length} cols`;
  if (node.batch !== undefined) {
    const batch = nodeBatch(node, trace);
    return `${batch.length} cols${trace.openedGate(batch) ? ' DA' : ''}`;
  }
  if (node.span === 'el' && trace.verdict) return EL_VERDICT[trace.verdict.status] ?? '';
  return '';
}

const SPAN_CLASS = {
  strip: 'c-strip',
  da: 'c-da',
  custody: 'c-custody',
  stf: 'c-stf',
  validate: 'c-validate',
  apply: 'c-apply',
  daWait: 'c-dawait',
};

function verdictClass(trace) {
  switch (trace.verdict?.status) {
    case Verdict.Valid:
      return 'c-valid';
    case Verdict.Invalid:
      return 'c-invalid';
    case undefined:
      return 'c-pending';
    default:
      return 'c-optimistic';
  }
}

/** Colours before and after the gate. Data rows split there: what the gate
 *  waited on in the `da` colour, the custody tail after it. A column is one
 *  colour; `el` wears the verdict. */
function barClasses(node, trace) {
  if (node.span === 'custody' || (node.span && isCols(node.span))) return ['c-da', 'c-custody'];
  if (!node.span) {
    const cls = countedForGate(node, trace) ? 'c-da' : 'c-custody';
    return [cls, cls];
  }
  const cls = SPAN_CLASS[node.span] ?? verdictClass(trace);
  return [cls, cls];
}

function cells(row, clock) {
  const { trace, node } = row;
  const interval = nodeInterval(node, trace);
  const offset = interval ? trace.offsetInSlot(clock, interval.start) : null;
  const len = interval ? interval.end - interval.start : 0;
  const instant = node.span === 'da' && !trace.columns.length;
  const duration = [interval && !instant ? fmtNanos(len) : '', attributes(node, trace)].filter(Boolean).join(' ');
  const strip = node.span === 'strip';
  const splits = node.span === 'da' || node.span === 'custody' || (node.span && isCols(node.span));
  return {
    time: interval ? wallTime(trace, interval.start) : '-',
    start: offset === null ? '-' : fmtNanos(offset),
    end: offset === null ? '-' : fmtNanos(offset + len),
    offset,
    len,
    split: splits && trace.available !== null ? trace.offsetInSlot(clock, trace.available) : null,
    duration,
    margin: strip ? trace.deadlineMargin(clock) : null,
    source: strip && trace.source !== null ? BLOCK_SOURCE[trace.source] : '',
    bar: barClasses(node, trace),
  };
}

/** Into-slot ns → percent of the axis; 5% headroom past the widest of the
 *  deadline and the latest strip end. */
function axisRange(rows, clock) {
  let max = clock.deadline();
  for (const { trace, node } of rows) {
    if (node.span !== 'strip') continue;
    const iv = trace.interval('strip');
    const end = iv ? trace.offsetInSlot(clock, iv.end) : null;
    if (end !== null) max = Math.max(max, end);
  }
  return Math.max(max, 1) * 1.05;
}

function bar(c, range) {
  if (c.offset === null || c.offset >= range) return '';
  const end = Math.min(c.offset + c.len, range);
  const pct = (v) => (v / range) * 100;
  const cut = c.split === null || c.split >= range ? end : Math.max(c.offset, Math.min(c.split, end));
  const seg = (from, to, cls) =>
    `<i class="${cls}" style="left:${pct(from)}%;width:max(${pct(to - from)}%,2px)"></i>`;
  const parts = [seg(c.offset, cut, c.bar[0])];
  if (cut < end) parts.push(seg(cut, end, c.bar[1]));
  return parts.join('');
}

function ticks(range) {
  const out = [];
  for (let sec = 0; sec * 1e9 < range; sec++) {
    out.push(`<span style="left:${((sec * 1e9) / range) * 100}%">${sec}s</span>`);
  }
  return `<div class="ticks">${out.join('')}</div>`;
}

function toggle(row, ui) {
  const { inst, trace, node } = row;
  const group = nodeOpens(node) ?? nodeParent(node, trace);
  if (group === null) return;
  const key = openKey(inst, trace, group);
  if (!ui.expanded.delete(key)) ui.expanded.add(key);
  // Keep the highlight on the toggled row, or on the group's opener when a
  // child folded it.
  const keep = nodeOpens(node) !== null ? nodeKey(node) : groupOpener(group);
  ui.selected = `${inst.key}|${trace.root}|${keep}`;
}

export function render(fleet, root, _now, ui) {
  ui.expanded ??= new Set();
  ui.charts ??= new LineCharts();
  const specs = new Map();
  const charts = slotCharts(fleet, specs);
  const rows = displayRows(fleet, ui.expanded);
  ui.rows = rows;
  const multi = fleet.instances.size > 1;

  const selected = rows.find((r) => rowKey(r) === ui.selected);
  const selIv = selected ? nodeInterval(selected.node, selected.trace) : null;
  const title = selIv
    ? `${TITLE} — selected ${wallTime(selected.trace, selIv.start)} → ${wallTime(selected.trace, selIv.end)}`
    : TITLE;

  if (!rows.length) {
    root.innerHTML = `${charts}<h2>${TITLE}</h2><p class="empty">no blocks observed yet</p>`;
    ui.charts.mount(root, specs);
    return;
  }
  const range = axisRange(rows, rows[0].inst.clock);

  let lastSlot = null;
  const body = rows
    .map((row, i) => {
      const c = cells(row, row.inst.clock);
      const strip = row.node.span === 'strip';
      const showSlot = !strip || row.trace.slot !== lastSlot;
      if (strip) lastSlot = row.trace.slot;
      const epoch = strip && showSlot && row.trace.slot % SLOTS_PER_EPOCH === 0 ? ' epoch' : '';
      const margin = c.margin
        ? `<td class="num ${c.margin.madeIt ? 'c-valid' : 'c-invalid'}">${c.margin.madeIt ? '+' : '-'}${fmtNanos(c.margin.delta)}</td>`
        : '<td></td>';
      const durCls = c.split !== null && c.offset !== null && c.offset + c.len > c.split ? c.bar[1] : c.bar[0];
      const open = ui.expanded.has(openKey(row.inst, row.trace, 'block')) ? ' open' : '';
      return `<tr class="ev${open}${rowKey(row) === ui.selected ? ' sel' : ''}${strip ? ' strip' : ''}" data-row="${i}">
        <td class="label${epoch}">${escape(label(row, showSlot))}</td>
        ${multi ? `<td>${strip ? escape(row.inst.label) : ''}</td>` : ''}
        <td class="meta">${strip ? row.trace.root.slice(0, 8) : ''}</td>
        <td>${c.time}</td><td class="num">${c.start}</td><td class="num">${c.end}</td>
        <td class="axis"><div class="track">${bar(c, range)}</div></td>
        <td class="${durCls}">${escape(c.duration)}</td>
        ${margin}
        <td>${c.source}</td>
      </tr>`;
    })
    .join('');

  root.innerHTML = `${charts}<h2>${escape(title)}</h2>
    <section><table class="dense events">
      <thead><tr>
        <th>slot/component</th>${multi ? '<th>instance</th>' : ''}<th>root</th><th>time</th>
        <th class="num">start</th><th class="num">end</th><th class="axis">${ticks(range)}</th>
        <th>duration</th><th class="num">deadline</th><th>source</th>
      </tr></thead>
      <tbody>${body}</tbody>
    </table></section>`;
  ui.charts.mount(root, specs);
}

export function click(target, ui) {
  const tr = target.closest('[data-row]');
  const row = tr && ui.rows?.[Number(tr.dataset.row)];
  if (!row) return;
  ui.selected = rowKey(row);
  toggle(row, ui);
}

/** ↑/↓ move the selection, Enter toggles, as in surfer. */
export function key(k, ui) {
  const rows = ui.rows ?? [];
  if (!rows.length) return false;
  const cur = Math.max(0, rows.findIndex((r) => rowKey(r) === ui.selected));
  if (k === 'ArrowDown' || k === 'ArrowUp') {
    const next = (cur + (k === 'ArrowDown' ? 1 : -1) + rows.length) % rows.length;
    ui.selected = rowKey(rows[next]);
    return true;
  }
  if (k === 'Enter') {
    toggle(rows[cur], ui);
    return true;
  }
  return false;
}
