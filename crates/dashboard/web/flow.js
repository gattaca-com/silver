// Flow pane: the tile graph in one of two modes, spine queues or tcaches,
// with Network's p2p traffic drawn in both.

import { LineCharts } from './chart.js';
import { SourceClass } from './wire.js';
import { escape, instanceTabs } from './view.js';
import {
  H, NODE_W, NO_BUCKETS, P2P_MARGIN, SEL_MARKER, TILES, W, chartSlot, detailPanel, drawNodes, fmtBytesRate,
  isDefaultLayout, markers, moveTile, resetLayout, saveLayout,
} from './flow_layout.js';
import * as queues from './flow_queues.js';
import * as tcaches from './flow_tcaches.js';

const MODES = { queues, tcaches };
const P2P_OFFSET = 12;
/** `ui.selected` prefix for the p2p arrows; neither mode's keys start so. */
const P2P_SELECT = 'p2p:';
const P2P = {
  recv: { label: 'p2p in', counter: 'P2pBytesRecv' },
  sent: { label: 'p2p out', counter: 'P2pBytesSent' },
};

function tileUtils(inst) {
  const utils = new Map();
  for (const { id, name } of inst.sourcesOf(SourceClass.Tile)) {
    const u = inst.tileUtils.get(id);
    if (u) utils.set(name, u);
  }
  return utils;
}

/** Slot of a `network` counter, or null before its descriptors arrive. */
function networkSlot(inst, counter) {
  const id = inst.sourceNamed('network');
  const i = id === null ? -1 : (inst.slotNames.get(id)?.indexOf(counter) ?? -1);
  return i < 0 ? null : { id, i };
}

/** Bytes/s over the last completed bucket of the `network` counters. */
function p2pRates(inst) {
  const rate = (dir) => {
    const slot = networkSlot(inst, P2P[dir].counter);
    return slot ? inst.rate(slot.id, slot.i) : null;
  };
  return { recv: rate('recv'), sent: rate('sent') };
}

/** Wire traffic enters and leaves Network through its left edge, each arrow
 *  with its name on the outside of its rate. */
function drawP2p(rates, selected) {
  const net = TILES.NetworkTile;
  const edge = net.x - NODE_W / 2 - 2;
  const far = -P2P_MARGIN + 10;
  const arrow = (dir, y, from, to, textYs) => {
    const { label, counter } = P2P[dir];
    const rate = rates[dir];
    const active = rate > 0;
    const value = rate === null ? '·' : fmtBytesRate(rate);
    const sel = selected === P2P_SELECT + dir ? ' selected' : '';
    const d = `M${from},${y} L${to},${y}`;
    return `<g class="p2p${sel}" data-p2p="${dir}"><title>${escape(`${label}: ${counter} delta over the last 1 s bucket`)}</title>
      <path class="hit" d="${d}"/>
      <path class="${active ? 'q5' : 'q-idle'}" d="${d}" stroke-width="3" marker-end="url(#ah-${sel ? SEL_MARKER : active ? 5 : 'idle'})"/>
      <text class="plabel" x="${(far + edge) / 2}" y="${textYs.label}">${escape(label)}</text>
      <text class="plabel" x="${(far + edge) / 2}" y="${textYs.value}">${value}</text></g>`;
  };
  const inY = net.y - P2P_OFFSET;
  const outY = net.y + P2P_OFFSET;
  return (
    arrow('recv', inY, far, edge, { label: inY - 22, value: inY - 8 }) +
    arrow('sent', outY, edge, far, { label: outY + 32, value: outY + 18 })
  );
}

/** Bytes/s of one p2p direction over the retained counter buckets. */
function p2pDetail(inst, dir, specs) {
  const p2p = P2P[dir];
  if (!p2p) return '';
  const title = `${escape(p2p.label)} · ${p2p.counter}`;
  const slot = networkSlot(inst, p2p.counter);
  const h = slot && inst.counterHistory.get(slot.id);
  const rates = h?.rates[slot.i];
  if (!rates?.length) return detailPanel(title, NO_BUCKETS);
  specs.set('flow-p2p', { labels: ['bytes/s'], data: [h.ts, rates], fmt: fmtBytesRate });
  return detailPanel(title, `<div class="flow-charts">${chartSlot('flow-p2p', 'bytes per second, 1 s buckets')}</div>`);
}

function modeSwitch(active) {
  const buttons = Object.keys(MODES)
    .map((m) => `<button class="${m === active ? 'active' : ''}" data-mode="${m}">${m}</button>`)
    .join('');
  const reset = isDefaultLayout() ? '' : '<button class="reset-layout" data-reset-layout>reset layout</button>';
  return `<div class="subtabs flow-modes">${buttons}${reset}</div>`;
}

/** Ctrl/Cmd+click on the instance tabs selects several, stacked. */
export const multiInstance = true;

/** One instance's diagram, with its detail to the right: a greyed box until
 *  something is selected. Chart keys are namespaced by instance so stacked
 *  rows do not share plots. */
function column(inst, ui, specs, multi) {
  const utils = tileUtils(inst);
  const own = new Map();
  const g = MODES[ui.mode].graph(inst, utils, ui, own);
  // A p2p selection matches no line, so the mode's own detail (the tcache
  // table, or nothing in queues mode) still follows it.
  const p2p = ui.selected?.startsWith(P2P_SELECT) ? p2pDetail(inst, ui.selected.slice(P2P_SELECT.length), own) : '';
  for (const [key, spec] of own) specs.set(`${inst.key}/${key}`, spec);
  const detail = (p2p + g.detail).replaceAll('data-chart="', `data-chart="${inst.key}/`);
  const side = detail
    ? `<div class="flow-side">${detail}</div>`
    : '<div class="flow-side flow-unselected">select a line or arrow</div>';
  const heading = multi ? `<h3>${escape(inst.label)}</h3>` : '';
  const html = `<div class="flow-col">${heading}<svg class="${ui.selected ? 'has-sel' : ''}" viewBox="${-P2P_MARGIN} 0 ${W + P2P_MARGIN} ${H}" role="img" aria-label="Tile ${ui.mode} flow for ${escape(inst.label)}">
      <defs>${markers()}</defs>
      ${g.paths}${drawP2p(p2pRates(inst), ui.selected)}${drawNodes(utils, g.notes)}${g.labels}
    </svg>${side}</div>`;
  return { html, legend: g.legend };
}

export function render(fleet, root, now, ui) {
  const { insts, html: tabs } = instanceTabs(fleet, ui.instance, now, ui.instances);
  if (!insts.length) {
    root.innerHTML = '<p class="empty">no instances yet</p>';
    return;
  }
  ui.mode ??= 'queues';
  const specs = new Map();
  const cols = insts.map((inst) => column(inst, ui, specs, insts.length > 1));
  root.innerHTML = `${tabs}${modeSwitch(ui.mode)}
    <section class="flow"><div class="flow-cols">${cols.map((c) => c.html).join('')}</div>${cols[0].legend}</section>`;
  ui.charts ??= new LineCharts();
  ui.charts.mount(root, specs);
}

/** A mode switch drops the selection: keys belong to one mode's graph. */
export function click(target, ui) {
  // The click that ends a drag is not a selection.
  if (ui.dragged) {
    ui.dragged = false;
    return;
  }
  if (target.closest('[data-reset-layout]')) {
    resetLayout();
    return;
  }
  const mode = target.closest('[data-mode]')?.dataset.mode;
  if (mode && MODES[mode]) {
    if (mode !== ui.mode) ui.selected = null;
    ui.mode = mode;
    return;
  }
  if (target.closest('[data-close-detail]')) {
    ui.selected = null;
    return;
  }
  const p2p = target.closest('.flow [data-p2p]');
  const key = p2p ? P2P_SELECT + p2p.dataset.p2p : MODES[ui.mode ?? 'queues'].selectKey(target);
  if (key) ui.selected = ui.selected === key ? null : key;
}

/** Shows the hovered queue's or tcache's labels and splits the hovered
 *  trunk in place; the next render re-applies both from `ui`. */
export function hover(target, ui, root) {
  const key = target.closest?.('.flow [data-q]')?.dataset.q ?? null;
  if (key !== ui.hover) {
    ui.hover = key;
    for (const el of root.querySelectorAll('.flow [data-q]')) {
      el.classList.toggle('show', el.dataset.q === key);
    }
  }
  const trunk = target.closest?.('.flow [data-trunk]')?.dataset.trunk ?? null;
  if (trunk !== ui.trunk) {
    ui.trunk = trunk;
    for (const el of root.querySelectorAll('.flow [data-trunk]')) {
      el.classList.toggle('split', el.dataset.trunk === trunk);
    }
  }
}

/** Diagram coordinates of a pointer event over the `index`th diagram. Each
 *  render replaces the SVG, so it is looked up afresh. */
function diagramPoint(root, index, e) {
  const svg = root.querySelectorAll('.flow-col > svg')[index];
  const ctm = svg?.getScreenCTM();
  if (!ctm) return null;
  return new DOMPoint(e.clientX, e.clientY).matrixTransform(ctm.inverse());
}

/** A tile box starts a drag; the layout is shared by every diagram. */
export function dragStart(e, ui, root) {
  ui.dragged = false;
  const node = e.target.closest?.('.flow .node[data-tile]');
  if (!node) return false;
  const index = [...root.querySelectorAll('.flow-col > svg')].indexOf(node.closest('svg'));
  const p = diagramPoint(root, index, e);
  if (!p) return false;
  const t = TILES[node.dataset.tile];
  ui.drag = { tile: node.dataset.tile, index, dx: t.x - p.x, dy: t.y - p.y, moved: false };
  return true;
}

export function dragMove(e, ui, root) {
  const d = ui.drag;
  const p = d && diagramPoint(root, d.index, e);
  if (!p) return false;
  moveTile(d.tile, p.x + d.dx, p.y + d.dy);
  d.moved = true;
  return true;
}

export function dragEnd(ui) {
  if (!ui.drag) return;
  if (ui.drag.moved) saveLayout();
  ui.dragged = ui.drag.moved;
  ui.drag = null;
}
