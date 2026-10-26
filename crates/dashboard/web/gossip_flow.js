// Gossip pane, flow view: a sankey of one instance's gossip messages over the
// last WINDOW_S seconds of 1 s counter buckets, per topic group. Copies
// received split into duplicates and unique messages; unique messages into
// accepted, rejected, and the rest (ignored, or still validating); accepted
// and our own published messages into relayed. IWANT-served copies are their
// own band. From the `gossip_topics` and `gossip_flow` counters.

import { entryOf } from './gossip_traffic.js';
import { escape } from './view.js';

const WINDOW_S = 60;
const ALL = 'all';
/** Slots per topic: `gossip_topics` sent, recv, mesh, subs; `gossip_flow`
 *  as `GossipFlowCounters`. */
const TOPIC_KINDS = 4;
const FLOW_KINDS = ['duplicate', 'accepted', 'published', 'rejected', 'iwant'];

const COLS = 4;
const W = 760;
const H = 360;
const NODE_W = 12;
const GAP = 16;
/** Right of the last column, for its labels. */
const LABEL_W = 280;
const MIN_NODE_H = 2;

/** Per slot of counter source `name`, its growth over the last WINDOW_S of
 *  completed buckets; a counter reset counts nothing. Null before two
 *  buckets exist. */
function windowGrowth(inst, name) {
  const id = inst.sourceNamed(name);
  const h = id === null ? null : inst.counterHistory.get(id);
  if (!h || h.ts.length < 2) return null;
  const last = h.ts.length - 1;
  let first = last;
  while (first > 0 && h.ts[last] - h.ts[first - 1] <= WINDOW_S) first--;
  const growth = Array.from(h.values, (v) => {
    const a = v?.[first];
    const b = v?.[last];
    return a === null || a === undefined || b === null || b === undefined || b < a ? 0 : b - a;
  });
  return { growth, secs: h.ts[last] - h.ts[first] };
}

/** Topic group → summed counts, plus ALL. */
function groupTotals(inst, topics, flow) {
  const groups = new Map();
  const add = (key, counts) => {
    const g = groups.get(key) ?? { recv: 0, sent: 0, duplicate: 0, accepted: 0, published: 0, rejected: 0, iwant: 0 };
    for (const [k, v] of Object.entries(counts)) g[k] += v;
    groups.set(key, g);
  };
  const slots = Math.floor(topics.growth.length / TOPIC_KINDS);
  for (let s = 0; s < slots; s++) {
    const counts = { sent: topics.growth[s * TOPIC_KINDS] ?? 0, recv: topics.growth[s * TOPIC_KINDS + 1] ?? 0 };
    FLOW_KINDS.forEach((k, i) => (counts[k] = flow?.growth[s * FLOW_KINDS.length + i] ?? 0));
    if (!Object.values(counts).some((v) => v > 0)) continue;
    add(entryOf(inst.topicName(s)), counts);
    add(ALL, counts);
  }
  return groups;
}

function fmtCount(v) {
  if (v >= 1e6) return `${(v / 1e6).toFixed(2)}M`;
  if (v >= 1e4) return `${(v / 1e3).toFixed(1)}k`;
  return String(Math.round(v));
}

/** Nodes `{ id, col, label, colour }`, links `{ from, to, value }`. A unique
 *  message is either accepted, rejected or neither yet; validation lag can
 *  make accepted + rejected exceed unique within the window, so unique is
 *  their maximum. */
function graph(g) {
  const unique = Math.max(g.recv, g.accepted + g.rejected);
  // Ordered so bands into the same node run side by side: our own and IWANT
  // traffic on top, beside relayed and served, network traffic below.
  const nodes = [
    { id: 'published', col: 0, label: 'published by us', colour: 'var(--series-1)' },
    { id: 'iwantIn', col: 0, label: 'IWANT hits', colour: 'var(--series-7)' },
    { id: 'received', col: 0, label: 'received copies', colour: 'var(--muted)' },
    { id: 'unique', col: 1, label: 'unique', colour: 'var(--muted)' },
    { id: 'duplicate', col: 1, label: 'duplicate', colour: 'var(--idle)' },
    { id: 'accepted', col: 2, label: 'accepted', colour: 'var(--ok)' },
    { id: 'pending', col: 2, label: 'ignored / validating', colour: 'var(--c-warn)' },
    { id: 'rejected', col: 2, label: 'rejected', colour: 'var(--bad)' },
    { id: 'relayed', col: 3, label: 'relayed', colour: 'var(--fill)' },
    { id: 'iwantOut', col: 3, label: 'served on IWANT', colour: 'var(--series-7)' },
  ];
  const links = [
    { from: 'published', to: 'relayed', value: g.published },
    { from: 'iwantIn', to: 'iwantOut', value: g.iwant },
    { from: 'received', to: 'unique', value: unique },
    { from: 'received', to: 'duplicate', value: g.duplicate },
    { from: 'unique', to: 'accepted', value: g.accepted },
    { from: 'unique', to: 'pending', value: unique - g.accepted - g.rejected },
    { from: 'unique', to: 'rejected', value: g.rejected },
    { from: 'accepted', to: 'relayed', value: g.accepted },
  ].filter((l) => l.value > 0);
  return { nodes, links };
}

/** Positions nodes column by column, stacked in list order, on one scale
 *  fitted to the fullest column; then stacks each node's bands in link
 *  order. Empty nodes are dropped. */
function layout({ nodes, links }) {
  const byId = new Map(nodes.map((n) => [n.id, { ...n, in: 0, out: 0 }]));
  for (const l of links) {
    byId.get(l.from).out += l.value;
    byId.get(l.to).in += l.value;
  }
  const shown = [...byId.values()].filter((n) => Math.max(n.in, n.out) > 0);
  for (const n of shown) n.value = Math.max(n.in, n.out);
  const cols = Array.from({ length: COLS }, (_, c) => shown.filter((n) => n.col === c));
  const scale = Math.min(
    ...cols.filter((c) => c.length).map((c) => (H - GAP * (c.length - 1)) / c.reduce((t, n) => t + n.value, 0)),
  );
  cols.forEach((col, c) => {
    let y = 0;
    for (const n of col) {
      n.x = (c * (W - NODE_W)) / (COLS - 1);
      n.y = y;
      n.h = Math.max(n.value * scale, MIN_NODE_H);
      n.outY = n.y;
      n.inY = n.y;
      y += n.h + GAP;
    }
  });
  const bands = links.map((l) => {
    const from = byId.get(l.from);
    const to = byId.get(l.to);
    const h = l.value * scale;
    const band = { ...l, colour: to.colour, h, x0: from.x + NODE_W, y0: from.outY, x1: to.x, y1: to.inY };
    from.outY += h;
    to.inY += h;
    return band;
  });
  return { nodes: shown, bands };
}

function bandPath({ x0, y0, x1, y1, h }) {
  const mx = (x0 + x1) / 2;
  return `M${x0},${y0} C${mx},${y0} ${mx},${y1} ${x1},${y1} L${x1},${y1 + h} C${mx},${y1 + h} ${mx},${y0 + h} ${x0},${y0 + h} Z`;
}

function sankey(g, secs) {
  const { nodes, bands } = layout(graph(g));
  const rate = (v) => (secs > 0 ? `${(v / secs).toFixed(1)}/s` : '');
  const nodeLabel = (n) => {
    if (n.id === 'relayed' && g.sent > 0) {
      return `${n.label} ${fmtCount(n.value)} → ${fmtCount(g.sent)} copies (×${(g.sent / n.value).toFixed(1)})`;
    }
    return `${n.label} ${fmtCount(n.value)}`;
  };
  const paths = bands
    .map((b) => `<path class="band" d="${bandPath(b)}" style="fill:${b.colour}"><title>${escape(`${b.from} → ${b.to}: ${fmtCount(b.value)} (${rate(b.value)})`)}</title></path>`)
    .join('');
  const boxes = nodes
    .map((n) => {
      const ty = n.y + n.h / 2;
      return `<g><title>${escape(`${n.label}: ${fmtCount(n.value)} (${rate(n.value)})`)}</title>
        <rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="${n.h}" style="fill:${n.colour}"/>
        <text x="${n.x + NODE_W + 6}" y="${ty}" dy="0.35em">${escape(nodeLabel(n))}</text></g>`;
    })
    .join('');
  return `<svg viewBox="0 -8 ${W + LABEL_W} ${H + 16}" role="img" aria-label="gossip message flow">${paths}${boxes}</svg>`;
}

function groupTabs(groups, active) {
  const keys = [ALL, ...[...groups.keys()].filter((k) => k !== ALL).sort((a, b) => groups.get(b).recv - groups.get(a).recv)];
  const buttons = keys
    .map((k) => `<button class="${k === active ? 'active' : ''}" data-flow-group="${escape(k)}">${escape(k)}</button>`)
    .join('');
  return `<div class="subtabs">${buttons}</div>`;
}

export function render(inst, ui) {
  const topics = windowGrowth(inst, 'gossip_topics');
  const flow = windowGrowth(inst, 'gossip_flow');
  if (!topics) return '<p class="empty">no gossip_topics buckets yet</p>';
  const groups = groupTotals(inst, topics, flow);
  const group = groups.has(ui.flowGroup) ? ui.flowGroup : ALL;
  const g = groups.get(group);
  const missing = flow ? '' : '<p class="empty">no gossip_flow counters from this node: outcomes need a newer silver build</p>';
  const meta = `<p class="meta">messages over the last ${Math.round(topics.secs)} s; ignored / validating is unique less accepted and rejected</p>`;
  const body = g ? sankey(g, topics.secs) : '<p class="empty">no gossip in the window</p>';
  return `${groupTabs(groups, group)}${missing}${meta}<div class="gossip-flow">${body}</div>`;
}

/** True when the click was the view's. */
export function click(target, ui) {
  const group = target.closest('[data-flow-group]')?.dataset.flowGroup;
  if (!group) return false;
  ui.flowGroup = group;
  return true;
}
