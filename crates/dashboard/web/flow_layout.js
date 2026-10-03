// Tile layout and drawing shared by the Flow pane's graph modes.

import { escape, fmtBytes } from './view.js';

export const W = 760;
export const H = 760;
export const NODE_W = 130;
export const NODE_H = 66;
/** Room left of the canvas for the p2p arrows into and out of Network. */
export const P2P_MARGIN = 100;
export const COLOUR_STEPS = 10;
export const WIDTH_MIN = 1.5;
export const WIDTH_MAX = 10;
const LANE_GAP = 16;
/** A box whose centre sits within this of a pair's line pushes its lanes to
 *  the other side. */
const NEAR_BOX = 220;

/** Keyed by the tile's Rust type name, as flux names its metrics files.
 *  Network and ApplicationBoundary flank the two columns, mirrored about the
 *  Network–ApplicationBoundary axis. Every straight tile-to-tile line clears
 *  every other box by ≥ 28, except the two that `PAIR_BOW` curves. */
export const TILES = {
  NetworkTile: { label: 'Network', x: 75, y: 380 },
  Controller: { label: 'Control', x: 240, y: 50 },
  StorageTile: { label: 'Storage', x: 240, y: 710 },
  BeaconStateTile: { label: 'BeaconState', x: 450, y: 260 },
  DataColumnsTile: { label: 'DataColumns', x: 450, y: 500 },
  ApplicationBoundaryTile: { label: 'API', x: 660, y: 380 },
};

/** Base bow of a tile pair, against its sorted direction as in `laneBows`:
 *  Control and Storage reach API around BeaconState and DataColumns. */
const PAIR_BOW = {
  'ApplicationBoundaryTile|Controller': 150,
  'ApplicationBoundaryTile|StorageTile': -150,
};

export const NET = 'NetworkTile';
export const CTL = 'Controller';
export const BS = 'BeaconStateTile';
export const STO = 'StorageTile';
export const DC = 'DataColumnsTile';
export const AB = 'ApplicationBoundaryTile';

export function fmtRate(r) {
  if (r >= 1e6) return `${(r / 1e6).toFixed(1)}M/s`;
  if (r >= 1e3) return `${(r / 1e3).toFixed(1)}k/s`;
  return `${Math.round(r)}/s`;
}

export function fmtNs(ns) {
  if (ns === null || ns === undefined) return '·';
  if (ns >= 1e6) return `${(ns / 1e6).toFixed(2)}ms`;
  if (ns >= 1e3) return `${(ns / 1e3).toFixed(1)}µs`;
  return `${Math.round(ns)}ns`;
}

export function fmtBytesRate(v) {
  return `${fmtBytes(Math.round(v))}/s`;
}

/** Log-scaled stroke width: `floor` → WIDTH_MIN, `decades` above it → WIDTH_MAX. */
export function logWidth(value, floor, decades) {
  if (!(value > 0)) return WIDTH_MIN;
  const d = Math.log10(Math.max(1, value / floor));
  return Math.min(WIDTH_MAX, WIDTH_MIN + ((WIDTH_MAX - WIDTH_MIN) * d) / decades);
}

/** Where the segment from the box centre towards (tx, ty) leaves the box. */
export function border(node, tx, ty) {
  const dx = tx - node.x;
  const dy = ty - node.y;
  const sx = dx === 0 ? Infinity : NODE_W / 2 / Math.abs(dx);
  const sy = dy === 0 ? Infinity : NODE_H / 2 / Math.abs(dy);
  const s = Math.min(sx, sy);
  return { x: node.x + dx * s, y: node.y + dy * s };
}

/** Quadratic curve between two points, bowed perpendicular by `bow`. */
export function curve(a, b, bow) {
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
  const cx = mx - ((b.y - a.y) / len) * bow;
  const cy = my + ((b.x - a.x) / len) * bow;
  return {
    d: `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`,
    mid: { x: (a.x + 2 * cx + b.x) / 4, y: (a.y + 2 * cy + b.y) / 4 },
  };
}

/** Side of the sorted pair's line A→B, as the sign of the bow `curve` bends
 *  towards, that faces away from the nearest third box beside the line; 0
 *  when no box is near, so the lanes fan out around the straight line. */
function laneSide(aName, bName) {
  const a = TILES[aName];
  const b = TILES[bName];
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = Math.hypot(dx, dy);
  let nearest = null;
  for (const [name, c] of Object.entries(TILES)) {
    if (name === aName || name === bName) continue;
    const along = ((c.x - a.x) * dx + (c.y - a.y) * dy) / (len * len);
    const across = ((c.x - a.x) * -dy + (c.y - a.y) * dx) / len;
    if (along < 0.15 || along > 0.85 || Math.abs(across) > NEAR_BOX) continue;
    if (!nearest || Math.abs(across) < Math.abs(nearest)) nearest = across;
  }
  return nearest === null ? 0 : -Math.sign(nearest);
}

/** Bow per edge, `{ fromName, toName }`, so parallel edges between one tile
 *  pair fan apart. Assigned in list order: a fixed order keeps each edge in
 *  its lane as its traffic comes and goes. */
export function laneBows(edges) {
  const pairKey = (e) => (e.fromName < e.toName ? `${e.fromName}|${e.toName}` : `${e.toName}|${e.fromName}`);
  const lanes = new Map();
  for (const e of edges) lanes.set(pairKey(e), (lanes.get(pairKey(e)) ?? 0) + 1);
  const seen = new Map();
  return edges.map((e) => {
    const k = pairKey(e);
    const n = lanes.get(k);
    const i = seen.get(k) ?? 0;
    seen.set(k, i + 1);
    // A quadratic's midpoint sits at half the control offset, so double it
    // to put parallel lanes (and their labels) LANE_GAP apart there.
    // Bow is measured against the pair's sorted direction, so lanes running
    // opposite ways fan out instead of mirroring onto each other.
    const [lo, hi] = e.fromName < e.toName ? [e.fromName, e.toName] : [e.toName, e.fromName];
    const base = PAIR_BOW[`${lo}|${hi}`] ?? 0;
    const side = base ? Math.sign(base) : laneSide(lo, hi);
    const lane = side === 0 ? i - (n - 1) / 2 : side * i;
    return (base + lane * LANE_GAP * 2) * (e.fromName < e.toName ? 1 : -1);
  });
}

/** Arrowhead of a selected line; markers do not inherit their line's colour. */
export const SEL_MARKER = 'sel';
/** Arrowhead of a line related to the selected one, fainter. */
export const REL_MARKER = 'rel';

export function markers() {
  const steps = [...Array(COLOUR_STEPS).keys()].map((s) => [s, `qf${s}`]);
  return [...steps, ['idle', 'qf-idle'], [SEL_MARKER, 'qf-sel'], [REL_MARKER, 'qf-rel']]
    .map(
      ([id, cls]) =>
        `<marker id="ah-${id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" markerUnits="userSpaceOnUse" orient="auto-start-reverse" style="overflow:visible"><path class="${cls}" d="M0,0 L10,5 L0,10 z" transform="scale(1.4)"/></marker>`,
    )
    .join('');
}

/** Tiles shaded by busy %; `notes` adds per-tile tooltip lines. */
export function drawNodes(utils, notes) {
  return Object.entries(TILES)
    .map(([name, t]) => {
      const u = utils.get(name);
      const busy = u?.total ? u.busy / u.total : null;
      const pct = busy === null ? 0 : Math.round(busy * 100);
      const detail = u ? `busy ${pct}%` : 'no tile metrics';
      const extra = (notes.get(name) ?? []).map((l) => `\n${l}`).join('');
      return `<g class="node" transform="translate(${t.x - NODE_W / 2},${t.y - NODE_H / 2})">
        <title>${escape(`${t.label} (${name})\n${detail}${extra}`)}</title>
        <rect width="${NODE_W}" height="${NODE_H}" rx="6" style="--busy:${pct}%"/>
        <text class="nlabel" x="${NODE_W / 2}" y="26">${escape(t.label)}</text>
        <text class="ndetail" x="${NODE_W / 2}" y="46">${escape(detail)}</text>
      </g>`;
    })
    .join('');
}

export function colourRamp() {
  return [...Array(COLOUR_STEPS).keys()].map((s) => `<i class="qb${s}"></i>`).join('');
}

export function widthSwatch(width, label) {
  return `<span><svg width="36" height="12"><line x1="2" y1="6" x2="34" y2="6" class="q5" stroke-width="${width}"/></svg>${label}</span>`;
}

export function detailPanel(title, body) {
  const close = '<button class="close" data-close-detail title="close">×</button>';
  return `<div class="flow-detail"><h3>${title}${close}</h3>${body}</div>`;
}

export function chartSlot(key, name) {
  return `<div><p class="meta">${name}</p><div class="chart" data-chart="${key}"></div></div>`;
}

export const NO_BUCKETS = '<p class="empty">no completed buckets yet</p>';
