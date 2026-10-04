// Tile layout and drawing shared by the Flow pane's graph modes.

import { escape, fmtBytes } from './view.js';

export const W = 760;
export const H = 760;
export const NODE_W = 130;
export const NODE_H = 66;
/** Room left of the canvas for the p2p arrows into and out of Network. */
export const P2P_MARGIN = 100;
export const COLOUR_STEPS = 10;
const WIDTH_MIN = 1.5;
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

const DEFAULTS = Object.fromEntries(Object.entries(TILES).map(([name, t]) => [name, { x: t.x, y: t.y }]));
const LAYOUT_KEY = 'silver-dashboard.tile-layout';

const atDefault = (name) => TILES[name].x === DEFAULTS[name].x && TILES[name].y === DEFAULTS[name].y;

export function isDefaultLayout() {
  return Object.keys(TILES).every(atDefault);
}

/** Centre of `name`, kept inside the diagram. */
export function moveTile(name, x, y) {
  TILES[name].x = Math.round(Math.min(W - NODE_W / 2, Math.max(NODE_W / 2, x)));
  TILES[name].y = Math.round(Math.min(H - NODE_H / 2, Math.max(NODE_H / 2, y)));
}

/** Per browser; storage may be unavailable, and then the layout lives only
 *  until reload. */
export function saveLayout() {
  try {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(Object.fromEntries(Object.entries(TILES).map(([n, t]) => [n, { x: t.x, y: t.y }]))));
  } catch {}
}

export function resetLayout() {
  for (const [name, p] of Object.entries(DEFAULTS)) moveTile(name, p.x, p.y);
  try {
    localStorage.removeItem(LAYOUT_KEY);
  } catch {}
}

function loadLayout() {
  let saved = null;
  try {
    saved = JSON.parse(localStorage.getItem(LAYOUT_KEY) ?? 'null');
  } catch {}
  for (const [name, p] of Object.entries(saved ?? {})) {
    if (TILES[name] && Number.isFinite(p?.x) && Number.isFinite(p?.y)) moveTile(name, p.x, p.y);
  }
}
loadLayout();

/** Base bow of a tile pair, against its sorted direction as in `laneBows`:
 *  Control and Storage reach API around BeaconState and DataColumns. Only
 *  while both tiles sit where the default layout puts them. */
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
function border(node, tx, ty) {
  const dx = tx - node.x;
  const dy = ty - node.y;
  const sx = dx === 0 ? Infinity : NODE_W / 2 / Math.abs(dx);
  const sy = dy === 0 ? Infinity : NODE_H / 2 / Math.abs(dy);
  const s = Math.min(sx, sy);
  return { x: node.x + dx * s, y: node.y + dy * s };
}

/** Quadratic curve between two points, bowed perpendicular by `bow`. */
function curve(a, b, bow) {
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
  const cx = mx - ((b.y - a.y) / len) * bow;
  const cy = my + ((b.x - a.x) / len) * bow;
  const at = (t) => ({
    x: (1 - t) ** 2 * a.x + 2 * (1 - t) * t * cx + t ** 2 * b.x,
    y: (1 - t) ** 2 * a.y + 2 * (1 - t) * t * cy + t ** 2 * b.y,
  });
  return {
    d: `M${a.x.toFixed(1)},${a.y.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`,
    mid: at(0.5),
    at,
  };
}

const SPOT_R_MIN = 3;
const SPOT_R_MAX = 8;

/** Spot radius for a stroke width from `logWidth`, on the same log scale. */
export function spotRadius(width) {
  return SPOT_R_MIN + ((SPOT_R_MAX - SPOT_R_MIN) * (width - WIDTH_MIN)) / (WIDTH_MAX - WIDTH_MIN);
}

/** One line per direction between two tiles, as wide as `width(total)` of
 *  its items' rates, with one spot per item spaced evenly in list order, so a
 *  spot keeps its place as traffic comes and goes. An item is `{ fromName,
 *  toName, rate, counted, fill, r, hollow, show, mark, attrs, title, label,
 *  pinned }`:
 *  `counted` adds its rate to the line, `fill` is the spot's class, `show`
 *  the hovered item's labels, `mark`
 *  (`selected` / `related`) also marks its line, `attrs` carries its selection
 *  and hover keys. Idle spots are painted first, marked ones last. */
export function drawTrunks(items, width) {
  const trunks = new Map();
  for (const it of items) {
    const k = `${it.fromName}>${it.toName}`;
    let t = trunks.get(k);
    if (!t) trunks.set(k, (t = { fromName: it.fromName, toName: it.toName, items: [], total: 0, mark: '' }));
    t.items.push(it);
    if (it.counted) t.total += it.rate ?? 0;
    if (it.mark === 'selected' || (it.mark && !t.mark)) t.mark = it.mark;
  }
  const list = [...trunks.values()];
  const bows = laneBows(list);
  const lines = [];
  const idle = [];
  const active = [];
  const top = [];
  const labels = [];
  list.forEach((t, i) => {
    const from = TILES[t.fromName];
    const to = TILES[t.toName];
    const { d, at } = curve(border(from, to.x, to.y), border(to, from.x, from.y), bows[i]);
    const busy = t.total > 0;
    const w = busy ? width(t.total) : WIDTH_MIN;
    const mark = t.mark ? ` ${t.mark}` : '';
    lines.push(`<path class="trunk${busy ? '' : ' idle'}${mark}" d="${d}" stroke-width="${w.toFixed(1)}" marker-end="url(#ah-trunk)"/>`);
    t.items.forEach((it, k) => {
      const p = at((k + 1) / (t.items.length + 1));
      const [x, y] = [p.x.toFixed(1), p.y.toFixed(1)];
      const fill = it.hollow ? `spot hollow ${it.fill}` : `spot ${it.fill}`;
      const show = it.show ? ' show' : '';
      const group = `<g class="edge${show}${it.mark ? ` ${it.mark}` : ''}" ${it.attrs}><title>${escape(it.title)}</title>
        <circle class="hit" cx="${x}" cy="${y}" r="${SPOT_R_MAX + 3}"/>
        <circle class="${fill}" cx="${x}" cy="${y}" r="${it.r.toFixed(1)}"/></g>`;
      (it.mark ? top : it.fill === 'qf-idle' ? idle : active).push(group);
      const pinned = it.pinned ? ' sel' : '';
      labels.push(`<text class="elabel${show}${pinned}" ${it.attrs} x="${x}" y="${(p.y - SPOT_R_MAX - 4).toFixed(1)}">${escape(it.label)}</text>`);
    });
  });
  return { paths: lines.join('') + idle.join('') + active.join('') + top.join(''), labels: labels.join('') };
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
function laneBows(edges) {
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
    const base = atDefault(lo) && atDefault(hi) ? (PAIR_BOW[`${lo}|${hi}`] ?? 0) : 0;
    const side = base ? Math.sign(base) : laneSide(lo, hi);
    const lane = side === 0 ? i - (n - 1) / 2 : side * i;
    return (base + lane * LANE_GAP * 2) * (e.fromName < e.toName ? 1 : -1);
  });
}

/** Arrowhead of a selected line; markers do not inherit their line's colour. */
export const SEL_MARKER = 'sel';

export function markers() {
  const steps = [...Array(COLOUR_STEPS).keys()].map((s) => [s, `qf${s}`]);
  return [...steps, ['idle', 'qf-idle'], ['trunk', 'qf-trunk'], [SEL_MARKER, 'qf-sel']]
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
      return `<g class="node" data-tile="${name}" transform="translate(${t.x - NODE_W / 2},${t.y - NODE_H / 2})">
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
