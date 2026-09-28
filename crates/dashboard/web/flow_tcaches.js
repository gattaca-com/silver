// TCache mode of the Flow pane. One line per tcache and consumer tile, from
// the producer, as thick as that tile's read rate and coloured by its lag.
// Dashed lines are declared ref forwarding. Selecting a line highlights the
// rest of its tcache's lines, fainter, and opens its row in the tcache table
// below the diagram; selecting a row highlights all of its tcache's lines.

import { tcacheMinTail } from './state.js';
import { tcacheTable } from './tcaches.js';
import { escape, fmtBytes } from './view.js';
import {
  AB, BS, COLOUR_STEPS, CTL, DC, NET, REL_MARKER, SEL_MARKER, STO, TILES, WIDTH_MIN, border,
  colourRamp, curve, fmtBytesRate, laneBows, logWidth, widthSwatch,
} from './flow_layout.js';

/** Width spans 1 KiB/s … ~100 MiB/s. */
const BYTES_FLOOR = 1024;
const BYTES_DECADES = 5;
const HEAD_SLOT = 1;
const FIRST_TAIL = 2;
const SELECT = 'tc:';

// [tcache, producer]; names as `TCacheId::name`. Mirrors the TCaches table in
// docs/spine-message-flow.md.
const TCACHES = [
  ['network_ingress', NET],
  ['network_processing', NET],
  ['cluster_inbound', NET],
  ['control_processing', CTL],
  ['control_gossip', CTL],
  ['control_rpc', CTL],
  ['cluster_outbound', CTL],
  ['control_slot', CTL],
  ['storage_delivery', STO],
  ['boundary_processing', AB],
  ['beacon_state_handoff', BS],
];

// Consumer name prefix → tile, after the names each tile passes to
// `TCacheReader::open` and `TileId::emitter`. A name matching none is listed
// on its producer as unassigned.
const CONSUMER_PREFIXES = [
  ['ctl_', CTL],
  ['control_', CTL],
  ['gossip_', CTL],
  ['bs_', BS],
  ['dc_', DC],
  ['ds_', STO],
  ['api_', AB],
  ['eng_', AB],
  ['p2p_', NET],
  ['peer_', NET],
  ['network_', NET],
];

// [tcache, forwarder, its emitter consumer, receivers], after the
// `TCacheReader::declare` calls; not observable at runtime, so update with
// them. The forwarder relays refs only: receivers read the producer's ring.
// DataColumns declaring its own emitter (persist reader) is left out.
const FORWARDS = [
  ['network_processing', BS, 'bs_network_processing', [CTL, DC, STO, AB]],
  ['network_processing', DC, 'dc_network_processing', [CTL, STO, AB]],
  ['control_processing', BS, 'bs_control_processing', [DC, STO, AB]],
  ['control_processing', DC, 'dc_control_processing', [STO, AB]],
  ['control_slot', DC, 'dc_control_slot', [STO, AB]],
  ['control_gossip', CTL, 'gossip_mcache', [NET]],
  ['control_gossip', DC, 'dc_control_gossip', [NET, CTL]],
];

function consumerTile(name) {
  return CONSUMER_PREFIXES.find(([prefix]) => name.startsWith(prefix))?.[1] ?? null;
}

function pct(part, whole) {
  return whole ? (part / whole) * 100 : 0;
}

/** 0% → lightest, ≥ 90% → darkest. */
function fillStep(frac) {
  return Math.max(0, Math.min(COLOUR_STEPS - 1, Math.floor(frac * COLOUR_STEPS)));
}

/** One tcache's latest bucket: write rate, occupancy, and its published
 *  consumers grouped into branches by tile. */
function cacheView(inst, cache, producer) {
  const id = inst.sourceNamed(`tcache-${cache}`);
  const values = id === null ? null : inst.counters.get(id)?.values;
  if (!values || values.length < FIRST_TAIL) return null;
  const names = inst.slotNames.get(id) ?? [];
  const capacity = values[0] ?? 0;
  const head = values[HEAD_SLOT] ?? 0;
  const view = {
    id,
    cache,
    producer,
    capacity,
    occupancy: Math.max(0, head - tcacheMinTail(values)),
    writeRate: inst.rate(id, HEAD_SLOT),
    branches: new Map(),
    selfs: [],
    unassigned: [],
    consumers: new Map(),
  };
  for (let i = FIRST_TAIL; i < values.length; i++) {
    if (values[i] === null) continue;
    const name = names[i] ?? `tail_${i - FIRST_TAIL}`;
    const c = { name, slot: i, rate: inst.rate(id, i), lag: Math.max(0, head - values[i]) };
    view.consumers.set(name, c);
    const tile = consumerTile(name);
    if (tile === null) view.unassigned.push(c);
    else if (tile === producer) view.selfs.push(c);
    else {
      let b = view.branches.get(tile);
      if (!b) view.branches.set(tile, (b = { tile, members: [] }));
      b.members.push(c);
    }
  }
  // Each of a tile's consumers reads every byte, so the tile's intake is the
  // fastest reader, not the sum; the worst lag is what the producer feels.
  for (const b of view.branches.values()) {
    b.rate = Math.max(0, ...b.members.map((c) => c.rate ?? 0));
    b.lag = Math.max(0, ...b.members.map((c) => c.lag));
  }
  return view;
}

function lagTitle(v, b) {
  const c = TILES[b.tile];
  const members = b.members
    .map((m) => `${m.name}: ${m.rate === null ? '·' : fmtBytesRate(m.rate)}, lag ${fmtBytes(m.lag)} (${pct(m.lag, v.capacity).toFixed(0)}%)`)
    .join('\n');
  return (
    `${v.cache}: ${TILES[v.producer].label} → ${c.label}\n` +
    `producer write ${v.writeRate === null ? '·' : fmtBytesRate(v.writeRate)}, ` +
    `occupancy ${fmtBytes(v.occupancy)} of ${fmtBytes(v.capacity)} (${pct(v.occupancy, v.capacity).toFixed(0)}%)\n` +
    `read ${fmtBytesRate(b.rate)}\n${members}`
  );
}

/** Data lines and dashed forwarding lines share lanes, so neither lies on
 *  the other. Idle lines are painted first, the selected tcache's last. */
function drawLines(views, hovered, selected) {
  // A row selects a whole tcache (no tile): all its data lines are selected.
  const [selCache, selTile] = selected?.split('|') ?? [];
  const byCache = new Map(views.map((v) => [v.cache, v]));
  const lines = [];
  for (const v of views) {
    for (const b of v.branches.values()) {
      lines.push({ cache: v.cache, fromName: v.producer, toName: b.tile, view: v, branch: b });
    }
  }
  for (const [cache, forwarder, emitter, receivers] of FORWARDS) {
    for (const r of receivers) lines.push({ cache, fromName: forwarder, toName: r, emitter, forward: true });
  }
  const bows = laneBows(lines);
  const idle = [];
  const active = [];
  const top = [];
  const labels = [];
  lines.forEach((e, i) => {
    const from = TILES[e.fromName];
    const to = TILES[e.toName];
    const { d, mid } = curve(border(from, to.x, to.y), border(to, from.x, from.y), bows[i]);
    const show = e.cache === hovered ? ' show' : '';
    const key = `${e.cache}|${e.toName}`;
    const isSel = !e.forward && e.cache === selCache && (selTile === undefined || e.toName === selTile);
    const related = !isSel && e.cache === selCache;
    const mark = isSel ? ' selected' : related ? ' related' : '';
    let cls;
    let width;
    let marker;
    let title;
    let label;
    if (e.forward) {
      const rate = byCache.get(e.cache)?.consumers.get(e.emitter)?.rate;
      cls = rate > 0 ? 'q3' : 'q-idle';
      width = WIDTH_MIN;
      marker = rate > 0 ? 3 : 'idle';
      title = `${e.cache}: ${from.label} forwards refs to ${to.label}\nreads via ${e.emitter}${rate > 0 ? ` at ${fmtBytesRate(rate)}` : ''}`;
      label = `${e.cache} refs`;
    } else {
      const { view: v, branch: b } = e;
      const reading = b.rate > 0;
      const step = fillStep(v.capacity ? b.lag / v.capacity : 0);
      cls = reading ? `q${step}` : 'q-idle';
      width = reading ? logWidth(b.rate, BYTES_FLOOR, BYTES_DECADES) : WIDTH_MIN;
      marker = reading ? step : 'idle';
      title = lagTitle(v, b);
      label = `${e.cache} ${reading ? fmtBytesRate(b.rate) : 'idle'} · lag ${pct(b.lag, v.capacity).toFixed(0)}%`;
    }
    if (isSel) marker = SEL_MARKER;
    else if (related) marker = REL_MARKER;
    const sel = e.forward ? '' : ` data-tc="${key}"`;
    const group = `<g class="edge${e.forward ? ' forward' : ''}${show}${mark}" data-q="${e.cache}"${sel}><title>${escape(title)}</title>
      <path class="hit" d="${d}"/>
      <path class="${cls}" d="${d}" stroke-width="${width.toFixed(1)}" marker-end="url(#ah-${marker})"/></g>`;
    (mark ? top : cls === 'q-idle' ? idle : active).push(group);
    // Forwarding labels stay hover-only; a selection labels its data lines.
    const pinned = mark && !e.forward ? ' sel' : '';
    labels.push(`<text class="elabel${show}${pinned}" data-q="${e.cache}" x="${mid.x.toFixed(1)}" y="${mid.y.toFixed(1)}">${escape(label)}</text>`);
  });
  return { paths: idle.join('') + active.join('') + top.join(''), labels: labels.join('') };
}

function legend() {
  const widths = [1024, 1024 ** 2, 10 * 1024 ** 2, 100 * 1024 ** 2]
    .map((r) => widthSwatch(logWidth(r, BYTES_FLOOR, BYTES_DECADES), fmtBytesRate(r)))
    .join('');
  return `<div class="flow-legend">
    <div><span class="meta">colour: consumer lag, % of capacity</span> <span class="ramp">0% ${colourRamp()} 100%</span> <span class="meta">grey: idle · hover for the tcache, click to open it in the table below</span></div>
    <div><span class="meta">width: consumer read</span> ${widths}</div>
    <div class="meta">One line per tcache and consumer tile, from its producer. Dashed: declared ref forwarding; the receiver reads the producer's ring.</div>
  </div>`;
}

/** The selected tcache's row: charting the head and the consumers of the
 *  selected line's tile, or every consumer for a row selection. */
function focus(views, key) {
  if (!key) return null;
  const [cache, tile] = key.split('|');
  if (!tile) return { name: `tcache-${cache}`, slots: null };
  const b = views.find((v) => v.cache === cache)?.branches.get(tile);
  return b ? { name: `tcache-${cache}`, slots: new Set(b.members.map((m) => m.slot)) } : null;
}

/** Selection key of a clicked line (`{cache}|{tile}`) or table row
 *  (`{cache}`, the whole tcache). */
export function selectKey(target) {
  const line = target.closest('.flow [data-tc]');
  if (line) return SELECT + line.dataset.tc;
  const row = target.closest('[data-tcache]');
  return row ? SELECT + row.dataset.tcache : null;
}

export function graph(inst, _utils, ui, specs) {
  const views = TCACHES.map(([cache, producer]) => cacheView(inst, cache, producer)).filter(Boolean);
  const key = ui.selected?.startsWith(SELECT) ? ui.selected.slice(SELECT.length) : null;
  const { paths, labels } = drawLines(views, ui.hover, key);

  const notes = new Map();
  const note = (tile, text) => notes.set(tile, [...(notes.get(tile) ?? []), text]);
  for (const v of views) {
    for (const c of v.selfs) note(v.producer, `self: ${c.name} reads ${v.cache}`);
    for (const c of v.unassigned) note(v.producer, `unassigned consumer ${c.name} on ${v.cache}`);
  }
  return { paths, labels, notes, detail: tcacheTable(inst, specs, focus(views, key)), legend: legend() };
}
