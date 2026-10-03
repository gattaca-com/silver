// TCache mode of the Flow pane. One line per direction between two tiles;
// each spot on it is one tcache read by the consumer tile from its producer,
// sized by that tile's read rate and coloured by its lag. Hollow spots are
// declared ref forwarding. Selecting a spot highlights the rest of its
// tcache's spots, fainter, and opens its row in the tcache table; selecting a
// row highlights all of its tcache's spots.

import { tcacheMinTail } from './state.js';
import { tcacheTable } from './tcaches.js';
import { escape, fmtBytes } from './view.js';
import {
  AB, BS, COLOUR_STEPS, CTL, DC, NET, STO, TILES, colourRamp, drawTrunks, fmtBytesRate, logWidth,
  spotRadius, widthSwatch,
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

const bytesWidth = (rate) => logWidth(rate, BYTES_FLOOR, BYTES_DECADES);

/** Data and forwarding spots share their direction's line; only data reads
 *  add to its width. */
function drawLines(views, hovered, selected) {
  // A row selects a whole tcache (no tile): all its data spots are selected.
  const [selCache, selTile] = selected?.split('|') ?? [];
  const byCache = new Map(views.map((v) => [v.cache, v]));
  const items = [];
  for (const v of views) {
    for (const b of v.branches.values()) {
      const reading = b.rate > 0;
      const step = fillStep(v.capacity ? b.lag / v.capacity : 0);
      const isSel = v.cache === selCache && (selTile === undefined || b.tile === selTile);
      const mark = isSel ? 'selected' : v.cache === selCache ? 'related' : '';
      items.push({
        fromName: v.producer,
        toName: b.tile,
        rate: b.rate,
        counted: true,
        fill: reading ? `qf${step}` : 'qf-idle',
        r: spotRadius(reading ? bytesWidth(b.rate) : 0),
        show: v.cache === hovered,
        mark,
        attrs: `data-q="${v.cache}" data-tc="${v.cache}|${b.tile}"`,
        title: lagTitle(v, b),
        label: `${v.cache} ${reading ? fmtBytesRate(b.rate) : 'idle'} · lag ${pct(b.lag, v.capacity).toFixed(0)}%`,
        pinned: Boolean(mark),
      });
    }
  }
  for (const [cache, forwarder, emitter, receivers] of FORWARDS) {
    const rate = byCache.get(cache)?.consumers.get(emitter)?.rate;
    for (const r of receivers) {
      items.push({
        fromName: forwarder,
        toName: r,
        rate,
        counted: false,
        fill: rate > 0 ? 'qf3' : 'qf-idle',
        r: spotRadius(0),
        hollow: true,
        show: cache === hovered,
        mark: '',
        attrs: `data-q="${cache}"`,
        title: `${cache}: ${TILES[forwarder].label} forwards refs to ${TILES[r].label}\nreads via ${emitter}${rate > 0 ? ` at ${fmtBytesRate(rate)}` : ''}`,
        label: `${cache} refs`,
        pinned: false,
      });
    }
  }
  return drawTrunks(items, bytesWidth);
}

function legend() {
  const widths = [1024, 1024 ** 2, 10 * 1024 ** 2, 100 * 1024 ** 2]
    .map((r) => widthSwatch(bytesWidth(r), fmtBytesRate(r)))
    .join('');
  return `<div class="flow-legend">
    <div><span class="meta">spot colour: consumer lag, % of capacity</span> <span class="ramp">0% ${colourRamp()} 100%</span> <span class="meta">grey: idle · hover a spot for its tcache, click to open it in the table</span></div>
    <div><span class="meta">line width: total consumer read · spot size: its read, same scale</span> ${widths}</div>
    <div class="meta">One line per direction between two tiles; one spot per tcache and consumer tile on it, from the producer. Hollow: declared ref forwarding; the receiver reads the producer's ring.</div>
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
