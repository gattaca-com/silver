// Spine-queue mode of the Flow pane. Each edge is one producer → consumer
// pair of one message type, read from flux's lazily created per-pair timers
// `{Consumer}-{Producer}-{MessageType}`.

import { SourceClass, TimingChannel } from './wire.js';
import { escape } from './view.js';
import {
  AB, BS, COLOUR_STEPS, CTL, DC, NET, NO_BUCKETS, SEL_MARKER, STO, TILES, WIDTH_MIN, border, chartSlot,
  colourRamp, curve, detailPanel, fmtNs, fmtRate, laneBows, logWidth, widthSwatch,
} from './flow_layout.js';

/** Width spans 1/s … 100k/s. */
const RATE_DECADES = 5;

// [queue, message type, producers, consumers]. Mirrors the queue table in
// docs/spine-message-flow.md; update both together. Every consumer of a
// broadcast queue reads every producer's messages, so the cross product is
// the expected pair set: drawn grey until its timer reports traffic.
// `engine_health` and `peer_stats` have no in-process consumer.
const QUEUES = [
  ['gossip_in', 'GossipMsgIn', [NET], [CTL]],
  ['new_gossip', 'NewGossipMsg', [CTL], [BS, DC]],
  ['p2p_send', 'P2pSend', [CTL, STO], [NET]],
  ['rpc_inbound', 'RpcInbound', [NET], [CTL, BS, DC, STO]],
  ['cluster_inbound', 'ClusterIn', [NET], [CTL]],
  ['cluster_outbound', 'ClusterMsgOut', [CTL], [NET]],
  ['beacon_api_requests', 'BeaconApiRequest', [AB], [CTL, BS, STO]],
  ['beacon_api_responses', 'BeaconApiResponse', [CTL, BS, STO], [AB]],
  ['peer_events', 'PeerEvent', [NET, CTL, BS, DC, STO], [CTL, AB]],
  ['peer_control', 'PeerControl', [CTL], [NET, STO]],
  ['beacon_events', 'BeaconStateEvent', [BS], [CTL, NET, STO, DC, AB]],
  ['data_columns', 'DataColumnsEvent', [DC], [CTL, BS, STO, AB]],
  ['retention', 'RetentionEvent', [CTL], [DC]],
  ['cells', 'CellStoreEvent', [CTL, DC], [CTL, DC]],
  ['sync_target', 'SyncUpdate', [CTL], [BS, DC, STO, AB]],
  ['sync_needs', 'SyncNeed', [CTL, BS, DC, STO], [CTL]],
  ['replay_blocks', 'ReplayBlock', [STO], [BS]],
  ['syncing_strategy', 'SyncingStrategy', [CTL], [STO]],
  ['engine_reqs', 'EngineReq', [BS, DC], [AB]],
  // AB consumes its own NewPayload responses; the self-edge is not drawn.
  ['engine_resps', 'EngineResp', [AB], [BS, DC, AB]],
];

const QUEUE_OF = new Map(QUEUES.map(([queue, msg]) => [msg, queue]));

/** `{Consumer}-{Producer}-{Msg}`; the producer may itself contain dashes
 *  (`unknown-producer`, `producer-{slot}`). */
function parseTimer(name) {
  const parts = name.split('-');
  if (parts.length < 3) return null;
  return { consumer: parts[0], producer: parts.slice(1, -1).join('-'), msg: parts.at(-1) };
}

/** Latest bucket and history per timer name. */
function timers(inst) {
  const latest = new Map();
  const histories = new Map();
  for (const { id, name } of inst.sourcesOf(SourceClass.Timing)) {
    const t = inst.timings.get(id);
    if (t) latest.set(name, t);
    const h = inst.timingHistory.get(id);
    if (h) histories.set(name, h);
  }
  return { latest, histories };
}

/** Expected pairs from QUEUES, merged with every observed pair between two
 *  known tiles. Self-consumption is not drawn; it is listed on the node. */
function layoutEdges(latest) {
  const edges = new Map();
  const selfs = [];
  const key = (p, c, msg) => `${p}>${c}>${msg}`;
  for (const [queue, msg, producers, consumers] of QUEUES) {
    for (const p of producers) {
      for (const c of consumers) {
        if (p !== c) edges.set(key(p, c, msg), { queue, msg, fromName: p, toName: c, rate: 0 });
      }
    }
  }
  for (const [name, t] of latest) {
    const pair = parseTimer(name);
    if (!pair || !TILES[pair.consumer] || !TILES[pair.producer]) continue;
    const observed = {
      queue: QUEUE_OF.get(pair.msg) ?? pair.msg,
      msg: pair.msg,
      fromName: pair.producer,
      toName: pair.consumer,
      timer: name,
      rate: t.latency?.count ?? 0,
      latency: t.latency,
      processing: t.processing,
    };
    if (pair.producer === pair.consumer) {
      if (observed.rate) selfs.push(observed);
      continue;
    }
    edges.set(key(pair.producer, pair.consumer, pair.msg), observed);
  }
  return { edges: [...edges.values()], selfs };
}

/** Two colour steps per decade of handler p50: 100ns → 0, 1µs → 2 … 10ms → 9.
 *  An active edge without a handler sample takes the lightest step. */
function handlerStep(p50Ns) {
  if (!(p50Ns > 0)) return 0;
  return Math.max(0, Math.min(COLOUR_STEPS - 1, Math.round(2 * Math.log10(p50Ns / 100))));
}

function edgeTitle(e, utils) {
  const lines = [`${e.queue} : ${e.msg}`, `${TILES[e.fromName].label} → ${TILES[e.toName].label}`];
  lines.push(e.rate ? fmtRate(e.rate) : 'no traffic this bucket');
  lines.push(`queue latency p50 ${fmtNs(e.latency?.p50Ns)} · p99 ${fmtNs(e.latency?.p99Ns)}`);
  lines.push(`handler p50 ${fmtNs(e.processing?.p50Ns)} · p99 ${fmtNs(e.processing?.p99Ns)}`);
  const count = e.processing?.count ?? 0;
  if (count && e.processing?.p50Ns) {
    const core = (count * e.processing.p50Ns) / 1e9;
    const util = utils.get(e.toName);
    const busy = util?.total ? util.busy / util.total : null;
    const tile = busy === null ? '' : ` (tile busy ${(busy * 100).toFixed(0)}%)`;
    lines.push(`≈ ${(core * 100).toFixed(1)}% of a core${tile}, from count × p50`);
  }
  return lines.join('\n');
}

/** Idle edges are painted first so traffic draws over them, and the selected
 *  edge last. Every edge carries its own hover label: hovering a queue shows
 *  the per-pair rate of each of its edges; the selected edge's stays shown. */
function drawEdges(edges, utils, hovered, selected) {
  const bows = laneBows(edges);
  const idle = [];
  const active = [];
  const top = [];
  const labels = [];
  edges.forEach((e, i) => {
    const from = TILES[e.fromName];
    const to = TILES[e.toName];
    const { d, mid } = curve(border(from, to.x, to.y), border(to, from.x, from.y), bows[i]);
    const step = e.rate > 0 ? handlerStep(e.processing?.p50Ns) : null;
    const cls = step === null ? 'q-idle' : `q${step}`;
    const width = step === null ? WIDTH_MIN : logWidth(e.rate, 1, RATE_DECADES);
    const show = e.queue === hovered ? ' show' : '';
    const isSel = Boolean(e.timer) && e.timer === selected;
    const sel = isSel ? ' selected' : '';
    const timer = e.timer ? ` data-timer="${escape(e.timer)}"` : '';
    const marker = isSel ? SEL_MARKER : step === null ? 'idle' : step;
    (isSel ? top : step === null ? idle : active).push(`<g class="edge${show}${sel}" data-q="${e.queue}"${timer}><title>${escape(edgeTitle(e, utils))}</title>
      <path class="hit" d="${d}"/>
      <path class="${cls}" d="${d}" stroke-width="${width.toFixed(1)}" marker-end="url(#ah-${marker})"/></g>`);
    labels.push(`<text class="elabel${show}${isSel ? ' sel' : ''}" data-q="${e.queue}" x="${mid.x.toFixed(1)}" y="${mid.y.toFixed(1)}">${escape(e.queue)} ${e.rate ? fmtRate(e.rate) : 'idle'}</text>`);
  });
  return { paths: idle.join('') + active.join('') + top.join(''), labels: labels.join('') };
}

/** Charts of the selected pair's timer over the retained buckets. */
function edgeDetail(e, histories, specs) {
  if (!e) return '';
  const h = histories.get(e.timer);
  const title = `${escape(e.queue)} : ${escape(e.msg)} · ${TILES[e.fromName].label} → ${TILES[e.toName].label}`;
  if (!h?.ts.length) return detailPanel(title, NO_BUCKETS);
  const latency = h.channels[TimingChannel.Latency];
  const processing = h.channels[TimingChannel.Processing];
  specs.set('flow-latency', { labels: ['p50', 'p99'], data: [h.ts, latency.p50, latency.p99], fmt: fmtNs });
  specs.set('flow-handler', { labels: ['p50', 'p99'], data: [h.ts, processing.p50, processing.p99], fmt: fmtNs });
  specs.set('flow-count', { labels: ['msgs/s'], data: [h.ts, latency.count], fmt: fmtRate });
  return detailPanel(title, `<div class="flow-charts">
    ${chartSlot('flow-latency', 'queue latency (publish → consume)')}
    ${chartSlot('flow-handler', 'handler time')}
    ${chartSlot('flow-count', 'count per 1 s bucket')}
  </div>`);
}

function legend() {
  const widths = [1, 10, 100, 1e3, 1e4, 1e5].map((r) => widthSwatch(logWidth(r, 1, RATE_DECADES), fmtRate(r))).join('');
  return `<div class="flow-legend">
    <div><span class="meta">colour: consumer handler p50</span> <span class="ramp">100ns ${colourRamp()} 10ms</span> <span class="meta">grey: no traffic · hover an edge for its queue, click for its timings</span></div>
    <div><span class="meta">width: msgs/s</span> ${widths}</div>
    <div class="meta">One edge per producer → consumer pair and message type, from flux's per-pair timers.</div>
  </div>`;
}

/** Selection key of a clicked queue edge: its timer name. */
export function selectKey(target) {
  return target.closest('.flow [data-timer]')?.dataset.timer ?? null;
}

export function graph(inst, utils, ui, specs) {
  const { latest, histories } = timers(inst);
  const { edges, selfs } = layoutEdges(latest);
  const { paths, labels } = drawEdges(edges, utils, ui.hover, ui.selected);
  const notes = new Map();
  for (const s of selfs) {
    const line = `self: ${s.queue} ${fmtRate(s.rate)}, handler p50 ${fmtNs(s.processing?.p50Ns)}`;
    notes.set(s.toName, [...(notes.get(s.toName) ?? []), line]);
  }
  const selected = ui.selected && edges.find((e) => e.timer === ui.selected);
  return { paths, labels, notes, detail: edgeDetail(selected, histories, specs), legend: legend() };
}
