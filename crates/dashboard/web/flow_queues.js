// Spine-queue mode of the Flow pane. One line per direction between two
// tiles; each spot on it is one producer → consumer pair of one message type,
// read from flux's lazily created per-pair timers
// `{Consumer}-{Producer}-{MessageType}`.

import { SourceClass, TimingChannel } from './wire.js';
import { escape } from './view.js';
import {
  BS, COLOUR_STEPS, CTL, DC, IO, NET, NO_BUCKETS, TILES, chartSlot, colourRamp, detailPanel,
  drawTrunks, fmtNs, fmtRate, logWidth, spotRadius, widthSwatch,
} from './flow_layout.js';

/** Width spans 1/s … 100k/s. */
const RATE_DECADES = 5;

// [queue, message type, producers, consumers]. Mirrors the queue table in
// docs/spine-message-flow.md; update both together. Every consumer of a
// broadcast queue reads every producer's messages, so the cross product is
// the expected pair set: drawn grey until its timer reports traffic.
// `engine_health` and `peer_stats` have no in-process consumer. Storage and
// ApplicationBoundary run as one IoTile, so traffic between them is
// self-consumption: listed on the node, not drawn.
const QUEUES = [
  ['gossip_in', 'GossipMsgIn', [NET], [CTL]],
  ['new_gossip', 'NewGossipMsg', [CTL], [BS, DC]],
  ['p2p_send', 'P2pSend', [CTL, IO], [NET]],
  ['rpc_inbound', 'RpcInbound', [NET], [CTL, BS, DC, IO]],
  ['cluster_inbound', 'ClusterIn', [NET], [CTL]],
  ['cluster_outbound', 'ClusterMsgOut', [CTL], [NET]],
  ['beacon_api_requests', 'BeaconApiRequest', [IO], [CTL, BS, IO]],
  ['beacon_api_responses', 'BeaconApiResponse', [CTL, BS, IO], [IO]],
  ['peer_events', 'PeerEvent', [NET, CTL, BS, DC, IO], [CTL, IO]],
  ['peer_control', 'PeerControl', [CTL], [NET, IO]],
  ['beacon_events', 'BeaconStateEvent', [BS], [CTL, NET, IO, DC]],
  ['data_columns', 'DataColumnsEvent', [DC], [CTL, BS, IO]],
  ['retention', 'RetentionEvent', [CTL], [DC]],
  ['cells', 'CellStoreEvent', [CTL, DC], [CTL, DC]],
  ['sync_target', 'SyncUpdate', [CTL], [BS, DC, IO]],
  ['sync_needs', 'SyncNeed', [CTL, BS, DC, IO], [CTL]],
  ['replay_blocks', 'ReplayBlock', [IO], [BS]],
  ['syncing_strategy', 'SyncingStrategy', [CTL], [IO]],
  ['engine_reqs', 'EngineReq', [BS, DC], [IO]],
  ['engine_resps', 'EngineResp', [IO], [BS, DC, IO]],
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

const rateWidth = (rate) => logWidth(rate, 1, RATE_DECADES);

/** A spot per pair: coloured by handler p50, sized by msgs/s. Hovering a
 *  queue labels each of its spots; the selected spot's label stays shown. */
function drawEdges(edges, utils, hovered, selected, split) {
  const items = edges.map((e) => {
    const step = e.rate > 0 ? handlerStep(e.processing?.p50Ns) : null;
    const isSel = Boolean(e.timer) && e.timer === selected;
    const timer = e.timer ? ` data-timer="${escape(e.timer)}"` : '';
    return {
      fromName: e.fromName,
      toName: e.toName,
      rate: e.rate,
      counted: true,
      fill: step === null ? 'qf-idle' : `qf${step}`,
      r: spotRadius(step === null ? 0 : rateWidth(e.rate)),
      show: e.queue === hovered,
      mark: isSel ? 'selected' : '',
      attrs: `data-q="${e.queue}"${timer}`,
      title: edgeTitle(e, utils),
      label: `${e.queue} ${e.rate ? fmtRate(e.rate) : 'idle'}`,
      pinned: isSel,
    };
  });
  return drawTrunks(items, rateWidth, split);
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
  const widths = [1, 10, 100, 1e3, 1e4, 1e5].map((r) => widthSwatch(rateWidth(r), fmtRate(r))).join('');
  return `<div class="flow-legend">
    <div><span class="meta">spot colour: consumer handler p50</span> <span class="ramp">100ns ${colourRamp()} 10ms</span> <span class="meta">grey: no traffic · hover a spot for its queue, click for its timings · hover a line to split it per queue</span></div>
    <div><span class="meta">line width and orange shade: total msgs/s · spot size: its msgs/s, same scale</span> ${widths}</div>
    <div class="meta">One line per direction between two tiles; one spot per producer → consumer pair and message type on it, from flux's per-pair timers.</div>
  </div>`;
}

/** Selection key of a clicked queue edge: its timer name. */
export function selectKey(target) {
  return target.closest('.flow [data-timer]')?.dataset.timer ?? null;
}

export function graph(inst, utils, ui, specs) {
  const { latest, histories } = timers(inst);
  const { edges, selfs } = layoutEdges(latest);
  const { paths, labels } = drawEdges(edges, utils, ui.hover, ui.selected, ui.trunk);
  const notes = new Map();
  for (const s of selfs) {
    const line = `self: ${s.queue} ${fmtRate(s.rate)}, handler p50 ${fmtNs(s.processing?.p50Ns)}`;
    notes.set(s.toName, [...(notes.get(s.toName) ?? []), line]);
  }
  const selected = ui.selected && edges.find((e) => e.timer === ui.selected);
  return { paths, labels, notes, detail: edgeDetail(selected, histories, specs), legend: legend() };
}
