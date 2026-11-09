// The cluster as a graph: one circle per node, one arrow per Raft link as
// the sending node reports it.

import { fmtUs } from './cluster_model.js';
import { escape, fmtSecs } from './view.js';

const W = 620;
const H = 400;
const NODE_R = 9;
/** Room outside the ring for each node's floating name. */
const LABEL_ROOM = 70;
const BEND = 12;
const ATTACH = NODE_R + 15;
const SPREAD = (12 * Math.PI) / 180;
const RTT_WARN_US = 20e3;
const RTT_BAD_US = 100e3;
const QUEUE_WARN = 64;
const LEVEL_COLOUR = { ok: 'var(--ok)', warn: 'var(--c-warn)', bad: 'var(--bad)' };

function points(list) {
  return list.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
}

function star(x, y, r) {
  return Array.from({ length: 10 }, (_, i) => {
    const a = -Math.PI / 2 + (Math.PI * i) / 5;
    const radius = i % 2 ? r * 0.5 : r * 1.4;
    return [x + radius * Math.cos(a), y + radius * Math.sin(a)];
  });
}

function triangle(x, y, r) {
  return [0, 1, 2].map((i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / 3;
    return [x + r * 1.2 * Math.cos(a), y + r * 1.2 * Math.sin(a)];
  });
}

/** The leader is a star, every follower a triangle. */
function nodeShape(leads, x, y, colour) {
  return `<polygon class="shape" points="${points(leads ? star(x, y, NODE_R) : triangle(x, y, NODE_R))}" style="fill:${colour}"/>`;
}

function positions(count) {
  if (count === 1) return [[W / 2, H / 2]];
  const r = Math.min(W, H) / 2 - LABEL_ROOM;
  return Array.from({ length: count }, (_, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / count;
    return [W / 2 + r * Math.cos(a), H / 2 + r * Math.sin(a)];
  });
}

function overwritesGrew(node, nodeId) {
  const history = node.peerHistory(nodeId).filter((r) => r.link);
  return history.length > 1 && history.at(-1).link.overwrites > history[0].link.overwrites;
}

function linkHealth(node, peer) {
  const link = peer.link;
  const rtt = peer.raftRttUs ?? (link?.connected ? link.rttUs : null);
  const reasons = [];
  let lvl = 'ok';
  const raise = (to, why) => {
    reasons.push(why);
    if (to === 'bad' || lvl === 'ok') lvl = to;
  };
  if (!link) raise('warn', 'no link sample yet');
  else if (!link.connected) raise('bad', 'disconnected');
  if (link && overwritesGrew(node, peer.nodeId)) raise('bad', 'cluster stream evicted messages');
  if (rtt !== null && rtt >= RTT_BAD_US) raise('bad', `round trip ${fmtUs(rtt)}`);
  else if (rtt !== null && rtt >= RTT_WARN_US) raise('warn', `round trip ${fmtUs(rtt)}`);
  if (link && link.outQueueLen >= QUEUE_WARN) raise('warn', `queue ${link.outQueueLen}/128`);
  return { lvl, rtt, reasons };
}

function edge(node, peer, from, to, leads, hovered) {
  const [x1, y1] = from;
  const [x2, y2] = to;
  const a = Math.atan2(y2 - y1, x2 - x1);
  // Each arrow leaves and arrives SPREAD to one side of the straight line, so
  // the pair between two nodes never meets at either end.
  const sx = x1 + ATTACH * Math.cos(a - SPREAD);
  const sy = y1 + ATTACH * Math.sin(a - SPREAD);
  const ex = x2 + (ATTACH + 2) * Math.cos(a + Math.PI + SPREAD);
  const ey = y2 + (ATTACH + 2) * Math.sin(a + Math.PI + SPREAD);
  const cx = (sx + ex) / 2 + Math.sin(a) * BEND;
  const cy = (sy + ey) / 2 - Math.cos(a) * BEND;
  const { lvl } = linkHealth(node, peer);
  const key = linkKey(node, peer);
  return `<g class="edge ${lvl}${key === hovered ? ' hl' : ''}" data-link="${key}">
    <path class="hit" d="M${sx},${sy} Q${cx},${cy} ${ex},${ey}"/>
    <path d="M${sx},${sy} Q${cx},${cy} ${ex},${ey}" style="stroke:${LEVEL_COLOUR[lvl]}" marker-end="url(#ct-arrow-${lvl})"/></g>`;
}

/** Names one Raft link as its sending node reports it, shared by the edge and
 *  its Raft peers row. */
export function linkKey(node, peer) {
  return `${node.nodeId ?? `i${node.index}`}-${peer.nodeId}`;
}

export function topology(nodes, hovered) {
  const placed = nodes.filter((n) => n.nodeId !== null);
  if (!placed.length) return '<p class="empty">waiting for Raft peer records to identify the nodes</p>';
  const at = new Map(placed.map((n, i) => [n.nodeId, positions(placed.length)[i]]));
  const markers = Object.entries(LEVEL_COLOUR)
    .map(([lvl, colour]) => `<marker id="ct-arrow-${lvl}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" style="fill:${colour}"/></marker>`)
    .join('');
  const edges = placed.filter((node) => node.silentSecs === null).flatMap((node) => {
    const leads = node.value('Role') === 2;
    return node
      .peers()
      .filter((p) => at.has(p.nodeId))
      .map((p) => edge(node, p, at.get(node.nodeId), at.get(p.nodeId), leads, hovered));
  });
  const shapes = placed.map((node) => {
    const [x, y] = at.get(node.nodeId);
    const silent = node.silentSecs;
    const leads = silent === null && node.value('Role') === 2;
    const title = silent !== null
      ? `${node.label}, raft id ${node.nodeId}: no data for ${fmtSecs(silent)}, telemetry not reporting`
      : `${node.label}, raft id ${node.nodeId}, ${leads ? 'leader' : 'follower'}, term ${node.value('Term')}`;
    const [dx, dy] = [x - W / 2, y - H / 2];
    const len = Math.hypot(dx, dy) || 1;
    const lx = x + (dx / len) * (NODE_R + 10);
    const ly = y + (dy / len) * (NODE_R + 10) + (dy > 0 ? 10 : dy < 0 ? -8 : 0);
    const anchor = Math.abs(dx) < len / 3 ? 'middle' : dx > 0 ? 'start' : 'end';
    return `<g class="tnode"><title>${escape(title)}</title>
      ${nodeShape(leads, x, y, silent === null ? node.colour : 'var(--idle)')}
      <text x="${lx}" y="${ly}" text-anchor="${anchor}">${escape(node.label)}</text>
      <text x="${lx}" y="${ly + 13}" text-anchor="${anchor}" class="sub">id ${node.nodeId}${silent === null ? '' : ' · no data'}</text></g>`;
  });
  return `<svg class="ctopo" viewBox="0 0 ${W} ${H}" role="img"><defs>${markers}</defs>${edges.join('')}${shapes.join('')}</svg>
    <p class="meta"><span class="ok">■</span> healthy <span class="warn">■</span> slow or queueing <span class="bad">■</span> down or losing messages · ★ leader, ▲ follower, grey: no data · hover a link for its numbers in Raft peers</p>`;
}
