// Point-in-time cluster state: status tiles and the peer table.

import { ROLES, fmtUs } from './cluster_model.js';
import { escape } from './view.js';
import { linkKey } from './cluster_topology.js';
import { CLUSTER_PROGRESS } from './wire.js';

const dash = '·';

function cell(label, value, level, title) {
  return { label, value, level, title };
}

function nodeCells(node) {
  const role = ROLES[node.value('Role')] ?? '?';
  const leader = node.value('LeaderId');
  const term = node.value('Term');
  const latched = node.value('FloorLatched') === 1;
  const failed = node.value('Failed') === 1;
  const conflicts =
    node.windowTotal('AttestationLockConflicting') +
    node.windowTotal('AttestationLockSurrounding') +
    node.windowTotal('BlockLockConflicting');
  return [
    cell('role', role, role === 'leader' ? 'ok' : role === 'candidate' ? 'warn' : 'info',
      'This node\'s Raft role. One leader per cluster; a candidate is mid-election.'),
    cell('leader · term', leader ? `${leader} · ${term}` : `none · ${term ?? dash}`, leader ? 'info' : 'bad',
      'The leader this node follows and the current term. A rising term means elections.'),
    cell('duties from slot', latched ? String(node.value('StartupFloorSlot')) : 'refusing', latched ? 'ok' : 'warn',
      'The startup floor. After a restart the node cannot know what it signed before, so it refuses every duty until it is synced, then accepts only slots from this one on. "refusing" means it has not latched yet.'),
    cell('raft', failed ? 'FAILED' : 'running', failed ? 'bad' : 'ok',
      'Failed means Raft processing stopped after an error; the node refuses all duties.'),
    cell('conflicts', String(conflicts), conflicts ? 'bad' : 'ok',
      'Conflicting or surrounding attestation locks and conflicting block locks in the last 4 minutes. Any nonzero value means two signers exist.'),
  ];
}

/** One row per node, one column per metric. */
export function statusTiles(nodes) {
  const rows = nodes.map((node) => ({ node, cells: nodeCells(node) }));
  const head = rows[0].cells
    .map((c) => `<th title="${escape(c.title)}">${escape(c.label)}</th>`)
    .join('');
  const body = rows
    .map(({ node, cells }) => {
      const name = `<th style="color:${node.colour}">${escape(node.label)}${node.nodeId ? ` <span class="meta">raft ${node.nodeId}</span>` : ''}</th>`;
      const tds = cells.map((c) => `<td class="hcell ${c.level}" title="${escape(c.title)}">${escape(c.value)}</td>`);
      return `<tr>${name}${tds.join('')}</tr>`;
    })
    .join('');
  return `<section><table class="health"><thead><tr><th>node</th>${head}</tr></thead><tbody>${body}</tbody></table></section>`;
}

function lastSlotValue(bySlot) {
  const slots = [...bySlot.keys()].sort((a, b) => a - b);
  return slots.length > 1 ? bySlot.get(slots.at(-2)) : null;
}

const PEER_COLUMNS = [
  ['from → peer', 'The reporting node and the voter its row describes. L marks the leader.'],
  ['link', 'QUIC connection to the peer, and its round trip.'],
  ['raft rtt', 'Heartbeat → response round trip, measured by the leader only. Includes the peer\'s loop stalls.'],
  ['last heard', 'Time since this node last received any Raft message from the peer.'],
  ['replication', 'Leader only: the peer\'s state and how many log entries it lags behind the leader.'],
  ['in flight', 'Leader only: appends sent and not yet acknowledged.'],
  ['msgs/slot out · in', 'Raft messages to and from the peer in the last complete slot.'],
  ['queue', 'Messages waiting in the cluster stream to the peer, out of 128.'],
  ['evicted', 'Messages the full cluster stream dropped, oldest first, since start. Any growth means lost Raft messages.'],
];

/** One row per Raft link as its sending node reports it. */
export function peerTable(nodes, hovered) {
  const rows = nodes.flatMap((node) =>
    node.peers().map((p) => {
      const link = p.link;
      const replicating = p.progress !== 0;
      const progress = CLUSTER_PROGRESS[p.progress] ?? '?';
      const lag = (node.value('LastIndex') ?? 0) - p.matchIndex;
      const out = lastSlotValue(node.peerPerSlot(p.nodeId, 'messagesOut'));
      const inn = lastSlotValue(node.peerPerSlot(p.nodeId, 'messagesIn'));
      const indexes = `replicated up to entry ${p.matchIndex}, next to send ${p.nextIndex}`;
      const cells = [
        `<span style="color:${node.colour}">${escape(node.label)}</span> → ${p.nodeId}${p.isLeader ? ' L' : ''}`,
        !link ? dash : link.connected ? `<span class="ok">✓</span> ${fmtUs(link.rttUs)}` : '<span class="bad">✗</span>',
        fmtUs(p.raftRttUs),
        fmtUs(p.lastContactUs),
        replicating
          ? `<span class="${progress === 'replicate' ? 'ok' : 'bad'}" title="${escape(indexes)}">${progress} · lag ${lag}</span>`
          : dash,
        replicating ? String(p.inflight) : dash,
        `${out ?? dash} · ${inn ?? dash}`,
        link ? String(link.outQueueLen) : dash,
        link ? `<span class="${link.overwrites ? 'bad' : ''}">${link.overwrites}</span>` : dash,
      ];
      const key = linkKey(node, p);
      return `<tr data-link="${key}"${key === hovered ? ' class="hl"' : ''}>${cells.map((c) => `<td>${c}</td>`).join('')}</tr>`;
    }),
  );
  const key = PEER_COLUMNS.slice(1).map(([h, t]) => `<b>${h}</b>: ${escape(t)}`).join('<br>');
  return `<section><table class="cpeers">
    <thead><tr>${PEER_COLUMNS.map(([h, t]) => `<th title="${escape(t)}">${h}</th>`).join('')}</tr></thead>
    <tbody>${rows.join('') || `<tr><td colspan="${PEER_COLUMNS.length}" class="empty">no Raft peer records yet</td></tr>`}</tbody>
  </table></section><p class="meta cpeers-key">${key}</p>`;
}
