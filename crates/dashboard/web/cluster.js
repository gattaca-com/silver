// The Cluster tab: the slashing-protection Raft cluster across the fleet's
// clustered instances, one titled section per view.

import { LineCharts } from './chart.js';
import * as charts from './cluster_charts.js';
import { peerTable, statusTiles } from './cluster_health.js';
import { stageBars } from './cluster_latency.js';
import { clusterNodes, windowSlots } from './cluster_model.js';
import { leaderTimeline } from './cluster_leader.js';
import { topology } from './cluster_topology.js';
import { escape } from './view.js';

const BAR_SLOTS = 20;

function section(title, caption, body, cls = '') {
  return `<div class="csection ${cls}"><h2>${escape(title)}</h2><p class="caption">${escape(caption)}</p>${body}</div>`;
}

const row = (...sections) => `<div class="cluster-pair">${sections.join('')}</div>`;
const evenRow = (...sections) => `<div class="cluster-pair even">${sections.join('')}</div>`;

function chart(specs, key, spec, title) {
  specs.set(key, spec);
  return `<div><p class="meta">${escape(title)}</p><div class="chart" data-chart="${key}"></div></div>`;
}

export function available(fleet) {
  return clusterNodes(fleet).length > 0;
}

export function render(fleet, root, _now, ui) {
  const nodes = clusterNodes(fleet);
  if (!nodes.length) {
    root.innerHTML = '<p class="empty">no instance exports the cluster counters</p>';
    return;
  }
  ui.charts ??= new LineCharts();
  const specs = new Map();
  const slots = windowSlots(nodes, BAR_SLOTS);

  const latency = section('Clustering latency', 'p99 per second, per node: Control receiving a signed attestation or block until its lock is released for validation. Nearly all of it is the Raft commit. A commit taking 500 ms times out and the duty fails.',
    chart(specs, 'cl-latency', charts.latency(nodes), 'p99 per second; the commit timeout is 500 ms'));
  const locks = section('Locks per slot', 'Bands: proposals per slot, stacked by the node the validator client sent them to. Line: the locks they took; the rest were byte-identical repeats. Right axis: refusals, which stay at 0 with a single signer.',
    chart(specs, 'cl-locks', charts.locks(nodes), 'proposals, locks taken and refusals per slot'));
  const peers = section('Raft peers', 'Every link as its sending node reports it. Hover a row to find its arrow in Topology, or an arrow to find its row here.',
    peerTable(nodes, ui.link));
  const traffic = section('Raft traffic', 'Messages each node sent to each peer per slot. A node\'s second peer is dashed.',
    chart(specs, 'cl-msgs', charts.messages(nodes), 'messages per slot, node → peer'));

  root.innerHTML = [
    `<div class="ccols">
      <div class="ccol">${[
        section('Health', 'One row per node. Green is healthy, amber needs watching, red needs action. Window: the last 4 minutes. Hover a column header for what it means.',
          statusTiles(nodes)),
        section('Leader over time', 'Which node led the cluster over the last 4 minutes, coloured by node. Healthy: one colour, no red.', leaderTimeline(nodes)),
        peers,
      ].join('')}</div>
      <div class="ccol">${[
        section('Topology', 'Who leads and how each Raft link is doing, as the sending node reports it. Healthy: every arrow green.',
          topology(nodes, ui.link)),
        latency,
      ].join('')}</div>
    </div>`,
    section('Where commit time goes',
      `Mean of each stage per slot, per node, over the last ${BAR_SLOTS} slots. Append is the hop to and from the leader (about 0 on the leader), persist the journal write, quorum the wait for other nodes. Hover a coloured segment for its value.`,
      stageBars(nodes, slots, ui.tip)),
    evenRow(locks, traffic),
  ].join('');
  ui.charts.mount(root, specs);
}

/** A hovered Raft link lights its arrow and its peer row together; a hovered
 *  commit-time segment shows its value in the readout. Both are kept in `ui`
 *  because every render replaces the elements. */
export function hover(target, ui, root) {
  const link = target.closest?.('[data-link]')?.dataset.link ?? null;
  if (link !== ui.link) {
    ui.link = link;
    for (const el of root.querySelectorAll('[data-link]')) el.classList.toggle('hl', el.dataset.link === link);
  }
  const tip = target.closest?.('[data-tip]')?.dataset.tip;
  if (tip !== undefined && tip !== ui.tip) {
    ui.tip = tip;
    const readout = root.querySelector('.ctip');
    if (readout) readout.textContent = tip;
  }
}
