import { escape, fixed, fmtSecs, instanceTabs, shortId } from './view.js';

const dash = '·';
const num = (v) => (v === null || v === undefined ? dash : String(v));

const SCORE_HINTS = [
  ['p1', 'Time in mesh: reward per meshed topic, growing linearly with tenure up to a cap.'],
  ['p2', 'First deliveries: reward for being first to deliver a message. Capped and weighted per topic class; decays.\nTopic row: raw decayed count.'],
  ['p3', 'Mesh delivery deficit: penalty, squared shortfall below the topic class delivery threshold. Starts one grace window after graft.\nTopic row: raw decayed mesh deliveries.'],
  ['p3b', 'Mesh failure: P3 deficit carried forward after the peer left a mesh; decays.'],
  ['p4', 'Invalid messages: penalty, squared count of invalid messages delivered; decays slowly.'],
  ['p5', 'Application score: RPC misbehaviour penalties (timeouts, premature closes); decays toward zero.\nTopic row: share of our fanout publishes sent to this peer.'],
  ['p6', 'IP colocation: penalty, squared count of connected peers sharing this /24 (v4) or /64 (v6) above the threshold.'],
  ['p7', 'Behaviour penalty: protocol misbehaviour (e.g. broken IWANT promises), squared excess over a free budget; decays.'],
];

// [header, sort key, cell, header tooltip]. Rows missing a side sort as absent.
const COLUMNS = [
  ['conn', (r) => r.p2p?.connection, (r) => (r.p2p ? `${r.p2p.connection}${r.p2p.inbound ? ' ✓' : ''}` : dash)],
  ['peer', (r) => r.id, (r) => shortId(r.id)],
  ['addr', (r) => r.p2p?.addr, (r) => escape(r.p2p?.addr ?? dash)],
  ['age', (r) => r.p2p?.connectedMs, (r) => (r.p2p ? fmtSecs(r.p2p.connectedMs / 1000) : dash)],
  ['rtt', (r) => r.p2p?.rttUs, (r) => (r.p2p ? `${(r.p2p.rttUs / 1000).toFixed(1)}ms` : dash)],
  ['lost', (r) => r.p2p?.lostPackets, (r) => num(r.p2p?.lostPackets)],
  ['rxdg', (r) => r.p2p?.rxDatagrams, (r) => num(r.p2p?.rxDatagrams)],
  ['txdg', (r) => r.p2p?.txDatagrams, (r) => num(r.p2p?.txDatagrams)],
  [
    'mesh',
    (r) => r.scores?.meshCount,
    (r) => num(r.scores?.meshCount),
    'Topic meshes this peer is in.\nTopic row: act = P3 scoring active, grace = within the post-graft grace window, — = topic not delivery-scored.',
  ],
  ...SCORE_HINTS.map(([name, hint], i) => [name, (r) => r.scores?.p[i], (r) => fixed(r.scores?.p[i]), hint]),
  [
    'total',
    (r) => r.scores?.total,
    (r) => fixed(r.scores?.total),
    'Sum of P1–P7. Below the gossip threshold we ignore its IHAVE/IWANT; below publish we stop publishing to it; below graylist it is banned.',
  ],
  ['agent', (r) => r.scores?.agent, (r) => escape(r.scores?.agent ?? dash)],
];
const SCORE_FROM = COLUMNS.findIndex(([name]) => name === 'mesh');
const DEFAULT_SORT = SCORE_FROM;

function compare(a, b) {
  if (a === b) return 0;
  if (a === undefined || a === null) return -1;
  if (b === undefined || b === null) return 1;
  return typeof a === 'string' ? a.localeCompare(b) : a - b;
}

/** Laid out under the peer columns it relates to: meshed time under age,
 *  P3 state under mesh,
 *  delivery counters under p2..p4, forward ratio under p5. */
function topicRow(inst, t) {
  const cells = new Array(COLUMNS.length).fill('');
  const col = (name) => COLUMNS.findIndex(([n]) => n === name);
  cells[col('addr')] = `└ ${escape(inst.topicName(t.topicSlot))}`;
  cells[col('age')] = fmtSecs(t.meshedSecs);
  cells[col('mesh')] = !t.p3Scored ? '—' : t.meshActive ? 'act' : 'grace';
  cells[col('p2')] = fixed(t.firstDeliveries);
  cells[col('p3')] = fixed(t.meshDeliveries);
  cells[col('p3b')] = fixed(t.meshFailurePenalty);
  cells[col('p4')] = fixed(t.invalidDeliveries);
  cells[col('p5')] = t.fanoutTotal ? `${Math.round((t.fanoutSent * 100) / t.fanoutTotal)}%` : dash;
  return `<tr class="sub open">${cells.map((c) => `<td>${c}</td>`).join('')}</tr>`;
}

function agents(rows) {
  const counts = new Map();
  for (const r of rows) {
    const client = (r.scores?.agent || 'unknown').split('/')[0];
    counts.set(client, (counts.get(client) ?? 0) + 1);
  }
  return [...counts]
    .sort((a, b) => b[1] - a[1])
    .map(([c, n]) => `<span class="badge">${escape(c)} ${n}</span>`)
    .join('');
}

export function render(fleet, root, now, ui) {
  const { inst, html: tabs } = instanceTabs(fleet, ui.instance, now);
  if (!inst) {
    root.innerHTML = '<p class="empty">no instances yet</p>';
    return;
  }
  ui.sort ??= DEFAULT_SORT;
  ui.desc ??= true;
  ui.expanded ??= new Set();

  const rows = [...inst.livePeers()].map(([id, p]) => ({ id, ...p }));
  const key = COLUMNS[ui.sort][1];
  rows.sort((a, b) => compare(key(a), key(b)) * (ui.desc ? -1 : 1));

  const head = COLUMNS.map(([name, , , hint], i) => {
    const arrow = i === ui.sort ? (ui.desc ? ' ▼' : ' ▲') : '';
    const cls = i >= SCORE_FROM ? 'score' : '';
    const title = hint ? ` title="${escape(hint)}"` : '';
    return `<th class="${cls}" data-sort="${i}"${title}>${name}${arrow}</th>`;
  }).join('');
  const body = rows
    .map((r) => {
      const open = ui.expanded.has(r.id);
      const cells = COLUMNS.map(([, , cell], i) => `<td class="${i >= SCORE_FROM ? 'score' : ''}">${cell(r)}</td>`);
      const topics = open
        ? [...r.topics.values()]
            .sort((a, b) => inst.topicName(a.topicSlot).localeCompare(inst.topicName(b.topicSlot)))
            .map((t) => topicRow(inst, t))
            .join('')
        : '';
      return `<tr class="row${open ? ' open' : ''}" data-peer="${r.id}">${cells.join('')}</tr>${topics}`;
    })
    .join('');

  root.innerHTML = `${tabs}
    <p class="summary">${rows.length} peers ${agents(rows)}</p>
    <section><table class="dense">
      <thead><tr>${head}</tr></thead>
      <tbody>${body || `<tr><td colspan="${COLUMNS.length}" class="empty">no peer stats yet</td></tr>`}</tbody>
    </table></section>`;
}

export function click(target, ui) {
  const th = target.closest('[data-sort]');
  if (th) {
    const col = Number(th.dataset.sort);
    ui.desc = col === ui.sort ? !ui.desc : true;
    ui.sort = col;
    return;
  }
  const row = target.closest('[data-peer]');
  if (row) {
    const id = row.dataset.peer;
    if (!ui.expanded.delete(id)) ui.expanded.add(id);
  }
}
