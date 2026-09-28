import { escape, fixed, fmtSecs, instanceTabs, shortId } from './view.js';

const dash = '·';
const num = (v) => (v === null || v === undefined ? dash : String(v));

// [header, sort key, cell]. Rows missing a side sort as absent.
const COLUMNS = [
  ['conn', (r) => r.p2p?.connection, (r) => (r.p2p ? `${r.p2p.connection}${r.p2p.inbound ? ' ✓' : ''}` : dash)],
  ['peer', (r) => r.id, (r) => shortId(r.id)],
  ['addr', (r) => r.p2p?.addr, (r) => escape(r.p2p?.addr ?? dash)],
  ['age', (r) => r.p2p?.connectedMs, (r) => (r.p2p ? fmtSecs(r.p2p.connectedMs / 1000) : dash)],
  ['rtt', (r) => r.p2p?.rttUs, (r) => (r.p2p ? `${(r.p2p.rttUs / 1000).toFixed(1)}ms` : dash)],
  ['lost', (r) => r.p2p?.lostPackets, (r) => num(r.p2p?.lostPackets)],
  ['rxdg', (r) => r.p2p?.rxDatagrams, (r) => num(r.p2p?.rxDatagrams)],
  ['txdg', (r) => r.p2p?.txDatagrams, (r) => num(r.p2p?.txDatagrams)],
  ['mesh', (r) => r.scores?.meshCount, (r) => num(r.scores?.meshCount)],
  ...['p1', 'p2', 'p3', 'p3b', 'p4', 'p5', 'p6', 'p7'].map((name, i) => [
    name,
    (r) => r.scores?.p[i],
    (r) => fixed(r.scores?.p[i]),
  ]),
  ['total', (r) => r.scores?.total, (r) => fixed(r.scores?.total)],
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

  const head = COLUMNS.map(([name], i) => {
    const arrow = i === ui.sort ? (ui.desc ? ' ▼' : ' ▲') : '';
    const cls = i >= SCORE_FROM ? 'score' : '';
    return `<th class="${cls}" data-sort="${i}">${name}${arrow}</th>`;
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
