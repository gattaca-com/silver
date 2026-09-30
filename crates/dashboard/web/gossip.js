import { escape, fixed, fmtSecs, instanceTabs, shortId } from './view.js';

/** Slots per topic in `gossip_topics`: sent, recv, mesh, subs. */
const PER_TOPIC = 4;
const dash = '·';

function median(values) {
  if (!values.length) return null;
  values.sort((a, b) => a - b);
  const mid = values.length >> 1;
  return values.length % 2 ? values[mid] : (values[mid - 1] + values[mid]) / 2;
}

function fwd(total, sent) {
  return total ? `${Math.round((sent * 100) / total)}%` : dash;
}

function memberRow(m) {
  const t = m.topic;
  return `<tr class="sub open">
    <td>└ ${shortId(m.id)} ${escape(m.agent)}</td>
    <td>${m.conn ?? dash}</td><td></td><td></td><td></td>
    <td>${!t.p3Scored ? '—' : t.meshActive ? 'act' : 'grace'}</td>
    <td class="num">${fmtSecs(t.meshedSecs)}</td>
    <td class="num">${fixed(t.firstDeliveries)}</td>
    <td class="num">${fixed(t.meshDeliveries)}</td>
    <td class="num">${fixed(t.meshFailurePenalty)}</td>
    <td class="num">${fixed(t.invalidDeliveries)}</td>
    <td class="num">${fwd(t.fanoutTotal, t.fanoutSent)}</td>
  </tr>`;
}

export function render(fleet, root, now, ui) {
  const { inst, html: tabs } = instanceTabs(fleet, ui.instance, now);
  if (!inst) {
    root.innerHTML = '<p class="empty">no instances yet</p>';
    return;
  }
  ui.expanded ??= new Set();

  const meshed = new Map();
  for (const [id, p] of inst.livePeers()) {
    for (const t of p.topics.values()) {
      let members = meshed.get(t.topicSlot);
      if (!members) meshed.set(t.topicSlot, (members = []));
      members.push({ id, conn: p.p2p?.connection, agent: p.scores?.agent ?? '', topic: t });
    }
  }

  // Topics with any signal: meshed peers, or a live mesh/subs gauge, which
  // also catches subscribed-but-unmeshed topics peer stats cannot see.
  const source = inst.sourceNamed('gossip_topics');
  const gauges = source === null ? null : inst.counters.get(source)?.values;
  const topicSlots = new Set(meshed.keys());
  for (let s = 0; gauges && s * PER_TOPIC < gauges.length; s++) {
    if (gauges[s * PER_TOPIC + 2] || gauges[s * PER_TOPIC + 3]) topicSlots.add(s);
  }

  const rate = (i) => {
    const r = source === null ? null : inst.rate(source, i);
    return r === null ? dash : r.toFixed(1);
  };
  const rows = [...topicSlots]
    .sort((a, b) => a - b)
    .map((slot) => {
      const base = slot * PER_TOPIC;
      const members = meshed.get(slot) ?? [];
      const scored = members[0]?.topic.p3Scored;
      const sum = (f) => members.reduce((acc, m) => acc + f(m.topic), 0);
      const open = ui.expanded.has(slot);
      const detail = open
        ? members
            .slice()
            .sort((a, b) => b.topic.firstDeliveries - a.topic.firstDeliveries)
            .map(memberRow)
            .join('')
        : '';
      const agg = members.length
        ? `<td>${scored ? members.filter((m) => m.topic.meshActive).length : '—'}</td>
           <td class="num">${fmtSecs(median(members.map((m) => m.topic.meshedSecs)))}</td>
           <td class="num">${fixed(median(members.map((m) => m.topic.firstDeliveries)))}</td>
           <td class="num">${fixed(median(members.map((m) => m.topic.meshDeliveries)))}</td>
           <td class="num">${fixed(sum((t) => t.meshFailurePenalty))}</td>
           <td class="num">${fixed(sum((t) => t.invalidDeliveries))}</td>
           <td class="num">${fwd(sum((t) => t.fanoutTotal), sum((t) => t.fanoutSent))}</td>`
        : '<td></td>'.repeat(7);
      return `<tr class="row${open ? ' open' : ''}" data-topic="${slot}">
        <td>${escape(inst.topicName(slot))}</td>
        <td class="num">${gauges?.[base + 2] ?? dash}</td>
        <td class="num">${gauges?.[base + 3] ?? dash}</td>
        <td class="num">${rate(base + 1)}</td>
        <td class="num">${rate(base)}</td>
        ${agg}
      </tr>${detail}`;
    })
    .join('');

  root.innerHTML = `${tabs}
    <section><table class="dense">
      <thead><tr>
        <th>topic</th><th class="num">mesh</th><th class="num">subs</th>
        <th class="num">rx/s</th><th class="num">tx/s</th><th>act</th>
        <th class="num">age</th><th class="num">fd</th><th class="num">md</th>
        <th class="num">p3b</th><th class="num">p4</th><th class="num">fwd</th>
      </tr></thead>
      <tbody>${rows || '<tr><td colspan="12" class="empty">no gossip topics yet</td></tr>'}</tbody>
    </table></section>`;
}

export function click(target, ui) {
  const row = target.closest('[data-topic]');
  if (!row) return;
  const slot = Number(row.dataset.topic);
  if (!ui.expanded.delete(slot)) ui.expanded.add(slot);
}
