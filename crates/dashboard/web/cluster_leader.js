// The leader timeline: which node led the cluster each second.

import { escape } from './view.js';

function runs(ts, ys) {
  const out = [];
  ts.forEach((t, k) => {
    const v = ys[k];
    if (v === null || v === undefined) return;
    const last = out.at(-1);
    if (last && last.v === v) last.end = ts[k + 1] ?? t + 1;
    else out.push({ v, start: t, end: ts[k + 1] ?? t + 1 });
  });
  return out;
}

/** The leader most nodes report each second; red where none reports one. */
export function leaderTimeline(nodes) {
  const byId = new Map(nodes.filter((n) => n.nodeId !== null).map((n) => [n.nodeId, n]));
  const votes = new Map();
  for (const node of nodes) {
    const { ts, ys } = node.series('LeaderId');
    ts.forEach((t, k) => {
      if (ys[k] === null || ys[k] === undefined) return;
      const second = Math.round(t);
      if (!votes.has(second)) votes.set(second, new Map());
      const tally = votes.get(second);
      tally.set(ys[k], (tally.get(ys[k]) ?? 0) + 1);
    });
  }
  const seconds = [...votes.keys()].sort((a, b) => a - b);
  if (!seconds.length) return '<p class="empty">no leader history yet</p>';
  const leaders = seconds.map((t) => {
    const nonzero = [...votes.get(t)].filter(([id]) => id !== 0).sort((a, b) => b[1] - a[1]);
    return nonzero.length ? nonzero[0][0] : 0;
  });
  const t0 = seconds[0];
  const t1 = seconds.at(-1) + 1;
  const pct = (t) => `${((t - t0) / (t1 - t0)) * 100}%`;
  const clock = (t) => new Date(t * 1000).toISOString().slice(11, 19);
  const spans = runs(seconds, leaders).map((r) => {
    const node = byId.get(r.v);
    const name = r.v === 0 ? 'no leader' : node ? `${node.label} leads` : `raft ${r.v} leads`;
    const colour = r.v === 0 ? 'var(--bad)' : (node?.colour ?? 'var(--idle)');
    return `<i style="left:${pct(r.start)};width:max(2px, calc(${pct(r.end)} - ${pct(r.start)}));background:${colour}" title="${escape(`${name}, ${clock(r.start)}–${clock(r.end)} UTC`)}"></i>`;
  });
  const axis = [0, 0.25, 0.5, 0.75, 1].map((f) => `<span>${clock(t0 + f * (t1 - t0))}</span>`).join('');
  const legend = nodes
    .map((n) => `<span style="color:${n.colour}">■</span> ${escape(n.label)}`)
    .concat('<span class="bad">■</span> no leader')
    .join(' ');
  return `<div class="leader-line">${spans.join('')}</div><div class="lane-axis">${axis}</div>
    <p class="meta">${legend} · times UTC</p>`;
}
