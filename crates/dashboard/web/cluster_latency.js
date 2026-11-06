// Where commit time goes per slot, from ClusterCommit samples.

import { fmtUs, mean } from './cluster_model.js';
import { escape } from './view.js';

const STAGES = [
  ['appendUs', 'append', 'var(--c-validate)', 'proposal → entry in this node\'s log (a follower forwards to the leader and waits for its append)'],
  ['persistUs', 'persist', 'var(--c-stf)', 'entry in log → journal write done'],
  ['quorumUs', 'quorum', 'var(--c-apply)', 'journal done → committed by a quorum and applied'],
];
const BW = 440;
const BH = 180;
const LEFT = 46;
const BOTTOM = 18;
const Y_TICKS = [0, 0.25, 0.5, 0.75, 1];
const X_LABEL_EVERY = 5;

function stageMeans(list) {
  const complete = list.filter((c) => STAGES.every(([key]) => c[key] !== null));
  return { count: complete.length, means: STAGES.map(([key]) => mean(complete.map((c) => c[key]))) };
}

export function stageBars(nodes, slots, tip) {
  const perNode = nodes.map((node) => {
    const bySlot = node.commitsBySlot();
    return slots.map((slot) => ({ slot, ...stageMeans(bySlot.get(slot) ?? []) }));
  });
  const top = Math.max(1, ...perNode.flat().map((s) => s.means.reduce((a, b) => a + (b ?? 0), 0)));
  const plotH = BH - BOTTOM - 10;
  const bw = (BW - LEFT) / Math.max(1, slots.length);
  const yTicks = Y_TICKS.map((f) => {
    const y = BH - BOTTOM - f * plotH;
    return `<line class="grid" x1="${LEFT}" x2="${BW}" y1="${y}" y2="${y}"/><text class="axis" x="${LEFT - 4}" y="${y + 3}" text-anchor="end">${fmtUs(f * top)}</text>`;
  }).join('');
  const xLabels = slots
    .map((slot, k) => (k % X_LABEL_EVERY ? '' : `<text class="axis" x="${LEFT + k * bw}" y="${BH - 4}">${slot}</text>`))
    .join('');
  const charts = nodes.map((node, i) => {
    const bars = perNode[i].map((s, k) => {
      if (!s.count) return '';
      let acc = 0;
      const segs = s.means.map((m, j) => {
        const h = ((m ?? 0) / top) * plotH;
        acc += h;
        const what = `${node.label}, slot ${s.slot}: ${STAGES[j][1]} ${fmtUs(m)} (mean of ${s.count} commit${s.count === 1 ? '' : 's'})`;
        return `<rect class="seg" data-tip="${escape(what)}" x="${LEFT + k * bw}" y="${BH - BOTTOM - acc}" width="${Math.max(1, bw - 1)}" height="${h}" style="fill:${STAGES[j][2]}"/>`;
      });
      return segs.join('');
    });
    return `<div><p class="meta" style="color:${node.colour}">${escape(node.label)}</p>
      <svg class="cbars" viewBox="0 0 ${BW} ${BH}">
        ${yTicks}${xLabels}
        ${bars.join('')}
      </svg></div>`;
  });
  const legend = STAGES.map(([, name, colour, what]) => `<span title="${escape(what)}"><i class="swatch" style="background:${colour}"></i>${name}</span>`).join('');
  const readout = `<p class="meta ctip">${escape(tip ?? 'hover a coloured segment for its value')}</p>`;
  return `<div class="cluster-pair">${charts.join('')}</div><div class="home-legend cbars-legend">${legend}</div>${readout}`;
}
