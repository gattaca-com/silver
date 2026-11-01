// Home page, votes card: for the last reported slot, per client and voted
// block root, two bars on one scale. "silver", in the client's colour: the
// singles the node held at the slot's aggregate due time. "recv": stacked per
// committee in its own hue, the largest valid aggregate received during the
// slot, largest first.

import { escape, shortId } from './view.js';

const W = 760;
const H = 200;
const AXIS_W = 48;
const LABEL_H = 34;
const BAR_W = 40;
const PAIR_GAP = 8;
const GROUP_GAP = 24;
/** Roots per client past this, by fewest votes, are not drawn. */
const ROOTS_MAX = 3;

/** Each client reports a slot whole at its end, so the newest is complete. */
function shownSlot(instances) {
  const slots = instances.flatMap((inst) => [...inst.votes.slots.keys()]);
  return slots.length ? Math.max(...slots) : null;
}

function bars(inst, slot) {
  const roots = inst.votes.slots.get(slot);
  if (!roots) return [];
  const blockRoot = inst.traces.find((t) => t.slot === slot)?.root ?? null;
  return [...roots]
    .map(([root, r]) => {
      const aggregates = [...r.largest].sort((a, b) => b[1] - a[1]);
      return { root, isBlock: root === blockRoot, atDue: r.atDue ?? 0, aggregates };
    })
    .sort((a, b) => b.atDue - a.atDue)
    .slice(0, ROOTS_MAX);
}

/** Fixed per committee, so one committee matches across clients and slots;
 *  golden-angle hue steps keep neighbouring indices apart. */
function committeeColour(committee) {
  return `hsl(${Math.round((committee * 137.508) % 360)} 55% 55%)`;
}

function stack(x, segments, scale, title) {
  let y = H - LABEL_H;
  return segments
    .map(({ value, fill, label }) => {
      const h = value * scale;
      y -= h;
      return `<rect x="${x}" y="${y}" width="${BAR_W}" height="${h}" style="fill:${fill}"><title>${escape(`${title}: ${label}`)}</title></rect>`;
    })
    .join('');
}

function svg(groups, slot) {
  const sum = (b) => b.aggregates.reduce((t, [, v]) => t + v, 0);
  const total = (b) => Math.max(b.atDue, sum(b));
  const max = Math.max(1, ...groups.flatMap((g) => g.bars.map(total)));
  const scale = (H - LABEL_H - 8) / max;
  let x = AXIS_W;
  const marks = [];
  for (const { inst, colour, bars: rootBars } of groups) {
    for (const b of rootBars) {
      const who = `${inst.label} ${b.isBlock ? 'block' : 'root'} ${shortId(b.root)}`;
      const silver = [{ value: b.atDue, fill: colour, label: `${b.atDue} aggregated at deadline` }];
      const received = b.aggregates.map(([committee, v]) => ({
        value: v,
        fill: committeeColour(committee),
        label: `committee ${committee}: ${v}`,
      }));
      marks.push(stack(x, silver, scale, `${who} silver`));
      marks.push(stack(x + BAR_W + PAIR_GAP, received, scale, `${who} recv (${b.aggregates.length} committees, ${sum(b)})`));
      const mid = x + BAR_W + PAIR_GAP / 2;
      marks.push(`<text class="sub" x="${x + BAR_W / 2}" y="${H - LABEL_H + 12}">silver</text>`);
      marks.push(`<text class="sub" x="${x + BAR_W * 1.5 + PAIR_GAP}" y="${H - LABEL_H + 12}">recv</text>`);
      marks.push(`<text x="${mid}" y="${H - LABEL_H + 26}" style="fill:${colour}">${escape(b.isBlock ? 'block' : shortId(b.root))}</text>`);
      x += 2 * BAR_W + PAIR_GAP + GROUP_GAP;
    }
  }
  const base = H - LABEL_H;
  const axis = `<line x1="${AXIS_W - 6}" x2="${Math.max(x, W)}" y1="${base}" y2="${base}"/>
    <text class="axis" x="${AXIS_W - 8}" y="${base - max * scale}" dy="0.35em">${max}</text>
    <text class="axis" x="${AXIS_W - 8}" y="${base}" dy="0.35em">0</text>`;
  return `<svg viewBox="0 0 ${Math.max(x, W)} ${H}" role="img" aria-label="votes per block root, slot ${slot}">${axis}${marks.join('')}</svg>`;
}

/** The card; empty until a client reports votes. */
export function voteChart(fleet) {
  const instances = fleet.sorted();
  const slot = shownSlot(instances);
  const title = 'silver attestations aggregated at deadline vs largest received aggregate per committee';
  if (slot === null) return `<div class="votes"><p class="meta">${title}</p><p class="empty">no vote stats yet</p></div>`;
  const groups = instances
    .map((inst, i) => ({ inst, colour: `var(--series-${i + 1})`, bars: bars(inst, slot) }))
    .filter((g) => g.bars.length);
  return `<div class="votes"><p class="meta">${title}, slot ${slot}</p>${svg(groups, slot)}</div>`;
}
