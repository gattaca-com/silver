// Home page, votes card: for the newest slot, filled as its reports arrive
// (deadline, each new largest aggregate, slot end), per client, three bars on
// one scale for votes naming the slot's own block. "silver": the singles the
// node held at the slot's aggregate due time, in the client's colour. "recv":
// stacked per subscribed committee in its own hue, the largest valid
// aggregate received during the slot, largest first. "end": the singles held
// at the slot's end, in light grey.

import { escape, shortId } from './view.js';

const W = 760;
const H = 200;
const AXIS_W = 48;
const LABEL_H = 34;
/** Above the tallest bar, for its total. */
const TOP_H = 18;
const BAR_W = 40;
const PAIR_GAP = 8;
const GROUP_GAP = 24;

function shownSlot(instances) {
  const slots = instances.flatMap((inst) => [...inst.votes.slots.keys()]);
  return slots.length ? Math.max(...slots) : null;
}

/** Votes for the block the client received for `slot`; none when it saw no
 *  block for it, as on a missed slot. */
function bars(inst, slot) {
  const root = inst.traces.find((t) => t.slot === slot)?.root;
  const r = root === undefined ? undefined : inst.votes.slots.get(slot)?.get(root);
  if (!r) return [];
  const aggregates = [...r.largest].sort((a, b) => b[1] - a[1]);
  const atDue = r.atDue ?? 0;
  return [{ root, atDue, atEnd: r.atEnd, aggregates }];
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

const END_FILL = 'color-mix(in srgb, var(--muted) 60%, #ffffff)';

function svg(groups, slot) {
  const sum = (b) => b.aggregates.reduce((t, [, v]) => t + v, 0);
  const total = (b) => Math.max(b.atDue, b.atEnd ?? 0, sum(b));
  const max = Math.max(1, ...groups.flatMap((g) => g.bars.map(total)));
  const scale = (H - LABEL_H - TOP_H) / max;
  let x = AXIS_W;
  const marks = [];
  for (const { inst, colour, bars: rootBars } of groups) {
    for (const b of rootBars) {
      const who = `${inst.label} block ${shortId(b.root)}`;
      const columns = [
        { name: 'silver', total: b.atDue, segments: [{ value: b.atDue, fill: colour, label: `${b.atDue} aggregated at deadline` }] },
        {
          name: 'recv',
          total: sum(b),
          title: `${b.aggregates.length} committees`,
          segments: b.aggregates.map(([committee, v]) => ({
            value: v,
            fill: committeeColour(committee),
            label: `committee ${committee}: ${v}`,
          })),
        },
        {
          name: 'end',
          total: b.atEnd,
          segments: b.atEnd === null ? [] : [{ value: b.atEnd, fill: END_FILL, label: `${b.atEnd} aggregated at slot end` }],
        },
      ];
      columns.forEach((c, i) => {
        const cx = x + i * (BAR_W + PAIR_GAP);
        marks.push(stack(cx, c.segments, scale, `${who} ${c.name}${c.title ? ` (${c.title})` : ''}`));
        if (c.total !== null) {
          marks.push(`<text class="total" x="${cx + BAR_W / 2}" y="${H - LABEL_H - c.total * scale - 4}">${c.total}</text>`);
        }
        marks.push(`<text class="sub" x="${cx + BAR_W / 2}" y="${H - LABEL_H + 12}">${c.name}</text>`);
      });
      const width = columns.length * BAR_W + (columns.length - 1) * PAIR_GAP;
      marks.push(`<text x="${x + width / 2}" y="${H - LABEL_H + 26}" style="fill:${colour}">${escape(inst.label)}</text>`);
      x += width + GROUP_GAP;
    }
  }
  const base = H - LABEL_H;
  const axis = `<line x1="${AXIS_W - 6}" x2="${Math.max(x, W)}" y1="${base}" y2="${base}"/>
    <text class="axis" x="${AXIS_W - 8}" y="${base - max * scale}" dy="0.35em">${max}</text>
    <text class="axis" x="${AXIS_W - 8}" y="${base}" dy="0.35em">0</text>`;
  return `<svg viewBox="0 0 ${Math.max(x, W)} ${H}" role="img" aria-label="votes for the block of slot ${slot}">${axis}${marks.join('')}</svg>`;
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
  if (!groups.length) return `<div class="votes"><p class="meta">${title}, slot ${slot}</p><p class="empty">no block seen for slot ${slot}</p></div>`;
  return `<div class="votes"><p class="meta">${title}, slot ${slot}</p>${svg(groups, slot)}</div>`;
}
