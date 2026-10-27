// Landing pane: stf validate + apply percentiles per instance, then summaries of the
// Slots, Gossip traffic and Data flow panes; pressing a summary opens its pane.

import { LineCharts, SERIES_MAX } from './chart.js';
import { fmtNanos } from './events.js';
import { queuesDiagram } from './flow.js';
import { trafficChart } from './gossip_traffic.js';
import { attestationsChart } from './slot_charts.js';
import { escape } from './view.js';

export const renderMs = 100;

const PERCENTILES = [50, 90, 99];
const ATTESTATIONS_HEIGHT = 200;
const TRAFFIC_HEIGHT = 160;

/** Nearest rank on ascending `sorted`. */
function percentile(sorted, p) {
  return sorted[Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)];
}

function stfRow(inst, colour) {
  const durations = [];
  for (const trace of inst.traces) {
    if (trace.attestable === null) continue;
    const validate = trace.interval('validate');
    const apply = trace.interval('apply');
    if (validate && apply) durations.push(validate.end - validate.start + apply.end - apply.start);
  }
  durations.sort((a, b) => a - b);
  const cells = PERCENTILES.map(
    (p) => `<td class="num">${durations.length ? fmtNanos(percentile(durations, p)) : '·'}</td>`,
  ).join('');
  return `<tr style="color:${colour}"><td>${escape(inst.label)}</td>${cells}<td class="num meta">${durations.length}</td></tr>`;
}

/** Entries in stacking order, bottom first, each in its chart colour. */
function trafficLegend(spec) {
  const entries = spec.labels
    .map((label, i) => `<span><i class="swatch" style="background:var(--series-${spec.colourOf[i] + 1})"></i>${escape(label)}</span>`)
    .reverse();
  return `<div class="home-legend">${entries.join('')}</div>`;
}

/** Per-topic totals are left to the traffic pane: at this size they cover the
 *  plot. */
function trafficCard(inst, specs, nowS) {
  let legend = '';
  // A fresh view state: recv's busiest entries are picked, and sent keeps
  // them so a colour names the same topic in both.
  const view = {};
  const cells = ['recv', 'sent'].map((dir) => {
    const chart = trafficChart(inst, view, dir, nowS);
    view.picked ??= view.autoPicked;
    if (!chart) return `<p class="empty">no ${dir} samples yet</p>`;
    const key = `home-traffic-${dir}-${inst.key}`;
    specs.set(key, { ...chart.spec, height: TRAFFIC_HEIGHT, cornerLabels: null });
    legend ||= trafficLegend(chart.spec);
    return `<div><p class="meta">${dir}</p><div class="chart" data-chart="${key}"></div></div>`;
  });
  return `<div class="home-card" data-goto="gossip" data-goto-view="traffic" data-goto-instance="${inst.key}">
    <h3>${escape(inst.label)}</h3><div class="home-pair">${cells.join('')}</div>${legend}</div>`;
}

function flowCard(inst) {
  return `<div class="home-card flow" data-goto="flow" data-goto-instance="${inst.key}">
    <h3>${escape(inst.label)}</h3>${queuesDiagram(inst)}</div>`;
}

export function render(fleet, root, _now, ui) {
  const all = fleet.sorted();
  if (!all.length) {
    root.innerHTML = '<p class="empty">no instances connected</p>';
    return;
  }
  ui.charts ??= new LineCharts();
  const specs = new Map();
  const nowS = Date.now() / 1000;
  // Fleet order, as the charts colour their series.
  const colour = (i) => (i < SERIES_MAX ? `var(--series-${i + 1})` : 'var(--fg)');
  const head = PERCENTILES.map((p) => `<th class="num">p${p}</th>`).join('');
  const attestations = attestationsChart(fleet, specs, 'home-attestations', ATTESTATIONS_HEIGHT);
  root.innerHTML = `
    <h2>stf validate + apply <span class="meta">blocks reaching attestable</span></h2>
    <section><table class="apply-big">
      <thead><tr><th>instance</th>${head}<th class="num">slots</th></tr></thead>
      <tbody>${all.map((inst, i) => stfRow(inst, colour(i))).join('')}</tbody>
    </table></section>
    <div class="home-card home-wide" data-goto="events">
      <h3>${attestations}</h3><div class="chart" data-chart="home-attestations"></div></div>
    <h2>gossip traffic <span class="meta">bytes per 100 ms</span></h2>
    <div class="home-rows">${all.map((inst) => trafficCard(inst, specs, nowS)).join('')}</div>
    <h2>data flow</h2>
    <div class="home-grid">${all.map(flowCard).join('')}</div>`;
  ui.charts.mount(root, specs);
}
