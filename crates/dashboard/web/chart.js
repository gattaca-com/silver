// uPlot line charts that outlive the pane's per-second innerHTML rebuild:
// each chart owns a container that is re-parented into its new placeholder
// and fed new data, so the plot, cursor and hover survive the redraw.

const HEIGHT = 200;
/** Categorical slots in fixed order; series past the last are not drawn. */
export const SERIES_MAX = 8;

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Last non-null value of each series, drawn beside its final point in the
 *  series' colour. */
function endLabels(colours, holder) {
  return (u) => {
    const dpr = devicePixelRatio;
    const { ctx } = u;
    ctx.save();
    ctx.font = `${11 * dpr}px ui-monospace, SFMono-Regular, Menlo, monospace`;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'bottom';
    for (let s = 1; s < u.series.length; s++) {
      const ys = u.data[s];
      let i = ys.length - 1;
      while (i >= 0 && (ys[i] === null || ys[i] === undefined)) i--;
      if (i < 0) continue;
      const x = u.valToPos(u.data[0][i], 'x', true);
      const y = u.valToPos(ys[i], u.series[s].scale, true);
      ctx.fillStyle = colours[s - 1];
      ctx.fillText(holder.spec.endLabel(s - 1, ys[i]), x - 4 * dpr, y - 3 * dpr);
    }
    ctx.restore();
  };
}

/** A dashed full-height line at each `{ x, series }` of `holder.spec.markers`,
 *  in that series' colour. */
function markers(colours, holder) {
  return (u) => {
    const dpr = devicePixelRatio;
    const { ctx } = u;
    const { top, height } = u.bbox;
    ctx.save();
    ctx.lineWidth = dpr;
    ctx.setLineDash([4 * dpr, 3 * dpr]);
    for (const { x, series } of holder.spec.markers ?? []) {
      const px = u.valToPos(x, 'x', true);
      ctx.strokeStyle = colours[series];
      ctx.beginPath();
      ctx.moveTo(px, top);
      ctx.lineTo(px, top + height);
      ctx.stroke();
    }
    ctx.restore();
  };
}

/** `holder.spec.cornerLabels[i]`, stacked in the plot's top-right corner in
 *  series `i`'s colour. */
function cornerLabels(colours, holder) {
  return (u) => {
    const dpr = devicePixelRatio;
    const { ctx } = u;
    const { left, top, width } = u.bbox;
    ctx.save();
    ctx.font = `${11 * dpr}px ui-monospace, SFMono-Regular, Menlo, monospace`;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'top';
    holder.spec.cornerLabels.forEach((text, i) => {
      ctx.fillStyle = colours[i];
      ctx.fillText(text, left + width - 4 * dpr, top + (4 + 14 * i) * dpr);
    });
    ctx.restore();
  };
}

/** Optional spec fields: `height`; `xSeconds`, a plain seconds x axis in
 *  place of wall-clock time; `xRange` / `yRange`, fixed [min, max]
 *  re-read on every redraw; `right` (series indexes on a right axis) with
 *  `fmtRight`; `stepped`; `spanGaps`; `endLabel(i, v)` for a label at each
 *  series' last point; `markers`; `cornerLabels`; `colourOf[i]`, the colour
 *  slot of series `i` (default `i`); `dashed`, series indexes drawn dashed;
 *  `legend: false` hides the per-series legend. `holder.spec` is the latest
 *  spec. */
function options(spec, width, holder) {
  const muted = cssVar('--muted');
  const grid = { stroke: cssVar('--line'), width: 1 };
  const axis = { stroke: muted, grid, ticks: grid };
  const colours = spec.labels.map((_, i) => cssVar(`--series-${(spec.colourOf?.[i] ?? i) + 1}`));
  const onRight = (i) => spec.right?.includes(i) ?? false;
  const fmtOf = (i) => (onRight(i) ? spec.fmtRight : spec.fmt);
  const scales = { x: { time: !spec.xSeconds }, y: {} };
  if (spec.xRange) scales.x.range = () => holder.spec.xRange;
  if (spec.yRange) scales.y.range = () => holder.spec.yRange;
  const xAxis = spec.xSeconds ? { ...axis, values: (_u, vals) => vals.map((v) => `${v}s`) } : axis;
  const axes = [xAxis, { ...axis, size: 80, values: (_u, vals) => vals.map((v) => spec.fmt(v)) }];
  if (spec.right) {
    scales.y2 = {};
    axes.push({ ...axis, scale: 'y2', side: 1, size: 70, grid: { show: false }, values: (_u, vals) => vals.map((v) => spec.fmtRight(v)) });
  }
  return {
    width,
    height: spec.height ?? HEIGHT,
    scales,
    axes,
    series: [
      {},
      ...spec.labels.map((label, i) => ({
        label,
        scale: onRight(i) ? 'y2' : 'y',
        stroke: colours[i],
        width: 2,
        ...(spec.dashed?.includes(i) ? { dash: [6, 4] } : {}),
        points: { show: false },
        spanGaps: spec.spanGaps ?? false,
        ...(spec.stepped ? { paths: uPlot.paths.stepped({ align: 1 }) } : {}),
        value: (_u, v) => (v === null ? '·' : fmtOf(i)(v)),
      })),
    ],
    hooks: {
      draw: [
        ...(spec.endLabel ? [endLabels(colours, holder)] : []),
        ...(spec.markers ? [markers(colours, holder)] : []),
        ...(spec.cornerLabels ? [cornerLabels(colours, holder)] : []),
      ],
    },
    legend: { show: spec.legend ?? true, live: true },
  };
}

export class LineCharts {
  constructor() {
    this.charts = new Map();
  }

  /** `specs`: key → { labels, data: [xs, ...ys], fmt }. Placeholders are
   *  `[data-chart=key]`; charts without one this pass are destroyed. */
  mount(root, specs) {
    if (typeof uPlot === 'undefined' || !root.querySelectorAll) return;
    const seen = new Set();
    for (const slot of root.querySelectorAll('[data-chart]')) {
      const key = slot.dataset.chart;
      const spec = specs.get(key);
      if (!spec) continue;
      seen.add(key);
      const width = Math.max(slot.clientWidth, 200);
      // Series identity, layout and theme are baked into the plot; a change
      // rebuilds it.
      const layout = [spec.height, spec.right, spec.stepped, spec.spanGaps, !!spec.xSeconds, !!spec.xRange, !!spec.yRange, !!spec.endLabel, !!spec.markers, !!spec.cornerLabels, spec.colourOf, spec.dashed, spec.legend];
      const shape = `${spec.labels.join('\u0000')}|${JSON.stringify(layout)}|${cssVar('--series-1')}`;
      let chart = this.charts.get(key);
      if (chart && chart.shape !== shape) {
        chart.plot.destroy();
        chart = null;
      }
      if (!chart) {
        const el = document.createElement('div');
        chart = { el, shape, spec };
        chart.plot = new uPlot(options(spec, width, chart), spec.data, el);
        this.charts.set(key, chart);
      } else {
        chart.spec = spec;
        chart.plot.setData(spec.data);
        if (chart.plot.width !== width) chart.plot.setSize({ width, height: spec.height ?? HEIGHT });
      }
      slot.appendChild(chart.el);
    }
    for (const [key, chart] of this.charts) {
      if (!seen.has(key)) {
        chart.plot.destroy();
        this.charts.delete(key);
      }
    }
  }
}
