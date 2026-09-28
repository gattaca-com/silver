const KIB = 1024;
const MIB = KIB * 1024;
const GIB = MIB * 1024;

/** Same units as silver_metrics::fmt_bytes. */
export function fmtBytes(b) {
  if (b >= GIB) return `${(b / GIB).toFixed(2)} GiB`;
  if (b >= MIB) return `${(b / MIB).toFixed(2)} MiB`;
  if (b >= KIB) return `${(b / KIB).toFixed(2)} KiB`;
  return `${b} B`;
}

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escape(s) {
  return String(s).replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

export function instanceHeading(inst, now) {
  const stale = inst.stale(now) ? '<span class="badge stale">stale</span>' : '';
  const lost = inst.lost ? `<span class="badge">lost ${inst.lost}</span>` : '';
  const build = inst.buildInfo ? `<span class="meta">${escape(inst.buildInfo.trim())}</span>` : '';
  return `<h2>${escape(inst.label)}${stale}${lost}${build}</h2>`;
}

export function fmtSecs(secs) {
  secs = Math.floor(secs);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h${Math.floor((secs % 3600) / 60)}m`;
}

/** Last 4 id bytes, as surfer shows peers. */
export function shortId(hex) {
  return hex.slice(-8);
}

export function fixed(v, digits = 1) {
  return v === null || v === undefined ? '·' : v.toFixed(digits);
}

/** Tab strip over the fleet. Falls back to the first instance when the
 *  selected one is gone. `multi`, a set of keys, marks a multi-selection;
 *  `insts` lists its live members in fleet order, else just `inst`. */
export function instanceTabs(fleet, selectedKey, now, multi = null) {
  const instances = fleet.sorted();
  const inst = instances.find((i) => i.key === selectedKey) ?? instances[0] ?? null;
  const picked = multi ? instances.filter((i) => multi.has(i.key)) : [];
  const insts = picked.length > 1 ? picked : inst ? [inst] : [];
  const tabs = instances
    .map((i) => {
      const cls = [insts.includes(i) ? 'active' : '', i.stale(now) ? 'stale' : ''].join(' ');
      return `<button class="${cls}" data-instance="${i.key}">${escape(i.label)}</button>`;
    })
    .join('');
  return { inst, insts, html: `<div class="subtabs">${tabs}</div>` };
}
