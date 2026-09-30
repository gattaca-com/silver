import { decode } from './wire.js';
import { Fleet } from './state.js';
import * as events from './events.js';
import * as flow from './flow.js';
import * as gossip from './gossip.js';
import * as peers from './peers.js';

const RENDER_MS = 1000;
const RECONNECT_MS = 2000;

const PANES = { events, peers, gossip, flow };
/** Per-pane view state (selected instance, sort, expanded rows); survives
 *  re-renders and reconnects. */
const ui = Object.fromEntries(Object.keys(PANES).map((p) => [p, {}]));

let fleet = new Fleet();
let active = PANES[location.hash.slice(1)] ? location.hash.slice(1) : 'events';

const root = document.getElementById('pane');
const status = document.getElementById('status');

function renderTabs() {
  for (const tab of document.querySelectorAll('nav [data-pane]')) {
    tab.classList.toggle('active', tab.dataset.pane === active);
  }
}

/** Replacing the pane's HTML briefly collapses it (chart slots stay empty
 *  until re-mounted), which clamps the window scroll, and horizontal table
 *  scroll goes with the old sections; both are restored after the redraw. */
function render() {
  const y = window.scrollY;
  const xs = [...root.querySelectorAll('section')].map((s) => s.scrollLeft);
  PANES[active].render(fleet, root, performance.now(), ui[active]);
  root.querySelectorAll('section').forEach((s, i) => {
    if (xs[i]) s.scrollLeft = xs[i];
  });
  if (window.scrollY !== y) window.scrollTo(window.scrollX, y);
}

root.addEventListener('mouseover', (e) => PANES[active].hover?.(e.target, ui[active], root));
root.addEventListener('mouseleave', () => PANES[active].hover?.(root, ui[active], root));

root.addEventListener('click', (e) => {
  const tab = e.target.closest('[data-instance]');
  if (tab) {
    const pane = ui[active];
    const key = tab.dataset.instance;
    // Ctrl/Cmd+click builds a multi-selection on panes that show several
    // instances side by side; a plain click returns to one.
    if (PANES[active].multiInstance && (e.ctrlKey || e.metaKey)) {
      pane.instances ??= new Set(pane.instance ? [pane.instance] : []);
      if (pane.instances.delete(key)) {
        pane.instance = pane.instances.values().next().value ?? key;
      } else {
        pane.instances.add(key);
        pane.instance = key;
      }
    } else {
      pane.instances = null;
      pane.instance = key;
    }
  } else {
    PANES[active].click?.(e.target, ui[active]);
  }
  render();
});

document.addEventListener('keydown', (e) => {
  if (PANES[active].key?.(e.key, ui[active])) {
    e.preventDefault();
    render();
  }
});

document.querySelector('nav').addEventListener('click', (e) => {
  const pane = e.target.dataset?.pane;
  if (!pane || !PANES[pane]) return;
  active = pane;
  history.replaceState(null, '', `#${pane}`);
  renderTabs();
  root.innerHTML = '';
  window.scrollTo(0, 0);
  render();
});

// The server replays every ring on connect, so a reconnect starts from an
// empty fleet rather than merging a second replay into the first.
function connect() {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${scheme}://${location.host}/ws`);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => {
    fleet = new Fleet();
    status.textContent = 'live';
    status.className = 'live';
  };
  ws.onmessage = (e) => {
    const d = decode(e.data);
    if (d) fleet.apply(d);
  };
  ws.onclose = () => {
    status.textContent = 'reconnecting';
    status.className = 'down';
    setTimeout(connect, RECONNECT_MS);
  };
}

renderTabs();
connect();
setInterval(render, RENDER_MS);
