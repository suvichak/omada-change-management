const $ = (s) => document.querySelector(s);
let state = null;
let lastJson = '';
let skew = 0;
let timersEl = null;
let swiping = 0; // a swipe in progress: hold re-renders so the control isn't replaced under the finger

// Phones/tablets confirm by swiping; a mouse keeps the confirm() dialog.
const touch = () => matchMedia('(hover: none) and (pointer: coarse)').matches;

function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}

const fmt = (t) => (t ? new Date(t * 1000).toLocaleString() : '—');
const nowSrv = () => Math.floor(Date.now() / 1000) + skew;
function dur(s) {
  s = Math.max(0, Math.round(s));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m ? `${m}m ${String(r).padStart(2, '0')}s` : `${r}s`;
}
function pretty(t) {
  try { return JSON.stringify(JSON.parse(t), null, 2); } catch { return t || ''; }
}

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { 'X-OW-CSRF': '1' } });
  if (r.status === 401) { location.href = '/login'; throw new Error('login required'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
  return j;
}

const ACTIONS = {
  pending: [
    ['approve', 'Approve & apply', 'primary',
      'Snapshot the controller VM, confirm the internet is stable, and run these commands against Omada now?'],
    ['reject', 'Reject', '', 'Reject this proposal?'],
  ],
  watching: [
    ['keep', 'Keep change', 'primary',
      'End the watch and keep this change? Auto-revert will no longer protect it.'],
    ['revert', 'Revert now', 'danger',
      'Roll the controller VM back to the pre-change snapshot now? The controller restarts, and anything changed on it since the snapshot is lost.'],
    ['hold', 'Hold auto-revert', '',
      'Turn off the automatic revert for this change? Use this when the outage is not caused by the change (e.g. the ISP).'],
  ],
  revert_failed: [
    ['revert', 'Retry revert', 'danger', 'Try the rollback again?'],
    ['abandon', 'Close — fix by hand', '', 'Close this proposal without a successful revert?'],
  ],
};

// Errors: alert() on a computer, a toast on a phone (no native dialogs there).
let toastTimer = null;
function notify(msg) {
  if (!touch()) { alert(msg); return; }
  let t = $('#toast');
  if (!t) { t = h('div', { id: 'toast', onclick: () => t.classList.remove('show') }); document.body.append(t); }
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 8000);
}

// question === null: already confirmed by a swipe.
async function act(p, action, question) {
  if (question !== null && !confirm(question)) return;
  try {
    await api(`/ui/api/proposals/${p.id}/${action}`, { method: 'POST' });
  } catch (e) {
    notify(e.message);
  }
  lastJson = '';
  refresh();
}

// Slide-to-confirm: drag the knob; releasing past COMMIT runs onDone.
// The drag must start on the knob (plus GRAB_SLOP px), and the track is inset from the
// screen edges, so the thumb never lands in the OS edge-swipe-back zone (iOS Safari,
// Android gesture nav), which the page cannot block. touch-action: none on the track
// keeps a thumb arc that drifts vertically from being stolen by page scroll.
const COMMIT = 0.7;
const GRAB_SLOP = 16;
function swipe(label, cls, onDone) {
  const text = h('span', { class: 'swipe-label' }, label);
  const knob = h('div', { class: 'knob' }, '»');
  const track = h('div', { class: `swipe ${cls}` }, text, knob);
  let start = null;
  let x = 0;
  let max = 1;
  const move = (v) => {
    x = v;
    knob.style.transform = `translateX(${v}px)`; // CSSOM, not a style attribute (CSP)
    text.style.opacity = String(Math.max(0, 1 - v / max));
    track.classList.toggle('armed', v >= max * COMMIT);
  };
  const end = (commit) => {
    if (start === null) return;
    start = null;
    swiping--;
    knob.classList.remove('drag');
    if (commit && x >= max * COMMIT) {
      move(max);
      track.classList.add('done');
      text.textContent = 'Working…';
      text.style.opacity = '1';
      onDone();
    } else {
      move(0);
    }
  };
  track.addEventListener('pointerdown', (e) => {
    if (track.classList.contains('done') || start !== null) return;
    const k = knob.getBoundingClientRect();
    if (e.clientX < k.left - GRAB_SLOP || e.clientX > k.right + GRAB_SLOP) return;
    max = Math.max(1, track.clientWidth - knob.offsetWidth - 2 * knob.offsetLeft);
    start = e.clientX - x;
    swiping++;
    knob.classList.add('drag');
    track.setPointerCapture(e.pointerId);
  });
  track.addEventListener('pointermove', (e) => {
    if (start !== null) move(Math.min(max, Math.max(0, e.clientX - start)));
  });
  track.addEventListener('pointerup', () => end(true));
  track.addEventListener('pointercancel', () => end(false));
  return track;
}

// One line per watch phase: settle → watch (needs a stable streak) → close, or down → revert.
function watchRows(p, n) {
  const st = state.settings;
  const need = st.stable_minutes * 60;
  const rows = [];
  const settle = p.settle_until || p.applied_at || n;
  if (n < settle) {
    rows.push(h('div', { class: 'phase' }, h('b', {}, '1 · Settling'),
      ` — devices re-provision; first internet check in ${dur(settle - n)}`));
    rows.push(h('div', { class: 'muted' },
      `Then ${st.watch_minutes} min watch, closing once the internet has been up ${st.stable_minutes} min in a row`));
  } else if (p.down_since) {
    rows.push(h('div', { class: 'phase err' }, h('b', {}, 'Internet DOWN'), ` for ${dur(n - p.down_since)}`));
    if (p.revert_at) {
      rows.push(h('div', { class: 'err big' }, `Auto-revert in ${dur(p.revert_at - n)} (at ${fmt(p.revert_at)}) unless it comes back`));
    }
  } else {
    const stable = p.up_since ? n - p.up_since : 0;
    const closeAt = Math.max(p.watch_until, (p.up_since || n) + need);
    rows.push(h('div', { class: 'phase' }, h('b', {}, '2 · Watching'),
      n < p.watch_until ? ` — ${dur(p.watch_until - n)} of the ${st.watch_minutes} min watch left`
        : ' — watch time over, waiting for a full stable streak'));
    const pct = Math.min(100, Math.round((stable / need) * 100));
    const fill = h('div', { class: 'fill' });
    fill.style.width = `${pct}%`; // CSSOM, not a style attribute: the CSP blocks inline styles
    rows.push(h('div', { class: 'streak' },
      h('div', { class: 'bar' }, fill),
      ` Internet stable ${dur(Math.min(stable, need))} / ${dur(need)}`));
    rows.push(h('div', { class: 'ok' }, `Closes as completed in ${dur(closeAt - n)} if the internet stays up`));
  }
  if (p.hold) rows.push(h('div', { class: 'warn' }, 'Auto-revert is on hold for this change'));
  return rows;
}

function fillTimers(p) {
  if (!timersEl) return;
  const n = nowSrv();
  let rows = [];
  if (p.status === 'watching') {
    rows = watchRows(p, n);
  } else if (p.status === 'snapshotting') {
    rows.push(h('div', {}, 'Taking the controller VM snapshot…'));
  } else if (p.status === 'applying') {
    rows.push(h('div', {},
      `Checking the internet is stable for ${state.settings.preflight_stable_seconds} s, then running commands…`));
  } else if (p.status === 'reverting') {
    rows.push(h('div', { class: 'err big' }, 'Rolling the controller VM back…'));
  }
  timersEl.replaceChildren(...rows);
}

function resultCell(r) {
  const ok = r.http_status === 200 && r.error_code === 0;
  return h('details', {},
    h('summary', { class: ok ? 'ok' : 'err' }, ok ? 'OK' : `HTTP ${r.http_status} · errorCode ${r.error_code}`),
    h('pre', {}, pretty(r.response)));
}

function renderProposal(p, box, live) {
  box.replaceChildren();
  box.append(h('div', { class: 'row' },
    h('h2', {}, `#${p.id} ${p.title}`),
    h('span', { class: `badge s-${p.status}` }, p.status)));
  box.append(h('p', { class: 'reason' }, p.reason));
  box.append(h('p', { class: 'muted' },
    `submitted by ${p.submitted_by} · ${fmt(p.created_at)}`,
    p.approved_by ? ` · approved by ${p.approved_by} at ${fmt(p.approved_at)}` : '',
    p.snapshot ? ` · snapshot ${p.snapshot}` : ''));
  if (live) {
    timersEl = h('div', { class: 'timers' });
    box.append(timersEl);
    fillTimers(p);
  }
  if (p.error) box.append(h('p', { class: 'err' }, p.error));

  const results = Object.fromEntries((p.results || []).map((r) => [r.idx, r]));
  const tbody = h('tbody');
  p.commands.forEach((c, i) => {
    const hasQuery = c.query && Object.keys(c.query).length;
    tbody.append(h('tr', {},
      h('td', {}, i + 1),
      h('td', {}, h('code', { class: `m-${c.method}` }, c.method)),
      h('td', {},
        h('code', {}, c.path),
        c.note ? h('div', { class: 'muted' }, c.note) : null,
        hasQuery ? h('pre', {}, `query ${JSON.stringify(c.query, null, 2)}`) : null,
        c.body !== null && c.body !== undefined ? h('pre', {}, JSON.stringify(c.body, null, 2)) : null),
      h('td', {}, results[i] ? resultCell(results[i]) : '—')));
  });
  box.append(h('table', { class: 'cmds' },
    h('thead', {}, h('tr', {}, h('th', {}, '#'), h('th', {}, 'Method'), h('th', {}, 'Request'), h('th', {}, 'Result'))),
    tbody));

  if (live && ACTIONS[p.status]) {
    const acts = ACTIONS[p.status];
    box.append(touch()
      ? h('div', { class: 'actions swipes' }, acts.map(([a, label, cls, q]) =>
        h('div', {}, swipe(label, cls, () => act(p, a, null)), h('div', { class: 'muted hint' }, q))))
      : h('div', { class: 'actions' }, acts.map(([a, label, cls, q]) =>
        h('button', { class: cls, onclick: () => act(p, a, q) }, label))));
  }

  box.append(h('h3', {}, 'Log'));
  box.append(h('ul', { class: 'events' }, (p.events || []).map((e) =>
    h('li', {}, h('span', { class: 'muted' }, `${fmt(e.at)} · ${e.actor} · `), e.message))));
}

function render() {
  $('#user').textContent = state.user;
  const wd = state.watchdog_ok ? h('span', { class: 'ok' }, 'watchdog OK')
    : h('span', { class: 'err' }, `watchdog NOT running (last tick ${fmt(state.watchdog_tick)})`);
  const st = state.settings;
  const targets = st.probe_targets.join(' / ');
  const net = state.internet_up ? h('span', { class: 'ok' }, `internet up (${targets})`)
    : h('span', { class: 'err' }, `internet DOWN (${targets})`);
  $('#health').replaceChildren(net, ' · ', wd, h('span', { class: 'cfg' },
    ` · ${st.preflight_stable_seconds} s stable before writing · settle ${dur(st.settle_seconds)}`,
    ` · watch ${st.watch_minutes} min, closes after ${st.stable_minutes} min stable`,
    ` · auto-revert after ${st.revert_after_down_minutes} min down · VM ${st.vmid}`));

  const box = $('#open');
  if (state.open) {
    renderProposal(state.open, box, true);
  } else {
    timersEl = null;
    box.replaceChildren(h('h2', {}, 'No open proposal'),
      h('p', { class: 'muted' }, 'Waiting for the AI to submit a change set.'));
  }

  const tb = $('#history tbody');
  tb.replaceChildren(...state.history.map((r) => h('tr', { class: 'click', onclick: () => view(r.id) },
    h('td', {}, r.id), h('td', {}, r.title), h('td', {}, h('span', { class: `badge s-${r.status}` }, r.status)),
    h('td', {}, `${fmt(r.created_at)} (${r.submitted_by})`), h('td', {}, r.approved_by || '—'), h('td', {}, fmt(r.closed_at)))));
}

async function view(id) {
  if (state.open && state.open.id === id) { $('#viewer').classList.add('hidden'); return; }
  try {
    const p = await api(`/ui/api/proposals/${id}`);
    const v = $('#viewer');
    renderProposal(p, v, false);
    v.prepend(h('button', { class: 'link close', onclick: () => v.classList.add('hidden') }, 'close ✕'));
    v.classList.remove('hidden');
    v.scrollIntoView({ behavior: 'smooth' });
  } catch (e) {
    notify(e.message);
  }
}

async function refresh() {
  try {
    const s = await api('/ui/api/state');
    skew = s.now - Math.floor(Date.now() / 1000);
    const { now, ...rest } = s;
    const j = JSON.stringify(rest);
    state = s;
    if (j !== lastJson && !swiping) { lastJson = j; render(); }
  } catch (e) {
    $('#health').replaceChildren(h('span', { class: 'err' }, `cannot reach omadawrite: ${e.message}`));
  }
}

$('#logout').addEventListener('click', async () => {
  await fetch('/auth/logout', { method: 'POST', headers: { 'X-OW-CSRF': '1' } });
  location.href = '/login';
});

refresh();
setInterval(refresh, 5000);
setInterval(() => { if (state && state.open) fillTimers(state.open); }, 1000);
