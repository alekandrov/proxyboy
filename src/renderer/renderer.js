/* global esc, fmtSize, fmtDur, statusClass, shortType, b64ToBytes, bytesToText, looksBinary, hexdump,
   highlightJSON, headerGet, toCurl, parseCookies */
const api = window.proxyboy;
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const ROW_H = 22;

const store = (k, def) => { try { return JSON.parse(localStorage.getItem(k)) ?? def; } catch { return def; } };
const persist = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignorar */ } };

const S = {
  flows: [],
  byId: new Map(),
  view: [],
  selected: new Set(),
  focusId: null,
  host: '',
  chip: 'all',
  query: '',
  pinned: new Set(store('pinned', [])),
  reqTab: 'headers',
  resTab: 'body',
  bodyMode: store('bodyMode', 'pretty'),
  detail: null,
  app: null,
  recording: true,
};

// ---------------- Inicio ----------------
async function init() {
  if (navigator.platform.toLowerCase().includes('mac')) document.body.classList.add('mac');
  S.app = await api.state();
  renderAppState();
  for (const f of await api.allFlows()) addFlow(f);
  refresh();
  api.onFlows(({ added, updated }) => {
    for (const f of added) addFlow(f);
    let focusChanged = false;
    for (const f of updated) {
      const cur = S.byId.get(f.id);
      if (cur) Object.assign(cur, f);
      else addFlow(f);
      if (f.id === S.focusId) focusChanged = true;
    }
    refresh();
    if (focusChanged) loadDetail(S.focusId, true);
  });
  api.onCommand(runCommand);
  bindUI();
}

function addFlow(f) {
  if (S.byId.has(f.id)) return;
  S.byId.set(f.id, f);
  S.flows.push(f);
}

async function reloadState() {
  S.app = await api.state();
  renderAppState();
  renderSidebar();
}

function renderAppState() {
  const a = S.app;
  const ip = (a.ips[0] && a.ips[0].address) || '127.0.0.1';
  $('#proxy-info').textContent = `${ip}:${a.port}`;
  $('#empty-addr').textContent = `${ip}:${a.port}`;
  $('#btn-system-proxy').classList.toggle('on', a.systemProxy);
  $('#cert-dot').classList.toggle('ok', a.caTrusted);
  $('#btn-cert').title = a.caTrusted ? 'Certificado instalado y confiable' : 'Certificado NO instalado';
}

// ---------------- Filtros ----------------
function wildcard(p) {
  return new RegExp(`^${p.trim().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`, 'i');
}
function isSSLHost(host) {
  const s = S.app && S.app.settings;
  if (!s || !s.sslProxyingEnabled) return false;
  return s.sslProxyAll || s.sslHosts.some((p) => p && wildcard(p).test(host));
}

function matchChip(f) {
  const t = shortType(f.contentType, f);
  switch (S.chip) {
    case 'http': return f.scheme === 'http';
    case 'https': return f.scheme === 'https';
    case 'ws': return f.scheme === 'ws' || f.scheme === 'wss';
    case 'json': return t === 'json';
    case 'form': return t === 'form' || (f.contentType || '').includes('multipart');
    case 'xml': return t === 'xml';
    case 'js': return t === 'js';
    case 'css': return t === 'css';
    case 'img': return (f.contentType || '').startsWith('image/');
    case 'err': return f.state === 'failed' || (f.status && f.status >= 400);
    default: return true;
  }
}

function matchQuery(f) {
  if (!S.query) return true;
  const hay = `${f.method} ${f.url} ${f.status || ''} ${f.contentType} ${f.error || ''} ${f.tags.join(' ')}`.toLowerCase();
  return S.query.toLowerCase().split(/\s+/).filter(Boolean).every((term) => {
    if (term.startsWith('-') && term.length > 1) return !hay.includes(term.slice(1));
    return hay.includes(term);
  });
}

function matchHost(f) {
  if (!S.host) return true;
  if (S.host === '__pinned') return S.pinned.has(f.host);
  return f.host === S.host;
}

function computeView() {
  S.view = S.flows.filter((f) => matchHost(f) && matchChip(f) && matchQuery(f));
}

// ---------------- Render ----------------
let refreshQueued = false;
function refresh() {
  if (refreshQueued) return;
  refreshQueued = true;
  requestAnimationFrame(() => {
    refreshQueued = false;
    const vp = $('#rows-viewport');
    const atBottom = vp.scrollTop + vp.clientHeight >= vp.scrollHeight - ROW_H * 2;
    computeView();
    $('#rows-spacer').style.height = `${S.view.length * ROW_H}px`;
    if (atBottom) vp.scrollTop = vp.scrollHeight;
    renderRows();
    renderSidebar();
    $('#empty').hidden = S.flows.length > 0;
    $('#status-text').textContent = `${S.view.length} de ${S.flows.length} requests${S.recording ? '' : ' · en pausa'}`;
  });
}

function renderRows() {
  const vp = $('#rows-viewport');
  const start = Math.max(0, Math.floor(vp.scrollTop / ROW_H) - 5);
  const end = Math.min(S.view.length, start + Math.ceil(vp.clientHeight / ROW_H) + 10);
  const rows = $('#rows');
  rows.style.top = `${start * ROW_H}px`;
  let html = '';
  for (let i = start; i < end; i++) {
    const f = S.view[i];
    const sc = statusClass(f);
    const status = f.state === 'failed' ? 'ERR' : (f.status || '…');
    const tags = f.tags.filter((t) => t !== 'websocket').map((t) => `<span class="tag ${esc(t)}">${esc(t)}</span>`).join('');
    const lock = f.scheme === 'https' || f.scheme === 'wss' ? '🔒 ' : '';
    html += `<div class="row${S.selected.has(f.id) ? ' selected' : ''}${f.method === 'CONNECT' ? ' dim' : ''}" data-id="${f.id}">
      <div class="c id">${f.id}</div>
      <div class="c status ${sc}">${esc(status)}</div>
      <div class="c method">${esc(f.method)}</div>
      <div class="c host" title="${esc(f.host)}">${lock}${esc(f.host)}</div>
      <div class="c path" title="${esc(f.url)}">${esc(f.path || '')}${tags}</div>
      <div class="c type">${esc(shortType(f.contentType, f))}</div>
      <div class="c dur">${fmtDur(f.duration)}</div>
      <div class="c size">${f.resSize ? fmtSize(f.resSize) : ''}</div>
    </div>`;
  }
  rows.innerHTML = html;
}

let lastSidebar = '';
function renderSidebar() {
  const counts = new Map();
  for (const f of S.flows) counts.set(f.host, (counts.get(f.host) || 0) + 1);
  const hosts = [...counts.keys()].sort((a, b) => a.localeCompare(b));
  let pinnedCount = 0;
  for (const f of S.flows) if (S.pinned.has(f.host)) pinnedCount++;
  $('#count-all').textContent = S.flows.length;
  $('#count-pinned').textContent = pinnedCount;
  const html = hosts.map((h) => `<div class="side-item${S.host === h ? ' active' : ''}" data-host="${esc(h)}" title="${esc(h)}">
      ${S.pinned.has(h) ? '📌' : ''}<span class="name">${esc(h)}</span>${isSSLHost(h) ? '<span class="lock" title="SSL Proxying activo">🔓</span>' : ''}
      <span class="count">${counts.get(h)}</span></div>`).join('');
  if (html !== lastSidebar) { $('#domains').innerHTML = html; lastSidebar = html; }
  $$('#sidebar .side-section:first-child .side-item').forEach((el) => el.classList.toggle('active', el.dataset.host === S.host));
}

// ---------------- Selección / Inspector ----------------
function select(id, { additive = false, range = false } = {}) {
  if (range && S.focusId != null) {
    const a = S.view.findIndex((f) => f.id === S.focusId);
    const b = S.view.findIndex((f) => f.id === id);
    if (a >= 0 && b >= 0) for (let i = Math.min(a, b); i <= Math.max(a, b); i++) S.selected.add(S.view[i].id);
  } else if (additive) {
    if (S.selected.has(id)) S.selected.delete(id); else S.selected.add(id);
  } else {
    S.selected = new Set([id]);
  }
  S.focusId = id;
  renderRows();
  loadDetail(id);
}

let detailSeq = 0;
async function loadDetail(id, silent) {
  const seq = ++detailSeq;
  if (id == null) { S.detail = null; renderInspector(); return; }
  const d = await api.detail(id);
  if (seq !== detailSeq) return;
  S.detail = d;
  renderInspector(silent);
}

function renderInspector(keepScroll) {
  const d = S.detail;
  $('#inspector-empty').hidden = !!d;
  $('#inspector-body').hidden = !d;
  if (!d) return;
  const status = d.state === 'failed' ? '<span class="err">ERROR</span>'
    : d.response ? `<span class="${statusClass(d)}">${d.response.statusCode} ${esc(d.response.statusMessage || '')}</span>` : '<span class="s-pending">pendiente…</span>';
  $('#summary-bar').innerHTML = `<b>${esc(d.method)}</b><span class="url">${esc(d.url)}</span>${status}
    <span class="muted">${fmtDur(d.duration)}</span>${d.error ? `<span class="err" title="${esc(d.error)}">⚠ ${esc(d.error)}</span>` : ''}`;
  $$('.tabs[data-pane="req"] button').forEach((b) => b.classList.toggle('active', b.dataset.tab === S.reqTab));
  $$('.tabs[data-pane="res"] button').forEach((b) => b.classList.toggle('active', b.dataset.tab === S.resTab));
  const rc = $('#req-content'); const sc = $('#res-content');
  const st = [rc.scrollTop, sc.scrollTop];
  rc.innerHTML = renderReqTab(d);
  sc.innerHTML = renderResTab(d);
  if (keepScroll) { rc.scrollTop = st[0]; sc.scrollTop = st[1]; }
  bindBodyToolbar();
}

function kvTable(pairs, emptyMsg = 'Sin datos') {
  if (!pairs || !pairs.length) return `<div class="note">${emptyMsg}</div>`;
  return `<table class="kv">${pairs.map(([k, v]) => `<tr><td class="k">${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table>`;
}

function renderReqTab(d) {
  const r = d.request;
  switch (S.reqTab) {
    case 'headers': return kvTable([[':method', d.method], [':url', d.url], ...r.headers]);
    case 'query': {
      try { return kvTable([...new URL(d.url).searchParams], 'Sin parámetros de query'); } catch { return '<div class="note">—</div>'; }
    }
    case 'body': return renderBody(r.body, headerGet(r.headers, 'content-type'), 'req');
    case 'cookies': return kvTable(parseCookies(headerGet(r.headers, 'cookie')), 'Sin cookies');
    case 'raw': return `<pre class="code">${esc(rawRequest(d))}</pre>`;
    default: return '';
  }
}

function renderResTab(d) {
  const r = d.response;
  if (!r) return `<div class="note">${d.error ? esc(d.error) : 'Esperando respuesta…'}</div>`;
  switch (S.resTab) {
    case 'headers': return kvTable([[':status', `${r.statusCode} ${r.statusMessage || ''}`], ...r.headers]);
    case 'body':
      if (d.method === 'CONNECT') return `<div class="note">Túnel HTTPS sin interceptar (${fmtSize(d.reqSize)} ↑ / ${fmtSize(d.resSize)} ↓).<br><br>
        Para ver el contenido, habilitá SSL Proxying para <b>${esc(d.host)}</b> (clic derecho → "Habilitar SSL Proxying").</div>`;
      if (d.tags.includes('websocket')) return '<div class="note">Conexión WebSocket (los frames se reenvían sin decodificar).</div>';
      return renderBody(r.body, headerGet(r.headers, 'content-type'), 'res');
    case 'cookies': return kvTable(r.headers.filter(([k]) => k.toLowerCase() === 'set-cookie'), 'Sin Set-Cookie');
    case 'raw': return `<pre class="code">${esc(rawResponse(r))}</pre>`;
    case 'timing': return renderTiming(d);
    default: return '';
  }
}

function rawRequest(d) {
  let u; try { u = new URL(d.url); } catch { u = { pathname: d.path, search: '' }; }
  const head = `${d.method} ${d.method === 'CONNECT' ? d.url : u.pathname + u.search} HTTP/${d.httpVersion || '1.1'}\n${d.request.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}`;
  const body = d.request.body && d.request.body.size ? bytesToText(b64ToBytes(d.request.body.base64)) : '';
  return `${head}\n\n${body}`;
}
function rawResponse(r) {
  const head = `HTTP/${r.httpVersion || '1.1'} ${r.statusCode} ${r.statusMessage || ''}\n${r.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}`;
  const bytes = r.body ? b64ToBytes(r.body.base64) : new Uint8Array();
  const body = looksBinary(bytes) ? `<${fmtSize(bytes.length)} binarios>` : bytesToText(bytes);
  return `${head}\n\n${body}`;
}

function renderTiming(d) {
  const t = d.timings;
  const total = (t.end || Date.now()) - t.start;
  const wait = t.responseStart ? t.responseStart - t.start : null;
  const recv = t.end && t.responseStart ? t.end - t.responseStart : null;
  const bar = (ms) => (ms == null ? '' : `<div class="timing-bar" style="width:${Math.max(2, (ms / Math.max(total, 1)) * 100)}%"></div>`);
  return `<table class="kv">
    <tr><td class="k">Inicio</td><td>${new Date(d.startedAt).toLocaleString()}</td></tr>
    <tr><td class="k">Espera (TTFB)</td><td>${fmtDur(wait)}${bar(wait)}</td></tr>
    <tr><td class="k">Descarga</td><td>${fmtDur(recv)}${bar(recv)}</td></tr>
    <tr><td class="k">Total</td><td>${fmtDur(total)}${bar(total)}</td></tr>
    <tr><td class="k">Cliente</td><td>${esc(d.client || '')}</td></tr>
    <tr><td class="k">Tamaño request</td><td>${fmtSize(d.reqSize)}</td></tr>
    <tr><td class="k">Tamaño response</td><td>${fmtSize(d.resSize)} (en el cable)</td></tr></table>`;
}

function renderBody(body, contentType, which) {
  if (!body || !body.size) return '<div class="note">Sin body</div>';
  const bytes = b64ToBytes(body.base64);
  const ct = (contentType || '').toLowerCase();
  const modes = ['pretty', 'raw', 'hex'];
  const toolbar = `<div class="pane-toolbar" data-which="${which}">
    ${modes.map((m) => `<button class="small-btn${S.bodyMode === m ? ' active' : ''}" data-mode="${m}">${{ pretty: 'Pretty', raw: 'Raw', hex: 'Hex' }[m]}</button>`).join('')}
    <span class="muted">${fmtSize(body.size)}${body.truncated ? ' · truncado' : ''}</span>
    <span class="tb-flex"></span>
    <button class="small-btn" data-act="copy-body">Copiar</button>
    <button class="small-btn" data-act="save-body">Guardar…</button></div>`;
  let content;
  if (S.bodyMode === 'hex') {
    content = `<pre class="code">${esc(hexdump(bytes))}</pre>`;
  } else if (S.bodyMode === 'pretty' && ct.startsWith('image/')) {
    content = `<img class="body-img" src="data:${esc(ct.split(';')[0])};base64,${body.base64}">`;
  } else if (looksBinary(bytes)) {
    content = `<div class="note">Contenido binario (${esc(ct || 'desconocido')}). Usá Hex o Guardar.</div>`;
  } else {
    const text = bytesToText(bytes);
    if (S.bodyMode === 'pretty') content = prettyText(text, ct);
    else content = `<pre class="code">${esc(text)}</pre>`;
  }
  return toolbar + content;
}

function prettyText(text, ct) {
  const trimmed = text.trim();
  if (ct.includes('json') || /^[[{]/.test(trimmed)) {
    try { return `<pre class="code">${highlightJSON(JSON.stringify(JSON.parse(trimmed), null, 2))}</pre>`; } catch { /* no es JSON válido */ }
  }
  if (ct.includes('x-www-form-urlencoded')) {
    try { return kvTable([...new URLSearchParams(text)]); } catch { /* sigue */ }
  }
  return `<pre class="code">${esc(text)}</pre>`;
}

function bindBodyToolbar() {
  $$('.pane-toolbar').forEach((tb) => {
    tb.onclick = async (e) => {
      const b = e.target.closest('button');
      if (!b) return;
      const which = tb.dataset.which;
      const body = which === 'req' ? S.detail.request.body : S.detail.response.body;
      if (b.dataset.mode) { S.bodyMode = b.dataset.mode; persist('bodyMode', S.bodyMode); renderInspector(); }
      if (b.dataset.act === 'copy-body') { await api.copy(bytesToText(b64ToBytes(body.base64))); toast('Body copiado'); }
      if (b.dataset.act === 'save-body') {
        const name = (new URL(S.detail.url).pathname.split('/').pop() || 'body') + (which === 'req' ? '.request' : '');
        await api.saveBody(body.base64, name);
      }
    };
  });
}

// ---------------- Acciones ----------------
function selectedIds() { return S.selected.size ? [...S.selected] : (S.focusId != null ? [S.focusId] : []); }

async function toggleRecording() {
  S.recording = !S.recording;
  await api.setRecording(S.recording);
  $('#btn-record').classList.toggle('paused', !S.recording);
  toast(S.recording ? 'Grabando' : 'Grabación en pausa');
  refresh();
}

async function clearAll() {
  await api.clear();
  S.flows = []; S.byId.clear(); S.selected.clear(); S.focusId = null; S.detail = null;
  renderInspector(); refresh();
}

async function deleteSelected() {
  const ids = selectedIds();
  if (!ids.length) return;
  await api.deleteFlows(ids);
  const set = new Set(ids);
  S.flows = S.flows.filter((f) => !set.has(f.id));
  ids.forEach((id) => S.byId.delete(id));
  S.selected.clear(); S.focusId = null; S.detail = null;
  renderInspector(); refresh();
}

async function toggleSystemProxy() {
  try {
    S.app = await api.setSystemProxy(!S.app.systemProxy);
    renderAppState();
    toast(S.app.systemProxy ? `Proxy del sistema activado (${S.app.port})` : 'Proxy del sistema desactivado');
  } catch (e) { toast(`No se pudo cambiar el proxy del sistema: ${e.message}`); }
}

async function addSSLHost(pattern) {
  const hosts = [...new Set([...S.app.settings.sslHosts, pattern])];
  S.app = await api.updateSettings({ sslHosts: hosts });
  renderAppState(); lastSidebar = ''; renderSidebar();
  toast(`SSL Proxying habilitado para ${pattern}. Repetí el request para verlo.`);
}
async function removeSSLHost(pattern) {
  S.app = await api.updateSettings({ sslHosts: S.app.settings.sslHosts.filter((h) => h !== pattern) });
  renderAppState(); lastSidebar = ''; renderSidebar();
}

async function repeat(id) {
  const d = await api.detail(id);
  if (!d || d.method === 'CONNECT') return;
  try {
    await api.sendRequest({ method: d.method, url: d.url, headers: d.request.headers, body: d.request.body.size ? bytesToText(b64ToBytes(d.request.body.base64)) : null });
  } catch (e) { toast(`Error al repetir: ${e.message}`); }
}

function runCommand(cmd) {
  ({
    compose: () => openCompose(),
    'export-har': () => api.exportHAR(S.selected.size > 1 ? [...S.selected] : null),
    'toggle-recording': toggleRecording,
    clear: clearAll,
    'toggle-system-proxy': toggleSystemProxy,
    settings: openSSLSettings,
    rules: () => openRules(),
    certificate: openCertificate,
  }[cmd] || (() => {}))();
}

// ---------------- Menú contextual ----------------
function showMenu(x, y, items) {
  const m = $('#ctx-menu');
  m.innerHTML = items.map((it, i) => (it === '-' ? '<div class="sep"></div>' : `<div class="mi" data-i="${i}">${esc(it.label)}</div>`)).join('');
  m.hidden = false;
  const r = m.getBoundingClientRect();
  m.style.left = `${Math.min(x, innerWidth - r.width - 4)}px`;
  m.style.top = `${Math.min(y, innerHeight - r.height - 4)}px`;
  m.onclick = (e) => {
    const el = e.target.closest('.mi');
    if (!el) return;
    m.hidden = true;
    items[Number(el.dataset.i)].run();
  };
}
document.addEventListener('mousedown', (e) => { if (!e.target.closest('#ctx-menu')) $('#ctx-menu').hidden = true; });

async function rowMenu(e, id) {
  const f = S.byId.get(id);
  const d = await api.detail(id);
  if (!d) return;
  const isTunnel = f.method === 'CONNECT';
  const items = [
    { label: 'Copiar URL', run: () => api.copy(f.url).then(() => toast('URL copiada')) },
    ...(!isTunnel ? [
      { label: 'Copiar como cURL', run: () => api.copy(toCurl(d)).then(() => toast('cURL copiado')) },
      { label: 'Copiar body de la respuesta', run: () => api.copy(d.response && d.response.body.size ? bytesToText(b64ToBytes(d.response.body.base64)) : '').then(() => toast('Copiado')) },
      '-',
      { label: 'Repetir', run: () => repeat(id) },
      { label: 'Editar y repetir…', run: () => openCompose(d) },
      { label: 'Map Local (mockear respuesta)…', run: () => openRules(mapLocalFromDetail(d)) },
    ] : []),
    '-',
    isSSLHost(f.host)
      ? { label: `Deshabilitar SSL Proxying para ${f.host}`, run: () => removeSSLHost(f.host) }
      : { label: `Habilitar SSL Proxying para ${f.host}`, run: () => addSSLHost(f.host) },
    { label: `Bloquear ${f.host}`, run: () => addBlockRule(`*://${f.host}/*`) },
    { label: S.pinned.has(f.host) ? `Desfijar ${f.host}` : `Fijar ${f.host}`, run: () => togglePin(f.host) },
    '-',
    { label: S.selected.size > 1 ? `Exportar ${S.selected.size} como HAR…` : 'Exportar como HAR…', run: () => api.exportHAR(selectedIds()) },
    { label: 'Eliminar', run: deleteSelected },
  ];
  showMenu(e.clientX, e.clientY, items);
}

function hostMenu(e, host) {
  const parts = host.split('.');
  const wildcardHost = parts.length > 2 ? `*.${parts.slice(-2).join('.')}` : `*.${host}`;
  showMenu(e.clientX, e.clientY, [
    isSSLHost(host)
      ? { label: 'Deshabilitar SSL Proxying', run: () => removeSSLHost(host) }
      : { label: 'Habilitar SSL Proxying', run: () => addSSLHost(host) },
    { label: `Habilitar SSL Proxying para ${wildcardHost}`, run: () => addSSLHost(wildcardHost) },
    { label: S.pinned.has(host) ? 'Desfijar' : 'Fijar', run: () => togglePin(host) },
    { label: 'Copiar dominio', run: () => api.copy(host) },
    '-',
    { label: 'Eliminar requests de este dominio', run: async () => {
      const ids = S.flows.filter((f) => f.host === host).map((f) => f.id);
      S.selected = new Set(ids); await deleteSelected();
    } },
  ]);
}

function togglePin(host) {
  if (S.pinned.has(host)) S.pinned.delete(host); else S.pinned.add(host);
  persist('pinned', [...S.pinned]);
  lastSidebar = ''; refresh();
}

// ---------------- Modales ----------------
function openModal(title, bodyHTML, buttons) {
  $('#modal').innerHTML = `<div class="m-head">${esc(title)}</div><div class="m-body">${bodyHTML}</div>
    <div class="m-foot">${buttons.map((b, i) => `<button class="btn ${b.cls || ''}" data-b="${i}">${esc(b.label)}</button>`).join('')}</div>`;
  $('#modal-backdrop').hidden = false;
  $('#modal .m-foot').onclick = async (e) => {
    const el = e.target.closest('button');
    if (!el) return;
    const b = buttons[Number(el.dataset.b)];
    const keep = b.run ? await b.run() : false;
    if (keep !== true) closeModal();
  };
  const first = $('#modal input, #modal textarea');
  if (first) first.focus();
}
function closeModal() { $('#modal-backdrop').hidden = true; $('#modal').innerHTML = ''; }
$('#modal-backdrop').addEventListener('mousedown', (e) => { if (e.target.id === 'modal-backdrop') closeModal(); });

const headersToText = (pairs) => (pairs || []).map(([k, v]) => `${k}: ${v}`).join('\n');
const textToHeaders = (txt) => txt.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
  const i = l.indexOf(':');
  return i <= 0 ? [l, ''] : [l.slice(0, i).trim(), l.slice(i + 1).trim()];
});

function openCompose(d) {
  const method = d ? d.method : 'GET';
  const url = d ? d.url : 'https://';
  const headers = d ? d.request.headers.filter(([k]) => !['proxy-connection', 'content-length'].includes(k.toLowerCase())) : [['Accept', '*/*']];
  const body = d && d.request.body.size ? bytesToText(b64ToBytes(d.request.body.base64)) : '';
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  openModal(d ? 'Editar y repetir' : 'Nuevo request', `
    <div class="row2"><label class="narrow">Método<select id="c-method">${methods.map((m) => `<option${m === method ? ' selected' : ''}>${m}</option>`).join('')}</select></label>
    <label>URL<input id="c-url" value="${esc(url)}" spellcheck="false"></label></div>
    <label>Headers <span class="hint">Uno por línea: Nombre: valor</span><textarea id="c-headers" rows="8" spellcheck="false">${esc(headersToText(headers))}</textarea></label>
    <label>Body<textarea id="c-body" rows="8" spellcheck="false">${esc(body)}</textarea></label>`,
  [{ label: 'Cancelar' }, {
    label: 'Enviar', cls: 'primary', run: async () => {
      try {
        await api.sendRequest({ method: $('#c-method').value, url: $('#c-url').value.trim(), headers: textToHeaders($('#c-headers').value), body: $('#c-body').value || null });
        toast('Request enviado');
      } catch (e) { toast(`Error: ${e.message}`); return true; }
      return false;
    },
  }]);
}

function openSSLSettings() {
  const s = S.app.settings;
  openModal('SSL Proxying', `
    <label class="inline"><input type="checkbox" id="s-enabled" ${s.sslProxyingEnabled ? 'checked' : ''}> Habilitar SSL Proxying</label>
    <label class="inline"><input type="checkbox" id="s-all" ${s.sslProxyAll ? 'checked' : ''}> Interceptar <b>todos</b> los dominios HTTPS
      <span class="hint">(puede romper apps con certificate pinning)</span></label>
    <label>Dominios a interceptar <span class="hint">Uno por línea. Acepta comodines: *.uala.com.ar, api.*.com</span>
      <textarea id="s-hosts" rows="8" spellcheck="false">${esc(s.sslHosts.join('\n'))}</textarea></label>
    <label class="inline"><input type="checkbox" id="s-verify" ${s.verifyUpstreamTLS ? 'checked' : ''}> Verificar certificados de los servidores
      <span class="hint">(desactivalo solo para servidores de desarrollo con certificados propios)</span></label>
    <div class="row2"><label class="narrow">Puerto<input id="s-port" type="number" min="1" max="65535" value="${S.app.port}"></label>
    <label class="inline"><input type="checkbox" id="s-auto" ${s.autoSystemProxy ? 'checked' : ''}> Activar proxy del sistema al abrir Proxyboy</label></div>`,
  [{ label: 'Cancelar' }, {
    label: 'Guardar', cls: 'primary', run: async () => {
      try {
        S.app = await api.updateSettings({
          sslProxyingEnabled: $('#s-enabled').checked,
          sslProxyAll: $('#s-all').checked,
          sslHosts: $('#s-hosts').value.split('\n').map((l) => l.trim()).filter(Boolean),
          verifyUpstreamTLS: $('#s-verify').checked,
          autoSystemProxy: $('#s-auto').checked,
          port: Number($('#s-port').value) || 9090,
        });
        renderAppState(); lastSidebar = ''; renderSidebar();
      } catch (e) { toast(`Error: ${e.message}`); return true; }
      return false;
    },
  }]);
}

function openCertificate() {
  const a = S.app;
  const ips = a.ips.map((i) => `${i.address}:${a.port} <span class="muted">(${esc(i.name)})</span>`).join('<br>') || '—';
  openModal('Certificado raíz de Proxyboy', `
    <div>Estado: ${a.caTrusted ? '<b class="s-ok">✔ Instalado y confiable en este equipo</b>' : '<b class="s-err">✖ No instalado / no confiable</b>'}</div>
    <div><span class="muted">Nombre:</span> ${esc(a.caCommonName)}</div>
    <div><span class="muted">SHA-256:</span><code class="box">${esc(a.caFingerprint)}</code></div>
    <div><span class="muted">Archivo:</span><code class="box">${esc(a.caPath)}</code></div>
    <h3 style="margin:6px 0 0">Este equipo</h3>
    <div>${a.platform === 'darwin' ? 'Se agregará al llavero de inicio de sesión como raíz confiable (macOS pedirá tu contraseña).'
    : a.platform === 'win32' ? 'Se agregará al almacén "Entidades de certificación raíz de confianza" del usuario (Windows pedirá confirmación).'
      : 'En Linux: sudo cp proxyboy-ca.pem /usr/local/share/ca-certificates/proxyboy-ca.crt && sudo update-ca-certificates'}</div>
    <div class="muted">Firefox usa su propio almacén: importalo en Ajustes → Privacidad → Certificados. Node.js: export NODE_EXTRA_CA_CERTS=&lt;archivo&gt;.</div>
    <h3 style="margin:6px 0 0">Dispositivos móviles / simuladores</h3>
    <div>1. Configurá el proxy HTTP del Wi-Fi del dispositivo a:<br><span class="mono">${ips}</span></div>
    <div>2. Desde el dispositivo abrí <b class="mono">http://proxy.boy</b> y descargá el certificado.</div>
    <div class="muted">iOS: Ajustes → General → Información → Confianza de certificados → activar Proxyboy.<br>
    Android 7+: las apps deben confiar en CAs de usuario vía network_security_config (solo builds debug).</div>`,
  [
    { label: 'Mostrar archivo', run: () => { api.revealCert(); return true; } },
    { label: 'Exportar…', run: async () => { await api.exportCert(); return true; } },
    { label: 'Cerrar' },
    ...(a.platform !== 'linux' ? [{
      label: a.caTrusted ? 'Reinstalar' : 'Instalar y confiar', cls: 'primary', run: async () => {
        try { S.app = await api.installCert(); renderAppState(); toast(S.app.caTrusted ? 'Certificado instalado' : 'Revisá el diálogo del sistema'); } catch (e) { toast(`No se pudo instalar: ${e.message}`); }
        openCertificate();
        return true;
      },
    }] : []),
  ]);
}

// ---------- Reglas: Map Local + Block ----------
function mapLocalFromDetail(d) {
  const r = d.response;
  let u; try { u = new URL(d.url); } catch { u = null; }
  return {
    enabled: true,
    method: d.method,
    url: u ? `${u.protocol}//${u.host}${u.pathname}*` : d.url,
    status: r ? r.statusCode : 200,
    headers: r ? r.headers.filter(([k]) => !['content-length', 'content-encoding', 'transfer-encoding', 'connection'].includes(k.toLowerCase())) : [['Content-Type', 'application/json']],
    body: r && r.body.size ? bytesToText(b64ToBytes(r.body.base64)) : '',
  };
}

async function addBlockRule(url) {
  const rules = [...S.app.settings.blockRules, { id: Date.now(), enabled: true, url }];
  S.app = await api.updateSettings({ blockRules: rules });
  toast(`Bloqueado: ${url}`);
}

function openRules(prefill) {
  let ml = JSON.parse(JSON.stringify(S.app.settings.mapLocalRules));
  let bl = JSON.parse(JSON.stringify(S.app.settings.blockRules));
  let editing = null;
  if (prefill) { editing = { id: Date.now(), ...prefill }; ml.push(editing); }

  const draw = () => {
    const list = ml.map((r) => `<div class="rule${editing && editing.id === r.id ? ' sel' : ''}" data-id="${r.id}">
      <input type="checkbox" data-toggle="ml" ${r.enabled ? 'checked' : ''}><b>${esc(r.method || '*')}</b><span class="grow" data-edit>${esc(r.url)}</span>
      <span>${esc(r.status)}</span><button class="small-btn btn" data-del="ml">✕</button></div>`).join('') || '<div class="note">Sin reglas</div>';
    const blist = bl.map((r) => `<div class="rule" data-id="${r.id}"><input type="checkbox" data-toggle="bl" ${r.enabled ? 'checked' : ''}>
      <span class="grow">${esc(r.url)}</span><button class="small-btn btn" data-del="bl">✕</button></div>`).join('') || '<div class="note">Sin reglas</div>';
    const ed = editing ? `
      <div class="row2"><label class="narrow">Método<input id="r-method" value="${esc(editing.method || '*')}"></label>
      <label>URL (comodines *)<input id="r-url" value="${esc(editing.url)}" spellcheck="false"></label>
      <label class="narrow">Status<input id="r-status" type="number" value="${esc(editing.status)}"></label></div>
      <label>Headers de respuesta<textarea id="r-headers" rows="4" spellcheck="false">${esc(headersToText(editing.headers))}</textarea></label>
      <label>Body de respuesta<textarea id="r-body" rows="9" spellcheck="false">${esc(editing.body)}</textarea></label>
      <div><button class="btn" id="r-apply">Aplicar cambios a la regla</button></div>` : '';
    $('#rules-root').innerHTML = `
      <div style="display:flex;align-items:center"><b>Map Local</b><span class="hint" style="margin-left:8px">Responde con un mock sin ir al servidor</span>
        <span class="tb-flex"></span><button class="btn" id="r-add">＋ Nueva</button></div>
      <div class="rule-list" id="ml-list">${list}</div>${ed}
      <div style="display:flex;align-items:center;margin-top:8px"><b>Block List</b><span class="hint" style="margin-left:8px">Corta la conexión</span>
        <span class="tb-flex"></span><input id="b-url" placeholder="*://ads.example.com/*" style="width:260px"><button class="btn" id="b-add">Agregar</button></div>
      <div class="rule-list">${blist}</div>`;
  };

  const saveEditing = () => {
    if (!editing || !$('#r-url')) return;
    Object.assign(editing, {
      method: $('#r-method').value.trim().toUpperCase() || '*',
      url: $('#r-url').value.trim(),
      status: Number($('#r-status').value) || 200,
      headers: textToHeaders($('#r-headers').value),
      body: $('#r-body').value,
    });
  };

  openModal('Reglas', '<div id="rules-root" style="display:flex;flex-direction:column;gap:8px"></div>', [
    { label: 'Cancelar' },
    {
      label: 'Guardar', cls: 'primary', run: async () => {
        saveEditing();
        S.app = await api.updateSettings({ mapLocalRules: ml, blockRules: bl });
        toast('Reglas guardadas');
      },
    },
  ]);
  draw();
  $('#rules-root').onclick = (e) => {
    const rowEl = e.target.closest('.rule');
    const id = rowEl && Number(rowEl.dataset.id);
    if (e.target.id === 'r-add') { saveEditing(); editing = { id: Date.now(), enabled: true, method: 'GET', url: 'https://api.example.com/*', status: 200, headers: [['Content-Type', 'application/json']], body: '{\n  "ok": true\n}' }; ml.push(editing); draw(); }
    else if (e.target.id === 'r-apply') { saveEditing(); draw(); }
    else if (e.target.id === 'b-add') { const v = $('#b-url').value.trim(); if (v) { saveEditing(); bl.push({ id: Date.now(), enabled: true, url: v }); draw(); } }
    else if (e.target.dataset.del === 'ml') { ml = ml.filter((r) => r.id !== id); if (editing && editing.id === id) editing = null; draw(); }
    else if (e.target.dataset.del === 'bl') { saveEditing(); bl = bl.filter((r) => r.id !== id); draw(); }
    else if (e.target.dataset.toggle) { const arr = e.target.dataset.toggle === 'ml' ? ml : bl; const r = arr.find((x) => x.id === id); if (r) r.enabled = e.target.checked; }
    else if (rowEl && e.target.closest('#ml-list')) { saveEditing(); editing = ml.find((r) => r.id === id); draw(); }
  };
}

// ---------------- Toast ----------------
let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
}

// ---------------- Eventos de la UI ----------------
function bindUI() {
  $('#rows-viewport').addEventListener('scroll', renderRows);
  window.addEventListener('resize', renderRows);
  $('#rows').addEventListener('mousedown', (e) => {
    const row = e.target.closest('.row');
    if (!row || e.button !== 0) return;
    select(Number(row.dataset.id), { additive: e.metaKey || e.ctrlKey, range: e.shiftKey });
  });
  $('#rows').addEventListener('dblclick', (e) => {
    const row = e.target.closest('.row');
    if (row) { const d = S.detail; if (d && d.method !== 'CONNECT') openCompose(d); }
  });
  $('#rows').addEventListener('contextmenu', (e) => {
    const row = e.target.closest('.row');
    if (!row) return;
    e.preventDefault();
    const id = Number(row.dataset.id);
    if (!S.selected.has(id)) select(id);
    rowMenu(e, id);
  });
  $('#rows-viewport').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      let i = S.view.findIndex((f) => f.id === S.focusId);
      i = e.key === 'ArrowDown' ? Math.min(S.view.length - 1, i + 1) : Math.max(0, i - 1);
      if (S.view[i]) {
        select(S.view[i].id);
        const vp = $('#rows-viewport');
        const y = i * ROW_H;
        if (y < vp.scrollTop) vp.scrollTop = y;
        else if (y + ROW_H > vp.scrollTop + vp.clientHeight) vp.scrollTop = y + ROW_H - vp.clientHeight;
      }
    } else if (e.key === 'Backspace' || e.key === 'Delete') {
      deleteSelected();
    } else if ((e.metaKey || e.ctrlKey) && e.key === 'c') {
      const f = S.byId.get(S.focusId);
      if (f) api.copy(f.url).then(() => toast('URL copiada'));
    } else if ((e.metaKey || e.ctrlKey) && e.key === 'a') {
      e.preventDefault();
      S.selected = new Set(S.view.map((f) => f.id)); renderRows();
    }
  });

  $('#sidebar').addEventListener('click', (e) => {
    const it = e.target.closest('.side-item');
    if (!it) return;
    S.host = it.dataset.host;
    lastSidebar = '';
    refresh();
  });
  $('#sidebar').addEventListener('contextmenu', (e) => {
    const it = e.target.closest('#domains .side-item');
    if (!it) return;
    e.preventDefault();
    hostMenu(e, it.dataset.host);
  });

  $('#filters').addEventListener('click', (e) => {
    const c = e.target.closest('.chip');
    if (!c) return;
    S.chip = c.dataset.filter;
    $$('.chip').forEach((x) => x.classList.toggle('active', x === c));
    refresh();
  });

  let searchTimer;
  $('#search').addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { S.query = e.target.value.trim(); refresh(); }, 120);
  });

  $$('.tabs').forEach((tabs) => tabs.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    if (tabs.dataset.pane === 'req') S.reqTab = b.dataset.tab; else S.resTab = b.dataset.tab;
    renderInspector();
  }));

  $('#btn-record').onclick = toggleRecording;
  $('#btn-clear').onclick = clearAll;
  $('#btn-system-proxy').onclick = toggleSystemProxy;
  $('#btn-compose').onclick = () => openCompose();
  $('#btn-rules').onclick = () => openRules();
  $('#btn-settings').onclick = openSSLSettings;
  $('#btn-cert').onclick = async () => { await reloadState(); openCertificate(); };
  $('#proxy-info').onclick = () => api.copy($('#proxy-info').textContent).then(() => toast('Dirección copiada'));

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeModal(); $('#ctx-menu').hidden = true; }
    if ((e.metaKey || e.ctrlKey) && e.key === 'f') { e.preventDefault(); $('#search').focus(); $('#search').select(); }
  });

  // Resizers
  $$('.resizer').forEach((rz) => {
    rz.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const target = document.getElementById(rz.dataset.target);
      const vertical = rz.classList.contains('v');
      const start = vertical ? e.clientX : e.clientY;
      const size = vertical ? target.offsetWidth : target.offsetHeight;
      const sign = rz.dataset.target === 'inspector' ? -1 : 1;
      const move = (ev) => {
        const delta = ((vertical ? ev.clientX : ev.clientY) - start) * sign;
        if (vertical) target.style.width = `${Math.max(120, size + delta)}px`;
        else target.style.height = `${Math.max(100, size + delta)}px`;
        renderRows();
      };
      const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
  });

  // El estado del certificado / proxy del sistema puede cambiar fuera de la app
  window.addEventListener('focus', () => reloadState());
}

init();
