/* global esc, fmtSize, fmtDur, statusClass, shortType, b64ToBytes, bytesToText, looksBinary, hexdump,
   highlightJSON, headerGet, toCurl, parseCookies, decodeProtobuf, splitGrpcFrames, diffLines,
   HEAD_H, loadColumns, renderHeader, bindHeader, rowHTML, sortView, followsTail */
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
  appFilter: '',
  expandedApps: new Set(store('expandedApps', [])),
  collapsedSections: new Set(store('collapsedSections', [])),
  icons: new Map(), // appId -> dataURL | null | 'loading'
  chip: 'all',
  query: '',
  pinned: new Set(store('pinned', [])),
  reqTab: 'headers',
  resTab: 'body',
  bodyMode: store('bodyMode', 'pretty'),
  detail: null,
  app: null,
  recording: true,
  bpQueue: [],
};

// ---------------- Inicio ----------------
async function init() {
  if (navigator.platform.toLowerCase().includes('mac')) document.body.classList.add('mac');
  loadColumns();
  renderHeader();
  bindHeader();
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
  api.onBreakpoint((bp) => { S.bpQueue.push(bp); if (S.bpQueue.length === 1) showBreakpoint(); });
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
  const hay = `${f.method} ${f.url} ${f.status || ''} ${f.contentType} ${f.error || ''} ${f.tags.join(' ')} ${f.app ? f.app.name : ''}`.toLowerCase();
  return S.query.toLowerCase().split(/\s+/).filter(Boolean).every((term) => {
    if (term.startsWith('-') && term.length > 1) return !hay.includes(term.slice(1));
    return hay.includes(term);
  });
}

function matchHost(f) {
  if (S.appFilter && (!f.app || f.app.id !== S.appFilter)) return false;
  if (!S.host) return true;
  if (S.host === '__pinned') return S.pinned.has(f.host);
  return f.host === S.host;
}

function computeView() {
  S.view = sortView(S.flows.filter((f) => matchHost(f) && matchChip(f) && matchQuery(f)));
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
    if (atBottom && followsTail()) vp.scrollTop = vp.scrollHeight;
    renderRows();
    renderSidebar();
    $('#empty').hidden = S.flows.length > 0;
    const filtered = S.flows.length > 0 && S.view.length === 0;
    $('#empty-filter').hidden = !filtered;
    if (filtered) {
      const parts = [];
      if (S.appFilter) { const f = S.flows.find((x) => x.app && x.app.id === S.appFilter); parts.push(`app <b>${esc(f ? f.app.name : '')}</b>`); }
      if (S.host && S.host !== '__pinned') parts.push(`dominio <b>${esc(S.host)}</b>`);
      if (S.host === '__pinned') parts.push('solo <b>fijados</b>');
      if (S.query) parts.push(`búsqueda <b>"${esc(S.query)}"</b>`);
      if (S.chip !== 'all') parts.push(`tipo <b>${esc(S.chip)}</b>`);
      $('#empty-filter-desc').innerHTML = `Filtros activos: ${parts.join(' · ')}`;
    }
    renderHintBar();
    $('#status-text').textContent = `${S.view.length} de ${S.flows.length} requests${S.recording ? '' : ' · en pausa'}`;
  });
}

// ---------------- Íconos de apps ----------------
function appColor(name) {
  let h = 0;
  for (const ch of name || '?') h = (h * 31 + ch.charCodeAt(0)) % 360;
  return `hsl(${h} 55% 45%)`;
}
function appIconHTML(app) {
  if (!app) return '';
  const icon = S.icons.get(app.id);
  if (icon === undefined && app.source === 'process') {
    S.icons.set(app.id, 'loading');
    api.appIcon(app.id).then((url) => {
      S.icons.set(app.id, url || null);
      if (url) { lastSidebar = ''; refresh(); }
    });
  }
  if (icon && icon !== 'loading') return `<img class="app-icon" src="${icon}" alt="">`;
  return `<span class="app-icon letter" style="background:${appColor(app.name)}">${esc((app.name || '?').trim().charAt(0).toUpperCase())}</span>`;
}
function appSubtitle(app) {
  if (!app) return '';
  if (app.simulator) return `${app.device || 'Simulador'}${app.os ? ` · ${app.os}` : ''}`;
  return app.device || '';
}

function renderRows() {
  const vp = $('#rows-viewport');
  const start = Math.max(0, Math.floor(vp.scrollTop / ROW_H) - 5);
  const end = Math.min(S.view.length, start + Math.ceil(vp.clientHeight / ROW_H) + 10);
  const rows = $('#rows');
  rows.style.top = `${start * ROW_H}px`;
  let html = '';
  for (let i = start; i < end; i++) html += rowHTML(S.view[i]);
  rows.innerHTML = html;
}

let lastSidebar = '';
function renderSidebar() {
  const hostCounts = new Map();
  const apps = new Map(); // id -> { app, count, hosts: Map }
  let pinnedCount = 0;
  for (const f of S.flows) {
    hostCounts.set(f.host, (hostCounts.get(f.host) || 0) + 1);
    if (S.pinned.has(f.host)) pinnedCount++;
    if (f.app) {
      let a = apps.get(f.app.id);
      if (!a) { a = { app: f.app, count: 0, hosts: new Map() }; apps.set(f.app.id, a); }
      a.count++;
      a.hosts.set(f.host, (a.hosts.get(f.host) || 0) + 1);
    }
  }
  $('#count-all').textContent = S.flows.length;
  $('#count-pinned').textContent = pinnedCount;
  $('#count-apps').textContent = apps.size || '';
  $('#count-domains').textContent = hostCounts.size || '';

  const domainItem = (h, count, appId, child) => `<div class="side-item${child ? ' child' : ''}${S.host === h && S.appFilter === (appId || '') ? ' active' : ''}"
      data-host="${esc(h)}" data-app="${esc(appId || '')}" title="${esc(h)}">
      ${S.pinned.has(h) ? '📌' : ''}<span class="name">${esc(h)}</span>${isSSLHost(h) ? '<span class="lock" title="SSL Proxying activo">🔓</span>' : ''}
      <span class="count">${count}</span></div>`;

  const appList = [...apps.values()].sort((x, y) => x.app.name.localeCompare(y.app.name));
  let appsHTML = '';
  for (const { app, count, hosts } of appList) {
    const open = S.expandedApps.has(app.id);
    const sub = appSubtitle(app);
    appsHTML += `<div class="side-item${S.appFilter === app.id && !S.host ? ' active' : ''}" data-app="${esc(app.id)}" data-host=""
        title="${esc(app.name)}${sub ? ` — ${esc(sub)}` : ''}${app.source === 'user-agent' ? ' (detectada por User-Agent)' : ''}">
        <span class="twisty" data-act="toggle">${open ? '▾' : '▸'}</span>${appIconHTML(app)}
        <span class="name-wrap"><span class="name">${esc(app.name)}</span>${sub ? `<span class="app-sub">${esc(sub)}</span>` : ''}</span>
        ${isSSLApp(app) ? '<span class="lock" title="SSL Proxying activo para esta app">🔓</span>' : ''}
        <span class="count">${count}</span></div>`;
    if (open) {
      for (const h of [...hosts.keys()].sort((x, y) => x.localeCompare(y))) appsHTML += domainItem(h, hosts.get(h), app.id, true);
    }
  }
  if (!appList.length) appsHTML = '<div class="note">Las apps aparecen al capturar tráfico</div>';
  const domainsHTML = [...hostCounts.keys()].sort((a, b) => a.localeCompare(b)).map((h) => domainItem(h, hostCounts.get(h), '', false)).join('');

  const key = [appsHTML, domainsHTML, S.host, S.appFilter, [...S.collapsedSections].join(',')].join('|#|');
  if (key !== lastSidebar) {
    $('#apps').innerHTML = S.collapsedSections.has('apps') ? '' : appsHTML;
    $('#domains').innerHTML = S.collapsedSections.has('domains') ? '' : domainsHTML;
    $$('.side-title.collapsible').forEach((t) => t.classList.toggle('collapsed', S.collapsedSections.has(t.dataset.section)));
    lastSidebar = key;
  }
  $$('#sidebar .side-section:first-child .side-item').forEach((el) => el.classList.toggle('active', !S.appFilter && el.dataset.host === S.host));
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
    case 'headers': return kvTable([[':status', `${r.statusCode} ${r.statusMessage || ''}`], [':version', `HTTP/${r.httpVersion || '1.1'}`], ...r.headers])
      + (r.trailers && r.trailers.length ? `<div class="sub-title">Trailers</div>${kvTable(r.trailers)}` : '');
    case 'body':
      if (d.method === 'CONNECT') return `<div class="note">Túnel HTTPS sin interceptar (${fmtSize(d.reqSize)} ↑ / ${fmtSize(d.resSize)} ↓).<br><br>
        Para ver el contenido, habilitá SSL Proxying para <b>${esc(d.host)}</b> (clic derecho → "Habilitar SSL Proxying").</div>`;
      if (d.tags.includes('websocket')) return renderWebSocket(d);
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
    <tr><td class="k">Tamaño response</td><td>${fmtSize(d.resSize)} (en el cable)</td></tr>
    <tr><td class="k">Protocolo</td><td>Cliente HTTP/${esc(d.httpVersion || '1.1')} · Servidor HTTP/${esc((d.response && d.response.httpVersion) || '—')}</td></tr>
    ${d.originalUrl ? `<tr><td class="k">URL original</td><td>${esc(d.originalUrl)}</td></tr>` : ''}</table>
    ${d.notes && d.notes.length ? `<div class="sub-title">Notas / logs de scripts</div><pre class="code">${esc(d.notes.map((n) => `${new Date(n.time).toLocaleTimeString()}  ${n.text}`).join('\n'))}</pre>` : ''}`;
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
  } else if (S.bodyMode === 'pretty' && /grpc|protobuf/.test(ct)) {
    content = renderProtobuf(bytes, ct);
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

function renderProtobuf(bytes, ct) {
  const isGrpc = ct.includes('grpc');
  const frames = isGrpc ? splitGrpcFrames(bytes) : null;
  const parts = [];
  const show = (label, data) => {
    try {
      parts.push(`<div class="sub-title">${esc(label)}</div><pre class="code">${highlightJSON(JSON.stringify(decodeProtobuf(data), null, 2))}</pre>`);
    } catch (e) {
      parts.push(`<div class="sub-title">${esc(label)}</div><div class="note">No se pudo decodificar como Protobuf (${esc(e.message)}).</div><pre class="code">${esc(hexdump(data, 4096))}</pre>`);
    }
  };
  if (frames) {
    frames.forEach((f, i) => {
      if (f.trailers) parts.push(`<div class="sub-title">Trailers gRPC-Web</div><pre class="code">${esc(bytesToText(f.data))}</pre>`);
      else if (f.compressed) parts.push(`<div class="sub-title">Mensaje #${i + 1}</div><div class="note">Mensaje comprimido (grpc-encoding): no se decodifica.</div>`);
      else show(`Mensaje #${i + 1} · ${fmtSize(f.data.length)}`, f.data);
    });
    if (!frames.length) parts.push('<div class="note">Sin mensajes</div>');
  } else {
    show('Protobuf (sin esquema: las claves son números de campo)', bytes);
  }
  return parts.join('');
}

function renderWebSocket(d) {
  const msgs = d.ws || [];
  if (!msgs.length) return '<div class="note">Conexión WebSocket abierta, sin mensajes todavía.</div>';
  const shown = msgs.slice(-500);
  const rows = shown.map((m) => {
    const bytes = b64ToBytes(m.payload);
    let body;
    if (m.opcode === 'text') {
      const text = bytesToText(bytes);
      let pretty = null;
      if (/^\s*[[{]/.test(text)) { try { pretty = highlightJSON(JSON.stringify(JSON.parse(text), null, 2)); } catch { /* texto */ } }
      body = pretty || esc(text);
    } else if (m.opcode === 'close') {
      body = bytes.length >= 2 ? `código ${(bytes[0] << 8) + bytes[1]} ${esc(bytesToText(bytes.subarray(2)))}` : '';
    } else {
      body = esc(hexdump(bytes, 1024));
    }
    return `<div class="ws-msg ${m.dir}"><div class="ws-head"><span class="ws-dir">${m.dir === 'out' ? '↑ enviado' : '↓ recibido'}</span>
      <span>${esc(m.opcode)}</span><span class="muted">${fmtSize(m.size)}${m.truncated ? ' · truncado' : ''}</span>
      <span class="tb-flex"></span><span class="muted">${new Date(m.time).toLocaleTimeString()}</span></div>
      ${body ? `<pre class="code">${body}</pre>` : ''}</div>`;
  }).join('');
  return `${msgs.length > shown.length ? `<div class="note">Mostrando los últimos 500 de ${msgs.length} mensajes</div>` : ''}${rows}`;
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
  }[cmd] || (() => { if (cmd.startsWith('rules:')) openRules(cmd.slice(6)); }))();
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
      '-',
      { label: 'Breakpoint en este endpoint', run: () => addRule('breakpointRules', { method: d.method, url: endpointPattern(d.url), request: true, response: true }, `Breakpoint agregado: ${endpointPattern(d.url)}`) },
      { label: 'Map Local (mockear respuesta)…', run: () => openRules('mapLocalRules', mapLocalFromDetail(d)) },
      { label: 'Map Remote…', run: () => openRules('mapRemoteRules', { method: '*', url: endpointPattern(d.url) }) },
      { label: 'Script…', run: () => openRules('scriptRules', { name: `Script ${d.host}`, method: '*', url: endpointPattern(d.url) }) },
    ] : []),
    ...(S.selected.size === 2 ? [{ label: 'Comparar los 2 seleccionados', run: () => { const [x, y] = [...S.selected].sort((m, n) => m - n); openDiff(x, y); } }] : []),
    '-',
    isSSLHost(f.host)
      ? { label: `Deshabilitar SSL Proxying para ${f.host}`, run: () => removeSSLHost(f.host) }
      : { label: `Habilitar SSL Proxying para ${f.host}`, run: () => addSSLHost(f.host) },
    { label: `Bloquear ${f.host}`, run: () => addBlockRule(`*://${f.host}*`) },
    { label: S.pinned.has(f.host) ? `Desfijar ${f.host}` : `Fijar ${f.host}`, run: () => togglePin(f.host) },
    ...(f.app ? [{ label: `Ver solo ${f.app.name}`, run: () => { S.appFilter = f.app.id; S.host = ''; lastSidebar = ''; refresh(); } }] : []),
    '-',
    { label: S.selected.size > 1 ? `Exportar ${S.selected.size} como HAR…` : 'Exportar como HAR…', run: () => api.exportHAR(selectedIds()) },
    { label: 'Eliminar', run: deleteSelected },
  ];
  showMenu(e.clientX, e.clientY, items);
}

async function installCertInSims(udids) {
  try {
    const r = await api.installCertInSimulators(udids);
    S.app = await api.state();
    renderAppState();
    if (r.failed.length) toast(`No se pudo instalar en ${r.failed.length} simulador(es): ${r.failed[0].error}`);
    else toast('Certificado instalado en el simulador. Reiniciá la app para que use conexiones nuevas.');
  } catch (e) { toast(`Error: ${e.message}`); }
}

function isSSLApp(app) {
  const s = S.app && S.app.settings;
  return !!(s && s.sslProxyingEnabled && app && (s.sslApps || []).includes(app.id));
}

async function toggleSSLApp(app, on) {
  const list = new Set(S.app.settings.sslApps || []);
  if (on) list.add(app.id); else list.delete(app.id);
  S.app = await api.updateSettings({ sslApps: [...list] });
  renderAppState(); lastSidebar = ''; refresh();
  const needsCert = on && app.simulator && app.udid && !(S.app.simulatorsWithCert || []).includes(app.udid);
  toast(on
    ? `SSL Proxying activado para todo el tráfico de ${app.name}.${needsCert ? ' Falta instalar el certificado en el simulador.' : ' Las conexiones nuevas se van a descifrar.'}`
    : `SSL Proxying desactivado para ${app.name}`);
}

function appHosts(appId) {
  return [...new Set(S.flows.filter((f) => f.app && f.app.id === appId).map((f) => f.host))];
}

async function enableSSLForApp(app) {
  const hosts = appHosts(app.id);
  const current = new Set(S.app.settings.sslHosts);
  const added = hosts.filter((h) => !current.has(h));
  if (added.length) {
    S.app = await api.updateSettings({ sslHosts: [...current, ...added] });
    renderAppState(); lastSidebar = ''; refresh();
  }
  const needsCert = app.simulator && app.udid && !(S.app.simulatorsWithCert || []).includes(app.udid);
  toast(`SSL Proxying activado para ${added.length} dominio(s) de ${app.name}.${needsCert ? ' Instalá el certificado en el simulador.' : ' Reiniciá la app para ver las conexiones nuevas.'}`);
}

async function restartSimApp(app) {
  try {
    await api.restartSimulatorApp(app.udid, app.bundleId);
    toast(`${app.name} reiniciada en ${app.device}`);
  } catch (e) { toast(`No se pudo reiniciar: ${e.message}`); }
}

function appMenu(e, appId) {
  const f = S.flows.find((x) => x.app && x.app.id === appId);
  if (!f) return;
  const app = f.app;
  const hosts = appHosts(appId);
  const pending = hosts.filter((h) => !isSSLHost(h));
  const certOk = (S.app.simulatorsWithCert || []).includes(app.udid);
  showMenu(e.clientX, e.clientY, [
    { label: 'Ver solo esta app', run: () => { S.appFilter = appId; S.host = ''; lastSidebar = ''; refresh(); } },
    isSSLApp(app)
      ? { label: `Deshabilitar SSL Proxying para ${app.name}`, run: () => toggleSSLApp(app, false) }
      : { label: `Habilitar SSL Proxying para todo el tráfico de ${app.name}`, run: () => toggleSSLApp(app, true) },
    ...(pending.length ? [{ label: `Habilitar SSL Proxying solo para sus dominios actuales (${pending.length})`, run: () => enableSSLForApp(app) }] : []),
    ...(app.simulator && app.udid ? [
      '-',
      { label: `${certOk ? 'Reinstalar' : 'Instalar'} certificado en ${app.device}`, run: () => installCertInSims([app.udid]) },
      ...(app.bundleId ? [{ label: `Reiniciar ${app.name} en el simulador`, run: () => restartSimApp(app) }] : []),
    ] : []),
    '-',
    { label: 'Eliminar sus requests', run: async () => {
      S.selected = new Set(S.flows.filter((x) => x.app && x.app.id === appId).map((x) => x.id)); await deleteSelected();
    } },
  ]);
}

// Aviso cuando la app/dominio filtrado solo tiene conexiones HTTPS sin descifrar
// Conexiones de la app seleccionada que no pasan por Proxyboy (se consulta cada pocos segundos)
const direct = { appId: null, at: 0, data: null, pending: false };
function checkDirect(appId) {
  if (direct.pending || (direct.appId === appId && Date.now() - direct.at < 5000)) return;
  direct.pending = true;
  api.directConnections(appId).then((data) => {
    direct.appId = appId; direct.at = Date.now(); direct.data = data; direct.pending = false;
    renderHintBar();
  }).catch(() => { direct.pending = false; });
}

function renderHintBar() {
  const bar = $('#hint-bar');
  let html = '';
  if (S.appFilter) {
    const flows = S.flows.filter((f) => f.app && f.app.id === S.appFilter);
    const app = flows[0] && flows[0].app;
    const tunnels = isSSLApp(app) ? [] : flows.filter((f) => f.method === 'CONNECT' && f.tags.includes('tunnel'));
    const sslErrors = flows.filter((f) => f.tags.includes('ssl-error'));
    if (app && app.source === 'process') checkDirect(app.id);
    const d = direct.appId === S.appFilter ? direct.data : null;
    if (app && d && d.count) {
      const list = d.remotes.map(esc).join(', ');
      html = S.app.systemProxy
        ? `⚠ <span><b>${esc(app.name)}</b> tiene <b>${d.count}</b> conexión(es) abiertas que <b>no pasan por Proxyboy</b> (se abrieron antes de activar el proxy y la app las sigue reusando): esos requests no se ven. <span class="muted">${list}</span></span>
          <span class="tb-flex"></span>${app.simulator && app.bundleId ? '<button class="btn primary" data-hint="restart">Reiniciar app</button>' : '<span class="muted">Reiniciá la app.</span>'}`
        : `⚠ <span>El <b>proxy del sistema está apagado</b>: <b>${esc(app.name)}</b> se conecta directo (${d.count} conexión(es)) y sus requests no pasan por Proxyboy.</span>
          <span class="tb-flex"></span><button class="btn primary" data-hint="sysproxy">Activar proxy del sistema</button>`;
    } else if (app && sslErrors.length && app.simulator && !(S.app.simulatorsWithCert || []).includes(app.udid)) {
      html = `⚠ <span><b>${esc(app.name)}</b> rechaza el certificado: falta instalarlo en el simulador <b>${esc(app.device)}</b>.</span>
        <span class="tb-flex"></span><button class="btn primary" data-hint="cert">Instalar certificado en el simulador</button>`;
    } else if (app && tunnels.length) {
      html = `🔒 <span><b>${tunnels.length}</b> conexión(es) HTTPS de <b>${esc(app.name)}</b> no se descifran: SSL Proxying no está activo para esta app.</span>
        <span class="tb-flex"></span><button class="btn primary" data-hint="ssl">Habilitar SSL Proxying</button>
        ${app.simulator && app.udid && !(S.app.simulatorsWithCert || []).includes(app.udid) ? '<button class="btn" data-hint="cert">Instalar certificado en el simulador</button>' : ''}
        ${app.simulator && app.bundleId ? '<button class="btn" data-hint="restart">Reiniciar app</button>' : ''}`;
    }
    bar.onclick = (ev) => {
      const b = ev.target.closest('[data-hint]');
      if (!b || !app) return;
      if (b.dataset.hint === 'ssl') toggleSSLApp(app, true);
      if (b.dataset.hint === 'cert') installCertInSims([app.udid]).then(refresh);
      if (b.dataset.hint === 'restart') restartSimApp(app).then(() => { direct.at = 0; });
      if (b.dataset.hint === 'sysproxy') toggleSystemProxy().then(() => { direct.at = 0; refresh(); });
    };
  }
  if (bar.innerHTML !== html) bar.innerHTML = html;
  bar.hidden = !html;
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
function openModal(title, bodyHTML, buttons, { wide = false } = {}) {
  $('#modal').classList.toggle('wide', wide);
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
    <label class="inline"><input type="checkbox" id="s-http2" ${s.http2 !== false ? 'checked' : ''}> Habilitar HTTP/2
      <span class="hint">(necesario para gRPC; desactivalo si un cliente falla)</span></label>
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
          http2: $('#s-http2').checked,
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
    ${a.platform === 'darwin' ? `<h3 style="margin:6px 0 0">Simuladores de iOS</h3>
    <div class="muted">Cada simulador tiene su propio almacén de certificados: que la Mac confíe en Proxyboy no alcanza.</div>
    ${(a.simulators || []).length ? a.simulators.map((s) => `<div class="sim-row">📱 <b>${esc(s.name)}</b> <span class="muted">${esc(s.os)}</span>
      <span class="tb-flex"></span>${a.simulatorsWithCert.includes(s.udid) ? '<span class="s-ok">✔ instalado</span>' : '<span class="muted">sin instalar</span>'}</div>`).join('')
    : '<div class="muted">No hay simuladores encendidos.</div>'}` : ''}
    <h3 style="margin:6px 0 0">Android (emuladores y USB)</h3>
    ${androidSectionHTML(a)}
    <h3 style="margin:6px 0 0">Celulares por Wi-Fi</h3>
    <div>1. Configurá el proxy HTTP del Wi-Fi del dispositivo a:<br><span class="mono">${ips}</span></div>
    <div>2. Desde el dispositivo abrí <b class="mono">http://proxy.boy</b> y descargá el certificado.</div>
    <div class="muted">iOS: Ajustes → General → Información → Confianza de certificados → activar Proxyboy.<br>
    Android 7+: las apps deben confiar en CAs de usuario vía network_security_config (solo builds debug).</div>`,
  [
    ...((a.simulators || []).length ? [{
      label: 'Instalar en simuladores iOS', run: async () => {
        await installCertInSims(a.simulators.map((s) => s.udid));
        openCertificate();
        return true;
      },
    }] : []),
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
  $('#modal .m-body').onclick = async (e) => {
    const b = e.target.closest('[data-android]');
    if (!b) return;
    const serial = b.dataset.serial;
    b.disabled = true;
    try {
      if (b.dataset.android === 'setup') {
        const r = await api.androidSetup(serial);
        toast(`Proxy ${r.proxy} configurado y certificado copiado. Terminá la instalación en el dispositivo.`);
      } else if (b.dataset.android === 'clear') {
        await api.androidClear(serial);
        toast('Proxy quitado del dispositivo');
      } else if (b.dataset.android === 'refresh') {
        toast('Buscando dispositivos…');
      }
    } catch (err) { toast(`Error: ${err.message.split('\n')[0]}`); }
    S.app = await api.state();
    openCertificate();
  };
}

function androidSectionHTML(a) {
  if (a.androidDevices === null || a.androidDevices === undefined) {
    return '<div class="muted">No se encontró <span class="mono">adb</span>. Instalá Android Studio (SDK platform-tools) o definí ANDROID_HOME.</div>';
  }
  const rows = a.androidDevices.map((d) => {
    if (d.state !== 'device') {
      return `<div class="sim-row">🤖 <b>${esc(d.name)}</b><span class="tb-flex"></span><span class="muted">${d.state === 'unauthorized' ? 'aceptá la depuración USB en el teléfono' : esc(d.state)}</span></div>`;
    }
    const status = d.usingProxyboy ? '<span class="s-ok">✔ usando Proxyboy</span>'
      : d.proxy ? `<span class="s-4xx" title="Otro proxy configurado">proxy: ${esc(d.proxy)}</span>` : '<span class="muted">sin proxy</span>';
    return `<div class="sim-row">🤖 <b>${esc(d.name)}</b> <span class="muted">${d.emulator ? 'Emulador' : 'USB'} · Android ${esc(d.android || '?')}</span>
      <span class="tb-flex"></span>${status}
      ${d.usingProxyboy ? `<button class="btn" data-android="clear" data-serial="${esc(d.serial)}">Quitar proxy</button>` : ''}
      <button class="btn${d.usingProxyboy ? '' : ' primary'}" data-android="setup" data-serial="${esc(d.serial)}">${d.usingProxyboy ? 'Recopiar certificado' : 'Configurar'}</button></div>`;
  }).join('');
  return `${rows || '<div class="muted">No hay emuladores ni dispositivos conectados. Abrí un emulador o conectá el teléfono con depuración USB.</div>'}
    <div class="row-inline"><button class="btn" data-android="refresh">Buscar de nuevo</button></div>
    <div class="muted">"Configurar" pone el proxy en el dispositivo, copia el certificado a <span class="mono">Descargas/proxyboy-ca.crt</span>
    y abre Ajustes. Ahí: <b>Seguridad → Más ajustes de seguridad → Encriptación y credenciales → Instalar un certificado → Certificado de CA</b>.
    La app tiene que confiar en CAs de usuario (<span class="mono">network_security_config</span> con <span class="mono">&lt;certificates src="user"/&gt;</span> en debug).
    Al cerrar Proxyboy se quita el proxy del dispositivo.</div>`;
}

// ---------- Reglas ----------
const F = {
  method: { key: 'method', label: 'Método', narrow: true, placeholder: '*' },
  url: { key: 'url', label: 'URL (comodines *)', placeholder: 'https://api.example.com/v1/*' },
};
const RULE_TYPES = {
  mapLocalRules: {
    label: 'Map Local', hint: 'Responde con un mock sin ir al servidor',
    fields: [[F.method, F.url, { key: 'status', label: 'Status', type: 'number', narrow: true }],
      { key: 'headers', label: 'Headers de respuesta', type: 'headers', rows: 4 },
      { key: 'body', label: 'Body de respuesta', type: 'textarea', rows: 10 }],
    make: () => ({ method: 'GET', url: 'https://api.example.com/*', status: 200, headers: [['Content-Type', 'application/json']], body: '{\n  "ok": true\n}' }),
    summary: (r) => String(r.status),
  },
  mapRemoteRules: {
    label: 'Map Remote', hint: 'Redirige requests a otro servidor (ej. producción → local)',
    fields: [[F.method, F.url], { key: 'to', label: 'Destino (esquema://host:puerto[/path])', placeholder: 'http://localhost:8080' },
      { key: 'preserveHost', label: 'Mantener el header Host original', type: 'checkbox' }],
    make: () => ({ method: '*', url: 'https://api.example.com/*', to: 'http://localhost:8080', preserveHost: false }),
    summary: (r) => `→ ${r.to || ''}`,
  },
  breakpointRules: {
    label: 'Breakpoints', hint: 'Pausa el request/response para editarlo antes de seguir',
    fields: [[F.method, F.url], [{ key: 'request', label: 'Pausar request', type: 'checkbox' }, { key: 'response', label: 'Pausar response', type: 'checkbox' }]],
    make: () => ({ method: '*', url: 'https://api.example.com/*', request: true, response: true }),
    summary: (r) => [r.request && 'req', r.response && 'res'].filter(Boolean).join('+'),
  },
  scriptRules: {
    label: 'Scripts', hint: 'JavaScript que modifica requests y responses al vuelo',
    fields: [[{ key: 'name', label: 'Nombre', narrow: true }, F.method, F.url],
      { key: 'code', label: 'Código', type: 'textarea', rows: 18, code: true }],
    make: () => ({
      name: 'Mi script', method: '*', url: 'https://api.example.com/*',
      code: `// request: { method, url, headers, body }  ·  response: { statusCode, headers, body }
// Devolvé el objeto modificado. console.log() aparece en la pestaña Timing del request.
// context.sharedState persiste entre ejecuciones.

async function onRequest(context, url, request) {
  // request.headers['Authorization'] = 'Bearer token-de-prueba';
  return request;
}

async function onResponse(context, url, request, response) {
  // const body = JSON.parse(response.body);
  // body.feature_flag = true;
  // response.body = body;   // se serializa a JSON automáticamente
  return response;
}
`,
    }),
    summary: (r) => r.name || '',
  },
  blockRules: {
    label: 'Block List', hint: 'Corta la conexión de los requests que coincidan',
    fields: [[F.method, F.url]],
    make: () => ({ method: '*', url: '*://ads.example.com/*' }),
    summary: () => '',
  },
};

function mapLocalFromDetail(d) {
  const r = d.response;
  let u; try { u = new URL(d.url); } catch { u = null; }
  return {
    method: d.method,
    url: u ? `${u.protocol}//${u.host}${u.pathname}*` : d.url,
    status: r ? r.statusCode : 200,
    headers: r ? r.headers.filter(([k]) => !['content-length', 'content-encoding', 'transfer-encoding', 'connection'].includes(k.toLowerCase())) : [['Content-Type', 'application/json']],
    body: r && r.body.size ? bytesToText(b64ToBytes(r.body.base64)) : '',
  };
}

function endpointPattern(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}${u.pathname}*`; } catch { return url; }
}

async function addRule(type, rule, msg) {
  const list = [...(S.app.settings[type] || []), { id: Date.now(), enabled: true, ...rule }];
  S.app = await api.updateSettings({ [type]: list });
  if (msg) toast(msg);
}

async function addBlockRule(url) {
  await addRule('blockRules', { method: '*', url }, `Bloqueado: ${url}`);
}

function openRules(type = 'mapLocalRules', prefill) {
  const lists = {};
  for (const k of Object.keys(RULE_TYPES)) lists[k] = JSON.parse(JSON.stringify(S.app.settings[k] || []));
  let current = type;
  let editing = null;
  if (prefill) { editing = { id: Date.now(), enabled: true, ...RULE_TYPES[type].make(), ...prefill }; lists[type].push(editing); }

  const fieldHTML = (f, r) => {
    const v = r[f.key];
    const id = `rf-${f.key}`;
    if (f.type === 'checkbox') return `<label class="inline"><input type="checkbox" id="${id}" data-k="${f.key}" ${v ? 'checked' : ''}> ${esc(f.label)}</label>`;
    if (f.type === 'textarea' || f.type === 'headers') {
      const val = f.type === 'headers' ? headersToText(v) : (v || '');
      return `<label>${esc(f.label)}<textarea id="${id}" data-k="${f.key}" data-type="${f.type}" rows="${f.rows || 6}" spellcheck="false" ${f.code ? 'class="code-editor"' : ''}>${esc(val)}</textarea></label>`;
    }
    return `<label class="${f.narrow ? 'narrow' : ''}">${esc(f.label)}<input id="${id}" data-k="${f.key}" ${f.type === 'number' ? 'type="number"' : ''} value="${esc(v ?? '')}" placeholder="${esc(f.placeholder || '')}" spellcheck="false"></label>`;
  };

  const draw = () => {
    const T = RULE_TYPES[current];
    const list = lists[current];
    const tabs = Object.entries(RULE_TYPES).map(([k, t]) => {
      const n = lists[k].filter((r) => r.enabled).length;
      return `<button class="${k === current ? 'active' : ''}" data-type="${k}">${esc(t.label)}${n ? ` <span class="badge">${n}</span>` : ''}</button>`;
    }).join('');
    const rows = list.map((r) => `<div class="rule${editing && editing.id === r.id ? ' sel' : ''}" data-id="${r.id}">
      <input type="checkbox" data-toggle ${r.enabled ? 'checked' : ''}><b>${esc(r.method || '*')}</b>
      <span class="grow">${esc(r.url)}</span><span class="muted">${esc(T.summary(r))}</span>
      <button class="small-btn btn" data-del>✕</button></div>`).join('') || '<div class="note">Sin reglas. Creá una con ＋ Nueva o desde el menú contextual de un request.</div>';
    const editor = editing && list.includes(editing) ? T.fields.map((f) => (Array.isArray(f)
      ? `<div class="row2">${f.map((x) => fieldHTML(x, editing)).join('')}</div>` : fieldHTML(f, editing))).join('') : '';
    $('#rules-root').innerHTML = `<div class="tabs rule-tabs">${tabs}</div>
      <div style="display:flex;align-items:center"><span class="hint">${esc(T.hint)}</span><span class="tb-flex"></span>
      <button class="btn" id="r-add">＋ Nueva</button></div>
      <div class="rule-list">${rows}</div>
      ${editor ? `<div class="rule-editor">${editor}</div>` : ''}`;
  };

  // Los cambios del editor se aplican al objeto en vivo
  const onInput = (e) => {
    const k = e.target.dataset.k;
    if (!k || !editing) return;
    if (e.target.type === 'checkbox') editing[k] = e.target.checked;
    else if (e.target.dataset.type === 'headers') editing[k] = textToHeaders(e.target.value);
    else if (e.target.type === 'number') editing[k] = Number(e.target.value);
    else editing[k] = k === 'method' ? e.target.value.toUpperCase() : e.target.value;
  };

  openModal('Reglas', '<div id="rules-root" style="display:flex;flex-direction:column;gap:8px"></div>', [
    { label: 'Cerrar' },
    {
      label: 'Guardar', cls: 'primary', run: async () => {
        try {
          for (const r of lists.mapRemoteRules) if (r.enabled) new URL(r.to);
        } catch { toast('Map Remote: el destino debe ser una URL válida (ej. http://localhost:8080)'); return true; }
        S.app = await api.updateSettings(lists);
        toast('Reglas guardadas');
        draw(); // refresca los contadores de las pestañas
        return true; // la ventana queda abierta para seguir editando
      },
    },
  ], { wide: true });
  draw();
  const root = $('#rules-root');
  root.addEventListener('input', onInput);
  root.addEventListener('change', (e) => {
    if (e.target.dataset.toggle !== undefined) {
      const r = lists[current].find((x) => x.id === Number(e.target.closest('.rule').dataset.id));
      if (r) r.enabled = e.target.checked;
      return;
    }
    if (e.target.dataset.k) {
      // Refrescamos la fila de la lista sin perder el foco del editor
      const row = root.querySelector(`.rule[data-id="${editing.id}"]`);
      if (row) {
        row.querySelector('b').textContent = editing.method || '*';
        row.querySelector('.grow').textContent = editing.url;
        row.querySelector('.muted').textContent = RULE_TYPES[current].summary(editing);
      }
    }
  });
  root.addEventListener('keydown', (e) => {
    // Tab inserta indentación en el editor de código
    if (e.key === 'Tab' && e.target.classList.contains('code-editor')) {
      e.preventDefault();
      const t = e.target;
      const { selectionStart: a, selectionEnd: b } = t;
      t.value = `${t.value.slice(0, a)}  ${t.value.slice(b)}`;
      t.selectionStart = t.selectionEnd = a + 2;
      onInput(e);
    }
  });
  root.addEventListener('click', (e) => {
    const tab = e.target.closest('.rule-tabs button');
    if (tab) { current = tab.dataset.type; editing = null; draw(); return; }
    if (e.target.id === 'r-add') {
      editing = { id: Date.now(), enabled: true, ...RULE_TYPES[current].make() };
      lists[current].push(editing);
      draw();
      return;
    }
    const row = e.target.closest('.rule');
    if (!row) return;
    const id = Number(row.dataset.id);
    if (e.target.dataset.del !== undefined) {
      lists[current] = lists[current].filter((r) => r.id !== id);
      if (editing && editing.id === id) editing = null;
      draw();
    } else if (e.target.dataset.toggle === undefined) {
      editing = lists[current].find((r) => r.id === id);
      draw();
    }
  });
}

// ---------- Breakpoints (editor en vivo) ----------
function showBreakpoint() {
  const bp = S.bpQueue[0];
  if (!bp) { $('#bp-backdrop').hidden = true; return; }
  const isReq = bp.phase === 'request';
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  if (isReq && !methods.includes(bp.method)) methods.push(bp.method);
  const top = isReq
    ? `<div class="row2"><label class="narrow">Método<select id="bp-method">${methods.map((m) => `<option${m === bp.method ? ' selected' : ''}>${m}</option>`).join('')}</select></label>
       <label>URL<input id="bp-url" value="${esc(bp.url)}" spellcheck="false"></label></div>`
    : `<div class="mono muted">${esc(bp.method)} ${esc(bp.url)}</div>
       <div class="row2"><label class="narrow">Status<input id="bp-status" type="number" value="${bp.statusCode}"></label><span></span></div>`;
  const bodyField = bp.binaryBody
    ? `<div class="note">Body binario de ${fmtSize(bp.binaryBody)}: se envía sin cambios.</div>`
    : `<label>Body <span class="hint"><button class="small-btn btn" id="bp-format" type="button">Formatear JSON</button></span>
       <textarea id="bp-body" rows="12" spellcheck="false">${esc(bp.body || '')}</textarea></label>`;
  $('#bp-modal').innerHTML = `<div class="m-head">⏸ Breakpoint · ${isReq ? 'Request' : 'Response'}
      <span class="tb-flex"></span>${S.bpQueue.length > 1 ? `<span class="badge">${S.bpQueue.length - 1} más en cola</span>` : ''}</div>
    <div class="m-body">${top}
      <label>Headers <span class="hint">Uno por línea: Nombre: valor</span><textarea id="bp-headers" rows="7" spellcheck="false">${esc(headersToText(bp.headers))}</textarea></label>
      ${bodyField}</div>
    <div class="m-foot"><button class="btn danger" id="bp-abort">Abortar</button><span class="tb-flex"></span>
      ${S.bpQueue.length > 1 ? '<button class="btn" id="bp-all">Ejecutar todos</button>' : ''}
      <button class="btn primary" id="bp-exec">Ejecutar ⏎</button></div>`;
  $('#bp-backdrop').hidden = false;
  const originalBody = bp.body || '';
  const finish = async (action) => {
    const decision = { action };
    if (action === 'execute') {
      decision.headers = textToHeaders($('#bp-headers').value);
      if (isReq) { decision.method = $('#bp-method').value; decision.url = $('#bp-url').value.trim(); } else decision.statusCode = Number($('#bp-status').value) || bp.statusCode;
      const bodyEl = $('#bp-body');
      if (bodyEl && bodyEl.value !== originalBody) decision.body = bodyEl.value;
    }
    S.bpQueue.shift();
    await api.resolveBreakpoint(bp.bpId, decision);
    showBreakpoint();
  };
  $('#bp-exec').onclick = () => finish('execute');
  $('#bp-abort').onclick = () => finish('abort');
  if ($('#bp-all')) {
    $('#bp-all').onclick = async () => {
      await finish('execute');
      while (S.bpQueue.length) { const next = S.bpQueue.shift(); await api.resolveBreakpoint(next.bpId, { action: 'execute' }); }
      showBreakpoint();
    };
  }
  if ($('#bp-format')) {
    $('#bp-format').onclick = () => {
      try { $('#bp-body').value = JSON.stringify(JSON.parse($('#bp-body').value), null, 2); } catch { toast('El body no es JSON válido'); }
    };
  }
  $('#bp-modal').onkeydown = (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') finish('execute'); };
  const first = $('#bp-url') || $('#bp-status');
  if (first) first.focus();
}

// ---------- Comparar dos requests ----------
function flowAsText(d) {
  const pretty = (body, ct) => {
    if (!body || !body.size) return '';
    const bytes = b64ToBytes(body.base64);
    if (looksBinary(bytes)) return `<${fmtSize(bytes.length)} binarios>`;
    const text = bytesToText(bytes);
    if ((ct || '').includes('json') || /^\s*[[{]/.test(text)) { try { return JSON.stringify(JSON.parse(text), null, 2); } catch { /* texto */ } }
    return text;
  };
  const req = `${d.method} ${d.url}\n${d.request.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${pretty(d.request.body, headerGet(d.request.headers, 'content-type'))}`;
  const r = d.response;
  const res = r ? `HTTP ${r.statusCode} ${r.statusMessage || ''}\n${r.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${pretty(r.body, headerGet(r.headers, 'content-type'))}` : `(sin respuesta) ${d.error || ''}`;
  return { req, res };
}

async function openDiff(idA, idB) {
  const [a, b] = await Promise.all([api.detail(idA), api.detail(idB)]);
  if (!a || !b) return;
  const ta = flowAsText(a);
  const tb = flowAsText(b);
  const render = (x, y) => {
    const lines = diffLines(x, y);
    const changes = lines.filter((l) => l.t !== ' ').length;
    return { changes, html: lines.map((l) => `<div class="dl d${l.t === '+' ? 'add' : l.t === '-' ? 'del' : 'eq'}"><span class="dg">${l.t}</span>${esc(l.s)}</div>`).join('') };
  };
  const rq = render(ta.req, tb.req);
  const rs = render(ta.res, tb.res);
  openModal(`Comparar #${idA} ↔ #${idB}`, `
    <div class="diff-legend"><span class="ddel">− #${idA} ${esc(a.method)} ${esc(a.url)}</span><span class="dadd">+ #${idB} ${esc(b.method)} ${esc(b.url)}</span></div>
    <div class="sub-title">Request · ${rq.changes} líneas distintas</div><div class="diff">${rq.html}</div>
    <div class="sub-title">Response · ${rs.changes} líneas distintas</div><div class="diff">${rs.html}</div>`,
  [{ label: 'Cerrar', cls: 'primary' }], { wide: true });
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
        // El encabezado es sticky: la fila i empieza en HEAD_H + i * ROW_H dentro del área con scroll
        const y = i * ROW_H;
        if (y < vp.scrollTop) vp.scrollTop = y;
        else if (HEAD_H + y + ROW_H > vp.scrollTop + vp.clientHeight) vp.scrollTop = HEAD_H + y + ROW_H - vp.clientHeight;
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

  const toggleApp = (id) => {
    if (S.expandedApps.has(id)) S.expandedApps.delete(id); else S.expandedApps.add(id);
    persist('expandedApps', [...S.expandedApps]);
    lastSidebar = ''; renderSidebar();
  };
  $('#sidebar').addEventListener('click', (e) => {
    const title = e.target.closest('.side-title.collapsible');
    if (title) {
      const sec = title.dataset.section;
      if (S.collapsedSections.has(sec)) S.collapsedSections.delete(sec); else S.collapsedSections.add(sec);
      persist('collapsedSections', [...S.collapsedSections]);
      lastSidebar = ''; renderSidebar();
      return;
    }
    const it = e.target.closest('.side-item');
    if (!it) return;
    if (e.target.dataset.act === 'toggle') { toggleApp(it.dataset.app); return; }
    S.host = it.dataset.host || '';
    S.appFilter = it.dataset.app || '';
    lastSidebar = '';
    refresh();
  });
  $('#sidebar').addEventListener('dblclick', (e) => {
    const it = e.target.closest('#apps .side-item:not(.child)');
    if (it) toggleApp(it.dataset.app);
  });
  $('#sidebar').addEventListener('contextmenu', (e) => {
    const appItem = e.target.closest('#apps .side-item:not(.child)');
    if (appItem) { e.preventDefault(); appMenu(e, appItem.dataset.app); return; }
    const it = e.target.closest('#domains .side-item, #apps .side-item.child');
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

  $('#btn-clear-filters').onclick = () => {
    S.appFilter = ''; S.host = ''; S.query = ''; S.chip = 'all';
    $('#search').value = '';
    $$('.chip').forEach((x) => x.classList.toggle('active', x.dataset.filter === 'all'));
    lastSidebar = ''; refresh();
  };
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
