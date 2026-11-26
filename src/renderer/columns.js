/* global S, esc, fmtSize, fmtDur, statusClass, shortType, appIconHTML, appSubtitle, store, persist, showMenu,
   renderRows, refresh, $ */
// Columnas de la tabla principal (estilo Proxyman): ordenar, mover, redimensionar y elegir cuáles ver.
const HEAD_H = 24;

const pad = (n, w = 2) => String(n).padStart(w, '0');
const fmtClock = (ms) => {
  if (!ms) return '';
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
};
const fmtDate = (ms) => {
  const d = new Date(ms);
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
const STATE_LABEL = { completed: 'Completado', failed: 'Fallido', pending: 'Pendiente', tunnel: 'Abierto', paused: 'Pausado' };
const endTime = (f) => (f.duration != null ? f.startedAt + f.duration : null);
const isTunnel = (f) => f.method === 'CONNECT';
const decrypted = (f) => (f.scheme === 'https' || f.scheme === 'wss') && !isTunnel(f);
const visibleTags = (f) => f.tags.filter((t) => t !== 'websocket' && t !== 'h2' && t !== 'tunnel');

// key, label, ancho por defecto, alineación, valor para ordenar y HTML de la celda
const COLUMNS = [
  { key: 'statusIcon', label: '●', menu: 'Ícono de estado', width: 26, align: 'center', value: (f) => f.state,
    html: (f) => `<span class="state-dot ${statusClass(f)}"></span>` },
  { key: 'id', label: '#', menu: 'ID', width: 56, align: 'right', value: (f) => f.id, html: (f) => f.id },
  { key: 'url', label: 'URL', width: 420, flex: true, value: (f) => f.url,
    html: (f) => `${esc(f.url)}${tagsHTML(f)}`, title: (f) => f.url },
  { key: 'host', label: 'Host', width: 180, value: (f) => f.host, html: (f) => esc(f.host), title: (f) => f.host },
  { key: 'path', label: 'Path', width: 240, flex: true, value: (f) => f.path || '',
    html: (f) => `${esc(f.path || '')}${tagsHTML(f)}`, title: (f) => f.url },
  { key: 'client', label: 'Cliente', width: 130, value: (f) => (f.app ? f.app.name.toLowerCase() : ''),
    html: (f) => (f.app ? `${appIconHTML(f.app)}<span>${esc(f.app.name)}</span>` : ''),
    title: (f) => (f.app ? `${f.app.name}${appSubtitle(f.app) ? ` — ${appSubtitle(f.app)}` : ''}` : '') },
  { key: 'method', label: 'Método', width: 68, value: (f) => f.method, html: (f) => esc(f.method) },
  { key: 'code', label: 'Code', width: 52, value: (f) => (f.state === 'failed' ? 999 : f.status || 0),
    html: (f) => `<span class="${statusClass(f)}">${f.state === 'failed' ? 'ERR' : f.state === 'paused' ? '⏸' : (f.status || '…')}</span>` },
  { key: 'status', label: 'Estado', width: 96, value: (f) => f.state, html: (f) => esc(STATE_LABEL[f.state] || f.state) },
  { key: 'date', label: 'Fecha', width: 150, value: (f) => f.startedAt, html: (f) => fmtDate(f.startedAt) },
  { key: 'time', label: 'Hora', width: 96, value: (f) => f.startedAt, html: (f) => fmtClock(f.startedAt) },
  { key: 'timeComplete', label: 'Hora fin', width: 104, value: endTime, html: (f) => fmtClock(endTime(f)) },
  { key: 'duration', label: 'Duración', width: 76, align: 'right', value: (f) => f.duration, html: (f) => fmtDur(f.duration) },
  { key: 'type', label: 'Tipo', width: 80, value: (f) => shortType(f.contentType, f),
    html: (f) => `${esc(shortType(f.contentType, f))}${f.wsCount ? ` · ${f.wsCount} msg` : ''}` },
  { key: 'reqSize', label: 'Request', menu: 'Tamaño del request', width: 80, align: 'right', value: (f) => f.reqSize, html: (f) => (f.reqSize ? fmtSize(f.reqSize) : '') },
  { key: 'resSize', label: 'Response', menu: 'Tamaño de la response', width: 76, align: 'right', value: (f) => f.resSize, html: (f) => (f.resSize ? fmtSize(f.resSize) : '') },
  { key: 'ssl', label: 'SSL', width: 40, align: 'center', value: (f) => (decrypted(f) ? 2 : isTunnel(f) ? 1 : 0),
    html: (f) => (decrypted(f) ? '<span title="HTTPS descifrado">🔓</span>' : isTunnel(f) ? '<span title="Túnel cifrado (sin SSL Proxying)">🔒</span>' : ''),
    title: () => '' },
  { key: 'edited', label: 'Editado', width: 130, value: (f) => visibleTags(f).join(','),
    html: (f) => visibleTags(f).map((t) => `<span class="tag ${esc(t)}">${esc(t)}</span>`).join('') },
  { key: 'serverIp', label: 'IP servidor', width: 130, value: (f) => f.serverIp || '', html: (f) => esc((f.serverIp || '').replace(/^::ffff:/, '')) },
  { key: 'clientIp', label: 'IP cliente', width: 120, value: (f) => f.client || '', html: (f) => esc((f.client || '').replace(/^::ffff:/, '')) },
  { key: 'graphql', label: 'Query (GraphQL)', width: 170, value: (f) => f.graphql || '', html: (f) => esc(f.graphql || '') },
];
const COL = Object.fromEntries(COLUMNS.map((c) => [c.key, c]));
const DEFAULT_COLUMNS = ['statusIcon', 'id', 'method', 'code', 'host', 'path', 'client', 'type', 'time', 'duration', 'resSize', 'ssl'];

function tagsHTML(f) {
  // En URL/Path mostramos las etiquetas solo si la columna "Editado" no está visible
  if (S.cols.some((c) => c.key === 'edited')) return '';
  return visibleTags(f).map((t) => `<span class="tag ${esc(t)}">${esc(t)}</span>`).join('');
}

function defaultCols() {
  return DEFAULT_COLUMNS.map((key) => ({ key, width: COL[key].width }));
}

function loadColumns() {
  const saved = store('columns', null);
  const cols = Array.isArray(saved) ? saved.filter((c) => c && COL[c.key]) : [];
  S.cols = cols.length ? cols.map((c) => ({ key: c.key, width: Math.max(24, Number(c.width) || COL[c.key].width) })) : defaultCols();
  const sort = store('sort', null);
  S.sort = sort && COL[sort.key] ? sort : { key: 'id', dir: 'asc' };
}
function saveColumns() { persist('columns', S.cols); persist('sort', S.sort); }

// La primera columna "flexible" visible (URL o Path) ocupa el espacio libre
function flexKey() {
  const c = S.cols.find((x) => COL[x.key].flex);
  return c ? c.key : null;
}
function cellStyle(c, fk) {
  return c.key === fk ? `flex:1 0 ${c.width}px;min-width:${c.width}px` : `width:${c.width}px;flex:none`;
}
function tableWidth() {
  return S.cols.reduce((n, c) => n + c.width, 0);
}

function rowHTML(f) {
  const fk = flexKey();
  let html = `<div class="row${S.selected.has(f.id) ? ' selected' : ''}${isTunnel(f) ? ' dim' : ''}" data-id="${f.id}">`;
  for (const c of S.cols) {
    const def = COL[c.key];
    const title = def.title ? def.title(f) : '';
    html += `<div class="c k-${c.key}${def.align ? ` a-${def.align}` : ''}" style="${cellStyle(c, fk)}"${title ? ` title="${esc(title)}"` : ''}>${def.html(f)}</div>`;
  }
  return `${html}</div>`;
}

// ---------------- Ordenamiento ----------------
function sortView(view) {
  const { key, dir } = S.sort;
  if (key === 'id' && dir === 'asc') return view; // orden natural de llegada
  const get = COL[key].value;
  const mul = dir === 'asc' ? 1 : -1;
  return view.slice().sort((a, b) => {
    const va = get(a);
    const vb = get(b);
    const ea = va === null || va === undefined || va === '';
    const eb = vb === null || vb === undefined || vb === '';
    if (ea || eb) return ea === eb ? a.id - b.id : ea ? 1 : -1; // vacíos siempre al final
    if (va < vb) return -1 * mul;
    if (va > vb) return 1 * mul;
    return a.id - b.id;
  });
}
// Con orden cronológico ascendente seguimos el final de la lista mientras llegan requests
function followsTail() {
  const { key, dir } = S.sort;
  return dir === 'asc' && (key === 'id' || key === 'time' || key === 'date');
}

// ---------------- Encabezado ----------------
function renderHeader() {
  const fk = flexKey();
  const tw = `${tableWidth()}px`;
  document.documentElement.style.setProperty('--tw', tw);
  $('#thead').innerHTML = S.cols.map((c) => {
    const def = COL[c.key];
    const arrow = S.sort.key === c.key ? `<span class="sort-arrow">${S.sort.dir === 'asc' ? '▲' : '▼'}</span>` : '';
    return `<div class="c hc k-${c.key}${def.align ? ` a-${def.align}` : ''}${S.sort.key === c.key ? ' sorted' : ''}" style="${cellStyle(c, fk)}"
      data-key="${c.key}" draggable="true" title="${esc(def.menu || def.label)} — clic para ordenar, arrastrá para mover">
      <span class="hc-label">${esc(def.label)}</span>${arrow}<span class="col-resize" data-resize="${c.key}"></span></div>`;
  }).join('');
}

function columnsMenu(x, y) {
  const visible = new Set(S.cols.map((c) => c.key));
  showMenu(x, y, [
    ...COLUMNS.map((def) => ({
      label: `${visible.has(def.key) ? '✓' : ' '}  ${def.menu || def.label}`,
      run: () => {
        if (visible.has(def.key)) {
          if (S.cols.length > 1) S.cols = S.cols.filter((c) => c.key !== def.key);
        } else {
          S.cols.push({ key: def.key, width: def.width });
        }
        if (!S.cols.some((c) => c.key === S.sort.key)) S.sort = { key: 'id', dir: 'asc' };
        applyColumns();
        columnsMenu(x, y); // el menú queda abierto para tildar varias
      },
    })),
    '-',
    { label: 'Restablecer columnas', run: () => { S.cols = defaultCols(); S.sort = { key: 'id', dir: 'asc' }; applyColumns(); } },
  ]);
}

function applyColumns() {
  saveColumns();
  renderHeader();
  refresh();
}

function bindHeader() {
  const head = $('#thead');
  let suppressClick = false;

  // Ordenar
  head.addEventListener('click', (e) => {
    if (suppressClick) { suppressClick = false; return; }
    const cell = e.target.closest('.hc');
    if (!cell || e.target.dataset.resize) return;
    const key = cell.dataset.key;
    S.sort = S.sort.key === key ? { key, dir: S.sort.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' };
    applyColumns();
  });

  // Menú de columnas
  head.addEventListener('contextmenu', (e) => { e.preventDefault(); columnsMenu(e.clientX, e.clientY); });

  // Redimensionar
  let resizing = null;
  head.addEventListener('mousedown', (e) => {
    const key = e.target.dataset.resize;
    if (!key) return;
    e.preventDefault();
    e.stopPropagation();
    const col = S.cols.find((c) => c.key === key);
    resizing = { col, startX: e.clientX, startW: col.width };
    document.body.classList.add('col-resizing');
  });
  document.addEventListener('mousemove', (e) => {
    if (!resizing) return;
    resizing.col.width = Math.max(24, Math.round(resizing.startW + e.clientX - resizing.startX));
    renderHeader();
    renderRows();
  });
  document.addEventListener('mouseup', () => {
    if (!resizing) return;
    resizing = null;
    suppressClick = true;
    setTimeout(() => { suppressClick = false; }, 0);
    document.body.classList.remove('col-resizing');
    saveColumns();
  });
  // Doble clic en el borde: ancho por defecto
  head.addEventListener('dblclick', (e) => {
    const key = e.target.dataset.resize;
    if (!key) return;
    S.cols.find((c) => c.key === key).width = COL[key].width;
    applyColumns();
  });

  // Mover (drag & drop)
  let dragKey = null;
  head.addEventListener('dragstart', (e) => {
    const cell = e.target.closest('.hc');
    if (!cell || resizing) { e.preventDefault(); return; }
    dragKey = cell.dataset.key;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', dragKey);
    cell.classList.add('dragging');
  });
  const clearDrop = () => head.querySelectorAll('.drop-before,.drop-after').forEach((el) => el.classList.remove('drop-before', 'drop-after'));
  head.addEventListener('dragover', (e) => {
    const cell = e.target.closest('.hc');
    if (!dragKey || !cell || cell.dataset.key === dragKey) return;
    e.preventDefault();
    clearDrop();
    const r = cell.getBoundingClientRect();
    cell.classList.add(e.clientX < r.left + r.width / 2 ? 'drop-before' : 'drop-after');
  });
  head.addEventListener('dragleave', (e) => { if (!head.contains(e.relatedTarget)) clearDrop(); });
  head.addEventListener('drop', (e) => {
    e.preventDefault();
    const cell = e.target.closest('.hc');
    clearDrop();
    if (!dragKey || !cell || cell.dataset.key === dragKey) return;
    const r = cell.getBoundingClientRect();
    const after = e.clientX >= r.left + r.width / 2;
    const moving = S.cols.find((c) => c.key === dragKey);
    S.cols = S.cols.filter((c) => c.key !== dragKey);
    const idx = S.cols.findIndex((c) => c.key === cell.dataset.key) + (after ? 1 : 0);
    S.cols.splice(idx, 0, moving);
    applyColumns();
  });
  head.addEventListener('dragend', () => {
    dragKey = null;
    clearDrop();
    head.querySelectorAll('.dragging').forEach((el) => el.classList.remove('dragging'));
  });
}
