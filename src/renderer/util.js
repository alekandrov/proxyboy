// Utilidades de la UI (sin dependencias)
/* eslint-disable no-unused-vars */
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function fmtSize(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function fmtDur(ms) {
  if (ms == null) return '';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function statusClass(f) {
  if (f.state === 'failed') return 's-err';
  if (!f.status) return 's-pending';
  if (f.status < 300) return 's-ok';
  if (f.status < 400) return 's-3xx';
  if (f.status < 500) return 's-4xx';
  return 's-5xx';
}

function shortType(ct, f) {
  if (f.tags && f.tags.includes('websocket')) return 'websocket';
  if (f.method === 'CONNECT') return 'tunnel';
  if (!ct) return '';
  const base = ct.split(';')[0].trim().toLowerCase();
  const map = {
    'application/json': 'json', 'text/html': 'html', 'text/plain': 'text', 'application/javascript': 'js',
    'text/javascript': 'js', 'text/css': 'css', 'application/xml': 'xml', 'text/xml': 'xml',
    'application/x-www-form-urlencoded': 'form', 'application/octet-stream': 'binary', 'application/grpc': 'grpc',
  };
  if (map[base]) return map[base];
  if (base.endsWith('+json')) return 'json';
  if (base.startsWith('image/')) return base.slice(6);
  return base.split('/')[1] || base;
}

function b64ToBytes(b64) {
  const bin = atob(b64 || '');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToText(bytes) {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function looksBinary(bytes) {
  const n = Math.min(bytes.length, 2048);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b === 0) return true;
    if (b < 9 || (b > 13 && b < 32)) bad++;
  }
  return n > 0 && bad / n > 0.1;
}

function hexdump(bytes, max = 64 * 1024) {
  const lines = [];
  const len = Math.min(bytes.length, max);
  for (let i = 0; i < len; i += 16) {
    const chunk = bytes.slice(i, Math.min(i + 16, len));
    const hex = [...chunk].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    const ascii = [...chunk].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`);
  }
  if (bytes.length > max) lines.push(`… (${fmtSize(bytes.length - max)} más)`);
  return lines.join('\n');
}

// Resaltado JSON sobre texto ya formateado (escapa todo antes de envolver en spans)
function highlightJSON(text) {
  const re = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    out += esc(text.slice(last, m.index));
    const tok = m[0];
    let cls = 'j-num';
    if (tok.startsWith('"')) cls = m[2] ? 'j-key' : 'j-str';
    else if (tok === 'true' || tok === 'false') cls = 'j-bool';
    else if (tok === 'null') cls = 'j-null';
    out += `<span class="${cls}">${esc(tok)}</span>`;
    last = re.lastIndex;
  }
  return out + esc(text.slice(last));
}

function headerGet(pairs, name) {
  const n = name.toLowerCase();
  const p = (pairs || []).find(([k]) => k.toLowerCase() === n);
  return p ? p[1] : undefined;
}

function shellArg(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function toCurl(d) {
  const parts = [`curl ${d.method !== 'GET' ? `-X ${d.method} ` : ''}${shellArg(d.url)}`];
  for (const [k, v] of d.request.headers) {
    const lk = k.toLowerCase();
    if (lk === 'proxy-connection' || lk === 'content-length' || lk === 'host') continue;
    parts.push(`-H ${shellArg(`${k}: ${v}`)}`);
  }
  if (d.request.body && d.request.body.size) {
    parts.push(`--data-raw ${shellArg(bytesToText(b64ToBytes(d.request.body.base64)))}`);
  }
  if (headerGet(d.request.headers, 'accept-encoding')) parts.push('--compressed');
  return parts.join(' \\\n  ');
}

function parseCookies(str) {
  return (str || '').split(/;\s*/).filter(Boolean).map((p) => {
    const i = p.indexOf('=');
    return i < 0 ? [p, ''] : [p.slice(0, i), p.slice(i + 1)];
  });
}
