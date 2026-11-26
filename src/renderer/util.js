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
  if (f.tags && f.tags.includes('websocket')) return 'ws';
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

// ---------------- Protobuf / gRPC (sin esquema) ----------------
// Decodifica un mensaje protobuf a un objeto { "nroCampo": valor }. Los campos repetidos quedan como arrays.
function decodeProtobuf(bytes, depth = 0) {
  let i = 0;
  const out = {};
  const readVarint = () => {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      if (i >= bytes.length) throw new Error('varint truncado');
      const b = bytes[i++];
      result |= BigInt(b & 0x7f) << shift;
      if (!(b & 0x80)) break;
      shift += 7n;
      if (shift > 70n) throw new Error('varint inválido');
    }
    return result;
  };
  const num = (big) => (big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big.toString());
  const add = (k, v) => {
    if (out[k] === undefined) out[k] = v;
    else if (Array.isArray(out[k]) && out[k].__repeated) out[k].push(v);
    else { const arr = [out[k], v]; arr.__repeated = true; out[k] = arr; }
  };
  while (i < bytes.length) {
    const key = readVarint();
    const field = Number(key >> 3n);
    const wire = Number(key & 7n);
    if (field <= 0 || field > 536870911) throw new Error('campo inválido');
    if (wire === 0) {
      add(field, num(readVarint()));
    } else if (wire === 1) {
      if (i + 8 > bytes.length) throw new Error('fixed64 truncado');
      const dv = new DataView(bytes.buffer, bytes.byteOffset + i, 8);
      const asInt = dv.getBigUint64(0, true);
      const asDouble = dv.getFloat64(0, true);
      add(field, Number.isFinite(asDouble) && Math.abs(asDouble) > 1e-300 && Math.abs(asDouble) < 1e300 && !Number.isInteger(asDouble) ? asDouble : num(asInt));
      i += 8;
    } else if (wire === 2) {
      const len = Number(readVarint());
      if (i + len > bytes.length) throw new Error('longitud inválida');
      const sub = bytes.subarray(i, i + len);
      i += len;
      add(field, decodeLengthDelimited(sub, depth));
    } else if (wire === 5) {
      if (i + 4 > bytes.length) throw new Error('fixed32 truncado');
      const dv = new DataView(bytes.buffer, bytes.byteOffset + i, 4);
      const f = dv.getFloat32(0, true);
      add(field, Number.isFinite(f) && !Number.isInteger(f) && Math.abs(f) > 1e-30 ? Number(f.toPrecision(7)) : dv.getUint32(0, true));
      i += 4;
    } else {
      throw new Error(`wire type ${wire} no soportado`);
    }
  }
  for (const k of Object.keys(out)) if (Array.isArray(out[k])) delete out[k].__repeated;
  return out;
}

function decodeLengthDelimited(sub, depth) {
  if (!sub.length) return '';
  // ¿Es texto legible?
  const text = new TextDecoder('utf-8', { fatal: false }).decode(sub);
  const printable = !text.includes('�') && /^[\P{Cc}\n\r\t]*$/u.test(text);
  if (depth < 12) {
    try {
      const nested = decodeProtobuf(sub, depth + 1);
      if (Object.keys(nested).length && !(printable && text.length < 4)) return nested;
    } catch { /* no es un mensaje anidado */ }
  }
  if (printable) return text;
  return `0x${[...sub].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

// Separa los frames de gRPC / gRPC-Web: [flag(1) | longitud(4) | mensaje]
function splitGrpcFrames(bytes) {
  const frames = [];
  let i = 0;
  while (i + 5 <= bytes.length) {
    const flag = bytes[i];
    const len = (bytes[i + 1] << 24 >>> 0) + (bytes[i + 2] << 16) + (bytes[i + 3] << 8) + bytes[i + 4];
    if (i + 5 + len > bytes.length) return null;
    frames.push({ compressed: !!(flag & 1), trailers: !!(flag & 0x80), data: bytes.subarray(i + 5, i + 5 + len) });
    i += 5 + len;
  }
  return i === bytes.length ? frames : null;
}

// ---------------- Diff por líneas (LCS) ----------------
function diffLines(aText, bText) {
  const a = aText.split('\n');
  const b = bText.split('\n');
  const n = a.length;
  const m = b.length;
  if (n * m > 6e6) {
    // Demasiado grande para LCS: comparación línea a línea
    const out = [];
    for (let k = 0; k < Math.max(n, m); k++) {
      if (a[k] === b[k]) out.push({ t: ' ', s: a[k] });
      else {
        if (k < n) out.push({ t: '-', s: a[k] });
        if (k < m) out.push({ t: '+', s: b[k] });
      }
    }
    return out;
  }
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let x = n - 1; x >= 0; x--) {
    for (let y = m - 1; y >= 0; y--) {
      dp[x][y] = a[x] === b[y] ? dp[x + 1][y + 1] + 1 : Math.max(dp[x + 1][y], dp[x][y + 1]);
    }
  }
  const out = [];
  let x = 0; let y = 0;
  while (x < n && y < m) {
    if (a[x] === b[y]) { out.push({ t: ' ', s: a[x] }); x++; y++; }
    else if (dp[x + 1][y] >= dp[x][y + 1]) out.push({ t: '-', s: a[x++] });
    else out.push({ t: '+', s: b[y++] });
  }
  while (x < n) out.push({ t: '-', s: a[x++] });
  while (y < m) out.push({ t: '+', s: b[y++] });
  return out;
}
