// Identifica qué app hizo cada conexión al proxy.
// - Conexiones locales: se busca el proceso dueño del puerto de origen (lsof en macOS, netstat en Windows, ss en Linux)
//   y se leen nombre/ícono de su bundle. Las apps del simulador de iOS son procesos de macOS, así que también se detectan.
// - Conexiones remotas (celulares) o si el proceso ya cerró la conexión: se usa el User-Agent.
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const platform = process.platform;
const BATCH_DELAY = 15;

function run(cmd, args, timeout = 4000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      resolve(err && !stdout ? '' : String(stdout || ''));
    });
  });
}

function isLoopback(addr) {
  return !!addr && (addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1' || addr.startsWith('127.'));
}

// ---------------- Puerto → PID ----------------
async function portsToPids(proxyPort) {
  const map = new Map(); // puerto de origen del cliente -> pid
  if (platform === 'darwin') {
    const out = await run('lsof', ['-nP', `-iTCP:${proxyPort}`, '-sTCP:ESTABLISHED', '-Fpn']);
    let pid = null;
    for (const line of out.split('\n')) {
      if (line[0] === 'p') pid = Number(line.slice(1));
      else if (line[0] === 'n' && pid !== process.pid) {
        const m = /:(\d+)->.*:(\d+)$/.exec(line);
        if (m && Number(m[2]) === proxyPort) map.set(Number(m[1]), pid);
      }
    }
  } else if (platform === 'win32') {
    const out = await run('netstat', ['-ano', '-p', 'TCP']);
    for (const line of out.split(/\r?\n/)) {
      const m = /^\s*TCP\s+\S+:(\d+)\s+\S+:(\d+)\s+ESTABLISHED\s+(\d+)/i.exec(line);
      if (m && Number(m[2]) === proxyPort && Number(m[3]) !== process.pid) map.set(Number(m[1]), Number(m[3]));
    }
  } else {
    const out = await run('ss', ['-tnpH', 'state', 'established', `( dport = :${proxyPort} )`]);
    for (const line of out.split('\n')) {
      const m = /\S+:(\d+)\s+\S+:(\d+)\s+users:\(\(".*?",pid=(\d+)/.exec(line);
      if (m && Number(m[3]) !== process.pid) map.set(Number(m[1]), Number(m[3]));
    }
  }
  return map;
}

// ---------------- PID → ejecutable ----------------
async function pidsToExe(pids) {
  const map = new Map(); // pid -> { exe, description }
  if (!pids.length) return map;
  if (platform === 'darwin') {
    // En macOS `comm` es la ruta completa del ejecutable
    const out = await run('ps', ['-o', 'pid=,comm=', '-p', pids.join(',')]);
    for (const line of out.split('\n')) {
      const m = /^\s*(\d+)\s+(.+)$/.exec(line);
      if (m) map.set(Number(m[1]), { exe: m[2].trim() });
    }
  } else if (platform === 'win32') {
    const script = `Get-Process -Id ${pids.join(',')} -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Id)|$($_.Path)|$($_.Description)|$($_.ProcessName)" }`;
    const out = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], 8000);
    for (const line of out.split(/\r?\n/)) {
      const [pid, exe, description, name] = line.split('|');
      if (pid && /^\d+$/.test(pid.trim())) map.set(Number(pid), { exe: exe || name, description: description || name });
    }
  } else {
    for (const pid of pids) {
      try { map.set(pid, { exe: fs.readlinkSync(`/proc/${pid}/exe`) }); } catch { /* proceso terminado */ }
    }
  }
  return map;
}

// ---------------- Metadatos de bundles (macOS / simulador iOS) ----------------
async function readPlist(file) {
  const json = await run('plutil', ['-convert', 'json', '-o', '-', file]);
  if (json) { try { return JSON.parse(json); } catch { /* sigue */ } }
  // Algunos plists (con fechas/datos) no convierten a JSON: extraemos las claves que usamos
  const out = {};
  for (const k of ['CFBundleDisplayName', 'CFBundleName', 'CFBundleIdentifier', 'name', 'runtime']) {
    const v = (await run('plutil', ['-extract', k, 'raw', file])).trim();
    if (v && !v.includes('No value at that key path')) out[k] = v;
  }
  return out;
}

const deviceCache = new Map();
async function simulatorDevice(udid) {
  if (deviceCache.has(udid)) return deviceCache.get(udid);
  const plist = path.join(require('os').homedir(), 'Library/Developer/CoreSimulator/Devices', udid, 'device.plist');
  const p = readPlist(plist).then((d) => {
    const rt = /SimRuntime\.(\w+)-([\d-]+)/.exec(d.runtime || '');
    return { device: d.name || 'Simulador', os: rt ? `${rt[1]} ${rt[2].replace(/-/g, '.')}` : '' };
  });
  deviceCache.set(udid, p);
  return p;
}

// Apps de macOS: ícono .icns declarado en Info.plist, o AppIcon.icns, o el primer .icns de Resources
function findMacIcns(bundle, plist) {
  const res = path.join(bundle, 'Contents', 'Resources');
  const candidates = [];
  if (plist.CFBundleIconFile) {
    const f = plist.CFBundleIconFile;
    candidates.push(f.endsWith('.icns') ? f : `${f}.icns`);
  }
  candidates.push('AppIcon.icns');
  for (const c of candidates) {
    if (fs.existsSync(path.join(res, c))) return path.join(res, c);
  }
  try {
    const any = fs.readdirSync(res).find((f) => f.endsWith('.icns'));
    return any ? path.join(res, any) : null;
  } catch {
    return null;
  }
}

function findIosIcon(bundle, plist) {
  try {
    const files = fs.readdirSync(bundle).filter((f) => f.toLowerCase().endsWith('.png'));
    const declared = (((plist.CFBundleIcons || {}).CFBundlePrimaryIcon || {}).CFBundleIconFiles) || [];
    const prefixes = declared.length ? declared : ['AppIcon'];
    const candidates = files.filter((f) => prefixes.some((p) => f.startsWith(p)) && !f.includes('~ipad'));
    const list = candidates.length ? candidates : files.filter((f) => /^appicon/i.test(f));
    let best = null;
    let bestSize = 0;
    for (const f of list) {
      const size = fs.statSync(path.join(bundle, f)).size;
      if (size > bestSize) { best = f; bestSize = size; }
    }
    return best ? path.join(bundle, best) : null;
  } catch {
    return null;
  }
}

async function describeExe(pid, { exe, description }) {
  const base = path.basename(exe || '').replace(/\.exe$/i, '');
  const info = { id: exe, name: description || base || `PID ${pid}`, pid, exe, source: 'process' };
  if (platform !== 'darwin' || !exe) return info;

  // El primer ".app/" de la ruta es el bundle externo: los helpers (ej. "Google Chrome Helper") se agrupan con su app
  const idx = exe.indexOf('.app/');
  if (idx < 0) return info;
  const bundle = exe.slice(0, idx + 4);
  const sim = /CoreSimulator\/Devices\/([0-9A-F-]{36})\//i.exec(exe);
  const isIosBundle = fs.existsSync(path.join(bundle, 'Info.plist'));
  const plistPath = isIosBundle ? path.join(bundle, 'Info.plist') : path.join(bundle, 'Contents', 'Info.plist');
  const plist = fs.existsSync(plistPath) ? await readPlist(plistPath) : {};
  info.name = plist.CFBundleDisplayName || plist.CFBundleName || path.basename(bundle, '.app');
  info.bundleId = plist.CFBundleIdentifier;
  info.bundlePath = bundle;
  info.id = plist.CFBundleIdentifier || bundle;
  if (isIosBundle) info.iconFile = findIosIcon(bundle, plist);
  else info.icnsFile = findMacIcns(bundle, plist);
  if (sim) {
    const dev = await simulatorDevice(sim[1]);
    info.simulator = true;
    info.udid = sim[1];
    info.device = dev.device;
    info.os = dev.os;
    info.id = `${info.id}@${sim[1]}`;
  }
  return info;
}

// ---------------- User-Agent (respaldo) ----------------
function appFromUserAgent(ua, clientAddr) {
  if (!ua) return null;
  let name = null;
  if (/^Mozilla\//.test(ua)) {
    if (/Edg\//.test(ua)) name = 'Microsoft Edge';
    else if (/OPR\//.test(ua)) name = 'Opera';
    else if (/Firefox\//.test(ua)) name = 'Firefox';
    else if (/Chrome\//.test(ua)) name = 'Google Chrome';
    else if (/Safari\//.test(ua)) name = 'Safari';
    else name = 'Navegador';
  } else {
    const m = /^([^/\s;()]+)\/[\w.-]+/.exec(ua) || /^([^/\s;()]+)/.exec(ua);
    if (m) { try { name = decodeURIComponent(m[1]); } catch { name = m[1]; } }
  }
  if (!name) return null;
  const remote = clientAddr && !isLoopback(clientAddr);
  const ios = /iPhone|iPad|iOS|CFNetwork/.test(ua);
  const android = /Android|okhttp|Dalvik/i.test(ua);
  return {
    id: `ua:${name}${remote ? `@${clientAddr}` : ''}`,
    name,
    source: 'user-agent',
    device: remote ? `${ios ? 'iOS' : android ? 'Android' : 'Dispositivo'} · ${clientAddr.replace(/^::ffff:/, '')}` : undefined,
  };
}

// ---------------- Resolver con batching ----------------
class ProcessResolver {
  constructor(getProxyPort) {
    this.getProxyPort = getProxyPort;
    this.pending = new Map(); // puerto -> [resolve]
    this.timer = null;
    this.running = false;
    this.byPid = new Map(); // pid -> Promise<info> (verificamos que el exe no cambió)
    this.enabled = true;
  }

  lookup(clientPort) {
    if (!this.enabled) return Promise.resolve(null);
    return new Promise((resolve) => {
      const list = this.pending.get(clientPort) || [];
      list.push(resolve);
      this.pending.set(clientPort, list);
      this._schedule();
    });
  }

  _schedule() {
    if (this.timer || this.running) return;
    this.timer = setTimeout(() => { this.timer = null; this._flush(); }, BATCH_DELAY);
  }

  async _flush() {
    if (!this.pending.size) return;
    this.running = true;
    const batch = this.pending;
    this.pending = new Map();
    let ports = new Map();
    try {
      ports = await portsToPids(this.getProxyPort());
    } catch { /* sin datos: todos quedan en null */ }
    const pids = [...new Set([...batch.keys()].map((p) => ports.get(p)).filter(Boolean))];
    let exes = new Map();
    try { exes = await pidsToExe(pids); } catch { /* ignorar */ }
    for (const [port, resolvers] of batch) {
      const pid = ports.get(port);
      let info = null;
      if (pid && exes.has(pid)) {
        const e = exes.get(pid);
        const cached = this.byPid.get(pid);
        if (!cached || cached.exe !== e.exe) {
          this.byPid.set(pid, { exe: e.exe, promise: describeExe(pid, e).catch(() => null) });
        }
        info = await this.byPid.get(pid).promise;
      }
      for (const r of resolvers) r(info);
    }
    if (this.byPid.size > 500) this.byPid.clear();
    this.running = false;
    if (this.pending.size) this._schedule();
  }
}

module.exports = { ProcessResolver, appFromUserAgent, isLoopback, describeExe };
