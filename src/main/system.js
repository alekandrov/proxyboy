// Integración con el sistema operativo: proxy del sistema y confianza del certificado raíz.
// Soporta macOS (networksetup / security), Windows (registro / certutil) y Linux (GNOME, best-effort).
const { execFile } = require('child_process');
const os = require('os');
const path = require('path');

const platform = process.platform;

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true, ...opts }, (err, stdout, stderr) => {
      if (err) {
        err.stderr = stderr;
        return reject(err);
      }
      resolve(stdout.toString());
    });
  });
}

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

// ---------------- Proxy del sistema ----------------
async function macServices() {
  const out = await run('networksetup', ['-listallnetworkservices']);
  return out.split('\n').slice(1).map((l) => l.trim()).filter((l) => l && !l.startsWith('*'));
}

const WIN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

async function enableSystemProxy(port, host = '127.0.0.1') {
  if (platform === 'darwin') {
    const services = await macServices();
    const cmds = [];
    for (const s of services) {
      cmds.push(['-setwebproxy', s, host, String(port)]);
      cmds.push(['-setsecurewebproxy', s, host, String(port)]);
    }
    // Un solo diálogo de administrador si hace falta
    try {
      for (const c of cmds) await run('networksetup', c);
    } catch {
      const script = cmds.map((c) => ['networksetup', ...c].map(shellQuote).join(' ')).join(' && ');
      await run('osascript', ['-e', `do shell script ${JSON.stringify(script)} with administrator privileges`]);
    }
    return;
  }
  if (platform === 'win32') {
    await run('reg', ['add', WIN_KEY, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', `${host}:${port}`, '/f']);
    await run('reg', ['add', WIN_KEY, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', '<local>', '/f']);
    await run('reg', ['add', WIN_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f']);
    return;
  }
  // Linux (GNOME)
  await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'manual']);
  for (const k of ['http', 'https']) {
    await run('gsettings', ['set', `org.gnome.system.proxy.${k}`, 'host', host]);
    await run('gsettings', ['set', `org.gnome.system.proxy.${k}`, 'port', String(port)]);
  }
}

async function disableSystemProxy() {
  if (platform === 'darwin') {
    const services = await macServices();
    const cmds = [];
    for (const s of services) {
      cmds.push(['-setwebproxystate', s, 'off']);
      cmds.push(['-setsecurewebproxystate', s, 'off']);
    }
    try {
      for (const c of cmds) await run('networksetup', c);
    } catch {
      const script = cmds.map((c) => ['networksetup', ...c].map(shellQuote).join(' ')).join(' && ');
      await run('osascript', ['-e', `do shell script ${JSON.stringify(script)} with administrator privileges`]);
    }
    return;
  }
  if (platform === 'win32') {
    await run('reg', ['add', WIN_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f']);
    return;
  }
  await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'none']);
}

async function isSystemProxyEnabled(port) {
  try {
    if (platform === 'darwin') {
      const out = await run('scutil', ['--proxy']);
      return /HTTPEnable\s*:\s*1/.test(out) && new RegExp(`HTTPPort\\s*:\\s*${port}\\b`).test(out);
    }
    if (platform === 'win32') {
      const en = await run('reg', ['query', WIN_KEY, '/v', 'ProxyEnable']);
      const srv = await run('reg', ['query', WIN_KEY, '/v', 'ProxyServer']).catch(() => '');
      return /0x1/.test(en) && srv.includes(`:${port}`);
    }
    const mode = await run('gsettings', ['get', 'org.gnome.system.proxy', 'mode']);
    return mode.includes('manual');
  } catch {
    return false;
  }
}

// ---------------- Certificado raíz ----------------
async function installCertificate(certPath) {
  if (platform === 'darwin') {
    const keychain = path.join(os.homedir(), 'Library/Keychains/login.keychain-db');
    // macOS muestra su propio diálogo para autorizar el cambio de confianza
    await run('security', ['add-trusted-cert', '-r', 'trustRoot', '-k', keychain, certPath]);
    return;
  }
  if (platform === 'win32') {
    // Windows muestra un diálogo de seguridad para confirmar
    await run('certutil', ['-user', '-addstore', 'Root', certPath]);
    return;
  }
  throw new Error('En Linux instalá el certificado manualmente: sudo cp proxyboy-ca.pem /usr/local/share/ca-certificates/proxyboy-ca.crt && sudo update-ca-certificates');
}

async function isCertificateTrusted(certPath, commonName) {
  try {
    if (platform === 'darwin') {
      await run('security', ['verify-cert', '-c', certPath, '-p', 'ssl', '-L', '-q']);
      return true;
    }
    if (platform === 'win32') {
      const out = await run('certutil', ['-user', '-store', 'Root']);
      return out.includes(commonName);
    }
  } catch {
    return false;
  }
  return false;
}

async function removeCertificate(commonName) {
  if (platform === 'darwin') {
    await run('security', ['delete-certificate', '-c', commonName]);
    return;
  }
  if (platform === 'win32') {
    await run('certutil', ['-user', '-delstore', 'Root', commonName]);
  }
}

function localIPs() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push({ name, address: a.address });
    }
  }
  return out;
}

// ---------------- Simuladores de iOS (solo macOS con Xcode) ----------------
async function bootedSimulators() {
  if (platform !== 'darwin') return [];
  try {
    const data = JSON.parse(await run('xcrun', ['simctl', 'list', 'devices', 'booted', '-j']));
    const out = [];
    for (const [runtime, devices] of Object.entries(data.devices || {})) {
      const m = /SimRuntime\.(\w+)-([\d-]+)/.exec(runtime);
      for (const d of devices) {
        if (d.state === 'Booted') out.push({ udid: d.udid, name: d.name, os: m ? `${m[1]} ${m[2].replace(/-/g, '.')}` : '' });
      }
    }
    return out;
  } catch {
    return [];
  }
}

// Agrega la CA de Proxyboy como raíz confiable en el simulador (equivalente a instalar el perfil + confianza total)
async function installCertInSimulator(udid, certPath) {
  await run('xcrun', ['simctl', 'keychain', udid, 'add-root-cert', certPath]);
}

// Reinicia una app del simulador: cierra sus conexiones viejas para que las nuevas pasen por el proxy
async function restartSimulatorApp(udid, bundleId) {
  try { await run('xcrun', ['simctl', 'terminate', udid, bundleId]); } catch { /* no estaba corriendo */ }
  await run('xcrun', ['simctl', 'launch', udid, bundleId]);
}

module.exports = {
  enableSystemProxy, disableSystemProxy, isSystemProxyEnabled,
  installCertificate, isCertificateTrusted, removeCertificate, localIPs,
  bootedSimulators, installCertInSimulator, restartSimulatorApp,
};
