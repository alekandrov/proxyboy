// Proceso principal de Electron: arranca el proxy, persiste la configuración y habla con la UI.
const {
  app, BrowserWindow, ipcMain, dialog, Menu, clipboard, shell, nativeImage,
} = require('electron');
const path = require('path');
const fs = require('fs');
const { CertificateAuthority } = require('./ca');
const { ProxyServer } = require('./proxy');
const system = require('./system');

let win;
let proxy;
let ca;
let systemProxyOwned = false; // solo lo desactivamos al salir si lo activamos nosotros
const pending = { added: [], updated: new Map() };

const settingsPath = () => path.join(app.getPath('userData'), 'settings.json');
const defaults = {
  port: 9090,
  sslProxyingEnabled: true,
  sslProxyAll: false,
  sslHosts: [],
  verifyUpstreamTLS: true,
  http2: true,
  mapLocalRules: [],
  mapRemoteRules: [],
  blockRules: [],
  breakpointRules: [],
  scriptRules: [],
  autoSystemProxy: false,
};
let settings = { ...defaults };

function loadSettings() {
  try { settings = { ...defaults, ...JSON.parse(fs.readFileSync(settingsPath(), 'utf8')) }; } catch { /* primera vez */ }
}
function saveSettings() {
  fs.writeFileSync(settingsPath(), JSON.stringify(settings, null, 2));
}

function applySettingsToProxy() {
  proxy.updateSettings({
    sslProxyingEnabled: settings.sslProxyingEnabled,
    sslProxyAll: settings.sslProxyAll,
    sslHosts: settings.sslHosts,
    verifyUpstreamTLS: settings.verifyUpstreamTLS,
    http2: settings.http2,
  });
  proxy.setRules({
    mapLocal: settings.mapLocalRules,
    mapRemote: settings.mapRemoteRules,
    block: settings.blockRules,
    breakpoints: settings.breakpointRules,
    scripts: settings.scriptRules,
  });
}

// ---------------- Íconos .icns (macOS) ----------------
// nativeImage no lee .icns: lo convertimos una vez a PNG con `sips` (incluido en macOS) y lo cacheamos
function icnsToDataURL(icns) {
  const dir = path.join(app.getPath('userData'), 'icon-cache');
  const out = path.join(dir, `${require('crypto').createHash('sha1').update(icns).digest('hex')}.png`);
  const load = () => {
    const img = nativeImage.createFromPath(out);
    return img.isEmpty() ? null : img.toDataURL();
  };
  if (fs.existsSync(out)) return Promise.resolve(load());
  fs.mkdirSync(dir, { recursive: true });
  return new Promise((resolve) => {
    require('child_process').execFile('sips', ['-s', 'format', 'png', '--resampleHeightWidthMax', '64', icns, '--out', out],
      { timeout: 5000 }, (err) => resolve(err ? null : load()));
  });
}

// ---------------- Breakpoints ----------------
// El proxy espera la decisión del usuario; la UI muestra un editor y responde por IPC.
const pendingBreakpoints = new Map();
let nextBreakpointId = 1;
function handleBreakpoint(bp) {
  if (!win || win.isDestroyed()) return Promise.resolve({ action: 'execute' });
  return new Promise((resolve) => {
    const bpId = nextBreakpointId++;
    pendingBreakpoints.set(bpId, resolve);
    win.webContents.send('breakpoint', { ...bp, bpId });
    if (win.isMinimized()) win.restore();
    win.show();
    if (process.platform === 'darwin' && app.dock) app.dock.bounce('informational');
  });
}
function releaseAllBreakpoints() {
  for (const resolve of pendingBreakpoints.values()) resolve({ action: 'execute' });
  pendingBreakpoints.clear();
}

async function startProxy(preferredPort) {
  // Si el puerto está ocupado probamos los siguientes
  for (let p = preferredPort; p < preferredPort + 20; p++) {
    proxy.port = p;
    try {
      return await proxy.start();
    } catch (e) {
      if (e.code !== 'EADDRINUSE') throw e;
    }
  }
  throw new Error(`No hay puertos libres desde ${preferredPort}`);
}

// Enviamos los flows a la UI en lotes para no saturar el IPC
setInterval(() => {
  if (!win || win.isDestroyed()) return;
  if (!pending.added.length && !pending.updated.size) return;
  win.webContents.send('flows', { added: pending.added, updated: [...pending.updated.values()] });
  pending.added = [];
  pending.updated.clear();
}, 100);

async function state() {
  return {
    port: proxy.port,
    running: !!proxy.running,
    recording: proxy.settings.recording,
    settings,
    platform: process.platform,
    caPath: ca.caCertPath,
    caFingerprint: ca.caFingerprint,
    caCommonName: ca.caCert.subject.getField('CN').value,
    caTrusted: await system.isCertificateTrusted(ca.caCertPath, ca.caCert.subject.getField('CN').value),
    systemProxy: await system.isSystemProxyEnabled(proxy.port),
    ips: system.localIPs(),
  };
}

function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 880,
    minWidth: 900,
    minHeight: 500,
    title: 'Proxyboy',
    backgroundColor: '#1e1e1e',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  // Modo de verificación (desarrollo): PROXYBOY_STEPS='[{"js":"...","shot":"/ruta.png"}]'
  // ejecuta cada paso en la UI, guarda capturas y cierra la app.
  if (process.env.PROXYBOY_STEPS) {
    win.webContents.on('console-message', (_e, level, msg) => console.log('[renderer]', msg));
    setTimeout(async () => {
      for (const step of JSON.parse(process.env.PROXYBOY_STEPS)) {
        if (step.js) await win.webContents.executeJavaScript(step.js).catch((e) => console.log('step error', e));
        await new Promise((r) => setTimeout(r, step.wait || 700));
        if (step.shot) {
          fs.writeFileSync(step.shot, (await win.webContents.capturePage()).toPNG());
          console.log('screenshot saved', step.shot);
        }
      }
      app.exit(0);
    }, Number(process.env.PROXYBOY_DELAY || 6000));
  }
  win.on('closed', () => { releaseAllBreakpoints(); win = null; });
  win.webContents.on('did-start-navigation', releaseAllBreakpoints);
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}

function buildMenu() {
  const isMac = process.platform === 'darwin';
  const send = (cmd) => () => win && win.webContents.send('command', cmd);
  const template = [
    ...(isMac ? [{ role: 'appMenu' }] : []),
    {
      label: 'Archivo',
      submenu: [
        { label: 'Nuevo request…', accelerator: 'CmdOrCtrl+N', click: send('compose') },
        { label: 'Exportar HAR…', accelerator: 'CmdOrCtrl+S', click: send('export-har') },
        { type: 'separator' },
        isMac ? { role: 'close' } : { role: 'quit' },
      ],
    },
    { role: 'editMenu' },
    {
      label: 'Proxy',
      submenu: [
        { label: 'Grabar / Pausar', accelerator: 'CmdOrCtrl+R', click: send('toggle-recording') },
        { label: 'Limpiar sesión', accelerator: 'CmdOrCtrl+K', click: send('clear') },
        { type: 'separator' },
        { label: 'Proxy del sistema', accelerator: 'CmdOrCtrl+Shift+P', click: send('toggle-system-proxy') },
        { label: 'SSL Proxying…', click: send('settings') },
        { label: 'Reglas…', accelerator: 'CmdOrCtrl+Alt+L', click: send('rules') },
        { label: 'Breakpoints…', accelerator: 'CmdOrCtrl+Alt+B', click: send('rules:breakpointRules') },
        { label: 'Scripts…', accelerator: 'CmdOrCtrl+Alt+I', click: send('rules:scriptRules') },
        { label: 'Map Remote…', accelerator: 'CmdOrCtrl+Alt+R', click: send('rules:mapRemoteRules') },
        { label: 'Certificado…', click: send('certificate') },
      ],
    },
    { role: 'viewMenu' },
    { role: 'windowMenu' },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ---------------- IPC ----------------
function registerIPC() {
  ipcMain.handle('state', () => state());
  ipcMain.handle('flows:all', () => [...proxy.flows.values()].map((f) => proxy.summary(f)));
  ipcMain.handle('flows:detail', (_e, id) => proxy.detail(id));
  ipcMain.handle('flows:clear', () => { proxy.clear(); pending.added = []; pending.updated.clear(); });
  ipcMain.handle('flows:delete', (_e, ids) => { for (const id of ids) proxy.flows.delete(id); });
  ipcMain.handle('recording:set', (_e, on) => { proxy.updateSettings({ recording: !!on }); return on; });

  ipcMain.handle('settings:update', async (_e, patch) => {
    const portChanged = patch.port && Number(patch.port) !== proxy.port;
    settings = { ...settings, ...patch };
    saveSettings();
    applySettingsToProxy();
    if (portChanged) {
      const wasSystem = await system.isSystemProxyEnabled(proxy.port);
      await proxy.stop();
      await startProxy(Number(settings.port));
      if (wasSystem) await system.enableSystemProxy(proxy.port);
    }
    return state();
  });

  ipcMain.handle('system-proxy:set', async (_e, on) => {
    if (on) { await system.enableSystemProxy(proxy.port); systemProxyOwned = true; } else { await system.disableSystemProxy(); systemProxyOwned = false; }
    return state();
  });

  ipcMain.handle('cert:install', async () => {
    await system.installCertificate(ca.caCertPath);
    return state();
  });
  ipcMain.handle('cert:export', async () => {
    const { filePath, canceled } = await dialog.showSaveDialog(win, { defaultPath: 'proxyboy-ca.pem' });
    if (canceled || !filePath) return false;
    fs.writeFileSync(filePath, ca.caCertPem);
    return true;
  });
  ipcMain.handle('cert:reveal', () => shell.showItemInFolder(ca.caCertPath));

  // Íconos de apps: PNG del bundle (apps del simulador iOS) o ícono del sistema (apps de macOS / .exe de Windows)
  const iconCache = new Map();
  ipcMain.handle('app:icon', async (_e, id) => {
    if (iconCache.has(id)) return iconCache.get(id);
    const info = proxy.apps.get(id);
    let url = null;
    try {
      if (info && info.iconFile) {
        const img = nativeImage.createFromPath(info.iconFile);
        if (!img.isEmpty()) url = img.resize({ width: 32, height: 32, quality: 'best' }).toDataURL();
      }
      if (!url && info && info.icnsFile) url = await icnsToDataURL(info.icnsFile);
      // En Windows/Linux el sistema devuelve el ícono real del .exe; en macOS devuelve uno genérico
      if (!url && info && info.exe && process.platform !== 'darwin') url = (await app.getFileIcon(info.exe, { size: 'normal' })).toDataURL();
    } catch { /* sin ícono */ }
    if (info) iconCache.set(id, url);
    return url;
  });

  ipcMain.handle('breakpoint:resolve', (_e, bpId, decision) => {
    const resolve = pendingBreakpoints.get(bpId);
    if (resolve) { pendingBreakpoints.delete(bpId); resolve(decision); }
  });
  ipcMain.handle('breakpoint:pending', () => pendingBreakpoints.size);

  ipcMain.handle('request:send', (_e, req) => proxy.sendRequest(req));

  ipcMain.handle('har:export', async (_e, ids) => {
    const { filePath, canceled } = await dialog.showSaveDialog(win, {
      defaultPath: `proxyboy-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.har`,
      filters: [{ name: 'HAR', extensions: ['har'] }],
    });
    if (canceled || !filePath) return false;
    fs.writeFileSync(filePath, JSON.stringify(proxy.toHAR(ids), null, 2));
    return true;
  });

  ipcMain.handle('body:save', async (_e, { base64, name }) => {
    const { filePath, canceled } = await dialog.showSaveDialog(win, { defaultPath: name || 'body.bin' });
    if (canceled || !filePath) return false;
    fs.writeFileSync(filePath, Buffer.from(base64, 'base64'));
    return true;
  });

  ipcMain.handle('clipboard:write', (_e, text) => clipboard.writeText(text));
}

app.whenReady().then(async () => {
  loadSettings();
  ca = new CertificateAuthority(app.getPath('userData'));
  proxy = new ProxyServer({ ca, port: settings.port });
  applySettingsToProxy();
  proxy.on('flow', (f) => pending.added.push(f));
  proxy.on('flow-update', (f) => pending.updated.set(f.id, f));
  proxy.onBreakpoint = handleBreakpoint;
  await startProxy(settings.port);
  if (settings.autoSystemProxy) {
    try { await system.enableSystemProxy(proxy.port); systemProxyOwned = true; } catch { /* el usuario puede cancelar */ }
  }
  registerIPC();
  buildMenu();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

let quitting = false;
app.on('before-quit', async (e) => {
  if (quitting || !systemProxyOwned) return;
  // Restauramos el proxy del sistema para no dejar al usuario sin internet
  e.preventDefault();
  quitting = true;
  try { await system.disableSystemProxy(); } catch { /* ignorar */ }
  app.quit();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
