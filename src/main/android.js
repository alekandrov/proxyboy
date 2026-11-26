// Emuladores y dispositivos Android vía adb: configurar el proxy, copiar el certificado y restaurar al salir.
// - Emulador: el proxy apunta a 10.0.2.2 (la Mac/PC vista desde el emulador).
// - Dispositivo por USB: `adb reverse` expone el puerto del proxy en el teléfono como 127.0.0.1.
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const DEVICE_CERT_PATH = '/sdcard/Download/proxyboy-ca.crt';

function run(cmd, args, timeout = 15000) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true, timeout }, (err, stdout, stderr) => {
      if (err) {
        err.message = `${err.message}\n${String(stderr || '').trim()}`.trim();
        return reject(err);
      }
      resolve(String(stdout));
    });
  });
}

// adb del PATH o del SDK en su ubicación por defecto (macOS, Windows, Linux)
let adbCache;
function findAdb() {
  if (adbCache !== undefined) return adbCache;
  const exe = process.platform === 'win32' ? 'adb.exe' : 'adb';
  const sdkRoots = [
    process.env.ANDROID_HOME,
    process.env.ANDROID_SDK_ROOT,
    process.platform === 'darwin' && path.join(os.homedir(), 'Library/Android/sdk'),
    process.platform === 'win32' && process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Android', 'Sdk'),
    process.platform === 'linux' && path.join(os.homedir(), 'Android/Sdk'),
  ].filter(Boolean);
  const candidates = sdkRoots.map((r) => path.join(r, 'platform-tools', exe));
  for (const dir of (process.env.PATH || '').split(path.delimiter)) candidates.push(path.join(dir, exe));
  adbCache = candidates.find((c) => { try { return fs.statSync(c).isFile(); } catch { return false; } }) || null;
  return adbCache;
}

async function adb(serial, ...args) {
  const bin = findAdb();
  if (!bin) throw new Error('No se encontró adb (Android SDK platform-tools)');
  return run(bin, serial ? ['-s', serial, ...args] : args);
}

const isEmulator = (serial) => serial.startsWith('emulator-');

async function listDevices(proxyPort) {
  if (!findAdb()) return null; // sin SDK de Android
  let out;
  try { out = await adb(null, 'devices', '-l'); } catch { return []; }
  const devices = [];
  for (const line of out.split(/\r?\n/).slice(1)) {
    const m = /^(\S+)\s+(device|unauthorized|offline)\b(.*)$/.exec(line.trim());
    if (!m) continue;
    const [, serial, state, rest] = m;
    const model = (/model:(\S+)/.exec(rest) || [])[1];
    const d = { serial, state, emulator: isEmulator(serial), name: model ? model.replace(/_/g, ' ') : serial };
    if (state === 'device') {
      const [avd, release, proxy] = await Promise.all([
        d.emulator ? adb(serial, 'emu', 'avd', 'name').then((s) => s.split(/\r?\n/)[0].trim()).catch(() => '') : '',
        adb(serial, 'shell', 'getprop', 'ro.build.version.release').then((s) => s.trim()).catch(() => ''),
        adb(serial, 'shell', 'settings', 'get', 'global', 'http_proxy').then((s) => s.trim()).catch(() => ''),
      ]);
      if (avd && avd !== 'OK') d.name = avd.replace(/_/g, ' ');
      d.android = release;
      d.proxy = proxy === 'null' || proxy === ':0' ? '' : proxy;
      d.usingProxyboy = !!proxyPort && d.proxy === proxyAddress(d, proxyPort);
    }
    devices.push(d);
  }
  return devices;
}

function proxyAddress(device, port) {
  return `${device.emulator ? '10.0.2.2' : '127.0.0.1'}:${port}`;
}

// Configura el proxy y copia el certificado; abre la pantalla de seguridad para que el usuario lo instale
async function setup(serial, port, certPath) {
  const device = { serial, emulator: isEmulator(serial) };
  if (!device.emulator) await adb(serial, 'reverse', `tcp:${port}`, `tcp:${port}`);
  await adb(serial, 'shell', 'settings', 'put', 'global', 'http_proxy', proxyAddress(device, port));
  await adb(serial, 'push', certPath, DEVICE_CERT_PATH);
  // Desde Android 11 los certificados de CA solo se instalan desde Ajustes (no por intent)
  await adb(serial, 'shell', 'am', 'start', '-a', 'android.settings.SECURITY_SETTINGS').catch(() => {});
  return { proxy: proxyAddress(device, port), certOnDevice: DEVICE_CERT_PATH };
}

async function clearProxy(serial, port) {
  await adb(serial, 'shell', 'settings', 'put', 'global', 'http_proxy', ':0');
  if (!isEmulator(serial) && port) await adb(serial, 'reverse', '--remove', `tcp:${port}`).catch(() => {});
}

module.exports = { findAdb, listDevices, setup, clearProxy, DEVICE_CERT_PATH };
