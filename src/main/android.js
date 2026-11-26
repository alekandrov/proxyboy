// Emuladores y dispositivos Android vía adb: configurar el proxy, copiar el certificado y restaurar al salir.
// - Emulador: el proxy apunta a 10.0.2.2 (la Mac/PC vista desde el emulador).
// - Dispositivo por USB: `adb reverse` expone el puerto del proxy en el teléfono como 127.0.0.1.
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const forge = require('node-forge');

const DEVICE_CERT_PATH = '/sdcard/Download/proxyboy-ca.crt';
// App "Proxyboy VPN" (android-vpn/): captura todo el tráfico del dispositivo, también el de apps que ignoran el proxy (Flutter, React Native)
const VPN_PKG = 'com.proxyboy.vpn';
const VPN_APK = path.join(__dirname, 'assets', 'proxyboy-vpn.apk');

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
      const [avd, release, proxy, vpn] = await Promise.all([
        d.emulator ? adb(serial, 'emu', 'avd', 'name').then((s) => s.split(/\r?\n/)[0].trim()).catch(() => '') : '',
        adb(serial, 'shell', 'getprop', 'ro.build.version.release').then((s) => s.trim()).catch(() => ''),
        adb(serial, 'shell', 'settings', 'get', 'global', 'http_proxy').then((s) => s.trim()).catch(() => ''),
        vpnStatus(serial),
      ]);
      if (avd && avd !== 'OK') d.name = avd.replace(/_/g, ' ');
      d.android = release;
      d.proxy = proxy === 'null' || proxy === ':0' ? '' : proxy;
      d.usingProxyboy = !!proxyPort && d.proxy === proxyAddress(d, proxyPort);
      d.vpnInstalled = vpn.installed;
      d.vpnActive = vpn.active;
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

// ---------- Proxyboy VPN ----------
async function vpnStatus(serial) {
  try {
    const out = await adb(serial, 'shell', `pm path ${VPN_PKG}; dumpsys activity services ${VPN_PKG}/.ProxyboyVpnService | grep -c ServiceRecord`);
    return { installed: out.includes('package:'), active: /^[1-9]/m.test(out) };
  } catch {
    return { installed: false, active: false };
  }
}

// Comillas para `adb shell` (el dispositivo vuelve a interpretar la línea con sh)
const shQuote = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;

async function installVpn(serial) {
  // El APK puede estar dentro del .asar: adb necesita un archivo real
  const tmpApk = path.join(os.tmpdir(), 'proxyboy-vpn.apk');
  fs.writeFileSync(tmpApk, fs.readFileSync(VPN_APK));
  try {
    await run(findAdb(), ['-s', serial, 'install', '-r', tmpApk], 120000);
  } catch (e) {
    // Firmada con otra clave (ej. una build vieja): desinstalamos y reinstalamos
    if (!/INSTALL_FAILED_UPDATE_INCOMPATIBLE|signatures do not match/i.test(e.message)) throw e;
    await adb(serial, 'uninstall', VPN_PKG).catch(() => {});
    await run(findAdb(), ['-s', serial, 'install', tmpApk], 120000);
  }
}

// ---------- Certificado en el almacén de usuario (emuladores con root) ----------
// Nombre de archivo que usa Android para los certificados: hash "old" de OpenSSL del subject (MD5, little-endian)
function androidCertName(pem) {
  const tbs = forge.asn1.fromDer(forge.pem.decode(pem)[0].body).value[0];
  const off = tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC ? 1 : 0; // [0] version
  const subject = Buffer.from(forge.asn1.toDer(tbs.value[off + 4]).getBytes(), 'binary');
  return crypto.createHash('md5').update(subject).digest().readUInt32LE(0).toString(16).padStart(8, '0');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// adbd como root: solo en emuladores con imagen "Google APIs" (las "Google Play" no lo permiten)
async function ensureRoot(serial) {
  const isRoot = () => adb(serial, 'shell', 'id', '-u').then((s) => s.trim() === '0').catch(() => false);
  if (await isRoot()) return true;
  await adb(serial, 'root').catch(() => {});
  // adbd se reinicia: esperamos a que vuelva
  for (let i = 0; i < 20; i++) {
    await sleep(500);
    if (await isRoot()) return true;
  }
  return false;
}

// Instala la CA como certificado de usuario sin pasar por Ajustes. Las apps debug que confían en CAs de usuario
// (network_security_config con <certificates src="user"/>) y Chrome la aceptan. Devuelve false si no hay root.
async function installUserCert(serial, certPath) {
  if (!isEmulator(serial) || !(await ensureRoot(serial))) return false;
  const name = androidCertName(fs.readFileSync(certPath, 'utf8'));
  const tmp = '/data/local/tmp/proxyboy-ca.pem';
  const dir = '/data/misc/user/0/cacerts-added';
  await adb(serial, 'push', certPath, tmp);
  // Si ya hay otro certificado con el mismo hash usamos el siguiente sufijo (.1, .2…)
  await adb(serial, 'shell', `mkdir -p ${dir} && chown system:system ${dir} && chmod 755 ${dir} && `
    + `for n in 0 1 2 3 4 5 6 7 8 9; do f=${dir}/${name}.$n; `
    + `if [ ! -e $f ] || cmp -s ${tmp} $f; then cp ${tmp} $f && chown system:system $f && chmod 644 $f; break; fi; done; `
    + `restorecon -R ${dir}; rm -f ${tmp}`);
  return true;
}

// Instala (o actualiza) la app, le da el permiso de VPN sin diálogo y la conecta a Proxyboy.
// En emuladores con root también instala el certificado de Proxyboy.
async function startVpn(serial, port, certPath, deviceName) {
  const device = { serial, emulator: isEmulator(serial) };
  if (!device.emulator) await adb(serial, 'reverse', `tcp:${port}`, `tcp:${port}`);
  await installVpn(serial);
  await adb(serial, 'shell', 'appops', 'set', VPN_PKG, 'ACTIVATE_VPN', 'allow').catch(() => {});
  let certInstalled = false;
  if (certPath) {
    certInstalled = await installUserCert(serial, certPath).catch(() => false);
    // Sin root: queda en Descargas para instalarlo desde Ajustes
    if (!certInstalled) await adb(serial, 'push', certPath, DEVICE_CERT_PATH).catch(() => {});
  }
  const host = device.emulator ? '10.0.2.2' : '127.0.0.1';
  await adb(serial, 'shell', `am start -n ${VPN_PKG}/.MainActivity --es host ${host} --ei port ${Number(port)}`
    + `${deviceName ? ` --es device ${shQuote(deviceName)}` : ''} --ez connect true`);
  return { proxy: `${host}:${port}`, certInstalled, certOnDevice: certInstalled ? null : DEVICE_CERT_PATH };
}

// Cerrar la app apaga la VPN y el dispositivo vuelve a su red normal
async function stopVpn(serial, port) {
  await adb(serial, 'shell', 'am', 'force-stop', VPN_PKG);
  if (!isEmulator(serial) && port) await adb(serial, 'reverse', '--remove', `tcp:${port}`).catch(() => {});
}

module.exports = {
  findAdb, listDevices, setup, clearProxy, startVpn, stopVpn, installUserCert, androidCertName, DEVICE_CERT_PATH,
};
