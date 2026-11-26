#!/usr/bin/env node
// Configura emuladores / teléfonos Android desde la terminal (lo mismo que "Activar VPN" en la app):
//   npm run android                      → todos los dispositivos conectados
//   npm run android -- --serial emulator-5554 --port 9090
//   npm run android -- --stop            → apaga la VPN
//   npm run android -- --data ~/.proxyboy → CA del modo consola (`npm run proxy`) en vez de la de la app
const fs = require('fs');
const os = require('os');
const path = require('path');
const android = require('./android');

const args = process.argv.slice(2);
const arg = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};
const flag = (name) => args.includes(`--${name}`);

// Carpeta de datos de la app de escritorio (Electron userData), o la del modo consola
function defaultDataDir() {
  const appDir = process.platform === 'darwin' ? path.join(os.homedir(), 'Library', 'Application Support', 'proxyboy')
    : process.platform === 'win32' ? path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'proxyboy')
      : path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'proxyboy');
  return fs.existsSync(path.join(appDir, 'proxyboy-ca.pem')) ? appDir : path.join(os.homedir(), '.proxyboy');
}

(async () => {
  if (!android.findAdb()) {
    console.error('No se encontró adb. Instalá Android Studio (SDK platform-tools) o definí ANDROID_HOME.');
    process.exit(1);
  }
  const dataDir = arg('data', defaultDataDir());
  let port = Number(arg('port', 0));
  if (!port) {
    try { port = JSON.parse(fs.readFileSync(path.join(dataDir, 'settings.json'), 'utf8')).port; } catch { /* sin settings */ }
    port = port || 9090;
  }
  const certPath = path.join(dataDir, 'proxyboy-ca.pem');
  if (!flag('stop') && !fs.existsSync(certPath)) {
    console.error(`No existe ${certPath}. Abrí Proxyboy (o \`npm run proxy\`) una vez para generar el certificado.`);
    process.exit(1);
  }

  const serial = arg('serial');
  const devices = ((await android.listDevices(port)) || []).filter((d) => d.state === 'device' && (!serial || d.serial === serial));
  if (!devices.length) {
    console.error(serial ? `No está conectado ${serial}.` : 'No hay emuladores ni teléfonos conectados (adb devices).');
    process.exit(1);
  }

  for (const d of devices) {
    const label = `${d.name} (${d.serial}, Android ${d.android || '?'})`;
    try {
      if (flag('stop')) {
        await android.stopVpn(d.serial, port);
        console.log(`✔ ${label}: VPN apagada`);
        continue;
      }
      const r = await android.startVpn(d.serial, port, certPath, `${d.name} · Android ${d.android || '?'}`);
      console.log(`✔ ${label}: VPN activa → Proxyboy en ${r.proxy}`);
      console.log(r.certInstalled ? '  ✔ Certificado de Proxyboy instalado (certificado de usuario)'
        : `  ⚠ Sin root: el certificado quedó en ${r.certOnDevice}. Instalalo en Ajustes → Seguridad → Encriptación y credenciales → Instalar un certificado → Certificado de CA`);
    } catch (e) {
      console.log(`✖ ${label}: ${e.message.split('\n')[0]}`);
      process.exitCode = 1;
    }
  }
  if (!flag('stop')) {
    console.log(`\nCA usada: ${certPath}`);
    console.log('Para descifrar HTTPS: en Proxyboy, clic derecho sobre la app → SSL Proxying.');
    console.log('La app tiene que confiar en CAs de usuario (network_security_config con <certificates src="user"/> en debug-overrides).');
  }
})();
