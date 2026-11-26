#!/usr/bin/env node
// Modo consola (sin UI): `npm run proxy -- --port 9090 --ssl "*.uala.com.ar,api.example.com"`
const os = require('os');
const path = require('path');
const { CertificateAuthority } = require('./ca');
const { ProxyServer } = require('./proxy');

const args = process.argv.slice(2);
const arg = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
};

const dir = arg('data', path.join(os.homedir(), '.proxyboy'));
const ca = new CertificateAuthority(dir);
const proxy = new ProxyServer({ ca, port: Number(arg('port', 9090)) });
const ssl = arg('ssl', '');
proxy.updateSettings({ sslProxyAll: ssl === '*', sslHosts: ssl.split(',').filter(Boolean) });

proxy.on('flow-update', (f) => {
  if (f.state === 'pending' || f.state === 'tunnel') return;
  const status = f.status || 'ERR';
  const ms = f.duration != null ? `${f.duration}ms` : '';
  const app = f.app ? `[${f.app.name}${f.app.device ? ` · ${f.app.device}` : ''}] ` : '';
  console.log(`${String(status).padEnd(4)} ${f.method.padEnd(7)} ${app}${f.url} ${ms}${f.error ? `  ✖ ${f.error}` : ''}`);
});

proxy.start().then((port) => {
  console.log(`Proxyboy escuchando en http://0.0.0.0:${port}`);
  console.log(`Certificado raíz: ${ca.caCertPath}`);
  console.log(`SSL proxying: ${ssl || '(ninguno — usá --ssl "*.dominio.com" o --ssl "*")'}`);
});
