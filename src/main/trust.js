// CAs en las que confía Proxyboy al conectarse a los servidores reales: las de Node + las del sistema operativo.
// Sin las del sistema, si la compu tiene inspección TLS corporativa (Netskope, Zscaler…) o una CA interna
// instalada por la empresa, todos los requests descifrados fallarían con SELF_SIGNED_CERT_IN_CHAIN.
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

function run(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, windowsHide: true, timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return '';
  }
}

function systemCertificates() {
  let text = '';
  if (process.platform === 'darwin') {
    const keychains = [
      '/System/Library/Keychains/SystemRootCertificates.keychain',
      '/Library/Keychains/System.keychain', // acá instala el MDM las CAs corporativas
      path.join(os.homedir(), 'Library/Keychains/login.keychain-db'),
    ];
    for (const kc of keychains) if (fs.existsSync(kc)) text += run('security', ['find-certificate', '-a', '-p', kc]);
  } else if (process.platform === 'win32') {
    text = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      "Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root, Cert:\\LocalMachine\\CA | ForEach-Object { '-----BEGIN CERTIFICATE-----'; [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks'); '-----END CERTIFICATE-----' }"]);
  } else {
    for (const f of ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/cert.pem']) {
      try { text += fs.readFileSync(f, 'utf8'); break; } catch { /* siguiente */ }
    }
  }
  const seen = new Set(tls.rootCertificates.map((c) => c.replace(/\s+/g, '')));
  const out = [];
  for (const pem of text.match(PEM_RE) || []) {
    const key = pem.replace(/\s+/g, '');
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      // Solo CAs vigentes: el llavero también guarda certificados de usuario que no son autoridades
      const x = new crypto.X509Certificate(pem);
      if (!x.ca || Date.parse(x.validTo) < Date.now()) continue;
      out.push(pem);
    } catch { /* certificado que OpenSSL no entiende */ }
  }
  return out;
}

let context = null;
let extraCount = 0;

// Contexto TLS compartido para las conexiones hacia los servidores (se arma una vez: son cientos de CAs)
function secureContext() {
  if (!context) {
    const extra = process.env.PROXYBOY_NO_SYSTEM_CA ? [] : systemCertificates();
    extraCount = extra.length;
    try {
      context = tls.createSecureContext({ ca: [...tls.rootCertificates, ...extra] });
    } catch {
      context = tls.createSecureContext({});
      extraCount = 0;
    }
  }
  return context;
}

module.exports = { secureContext, systemCertificates, extraCount: () => extraCount };
