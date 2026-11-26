// Autoridad certificante local: genera (una vez) la CA raíz de Proxyboy y
// firma certificados por host al vuelo para interceptar HTTPS.
const fs = require('fs');
const path = require('path');
const net = require('net');
const tls = require('tls');
const forge = require('node-forge');

const pki = forge.pki;

function randomSerial() {
  // Serial positivo de 16 bytes en hex
  const bytes = forge.random.getBytesSync(16);
  const hex = forge.util.bytesToHex(bytes);
  return '01' + hex.slice(2);
}

class CertificateAuthority {
  constructor(dir) {
    this.dir = dir;
    this.caCertPath = path.join(dir, 'proxyboy-ca.pem');
    this.caKeyPath = path.join(dir, 'proxyboy-ca.key');
    this.cache = new Map(); // host -> tls.SecureContext
    fs.mkdirSync(dir, { recursive: true });
    this._loadOrCreate();
    // Una sola keypair para todos los certificados hoja: generar RSA por host es lento.
    this.leafKeys = pki.rsa.generateKeyPair(2048);
    this.leafKeyPem = pki.privateKeyToPem(this.leafKeys.privateKey);
  }

  _loadOrCreate() {
    if (fs.existsSync(this.caCertPath) && fs.existsSync(this.caKeyPath)) {
      this.caCert = pki.certificateFromPem(fs.readFileSync(this.caCertPath, 'utf8'));
      this.caKey = pki.privateKeyFromPem(fs.readFileSync(this.caKeyPath, 'utf8'));
      return;
    }
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = randomSerial();
    cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
    const attrs = [
      { name: 'commonName', value: `Proxyboy CA (${require('os').hostname()})` },
      { name: 'organizationName', value: 'Proxyboy' },
      { shortName: 'OU', value: 'Proxyboy Debugging Proxy' },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, digitalSignature: true, critical: true },
      { name: 'subjectKeyIdentifier' },
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    fs.writeFileSync(this.caCertPath, pki.certificateToPem(cert));
    fs.writeFileSync(this.caKeyPath, pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
    this.caCert = cert;
    this.caKey = keys.privateKey;
  }

  get caCertPem() {
    return pki.certificateToPem(this.caCert);
  }

  get caFingerprint() {
    const der = forge.asn1.toDer(pki.certificateToAsn1(this.caCert)).getBytes();
    return forge.md.sha256.create().update(der).digest().toHex().match(/../g).join(':').toUpperCase();
  }

  _createLeafPem(host) {
    const cert = pki.createCertificate();
    cert.publicKey = this.leafKeys.publicKey;
    cert.serialNumber = randomSerial();
    // Válido 1 año: macOS/iOS rechazan certificados de más de 825 días
    cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
    cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 3600 * 1000);
    cert.setSubject([{ name: 'commonName', value: host }, { name: 'organizationName', value: 'Proxyboy' }]);
    cert.setIssuer(this.caCert.subject.attributes);
    const altNames = net.isIP(host) ? [{ type: 7, ip: host }] : [{ type: 2, value: host }];
    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName', altNames },
      { name: 'authorityKeyIdentifier', keyIdentifier: this.caCert.generateSubjectKeyIdentifier().getBytes() },
    ]);
    cert.sign(this.caKey, forge.md.sha256.create());
    return pki.certificateToPem(cert);
  }

  secureContextFor(host) {
    host = (host || 'localhost').toLowerCase();
    let ctx = this.cache.get(host);
    if (!ctx) {
      ctx = tls.createSecureContext({
        key: this.leafKeyPem,
        cert: this._createLeafPem(host) + this.caCertPem,
      });
      this.cache.set(host, ctx);
    }
    return ctx;
  }
}

module.exports = { CertificateAuthority };
