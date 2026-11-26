// Smoke test del motor de proxy: HTTP, HTTPS interceptado, túnel, gzip, Map Local, repeat y HAR.
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileP = promisify(execFile);
const assert = require('assert');
const { CertificateAuthority } = require('../src/main/ca');
const { ProxyServer } = require('../src/main/proxy');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'proxyboy-test-'));
const ca = new CertificateAuthority(tmp);
const caFile = path.join(tmp, 'proxyboy-ca.pem');

function handler(req, res) {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    if (req.url === '/gzip') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' });
      return res.end(zlib.gzipSync(JSON.stringify({ hola: 'mundo' })));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ method: req.method, url: req.url, body }));
  });
}

(async () => {
  const httpSrv = http.createServer(handler).listen(0);
  // Servidor HTTPS de prueba con certificado de nuestra CA para "localhost"
  const httpsSrv = https.createServer({ key: ca.leafKeyPem, cert: ca._createLeafPem('localhost') }, handler).listen(0);
  await new Promise((r) => setTimeout(r, 200));
  const hp = httpSrv.address().port;
  const sp = httpsSrv.address().port;

  const proxy = new ProxyServer({ ca, port: 0, host: '127.0.0.1' });
  proxy.updateSettings({ sslHosts: ['localhost'], verifyUpstreamTLS: false });
  const port = await proxy.start();
  const curl = async (...args) => (await execFileP('curl', ['-s', '--noproxy', '', '--max-time', '10', '-x', `http://127.0.0.1:${port}`, ...args])).stdout;

  // 1. HTTP plano
  const r1 = JSON.parse(await curl(`http://localhost:${hp}/hola?x=1`, '-d', 'payload'));
  assert.strictEqual(r1.body, 'payload');

  // 2. HTTPS interceptado
  const r2 = JSON.parse(await curl('--cacert', caFile, `https://localhost:${sp}/seguro`));
  assert.strictEqual(r2.url, '/seguro');

  // 3. gzip decodificado en el inspector
  await curl(`http://localhost:${hp}/gzip`, '--compressed');

  // 4. Túnel sin interceptar (127.0.0.1 no está en la lista SSL) -> curl -k
  JSON.parse(await curl('-k', `https://127.0.0.1:${sp}/tunel`));

  // 5. Map Local
  proxy.mapLocalRules.push({ id: 1, enabled: true, method: 'GET', url: '*/mock*', status: 418, headers: [['Content-Type', 'text/plain']], body: 'soy una tetera' });
  assert.strictEqual(await curl(`http://localhost:${hp}/mock/1`), 'soy una tetera');

  // 6. Repeat de un request HTTPS
  console.log('repeat status', await proxy.sendRequest({ method: 'POST', url: `https://localhost:${sp}/repetido`, headers: [['Content-Type', 'text/plain']], body: 'otra vez' }));

  await new Promise((r) => setTimeout(r, 300));
  const flows = [...proxy.flows.values()].map((f) => proxy.summary(f));
  for (const f of flows) console.log(`#${f.id} ${f.method} ${f.url} -> ${f.status} [${f.state}] ${f.tags.join(',')}`);

  const byPath = (p) => flows.find((f) => f.path && f.path.startsWith(p));
  assert.ok(byPath('/hola') && byPath('/hola').status === 200);
  assert.ok(byPath('/seguro') && byPath('/seguro').scheme === 'https');
  assert.ok(flows.find((f) => f.method === 'CONNECT' && f.tags.includes('tunnel')));
  assert.strictEqual(byPath('/mock/1').status, 418);
  const rep = byPath('/repetido');
  assert.ok(rep && rep.status === 200);

  const gz = proxy.detail(byPath('/gzip').id);
  assert.strictEqual(Buffer.from(gz.response.body.base64, 'base64').toString(), '{"hola":"mundo"}');
  const repDetail = proxy.detail(rep.id);
  assert.ok(Buffer.from(repDetail.response.body.base64, 'base64').toString().includes('otra vez'));

  const har = proxy.toHAR();
  assert.ok(har.log.entries.length >= 5);

  console.log('\nOK: todos los checks pasaron');
  await proxy.stop();
  httpSrv.close(); httpsSrv.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
