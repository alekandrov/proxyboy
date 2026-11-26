// Smoke test del motor de proxy. Levanta servidores locales (HTTP, HTTPS, HTTP/2, WebSocket)
// y verifica captura, intercepción, reglas, HTTP/2 + trailers, WebSocket, repetir y HAR.
const http = require('http');
const https = require('https');
const http2 = require('http2');
const net = require('net');
const tls = require('tls');
const zlib = require('zlib');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const { promisify } = require('util');
const assert = require('assert');
const { CertificateAuthority } = require('../src/main/ca');
const { ProxyServer } = require('../src/main/proxy');

const execFileP = promisify(execFile);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'proxyboy-test-'));
const ca = new CertificateAuthority(tmp);
const caFile = path.join(tmp, 'proxyboy-ca.pem');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let passed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✔ ${name}`);
  } catch (e) {
    console.log(`  ✖ ${name}\n    ${e.stack.split('\n').slice(0, 3).join('\n    ')}`);
    process.exitCode = 1;
  }
}

function handler(req, res) {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    if (req.url === '/gzip') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' });
      return res.end(zlib.gzipSync(JSON.stringify({ hola: 'mundo' })));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ method: req.method, url: req.url, body, headers: req.headers }));
  });
}

// Servidor WebSocket mínimo: responde "eco:<mensaje>"
function wsServer() {
  const srv = http.createServer();
  srv.on('upgrade', (req, socket) => {
    const accept = crypto.createHash('sha1').update(`${req.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    srv.lastExtensions = req.headers['sec-websocket-extensions'];
    socket.on('data', (d) => {
      const len = d[1] & 0x7f;
      const mask = d.subarray(2, 6);
      const payload = Buffer.from(d.subarray(6, 6 + len)).map((b, i) => b ^ mask[i & 3]);
      const msg = Buffer.from(`eco:${Buffer.from(payload).toString()}`);
      socket.write(Buffer.concat([Buffer.from([0x81, msg.length]), msg]));
    });
  });
  return srv;
}

(async () => {
  const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));
  const leaf = { key: ca.leafKeyPem, cert: ca._createLeafPem('localhost') };
  const hp = await listen(http.createServer(handler));
  const sp = await listen(https.createServer(leaf, handler));
  const ws = wsServer();
  const wp = await listen(ws);
  // Servidor HTTP/2 puro, estilo gRPC: body binario + trailers
  const h2srv = http2.createSecureServer({ ...leaf, allowHTTP1: false });
  h2srv.on('stream', (stream, headers) => {
    stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
    stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0', 'grpc-message': 'ok' }));
    // Frame gRPC: flag 0 + longitud 4 bytes + mensaje protobuf (campo 1 = "hola")
    const msg = Buffer.from([0x0a, 0x04, ...Buffer.from('hola')]);
    const frame = Buffer.concat([Buffer.from([0]), Buffer.from([0, 0, 0, msg.length]), msg]);
    stream.end(frame);
    h2srv.lastPath = headers[':path'];
  });
  const h2p = await listen(h2srv);

  const proxy = new ProxyServer({ ca, port: 0, host: '127.0.0.1' });
  proxy.updateSettings({ sslHosts: ['localhost'], verifyUpstreamTLS: false });
  const port = await proxy.start();
  const curl = async (...args) => (await execFileP('curl', ['-s', '--noproxy', '', '--max-time', '10', '-x', `http://127.0.0.1:${port}`, ...args])).stdout;
  const flows = () => [...proxy.flows.values()];
  const lastFlow = (p) => flows().filter((f) => f.path && f.path.startsWith(p)).pop();

  console.log('Proxyboy smoke test');

  await check('HTTP plano con body', async () => {
    const r = JSON.parse(await curl(`http://localhost:${hp}/hola?x=1`, '-d', 'payload'));
    assert.strictEqual(r.body, 'payload');
    assert.strictEqual(lastFlow('/hola').response.statusCode, 200);
  });

  await check('HTTPS interceptado (HTTP/1.1)', async () => {
    const r = JSON.parse(await curl('--http1.1', '--cacert', caFile, `https://localhost:${sp}/seguro`));
    assert.strictEqual(r.url, '/seguro');
    assert.strictEqual(lastFlow('/seguro').scheme, 'https');
  });

  await check('HTTPS interceptado con cliente HTTP/2 → servidor HTTP/1.1', async () => {
    const r = JSON.parse(await curl('--http2', '--cacert', caFile, `https://localhost:${sp}/h2cliente`));
    assert.strictEqual(r.url, '/h2cliente');
    assert.strictEqual(lastFlow('/h2cliente').httpVersion, '2.0');
  });

  await check('HTTP/2 de punta a punta con trailers (gRPC)', async () => {
    const result = await new Promise((resolve, reject) => {
      const c = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: `localhost:${h2p}` });
      c.on('connect', (_res, socket) => {
        const session = http2.connect(`https://localhost:${h2p}`, {
          createConnection: () => tls.connect({ socket, servername: 'localhost', ALPNProtocols: ['h2'], ca: ca.caCertPem }),
        });
        session.on('error', reject);
        const st = session.request({ ':method': 'POST', ':path': '/pkg.Servicio/Metodo', 'content-type': 'application/grpc', te: 'trailers' });
        let trailers = null;
        const chunks = [];
        st.on('trailers', (t) => { trailers = t; });
        st.on('data', (d) => chunks.push(d));
        st.on('end', () => { session.close(); resolve({ trailers, body: Buffer.concat(chunks) }); });
        st.end(Buffer.from([0, 0, 0, 0, 0]));
      });
      c.on('error', reject);
      c.end();
    });
    assert.strictEqual(result.trailers['grpc-status'], '0');
    assert.strictEqual(result.body.subarray(5).toString('latin1'), '\n\u0004hola');
    const f = lastFlow('/pkg.Servicio');
    assert.ok(f.tags.includes('h2'), 'upstream debería ser h2');
    assert.strictEqual(f.response.trailers.find(([k]) => k === 'grpc-status')[1], '0');
  });

  await check('gzip decodificado en el inspector', async () => {
    await curl(`http://localhost:${hp}/gzip`, '--compressed');
    const d = proxy.detail(lastFlow('/gzip').id);
    assert.strictEqual(Buffer.from(d.response.body.base64, 'base64').toString(), '{"hola":"mundo"}');
  });

  await check('Túnel sin interceptar', async () => {
    JSON.parse(await curl('-k', `https://127.0.0.1:${sp}/tunel`));
    assert.ok(flows().find((f) => f.method === 'CONNECT' && f.tags.includes('tunnel')));
  });

  await check('Map Local', async () => {
    proxy.setRules({ mapLocal: [{ id: 1, enabled: true, method: 'GET', url: '*/mock*', status: 418, headers: [['Content-Type', 'text/plain']], body: 'soy una tetera' }] });
    assert.strictEqual(await curl(`http://localhost:${hp}/mock/1`), 'soy una tetera');
    assert.strictEqual(lastFlow('/mock/1').response.statusCode, 418);
    proxy.setRules({ mapLocal: [] });
  });

  await check('Map Remote (HTTP → HTTPS, cambia host y path)', async () => {
    proxy.setRules({ mapRemote: [{ id: 2, enabled: true, method: '*', url: `http://localhost:${hp}/viejo/*`, to: `https://localhost:${sp}/nuevo` }] });
    const r = JSON.parse(await curl(`http://localhost:${hp}/viejo/x?q=1`));
    assert.strictEqual(r.url, '/nuevo?q=1');
    assert.strictEqual(r.headers.host, `localhost:${sp}`);
    const f = lastFlow('/nuevo');
    assert.ok(f.tags.includes('map-remote'));
    assert.ok(f.originalUrl.includes('/viejo/x'));
    proxy.setRules({ mapRemote: [] });
  });

  await check('Block List', async () => {
    proxy.setRules({ block: [{ id: 3, enabled: true, url: '*/bloqueado*' }] });
    await curl(`http://localhost:${hp}/bloqueado`).catch(() => '');
    assert.strictEqual(lastFlow('/bloqueado').error, 'Bloqueado por regla');
    proxy.setRules({ block: [] });
  });

  await check('Breakpoints de request y response (editar)', async () => {
    const seen = [];
    proxy.onBreakpoint = async (bp) => {
      seen.push(bp.phase);
      if (bp.phase === 'request') return { action: 'execute', body: 'editado', headers: [...bp.headers, ['X-Bp', '1']] };
      return { action: 'execute', statusCode: 201, body: JSON.stringify({ reemplazado: true, original: JSON.parse(bp.body) }) };
    };
    proxy.setRules({ breakpoints: [{ id: 4, enabled: true, method: '*', url: '*/bp*', request: true, response: true }] });
    const out = JSON.parse(await curl('--http1.1', '--cacert', caFile, `https://localhost:${sp}/bp`, '-d', 'original'));
    assert.deepStrictEqual(seen, ['request', 'response']);
    assert.strictEqual(out.reemplazado, true);
    assert.strictEqual(out.original.body, 'editado');
    assert.strictEqual(out.original.headers['x-bp'], '1');
    assert.strictEqual(lastFlow('/bp').response.statusCode, 201);
  });

  await check('Breakpoint: abortar', async () => {
    proxy.onBreakpoint = async () => ({ action: 'abort' });
    await curl(`http://localhost:${hp}/bp-abort`);
    assert.match(lastFlow('/bp-abort').error, /Abortado/);
    proxy.setRules({ breakpoints: [] });
    proxy.onBreakpoint = null;
  });

  await check('Scripting (onRequest + onResponse + console.log)', async () => {
    proxy.setRules({
      scripts: [{
        id: 5, enabled: true, name: 'test', method: '*', url: '*/script*',
        code: `
          async function onRequest(context, url, request) {
            request.headers['X-Script'] = 'si';
            console.log('request a', url);
            return request;
          }
          async function onResponse(context, url, request, response) {
            const body = JSON.parse(response.body);
            body.agregado = 42;
            response.body = body;
            response.headers['X-Modificado'] = 'true';
            return response;
          }`,
      }],
    });
    const out = await (await execFileP('curl', ['-s', '-i', '--noproxy', '', '-x', `http://127.0.0.1:${port}`, `http://localhost:${hp}/script`])).stdout;
    const [head, body] = out.split('\r\n\r\n');
    const json = JSON.parse(body);
    assert.strictEqual(json.agregado, 42);
    assert.strictEqual(json.headers['x-script'], 'si');
    assert.match(head, /X-Modificado: true/i);
    const f = lastFlow('/script');
    assert.ok(f.notes.some((n) => n.text.includes('request a')));
    proxy.setRules({ scripts: [] });
  });

  await check('Script con error no rompe el request', async () => {
    proxy.setRules({ scripts: [{ id: 6, enabled: true, method: '*', url: '*/roto*', code: 'function onRequest(){ throw new Error("boom") }' }] });
    const r = JSON.parse(await curl(`http://localhost:${hp}/roto`));
    assert.strictEqual(r.url, '/roto');
    assert.ok(lastFlow('/roto').tags.includes('script-error'));
    proxy.setRules({ scripts: [] });
  });

  await check('WebSocket: mensajes capturados y compresión desactivada', async () => {
    const socket = net.connect(port, '127.0.0.1');
    await new Promise((r) => socket.once('connect', r));
    socket.write(`GET http://localhost:${wp}/chat HTTP/1.1\r\nHost: localhost:${wp}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n`
      + `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n`
      + 'Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n');
    let buf = '';
    await new Promise((r) => socket.on('data', function onD(d) { buf += d.toString('latin1'); if (buf.includes('\r\n\r\n')) { socket.off('data', onD); r(); } }));
    assert.match(buf, /101/);
    const mask = crypto.randomBytes(4);
    const msg = Buffer.from('hola');
    socket.write(Buffer.concat([Buffer.from([0x81, 0x80 | msg.length]), mask, msg.map((b, i) => b ^ mask[i & 3])]));
    const reply = await new Promise((r) => socket.once('data', r));
    assert.strictEqual(reply.subarray(2).toString(), 'eco:hola');
    await sleep(400);
    const f = lastFlow('/chat');
    assert.deepStrictEqual(f.ws.map((m) => [m.dir, m.payload.toString()]), [['out', 'hola'], ['in', 'eco:hola']]);
    assert.strictEqual(ws.lastExtensions, undefined);
    socket.destroy();
  });

  await check('Repetir request HTTPS', async () => {
    await proxy.sendRequest({ method: 'POST', url: `https://localhost:${sp}/repetido`, headers: [['Content-Type', 'text/plain']], body: 'otra vez' });
    await sleep(100);
    const d = proxy.detail(lastFlow('/repetido').id);
    assert.ok(Buffer.from(d.response.body.base64, 'base64').toString().includes('otra vez'));
  });

  await check('Identifica la app (proceso) que hizo cada request, también por HTTP/2', async () => {
    for (const p of ['/hola', '/seguro', '/h2cliente']) {
      const f = lastFlow(p);
      assert.ok(f.app, `sin app en ${p}`);
      assert.strictEqual(f.app.name, 'curl', `${p}: ${f.app.name} (${f.app.source})`);
      assert.strictEqual(f.app.source, 'process');
    }
  });

  await check('SSL Proxying por app: descifra cualquier dominio de esa app', async () => {
    const curlId = lastFlow('/hola').app.id;
    proxy.updateSettings({ sslApps: [curlId] });
    // 127.0.0.1 no está en sslHosts: sin la regla por app sería un túnel
    JSON.parse(await curl('--cacert', caFile, `https://127.0.0.1:${sp}/por-app`).catch(() => '{}'));
    const f = lastFlow('/por-app');
    assert.ok(f, 'el request debería verse descifrado');
    assert.strictEqual(f.app.name, 'curl');
    proxy.updateSettings({ sslApps: [] });
  });

  await check('App por User-Agent (celulares / respaldo)', async () => {
    const { appFromUserAgent } = require('../src/main/procinfo');
    const ios = appFromUserAgent('Ual%C3%A1/7.0.4 CFNetwork/1568.100.1 Darwin/24.0.0', '192.168.0.23');
    assert.strictEqual(ios.name, 'Ualá');
    assert.strictEqual(ios.device, 'iOS · 192.168.0.23');
    assert.strictEqual(appFromUserAgent('okhttp/4.12.0', '10.0.0.5').device, 'Android · 10.0.0.5');
    assert.strictEqual(appFromUserAgent('Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/120 Safari/537.36').name, 'Google Chrome');
  });

  await check('Exportar HAR', async () => {
    const har = proxy.toHAR();
    assert.ok(har.log.entries.length >= 10);
    assert.ok(har.log.entries.some((e) => e._webSocketMessages && e._webSocketMessages.length === 2));
  });

  console.log(`\n${passed} checks OK${process.exitCode ? ' — HAY FALLAS' : ''}`);
  await proxy.stop();
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(process.exitCode || 0);
})().catch((e) => { console.error(e); process.exit(1); });
