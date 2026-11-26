// Motor del proxy: HTTP forward proxy + túnel CONNECT con intercepción HTTPS (MITM).
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const zlib = require('zlib');
const { EventEmitter } = require('events');
const { URL } = require('url');

const MAX_CAPTURED_BODY = 10 * 1024 * 1024; // guardamos hasta 10 MB por body
const HOP_BY_HOP = new Set([
  'proxy-connection', 'proxy-authorization', 'connection', 'keep-alive',
  'transfer-encoding', 'te', 'trailer', 'upgrade',
]);

// Convierte un patrón con comodines (*.ejemplo.com, api.*/v1/*) en RegExp
function wildcardToRegExp(pattern) {
  const esc = pattern.trim().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp('^' + esc + '$', 'i');
}

function hostMatches(host, patterns) {
  return patterns.some((p) => p && wildcardToRegExp(p).test(host));
}

function rawHeadersToPairs(raw) {
  const pairs = [];
  for (let i = 0; i < raw.length; i += 2) pairs.push([raw[i], raw[i + 1]]);
  return pairs;
}

function pairsGet(pairs, name) {
  name = name.toLowerCase();
  const p = pairs.find(([k]) => k.toLowerCase() === name);
  return p ? p[1] : undefined;
}

class BodyCollector {
  constructor() { this.chunks = []; this.size = 0; this.truncated = false; this.captured = 0; }
  push(chunk) {
    this.size += chunk.length;
    if (this.captured + chunk.length <= MAX_CAPTURED_BODY) {
      this.chunks.push(chunk);
      this.captured += chunk.length;
    } else {
      this.truncated = true;
    }
  }
  buffer() { return Buffer.concat(this.chunks); }
}

function decodeBody(buf, encoding) {
  if (!buf || !buf.length || !encoding) return buf;
  try {
    const enc = encoding.toLowerCase().trim();
    if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buf);
    if (enc === 'deflate') {
      try { return zlib.inflateSync(buf); } catch { return zlib.inflateRawSync(buf); }
    }
    if (enc === 'br') return zlib.brotliDecompressSync(buf);
    if (enc === 'zstd' && typeof zlib.zstdDecompressSync === 'function') return zlib.zstdDecompressSync(buf);
  } catch {
    /* body corrupto o parcial: devolvemos crudo */
  }
  return buf;
}

class ProxyServer extends EventEmitter {
  constructor({ ca, port = 9090, host = '0.0.0.0' } = {}) {
    super();
    this.ca = ca;
    this.port = port;
    this.listenHost = host;
    this.flows = new Map();
    this.nextId = 1;
    this.maxFlows = 10000;
    this.settings = {
      sslProxyingEnabled: true,
      sslProxyAll: false,
      sslHosts: [], // ej: ['*.uala.com.ar', 'api.example.com']
      verifyUpstreamTLS: true,
      recording: true,
    };
    // Map Local: respuestas mockeadas
    this.mapLocalRules = []; // {id, enabled, method, url, status, headers:[[k,v]], body}
    this.blockRules = [];    // {id, enabled, url}
    this.agentHttp = new http.Agent({ keepAlive: true, maxSockets: 256 });
    this.agentHttps = new https.Agent({ keepAlive: true, maxSockets: 256 });
    this.agentHttpsInsecure = new https.Agent({ keepAlive: true, maxSockets: 256, rejectUnauthorized: false });

    this.server = http.createServer();
    this.server.on('request', (req, res) => this._onRequest(req, res, false));
    this.server.on('connect', (req, socket, head) => this._onConnect(req, socket, head));
    this.server.on('upgrade', (req, socket, head) => this._onUpgrade(req, socket, head, false));
    this.server.on('clientError', (err, socket) => socket.destroy());

    // Servidor interno que recibe las conexiones TLS ya desencriptadas
    this.mitmServer = http.createServer();
    this.mitmServer.on('request', (req, res) => this._onRequest(req, res, true));
    this.mitmServer.on('upgrade', (req, socket, head) => this._onUpgrade(req, socket, head, true));
    this.mitmServer.on('clientError', (err, socket) => socket.destroy());
  }

  start() {
    return new Promise((resolve, reject) => {
      const onErr = (e) => reject(e);
      this.server.once('error', onErr);
      this.server.listen(this.port, this.listenHost, () => {
        this.server.off('error', onErr);
        this.running = true;
        resolve(this.server.address().port);
      });
    });
  }

  stop() {
    return new Promise((resolve) => {
      if (!this.running) return resolve();
      this.running = false;
      this.server.close(() => resolve());
      if (this.server.closeAllConnections) this.server.closeAllConnections();
    });
  }

  updateSettings(patch) {
    Object.assign(this.settings, patch);
  }

  shouldIntercept(host) {
    if (!this.settings.sslProxyingEnabled) return false;
    if (this.settings.sslProxyAll) return true;
    return hostMatches(host, this.settings.sslHosts);
  }

  // ---------- Flows ----------
  _newFlow(data) {
    const flow = {
      id: this.nextId++,
      startedAt: Date.now(),
      state: 'pending',
      request: { headers: [], body: null, bodySize: 0 },
      response: null,
      timings: { start: Date.now() },
      tags: [],
      ...data,
    };
    if (!this.settings.recording) {
      flow._ephemeral = true;
      return flow;
    }
    this.flows.set(flow.id, flow);
    if (this.flows.size > this.maxFlows) {
      const oldest = this.flows.keys().next().value;
      this.flows.delete(oldest);
    }
    this.emit('flow', this.summary(flow));
    return flow;
  }

  _update(flow) {
    if (flow._ephemeral) return;
    this.emit('flow-update', this.summary(flow));
  }

  clear() { this.flows.clear(); }

  summary(f) {
    return {
      id: f.id,
      startedAt: f.startedAt,
      method: f.method,
      scheme: f.scheme,
      host: f.host,
      port: f.port,
      path: f.path,
      url: f.url,
      state: f.state,
      status: f.response ? f.response.statusCode : null,
      contentType: f.response ? pairsGet(f.response.headers, 'content-type') || '' : '',
      reqSize: f.request.bodySize,
      resSize: f.response ? f.response.bodySize : 0,
      duration: f.timings.end ? f.timings.end - f.timings.start : null,
      error: f.error || null,
      tags: f.tags,
      client: f.client,
    };
  }

  // Detalle completo para el inspector
  detail(id) {
    const f = this.flows.get(id);
    if (!f) return null;
    const encode = (headers, body, truncated) => {
      if (!body) return { size: 0, base64: '', truncated: false };
      const decoded = decodeBody(body, pairsGet(headers, 'content-encoding'));
      return { size: decoded.length, base64: decoded.toString('base64'), truncated: !!truncated };
    };
    return {
      ...this.summary(f),
      httpVersion: f.httpVersion,
      timings: f.timings,
      request: {
        headers: f.request.headers,
        body: encode(f.request.headers, f.request.body, f.request.truncated),
      },
      response: f.response
        ? {
          statusCode: f.response.statusCode,
          statusMessage: f.response.statusMessage,
          httpVersion: f.response.httpVersion,
          headers: f.response.headers,
          body: encode(f.response.headers, f.response.body, f.response.truncated),
        }
        : null,
    };
  }

  // ---------- Reglas ----------
  _matchMapLocal(method, url) {
    return this.mapLocalRules.find((r) => r.enabled
      && (!r.method || r.method === '*' || r.method.toUpperCase() === method)
      && wildcardToRegExp(r.url).test(url));
  }

  _matchBlock(url) {
    return this.blockRules.find((r) => r.enabled && wildcardToRegExp(r.url).test(url));
  }

  // ---------- HTTP ----------
  _onRequest(req, res, isMitm) {
    let target;
    try {
      if (isMitm) {
        const t = req.socket._proxyboyTarget || {};
        const hostHeader = req.headers.host || `${t.host}:${t.port}`;
        target = new URL(`https://${hostHeader}${req.url}`);
      } else if (/^https?:\/\//i.test(req.url)) {
        target = new URL(req.url);
      } else {
        return this._serveLocal(req, res);
      }
    } catch {
      res.writeHead(400);
      return res.end('Proxyboy: URL inválida');
    }

    if (!isMitm && (target.hostname === 'proxy.boy' || target.hostname === 'proxyboy.local')) {
      if (target.pathname.startsWith('/cert')) req.url = '/cert.pem';
      return this._serveLocal(req, res);
    }

    const isHttps = target.protocol === 'https:';
    const port = Number(target.port) || (isHttps ? 443 : 80);
    const flow = this._newFlow({
      method: req.method,
      scheme: isHttps ? 'https' : 'http',
      host: target.hostname,
      port,
      path: target.pathname + target.search,
      url: target.toString(),
      httpVersion: req.httpVersion,
      client: req.socket.remoteAddress,
    });
    flow.request.headers = rawHeadersToPairs(req.rawHeaders);

    const reqBody = new BodyCollector();

    // Bloqueo
    const block = this._matchBlock(flow.url);
    if (block) {
      flow.tags.push('blocked');
      req.resume();
      req.socket.destroy();
      flow.state = 'failed';
      flow.error = 'Bloqueado por regla';
      flow.timings.end = Date.now();
      return this._update(flow);
    }

    // Map Local (mock)
    const mock = this._matchMapLocal(req.method, flow.url);
    if (mock) {
      req.on('data', (c) => reqBody.push(c));
      req.on('end', () => {
        flow.request.body = reqBody.buffer();
        flow.request.bodySize = reqBody.size;
        const body = Buffer.from(mock.body || '', 'utf8');
        const headers = (mock.headers || []).filter(([k]) => k);
        if (!pairsGet(headers, 'content-length')) headers.push(['Content-Length', String(body.length)]);
        flow.tags.push('map-local');
        flow.timings.responseStart = Date.now();
        flow.response = {
          statusCode: Number(mock.status) || 200, statusMessage: http.STATUS_CODES[mock.status] || '',
          httpVersion: '1.1', headers, body, bodySize: body.length,
        };
        res.writeHead(flow.response.statusCode, headers.flat());
        res.end(body);
        flow.state = 'completed';
        flow.timings.end = Date.now();
        this._update(flow);
      });
      return;
    }

    const outHeaders = [];
    for (const [k, v] of flow.request.headers) {
      if (HOP_BY_HOP.has(k.toLowerCase())) continue;
      outHeaders.push(k, v);
    }

    const options = {
      method: req.method,
      hostname: target.hostname,
      port,
      path: flow.path,
      headers: outHeaders,
      agent: isHttps
        ? (this.settings.verifyUpstreamTLS ? this.agentHttps : this.agentHttpsInsecure)
        : this.agentHttp,
      servername: net.isIP(target.hostname) ? undefined : target.hostname,
      setHost: false,
    };

    const upstream = (isHttps ? https : http).request(options);
    upstream.on('response', (up) => {
      flow.timings.responseStart = Date.now();
      flow.response = {
        statusCode: up.statusCode,
        statusMessage: up.statusMessage,
        httpVersion: up.httpVersion,
        headers: rawHeadersToPairs(up.rawHeaders),
        body: null,
        bodySize: 0,
      };
      this._update(flow);
      const resHeaders = [];
      for (const [k, v] of flow.response.headers) {
        const lk = k.toLowerCase();
        if (lk === 'connection' || lk === 'keep-alive' || lk === 'proxy-connection') continue;
        resHeaders.push(k, v);
      }
      try {
        res.writeHead(up.statusCode, up.statusMessage, resHeaders);
      } catch (e) {
        res.writeHead(up.statusCode);
      }
      const resBody = new BodyCollector();
      up.on('data', (c) => { resBody.push(c); res.write(c); });
      up.on('end', () => {
        res.end();
        flow.response.body = resBody.buffer();
        flow.response.bodySize = resBody.size;
        flow.response.truncated = resBody.truncated;
        flow.state = 'completed';
        flow.timings.end = Date.now();
        this._update(flow);
      });
      up.on('error', (e) => this._fail(flow, e, res));
    });
    upstream.on('error', (e) => this._fail(flow, e, res));

    req.on('data', (c) => { reqBody.push(c); upstream.write(c); });
    req.on('end', () => {
      flow.request.body = reqBody.buffer();
      flow.request.bodySize = reqBody.size;
      flow.request.truncated = reqBody.truncated;
      upstream.end();
    });
    req.on('error', (e) => { upstream.destroy(); this._fail(flow, e, res); });
  }

  _fail(flow, err, res) {
    if (flow.state === 'failed') return;
    flow.state = 'failed';
    flow.error = err.code ? `${err.code}: ${err.message}` : err.message;
    flow.timings.end = Date.now();
    if (res && !res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`Proxyboy: error conectando con el servidor\n${flow.error}`);
    } else if (res) {
      res.destroy();
    }
    this._update(flow);
  }

  // Página local para descargar el certificado (http://proxy.boy o http://IP:puerto)
  _serveLocal(req, res) {
    if (req.url.startsWith('/cert')) {
      res.writeHead(200, {
        'Content-Type': 'application/x-x509-ca-cert',
        'Content-Disposition': 'attachment; filename="proxyboy-ca.pem"',
      });
      return res.end(this.ca.caCertPem);
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><meta name="viewport" content="width=device-width">
<body style="font-family:system-ui;padding:24px;max-width:600px;margin:auto">
<h1>Proxyboy</h1><p>El proxy está funcionando.</p>
<p><a href="/cert.pem" style="font-size:20px">Descargar certificado raíz (proxyboy-ca.pem)</a></p>
<p><b>iOS:</b> descargalo, instalalo en Ajustes → Perfil descargado y luego activá la confianza total en
Ajustes → General → Información → Ajustes de confianza de certificados.</p>
<p><b>Android:</b> Ajustes → Seguridad → Instalar certificado CA. Las apps deben confiar en CAs de usuario
(network_security_config).</p></body>`);
  }

  // ---------- CONNECT (HTTPS) ----------
  _onConnect(req, clientSocket, head) {
    const [host, portStr] = req.url.split(/:(?=\d+$)/);
    const port = Number(portStr) || 443;
    clientSocket.on('error', () => {});

    const forced = req.headers['x-proxyboy-intercept'] === '1';
    if (forced || this.shouldIntercept(host)) {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: Proxyboy\r\n\r\n');
      if (head && head.length) clientSocket.unshift(head);
      clientSocket.once('readable', () => {
        const first = clientSocket.read(1);
        if (!first) return clientSocket.destroy();
        clientSocket.unshift(first);
        if (first[0] !== 0x16) {
          // No es TLS (ej. HTTP plano sobre CONNECT): lo pasamos al servidor HTTP
          clientSocket._proxyboyTarget = { host, port };
          this.mitmServer.emit('connection', clientSocket);
          return;
        }
        this._mitmTLS(clientSocket, host, port);
      });
      return;
    }

    // Túnel sin interceptar
    const flow = this._newFlow({
      method: 'CONNECT', scheme: 'https', host, port, path: '', url: `${host}:${port}`,
      httpVersion: req.httpVersion, client: clientSocket.remoteAddress,
    });
    flow.request.headers = rawHeadersToPairs(req.rawHeaders);
    flow.tags.push('tunnel');
    const upstream = net.connect(port, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: Proxyboy\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
      flow.state = 'tunnel';
      flow.response = { statusCode: 200, statusMessage: 'Connection Established', httpVersion: '1.1', headers: [], body: null, bodySize: 0 };
      this._update(flow);
    });
    let up = 0; let down = 0;
    upstream.on('data', (c) => { down += c.length; });
    clientSocket.on('data', (c) => { up += c.length; });
    const done = () => {
      if (flow.timings.end) return;
      flow.timings.end = Date.now();
      flow.request.bodySize = up;
      if (flow.response) flow.response.bodySize = down;
      if (flow.state !== 'failed') flow.state = 'completed';
      this._update(flow);
    };
    upstream.on('error', (e) => {
      if (!flow.response) {
        clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        this._fail(flow, e);
      }
      clientSocket.destroy();
    });
    upstream.on('close', () => { done(); clientSocket.destroy(); });
    clientSocket.on('close', () => { done(); upstream.destroy(); });
  }

  _mitmTLS(clientSocket, host, port) {
    let sniHost = host;
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      secureContext: this.ca.secureContextFor(host),
      SNICallback: (servername, cb) => {
        sniHost = servername || host;
        try { cb(null, this.ca.secureContextFor(sniHost)); } catch (e) { cb(e); }
      },
      ALPNProtocols: ['http/1.1'],
    });
    tlsSocket._proxyboyTarget = { host, port };
    let established = false;
    tlsSocket.on('secure', () => {
      established = true;
      this.mitmServer.emit('connection', tlsSocket);
    });
    tlsSocket.on('error', (err) => {
      if (!established) {
        // Típicamente: el cliente no confía en la CA de Proxyboy o usa SSL pinning
        const flow = this._newFlow({
          method: 'CONNECT', scheme: 'https', host: sniHost, port, path: '', url: `${sniHost}:${port}`,
          client: clientSocket.remoteAddress,
        });
        flow.tags.push('ssl-error');
        this._fail(flow, new Error(`Handshake TLS fallido (¿el cliente confía en el certificado de Proxyboy? ¿SSL pinning?): ${err.message}`));
      }
      tlsSocket.destroy();
    });
  }

  // ---------- WebSocket / Upgrade ----------
  _onUpgrade(req, clientSocket, head, isMitm) {
    let target;
    try {
      if (isMitm) {
        const t = req.socket._proxyboyTarget || {};
        const isTls = req.socket instanceof tls.TLSSocket;
        target = new URL(`${isTls ? 'wss' : 'ws'}://${req.headers.host || `${t.host}:${t.port}`}${req.url}`);
      } else {
        target = new URL(req.url.replace(/^http/i, 'ws'));
      }
    } catch {
      return clientSocket.destroy();
    }
    const secure = target.protocol === 'wss:';
    const port = Number(target.port) || (secure ? 443 : 80);
    const flow = this._newFlow({
      method: req.method, scheme: secure ? 'wss' : 'ws', host: target.hostname, port,
      path: target.pathname + target.search, url: target.toString(), httpVersion: req.httpVersion,
      client: clientSocket.remoteAddress,
    });
    flow.request.headers = rawHeadersToPairs(req.rawHeaders);
    flow.tags.push('websocket');

    const connectOpts = { host: target.hostname, port };
    const upstream = secure
      ? tls.connect({ ...connectOpts, servername: target.hostname, rejectUnauthorized: this.settings.verifyUpstreamTLS, ALPNProtocols: ['http/1.1'] })
      : net.connect(connectOpts);
    const onReady = () => {
      let raw = `${req.method} ${flow.path} HTTP/1.1\r\n`;
      for (const [k, v] of flow.request.headers) {
        if (k.toLowerCase() === 'proxy-connection') continue;
        raw += `${k}: ${v}\r\n`;
      }
      upstream.write(raw + '\r\n');
      if (head && head.length) upstream.write(head);
      // Leemos los headers de respuesta para mostrar el 101
      let buf = Buffer.alloc(0);
      const onData = (c) => {
        buf = Buffer.concat([buf, c]);
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        upstream.off('data', onData);
        const lines = buf.slice(0, idx).toString('latin1').split('\r\n');
        const m = /^HTTP\/(\S+)\s+(\d+)\s*(.*)$/.exec(lines[0]) || [];
        flow.response = {
          statusCode: Number(m[2]) || 0, statusMessage: m[3] || '', httpVersion: m[1] || '1.1',
          headers: lines.slice(1).map((l) => { const i = l.indexOf(':'); return [l.slice(0, i), l.slice(i + 1).trim()]; }),
          body: null, bodySize: 0,
        };
        flow.timings.responseStart = Date.now();
        flow.state = 'tunnel';
        this._update(flow);
        clientSocket.write(buf);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      };
      upstream.on('data', onData);
    };
    upstream.once(secure ? 'secureConnect' : 'connect', onReady);
    const done = () => {
      if (flow.timings.end) return;
      flow.timings.end = Date.now();
      if (flow.state !== 'failed') flow.state = 'completed';
      this._update(flow);
    };
    upstream.on('error', (e) => { this._fail(flow, e); clientSocket.destroy(); });
    clientSocket.on('error', () => upstream.destroy());
    upstream.on('close', () => { done(); clientSocket.destroy(); });
    clientSocket.on('close', () => { done(); upstream.destroy(); });
  }

  // ---------- Repetir / Componer ----------
  // Envía un request (repetido o editado) a través del propio proxy para que quede registrado.
  sendRequest({ method, url, headers, body }) {
    return new Promise((resolve, reject) => {
      const target = new URL(url);
      const proxyPort = this.server.address().port;
      const hdrs = (headers || []).filter(([k]) => k && !HOP_BY_HOP.has(k.toLowerCase()) && k.toLowerCase() !== 'content-length');
      const payload = body ? Buffer.from(body, 'utf8') : null;
      if (payload) hdrs.push(['Content-Length', String(payload.length)]);
      if (!pairsGet(hdrs, 'host')) hdrs.unshift(['Host', target.host]);
      const finish = (resp) => { resp.resume(); resp.on('end', () => resolve(resp.statusCode)); };

      if (target.protocol === 'http:') {
        const r = http.request({ host: '127.0.0.1', port: proxyPort, method, path: target.toString(), headers: hdrs.flat(), setHost: false }, finish);
        r.on('error', reject);
        return r.end(payload || undefined);
      }
      // HTTPS: CONNECT al propio proxy y forzamos MITM para ese host
      const port = Number(target.port) || 443;
      const connReq = http.request({
        host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `${target.hostname}:${port}`,
        headers: { 'X-Proxyboy-Intercept': '1' },
      });
      connReq.on('connect', (res, socket) => {
        const r = https.request({
          socket, agent: false, method, host: target.hostname, port, servername: target.hostname,
          path: target.pathname + target.search, headers: hdrs.flat(), setHost: false,
          ca: this.ca.caCertPem,
        }, finish);
        r.on('error', reject);
        r.end(payload || undefined);
      });
      connReq.on('error', reject);
      connReq.end();
    });
  }

  // ---------- Exportar HAR ----------
  toHAR(ids) {
    const list = ids ? ids.map((i) => this.flows.get(i)).filter(Boolean) : [...this.flows.values()];
    const hdr = (pairs) => (pairs || []).map(([name, value]) => ({ name, value: String(value) }));
    const entries = list.filter((f) => f.method !== 'CONNECT').map((f) => {
      const req = f.request;
      const res = f.response;
      const resBody = res && res.body ? decodeBody(res.body, pairsGet(res.headers, 'content-encoding')) : Buffer.alloc(0);
      const reqBody = req.body ? decodeBody(req.body, pairsGet(req.headers, 'content-encoding')) : null;
      const u = new URL(f.url);
      const total = f.timings.end ? f.timings.end - f.timings.start : -1;
      return {
        startedDateTime: new Date(f.startedAt).toISOString(),
        time: total,
        request: {
          method: f.method, url: f.url, httpVersion: `HTTP/${f.httpVersion || '1.1'}`,
          headers: hdr(req.headers), cookies: [],
          queryString: [...u.searchParams].map(([name, value]) => ({ name, value })),
          postData: reqBody && reqBody.length ? { mimeType: pairsGet(req.headers, 'content-type') || '', text: reqBody.toString('utf8') } : undefined,
          headersSize: -1, bodySize: req.bodySize,
        },
        response: res ? {
          status: res.statusCode, statusText: res.statusMessage || '', httpVersion: `HTTP/${res.httpVersion || '1.1'}`,
          headers: hdr(res.headers), cookies: [],
          content: { size: resBody.length, mimeType: pairsGet(res.headers, 'content-type') || '', text: resBody.toString('base64'), encoding: 'base64' },
          redirectURL: pairsGet(res.headers, 'location') || '', headersSize: -1, bodySize: res.bodySize,
        } : { status: 0, statusText: f.error || '', httpVersion: '', headers: [], cookies: [], content: { size: 0, mimeType: '' }, redirectURL: '', headersSize: -1, bodySize: -1 },
        cache: {},
        timings: {
          send: 0,
          wait: f.timings.responseStart ? f.timings.responseStart - f.timings.start : -1,
          receive: f.timings.end && f.timings.responseStart ? f.timings.end - f.timings.responseStart : -1,
        },
      };
    });
    return { log: { version: '1.2', creator: { name: 'Proxyboy', version: '0.1.0' }, entries } };
  }
}

module.exports = { ProxyServer, decodeBody, wildcardToRegExp };
