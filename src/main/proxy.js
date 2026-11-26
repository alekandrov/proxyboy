// Motor del proxy: forward proxy HTTP + túnel CONNECT con intercepción HTTPS (MITM),
// HTTP/2 hacia cliente y servidor, WebSockets, y reglas (Map Local/Remote, Block, Breakpoints, Scripts).
const http = require('http');
const http2 = require('http2');
const https = require('https');
const net = require('net');
const tls = require('tls');
const zlib = require('zlib');
const { EventEmitter } = require('events');
const { Duplex } = require('stream');
const { URL } = require('url');
const { Upstream, HOP_BY_HOP } = require('./upstream');
const { FrameParser } = require('./websocket');
const { ProcessResolver, appFromUserAgent, isLoopback } = require('./procinfo');
const {
  wildcardToRegExp, hostMatches, findRule, applyMapRemote, runScriptHook,
} = require('./rules');

const MAX_CAPTURED_BODY = 10 * 1024 * 1024; // guardamos hasta 10 MB por body
const MAX_BUFFERED_BODY = 50 * 1024 * 1024; // límite al bufferear para breakpoints/scripts
const MAX_WS_MESSAGES = 2000;
const BREAKPOINT_TIMEOUT = 5 * 60 * 1000;

// Headers de respuesta prohibidos en HTTP/2 o que no se reenvían
const RESPONSE_STRIP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade']);

function rawHeadersToPairs(raw, { skipPseudo = true } = {}) {
  const pairs = [];
  for (let i = 0; i < raw.length; i += 2) {
    if (skipPseudo && raw[i].startsWith(':')) continue;
    pairs.push([raw[i], raw[i + 1]]);
  }
  return pairs;
}

function pairsGet(pairs, name) {
  name = name.toLowerCase();
  const p = (pairs || []).find(([k]) => k.toLowerCase() === name);
  return p ? p[1] : undefined;
}

function pairsSet(pairs, name, value) {
  const out = pairs.filter(([k]) => k.toLowerCase() !== name.toLowerCase());
  if (value !== undefined && value !== null) out.push([name, String(value)]);
  return out;
}

function pairsToObject(pairs) {
  const o = {};
  for (const [k, v] of pairs) o[k] = o[k] === undefined ? v : `${o[k]}, ${v}`;
  return o;
}

function objectToPairs(obj) {
  const out = [];
  for (const [k, v] of Object.entries(obj || {})) {
    for (const one of [].concat(v)) if (one !== undefined && one !== null) out.push([k, String(one)]);
  }
  return out;
}

class BodyCollector {
  constructor(limit = MAX_CAPTURED_BODY) { this.chunks = []; this.size = 0; this.truncated = false; this.captured = 0; this.limit = limit; }
  push(chunk) {
    this.size += chunk.length;
    if (this.captured + chunk.length <= this.limit) {
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

function isProbablyText(buf, contentType) {
  const ct = (contentType || '').toLowerCase();
  if (/json|xml|text|javascript|x-www-form-urlencoded|graphql|html|csv|yaml/.test(ct)) return true;
  if (/image|audio|video|octet-stream|protobuf|grpc|font|zip|pdf/.test(ct)) return false;
  const n = Math.min(buf.length, 2048);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return false;
  return true;
}

// Lee un stream completo a Buffer
function collect(stream, limit = MAX_BUFFERED_BODY) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stream.on('data', (c) => {
      size += c.length;
      if (size > limit) { stream.destroy(); reject(new Error('Body demasiado grande para bufferear')); return; }
      chunks.push(c);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

// http2 lee directamente del handle nativo del socket y perdería los bytes que el TLSSocket
// ya tiene en su buffer JS (el preface del cliente). Envolverlo en un Duplex fuerza la lectura por JS.
function duplexOver(sock) {
  const d = new Duplex({
    read() { sock.resume(); },
    write(chunk, enc, cb) { sock.write(chunk, enc, cb); },
    final(cb) { sock.end(); cb(); },
    destroy(err, cb) { sock.destroy(); cb(err); },
  });
  sock.on('data', (c) => { if (!d.push(c)) sock.pause(); });
  sock.on('end', () => d.push(null));
  sock.on('close', () => d.destroy());
  sock.on('error', (e) => d.destroy(e));
  d.remoteAddress = sock.remoteAddress;
  d._pbClient = sock._pbClient;
  d.remotePort = sock.remotePort;
  d.encrypted = true;
  d.alpnProtocol = 'h2';
  d.setTimeout = (ms, cb) => { sock.setTimeout(ms, cb); return d; };
  d.setNoDelay = (v) => { sock.setNoDelay(v); return d; };
  d.setKeepAlive = (...a) => { sock.setKeepAlive(...a); return d; };
  return d;
}

class ProxyServer extends EventEmitter {
  constructor({ ca, port = 9090, host = '0.0.0.0', resolveApps = true } = {}) {
    super();
    // Identificación de la app que hace cada conexión
    this.resolver = resolveApps ? new ProcessResolver(() => this.port) : null;
    this.apps = new Map(); // id -> info completa (para íconos)
    this.uaToApp = new Map(); // User-Agent -> app detectada por proceso (para conexiones que cierran antes de resolverse)
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
      http2: true,
      recording: true,
    };
    this.rules = {
      mapLocal: [],    // {id, enabled, method, url, status, headers:[[k,v]], body}
      mapRemote: [],   // {id, enabled, method, url, to, preserveHost}
      block: [],       // {id, enabled, method, url}
      breakpoints: [], // {id, enabled, method, url, request, response}
      scripts: [],     // {id, enabled, name, method, url, code}
    };
    // La UI asigna este handler: recibe el breakpoint y devuelve la decisión del usuario
    this.onBreakpoint = null;
    this.upstream = new Upstream();

    this.server = http.createServer();
    // Seguimos todas las conexiones (incluidos túneles CONNECT y WebSockets) para poder cerrarlas en stop()
    this.sockets = new Set();
    this.server.on('connection', (sock) => {
      this.sockets.add(sock);
      sock._pbClient = this._clientHolder(sock);
      sock.on('close', () => this.sockets.delete(sock));
    });
    this.server.on('request', (req, res) => this._onRequest(req, res, { mitm: false }));
    this.server.on('connect', (req, socket, head) => this._onConnect(req, socket, head));
    this.server.on('upgrade', (req, socket, head) => this._onUpgrade(req, socket, head, false));
    this.server.on('clientError', (err, socket) => socket.destroy());

    // Servidores internos que reciben las conexiones TLS ya desencriptadas
    this.mitmServer = http.createServer();
    this.mitmServer.on('request', (req, res) => this._onRequest(req, res, { mitm: true }));
    this.mitmServer.on('upgrade', (req, socket, head) => this._onUpgrade(req, socket, head, true));
    this.mitmServer.on('clientError', (err, socket) => socket.destroy());

    this.h2Server = http2.createServer({ settings: { enableConnectProtocol: false } });
    this.h2Server.on('request', (req, res) => this._onRequest(req, res, { mitm: true, h2: true }));
    // req.socket en HTTP/2 es un Proxy que no expone nuestras propiedades: pasamos la info por la sesión
    this.h2Server.on('session', (session) => { session._pbClient = this._h2PendingClient; this._h2PendingClient = null; });
    this.h2Server.on('sessionError', () => {});
    this.h2Server.on('streamError', () => {});
  }

  start() {
    return new Promise((resolve, reject) => {
      const onErr = (e) => reject(e);
      this.server.once('error', onErr);
      this.server.listen(this.port, this.listenHost, () => {
        this.server.off('error', onErr);
        this.running = true;
        this.port = this.server.address().port;
        resolve(this.port);
      });
    });
  }

  stop() {
    return new Promise((resolve) => {
      if (!this.running) return resolve();
      this.running = false;
      this.server.close(() => resolve());
      for (const sock of this.sockets) sock.destroy();
      this.sockets.clear();
      this.upstream.closeAll();
    });
  }

  updateSettings(patch) {
    Object.assign(this.settings, patch);
  }

  setRules(rules) {
    this.rules = { ...this.rules, ...rules };
  }

  shouldIntercept(host) {
    if (!this.settings.sslProxyingEnabled) return false;
    if (this.settings.sslProxyAll) return true;
    return hostMatches(host, this.settings.sslHosts);
  }

  // ---------- Flows ----------
  _clientHolder(sock) {
    const holder = { app: null, ready: null, settled: false };
    if (this.resolver && isLoopback(sock.remoteAddress)) {
      holder.ready = this.resolver.lookup(sock.remotePort).then((app) => {
        holder.settled = true;
        if (app) { holder.app = app; this.apps.set(app.id, app); }
        return app;
      });
    }
    return holder;
  }

  // Espera (con tope) a conocer la app del cliente: si respondemos antes, una conexión corta
  // puede cerrarse antes de que podamos ver qué proceso la abrió. Solo afecta al primer request de cada conexión.
  _waitClient(holder) {
    if (!holder || !holder.ready || holder.settled) return null;
    return Promise.race([holder.ready, new Promise((r) => setTimeout(r, 300))]);
  }

  // Asigna la app al flow: la del proceso si ya se conoce; si no, el User-Agent y luego el proceso cuando se resuelva
  _attachApp(flow, sock, headers) {
    const holder = sock && sock._pbClient;
    const uaString = pairsGet(headers || [], 'user-agent');
    if (holder && holder.app) {
      flow.app = holder.app;
      if (uaString) this.uaToApp.set(uaString, holder.app);
      return;
    }
    const learned = uaString && this.uaToApp.get(uaString);
    const ua = learned || appFromUserAgent(uaString, flow.client);
    if (ua) { flow.app = ua; this.apps.set(ua.id, ua); }
    if (holder && holder.ready) {
      holder.ready.then((app) => {
        if (!app) return;
        if (uaString) {
          if (this.uaToApp.size > 500) this.uaToApp.clear();
          this.uaToApp.set(uaString, app);
        }
        if (!flow.app || flow.app.id !== app.id) { flow.app = app; this._update(flow); }
      });
    }
  }

  _newFlow(data, sock, headers) {
    const flow = {
      id: this.nextId++,
      startedAt: Date.now(),
      state: 'pending',
      request: { headers: [], body: null, bodySize: 0 },
      response: null,
      timings: { start: Date.now() },
      tags: [],
      notes: [],
      ...data,
    };
    this._attachApp(flow, sock, headers);
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

  // Para eventos frecuentes (mensajes WebSocket) agrupamos las actualizaciones
  _updateThrottled(flow) {
    if (flow._updTimer) return;
    flow._updTimer = setTimeout(() => { flow._updTimer = null; this._update(flow); }, 250);
  }

  _note(flow, text) {
    flow.notes.push({ time: Date.now(), text });
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
      httpVersion: f.httpVersion,
      state: f.state,
      status: f.response ? f.response.statusCode : null,
      contentType: f.response ? pairsGet(f.response.headers, 'content-type') || '' : '',
      reqContentType: pairsGet(f.request.headers, 'content-type') || '',
      reqSize: f.request.bodySize,
      resSize: f.response ? f.response.bodySize : 0,
      duration: f.timings.end ? f.timings.end - f.timings.start : null,
      error: f.error || null,
      tags: f.tags,
      client: f.client,
      app: f.app ? { id: f.app.id, name: f.app.name, simulator: !!f.app.simulator, device: f.app.device, os: f.app.os, source: f.app.source } : null,
      wsCount: f.ws ? f.ws.length : 0,
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
      originalUrl: f.originalUrl,
      timings: f.timings,
      notes: f.notes,
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
          trailers: f.response.trailers || [],
          body: encode(f.response.headers, f.response.body, f.response.truncated),
        }
        : null,
      ws: f.ws ? f.ws.map((m) => ({ ...m, payload: m.payload.toString('base64') })) : null,
    };
  }

  // ---------- Breakpoints ----------
  async _breakpoint(flow, phase, data) {
    if (!this.onBreakpoint) return { action: 'execute' };
    flow.state = 'paused';
    flow.tags.push(`bp-${phase}`);
    this._update(flow);
    const bodyText = data.body && data.body.length && isProbablyText(data.body, pairsGet(data.headers, 'content-type'))
      ? data.body.toString('utf8') : null;
    const payload = {
      flowId: flow.id,
      phase,
      ...(phase === 'request'
        ? { method: data.method, url: data.url }
        : { statusCode: data.statusCode, method: flow.method, url: flow.url }),
      headers: data.headers,
      body: bodyText,
      binaryBody: bodyText === null && data.body && data.body.length ? data.body.length : 0,
    };
    let decision;
    try {
      decision = await Promise.race([
        this.onBreakpoint(payload),
        new Promise((r) => setTimeout(() => r({ action: 'execute', timeout: true }), BREAKPOINT_TIMEOUT)),
      ]);
    } catch {
      decision = { action: 'execute' };
    }
    flow.state = 'pending';
    if (decision && decision.timeout) this._note(flow, `Breakpoint de ${phase} expiró: se continuó sin cambios`);
    return decision || { action: 'execute' };
  }

  // ---------- HTTP (HTTP/1.1 y HTTP/2) ----------
  _resolveTarget(req, ctx) {
    if (ctx.h2) {
      const authority = req.headers[':authority'] || req.headers.host;
      return new URL(`https://${authority}${req.url}`);
    }
    if (ctx.mitm) {
      const t = req.socket._proxyboyTarget || {};
      const isTls = req.socket instanceof tls.TLSSocket;
      const hostHeader = req.headers.host || `${t.host}:${t.port}`;
      return new URL(`${isTls ? 'https' : 'http'}://${hostHeader}${req.url}`);
    }
    if (/^https?:\/\//i.test(req.url)) return new URL(req.url);
    return null;
  }

  async _onRequest(req, res, ctx) {
    let target;
    try {
      target = this._resolveTarget(req, ctx);
      if (!target) return this._serveLocal(req, res);
    } catch {
      res.writeHead(400);
      return res.end('Proxyboy: URL inválida');
    }
    if (!ctx.mitm && (target.hostname === 'proxy.boy' || target.hostname === 'proxyboy.local')) {
      if (target.pathname.startsWith('/cert')) req.url = '/cert.pem';
      return this._serveLocal(req, res);
    }

    const flow = this._newFlow({
      method: req.method,
      scheme: target.protocol.replace(':', ''),
      host: target.hostname,
      port: Number(target.port) || (target.protocol === 'https:' ? 443 : 80),
      path: target.pathname + target.search,
      url: target.toString(),
      httpVersion: req.httpVersion,
      client: req.socket ? req.socket.remoteAddress : undefined,
    }, ctx.h2 ? { _pbClient: req.stream && req.stream.session && req.stream.session._pbClient } : req.socket, rawHeadersToPairs(req.rawHeaders));
    flow.request.headers = rawHeadersToPairs(req.rawHeaders);
    // Para HTTP/2 agregamos Host para que la vista sea coherente con HTTP/1.1
    if (ctx.h2 && !pairsGet(flow.request.headers, 'host')) flow.request.headers.unshift(['Host', target.host]);

    try {
      await this._handle(req, res, ctx, flow, target);
    } catch (e) {
      this._fail(flow, e, res);
    }
  }

  async _handle(req, res, ctx, flow, target) {
    const rules = this.rules;
    const clientHolder = ctx.h2 ? req.stream && req.stream.session && req.stream.session._pbClient : req.socket && req.socket._pbClient;
    const clientReady = this._waitClient(clientHolder);
    let method = req.method;
    let url = flow.url;
    let headers = flow.request.headers;

    // Bloqueo
    if (findRule(rules.block, method, url)) {
      flow.tags.push('blocked');
      req.resume();
      if (ctx.h2) res.stream.close(http2.constants.NGHTTP2_REFUSED_STREAM);
      else req.socket.destroy();
      flow.state = 'failed';
      flow.error = 'Bloqueado por regla';
      flow.timings.end = Date.now();
      return this._update(flow);
    }

    // Map Remote
    const remote = findRule(rules.mapRemote, method, url);
    if (remote && remote.to) {
      const mapped = applyMapRemote(remote, url);
      flow.originalUrl = url;
      flow.tags.push('map-remote');
      this._note(flow, `Map Remote: ${url} → ${mapped}`);
      url = mapped.toString();
      if (!remote.preserveHost) headers = pairsSet(headers, 'Host', mapped.host);
    }

    const script = findRule(rules.scripts, method, url);
    const bp = findRule(rules.breakpoints, method, url);
    const bpReq = bp && bp.request !== false;
    const bpRes = bp && !!bp.response;
    const mockEarly = findRule(rules.mapLocal, method, url);
    const bufferRequest = !!(script || bpReq || mockEarly);
    const bufferResponse = !!(script || bpRes);

    let reqBody = null; // Buffer si bufferizamos
    const reqCollector = new BodyCollector();

    if (bufferRequest) {
      reqBody = await collect(req);
      reqCollector.push(reqBody);

      if (script) {
        try {
          const out = await runScriptHook(script, 'onRequest', [url, {
            method, url, headers: pairsToObject(headers), body: reqBody.length ? reqBody.toString('utf8') : null,
          }], (msg) => this._note(flow, `[script] ${msg}`));
          if (out) {
            if (out.method) method = String(out.method).toUpperCase();
            if (out.url) url = new URL(out.url).toString();
            if (out.headers) headers = objectToPairs(out.headers);
            if (out.body !== undefined && out.body !== null) reqBody = Buffer.from(String(out.body), 'utf8');
            flow.tags.push('script');
          }
        } catch (e) {
          this._note(flow, `[script] error en onRequest: ${e.message}`);
          flow.tags.push('script-error');
        }
      }

      if (bpReq) {
        const d = await this._breakpoint(flow, 'request', { method, url, headers, body: reqBody });
        if (d.action === 'abort') return this._abort(flow, req, res, ctx, 'Abortado en breakpoint de request');
        if (d.method) method = d.method.toUpperCase();
        if (d.url) url = new URL(d.url).toString();
        if (d.headers) headers = d.headers;
        if (typeof d.body === 'string') reqBody = Buffer.from(d.body, 'utf8');
      }
    }

    // Lo que finalmente se envía es lo que mostramos en el inspector
    const finalUrl = new URL(url);
    flow.method = method;
    flow.url = finalUrl.toString();
    flow.host = finalUrl.hostname;
    flow.scheme = finalUrl.protocol.replace(':', '');
    flow.port = Number(finalUrl.port) || (finalUrl.protocol === 'https:' ? 443 : 80);
    flow.path = finalUrl.pathname + finalUrl.search;
    flow.request.headers = headers;
    if (reqBody) {
      flow.request.body = reqBody.subarray(0, MAX_CAPTURED_BODY);
      flow.request.bodySize = reqBody.length;
      flow.request.truncated = reqBody.length > MAX_CAPTURED_BODY;
      if (pairsGet(headers, 'content-length') !== undefined) {
        headers = pairsSet(headers, 'Content-Length', reqBody.length);
        flow.request.headers = headers;
      }
    }

    // Map Local (mock): se evalúa sobre el request final (solo si ya leímos el body)
    const mock = bufferRequest ? findRule(rules.mapLocal, method, flow.url) : null;
    if (mock) {
      await clientReady;
      return this._respondMock(flow, res, ctx, mock);
    }

    // ---- Envío al servidor ----
    const up = this.upstream.request({
      protocol: finalUrl.protocol,
      hostname: finalUrl.hostname,
      port: flow.port,
      method,
      path: flow.path,
      headers,
      preferH2: !!ctx.h2,
      verifyTLS: this.settings.verifyUpstreamTLS,
    });

    const responsePromise = new Promise((resolve, reject) => {
      up.on('response', (meta, stream) => resolve({ meta, stream }));
      up.on('error', reject);
    });
    responsePromise.catch(() => {});

    if (reqBody) {
      up.end(reqBody);
    } else {
      req.on('data', (c) => { reqCollector.push(c); up.write(c); });
      req.on('end', () => {
        flow.request.body = reqCollector.buffer();
        flow.request.bodySize = reqCollector.size;
        flow.request.truncated = reqCollector.truncated;
        up.end();
      });
      req.on('error', (e) => { up.destroy(); this._fail(flow, e, res); });
    }

    const [{ meta, stream }] = await Promise.all([responsePromise, clientReady]);
    flow.timings.responseStart = Date.now();
    flow.response = {
      statusCode: meta.statusCode,
      statusMessage: meta.statusMessage,
      httpVersion: meta.httpVersion,
      headers: meta.headers,
      trailers: [],
      body: null,
      bodySize: 0,
    };
    if (meta.httpVersion === '2.0' && !flow.tags.includes('h2')) flow.tags.push('h2');

    if (bufferResponse) {
      return this._bufferedResponse(flow, res, ctx, meta, stream, { script, bpRes, method, url: flow.url, headers, reqBody });
    }

    this._update(flow);
    this._writeHead(res, ctx, meta.statusCode, meta.statusMessage, meta.headers);
    const resBody = new BodyCollector();
    stream.on('data', (c) => { resBody.push(c); res.write(c); });
    stream.on('end', () => {
      flow.response.trailers = meta.trailers;
      this._writeTrailers(res, ctx, meta.trailers);
      res.end();
      flow.response.body = resBody.buffer();
      flow.response.bodySize = resBody.size;
      flow.response.truncated = resBody.truncated;
      flow.state = 'completed';
      flow.timings.end = Date.now();
      this._update(flow);
    });
    stream.on('error', (e) => this._fail(flow, e, res));
  }

  async _bufferedResponse(flow, res, ctx, meta, stream, { script, bpRes, method, url, headers, reqBody }) {
    const raw = await collect(stream);
    let statusCode = meta.statusCode;
    let resHeaders = meta.headers;
    // Decodificamos para que scripts/breakpoints trabajen sobre el contenido real
    let body = decodeBody(raw, pairsGet(resHeaders, 'content-encoding'));
    if (body !== raw) resHeaders = pairsSet(resHeaders, 'Content-Encoding', null);

    if (script) {
      try {
        const out = await runScriptHook(script, 'onResponse', [url,
          { method, url, headers: pairsToObject(headers), body: reqBody && reqBody.length ? reqBody.toString('utf8') : null },
          { statusCode, headers: pairsToObject(resHeaders), body: body.length ? body.toString('utf8') : null },
        ], (msg) => this._note(flow, `[script] ${msg}`));
        if (out) {
          if (out.statusCode) statusCode = Number(out.statusCode);
          if (out.headers) resHeaders = objectToPairs(out.headers);
          if (out.body !== undefined && out.body !== null) {
            body = Buffer.from(typeof out.body === 'string' ? out.body : JSON.stringify(out.body), 'utf8');
          }
          if (!flow.tags.includes('script')) flow.tags.push('script');
        }
      } catch (e) {
        this._note(flow, `[script] error en onResponse: ${e.message}`);
        flow.tags.push('script-error');
      }
    }

    if (bpRes) {
      const d = await this._breakpoint(flow, 'response', { statusCode, headers: resHeaders, body });
      if (d.action === 'abort') return this._abort(flow, null, res, ctx, 'Abortado en breakpoint de response');
      if (d.statusCode) statusCode = Number(d.statusCode);
      if (d.headers) resHeaders = d.headers;
      if (typeof d.body === 'string') body = Buffer.from(d.body, 'utf8');
    }

    // El body ya está completo: reemplazamos chunked por Content-Length
    resHeaders = pairsSet(resHeaders, 'Transfer-Encoding', null);
    resHeaders = pairsSet(resHeaders, 'Content-Length', body.length);
    flow.response.statusCode = statusCode;
    flow.response.statusMessage = statusCode === meta.statusCode ? meta.statusMessage : http.STATUS_CODES[statusCode] || '';
    flow.response.headers = resHeaders;
    flow.response.body = body.subarray(0, MAX_CAPTURED_BODY);
    flow.response.bodySize = body.length;
    flow.response.truncated = body.length > MAX_CAPTURED_BODY;
    flow.response.trailers = meta.trailers;
    this._writeHead(res, ctx, statusCode, flow.response.statusMessage, resHeaders);
    this._writeTrailers(res, ctx, meta.trailers);
    res.end(body);
    flow.state = 'completed';
    flow.timings.end = Date.now();
    this._update(flow);
  }

  _writeHead(res, ctx, status, message, pairs) {
    const filtered = pairs.filter(([k]) => {
      const lk = k.toLowerCase();
      if (RESPONSE_STRIP.has(lk)) return false;
      if (ctx.h2 && (lk.startsWith(':') || lk === 'host')) return false;
      return true;
    });
    if (ctx.h2) {
      const obj = {};
      for (const [k, v] of filtered) {
        const lk = k.toLowerCase();
        obj[lk] = obj[lk] === undefined ? v : [].concat(obj[lk], v);
      }
      res.writeHead(status, obj);
      return;
    }
    try {
      res.writeHead(status, message || undefined, filtered.flat());
    } catch {
      res.writeHead(status);
    }
  }

  _writeTrailers(res, ctx, trailers) {
    // Los trailers son esenciales para gRPC (grpc-status); en HTTP/1.1 se omiten
    if (!ctx.h2 || !trailers || !trailers.length) return;
    const obj = {};
    for (const [k, v] of trailers) obj[k.toLowerCase()] = v;
    try { res.addTrailers(obj); } catch { /* ignorar */ }
  }

  _respondMock(flow, res, ctx, mock) {
    const body = Buffer.from(mock.body || '', 'utf8');
    let headers = (mock.headers || []).filter(([k]) => k);
    headers = pairsSet(headers, 'Content-Length', body.length);
    flow.tags.push('map-local');
    flow.timings.responseStart = Date.now();
    const status = Number(mock.status) || 200;
    flow.response = {
      statusCode: status, statusMessage: http.STATUS_CODES[status] || '',
      httpVersion: ctx.h2 ? '2.0' : '1.1', headers, body, bodySize: body.length, trailers: [],
    };
    this._writeHead(res, ctx, status, flow.response.statusMessage, headers);
    res.end(body);
    flow.state = 'completed';
    flow.timings.end = Date.now();
    this._update(flow);
  }

  _abort(flow, req, res, ctx, reason) {
    if (req) req.resume();
    flow.state = 'failed';
    flow.error = reason;
    flow.timings.end = Date.now();
    if (!res.headersSent) {
      this._writeHead(res, ctx, 499, 'Aborted', [['Content-Type', 'text/plain; charset=utf-8']]);
      res.end(`Proxyboy: ${reason}`);
    }
    this._update(flow);
  }

  _fail(flow, err, res) {
    if (flow.state === 'failed') return;
    flow.state = 'failed';
    flow.error = err.code ? `${err.code}: ${err.message}` : err.message;
    flow.timings.end = Date.now();
    try {
      if (res && !res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(`Proxyboy: error conectando con el servidor\n${flow.error}`);
      } else if (res && res.stream) {
        res.stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
      } else if (res) {
        res.destroy();
      }
    } catch { /* la conexión ya está cerrada */ }
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
        this._mitmTLS(clientSocket, host, port, { allowH2: !forced });
      });
      return;
    }

    // Túnel sin interceptar
    const flow = this._newFlow({
      method: 'CONNECT', scheme: 'https', host, port, path: '', url: `${host}:${port}`,
      httpVersion: req.httpVersion, client: clientSocket.remoteAddress,
    }, clientSocket, rawHeadersToPairs(req.rawHeaders));
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

  _mitmTLS(clientSocket, host, port, { allowH2 = true } = {}) {
    let sniHost = host;
    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      secureContext: this.ca.secureContextFor(host),
      SNICallback: (servername, cb) => {
        sniHost = servername || host;
        try { cb(null, this.ca.secureContextFor(sniHost)); } catch (e) { cb(e); }
      },
      ALPNProtocols: this.settings.http2 && allowH2 ? ['h2', 'http/1.1'] : ['http/1.1'],
    });
    tlsSocket._proxyboyTarget = { host, port };
    tlsSocket._pbClient = clientSocket._pbClient;
    let established = false;
    tlsSocket.on('secure', () => {
      established = true;
      if (tlsSocket.alpnProtocol === 'h2') {
        this._h2PendingClient = tlsSocket._pbClient;
        this.h2Server.emit('connection', duplexOver(tlsSocket));
      }
      else this.mitmServer.emit('connection', tlsSocket);
    });
    tlsSocket.on('error', (err) => {
      if (!established) {
        // Típicamente: el cliente no confía en la CA de Proxyboy o usa SSL pinning
        const flow = this._newFlow({
          method: 'CONNECT', scheme: 'https', host: sniHost, port, path: '', url: `${sniHost}:${port}`,
          client: clientSocket.remoteAddress,
        }, clientSocket);
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
    }, clientSocket, rawHeadersToPairs(req.rawHeaders));
    flow.request.headers = rawHeadersToPairs(req.rawHeaders);
    flow.tags.push('websocket');
    flow.ws = [];

    if (findRule(this.rules.block, req.method, flow.url.replace(/^ws/, 'http'))) {
      flow.tags.push('blocked');
      flow.state = 'failed';
      flow.error = 'Bloqueado por regla';
      clientSocket.destroy();
      return this._update(flow);
    }

    // Quitamos permessage-deflate para poder leer los mensajes
    const outHeaders = flow.request.headers.filter(([k]) => {
      const lk = k.toLowerCase();
      return lk !== 'proxy-connection' && lk !== 'sec-websocket-extensions';
    });
    if (pairsGet(flow.request.headers, 'sec-websocket-extensions')) {
      this._note(flow, 'Se quitó Sec-WebSocket-Extensions (compresión) para poder inspeccionar los mensajes');
    }

    const record = (dir) => (m) => {
      if (flow.ws.length >= MAX_WS_MESSAGES) flow.ws.shift();
      flow.ws.push({ dir, time: Date.now(), opcode: m.opcode, size: m.size, truncated: !!m.truncated, payload: m.payload });
      this._updateThrottled(flow);
    };
    const outParser = new FrameParser(record('out'));
    const inParser = new FrameParser(record('in'));

    const connectOpts = { host: target.hostname, port };
    const upstream = secure
      ? tls.connect({ ...connectOpts, servername: target.hostname, rejectUnauthorized: this.settings.verifyUpstreamTLS, ALPNProtocols: ['http/1.1'] })
      : net.connect(connectOpts);
    const onReady = () => {
      let raw = `${req.method} ${flow.path} HTTP/1.1\r\n`;
      for (const [k, v] of outHeaders) raw += `${k}: ${v}\r\n`;
      upstream.write(`${raw}\r\n`);
      if (head && head.length) { outParser.push(head); upstream.write(head); }
      // Leemos los headers de respuesta para mostrar el 101
      let buf = Buffer.alloc(0);
      const onData = (c) => {
        buf = Buffer.concat([buf, c]);
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        upstream.off('data', onData);
        const lines = buf.subarray(0, idx).toString('latin1').split('\r\n');
        const m = /^HTTP\/(\S+)\s+(\d+)\s*(.*)$/.exec(lines[0]) || [];
        flow.response = {
          statusCode: Number(m[2]) || 0, statusMessage: m[3] || '', httpVersion: m[1] || '1.1',
          headers: lines.slice(1).map((l) => { const i = l.indexOf(':'); return [l.slice(0, i), l.slice(i + 1).trim()]; }),
          body: null, bodySize: 0, trailers: [],
        };
        flow.timings.responseStart = Date.now();
        flow.state = 'tunnel';
        this._update(flow);
        clientSocket.write(buf.subarray(0, idx + 4));
        const rest = buf.subarray(idx + 4);
        if (rest.length) { inParser.push(rest); clientSocket.write(rest); }
        upstream.on('data', (d) => { inParser.push(d); flow.response.bodySize += d.length; });
        clientSocket.on('data', (d) => { outParser.push(d); flow.request.bodySize += d.length; });
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
      const hdrs = (headers || []).filter(([k]) => k && !k.startsWith(':') && !HOP_BY_HOP.has(k.toLowerCase()) && k.toLowerCase() !== 'content-length');
      const payload = body ? Buffer.from(body, 'utf8') : null;
      if (payload) hdrs.push(['Content-Length', String(payload.length)]);
      if (!pairsGet(hdrs, 'host')) hdrs.unshift(['Host', target.host]);
      const finish = (resp) => { resp.resume(); resp.on('end', () => resolve(resp.statusCode)); };

      if (target.protocol === 'http:') {
        const r = http.request({ host: '127.0.0.1', port: proxyPort, method, path: target.toString(), headers: hdrs.flat(), setHost: false }, finish);
        r.on('error', reject);
        return r.end(payload || undefined);
      }
      // HTTPS: CONNECT al propio proxy forzando la intercepción de ese host
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
        _webSocketMessages: f.ws ? f.ws.map((m) => ({
          type: m.dir === 'out' ? 'send' : 'receive', time: m.time / 1000, opcode: m.opcode === 'text' ? 1 : 2,
          data: m.opcode === 'text' ? m.payload.toString('utf8') : m.payload.toString('base64'),
        })) : undefined,
      };
    });
    return { log: { version: '1.2', creator: { name: 'Proxyboy', version: '0.2.0' }, entries } };
  }
}

module.exports = { ProxyServer, decodeBody, wildcardToRegExp };
