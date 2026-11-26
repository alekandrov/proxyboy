// Conexiones hacia el servidor real: HTTP/1.1 (http/https) y HTTP/2 (con negociación ALPN y sesiones reutilizables).
const http = require('http');
const https = require('https');
const http2 = require('http2');
const tls = require('tls');
const net = require('net');
const trust = require('./trust');
const { EventEmitter } = require('events');

// Headers que no se reenvían entre saltos
const HOP_BY_HOP = new Set([
  'proxy-connection', 'proxy-authorization', 'connection', 'keep-alive',
  'transfer-encoding', 'te', 'trailer', 'upgrade',
]);

function pairsToH2Headers(pairs) {
  const out = {};
  for (const [k, v] of pairs) {
    const lk = k.toLowerCase();
    if (lk.startsWith(':') || lk === 'host') continue;
    if (HOP_BY_HOP.has(lk) && !(lk === 'te' && String(v).toLowerCase() === 'trailers')) continue;
    if (lk === 'cookie' && out.cookie) { out.cookie += `; ${v}`; continue; }
    if (out[lk] === undefined) out[lk] = v;
    else out[lk] = [].concat(out[lk], v);
  }
  return out;
}

function h2HeadersToPairs(obj) {
  const pairs = [];
  for (const [k, v] of Object.entries(obj)) {
    if (k.startsWith(':')) continue;
    for (const one of [].concat(v)) pairs.push([k, String(one)]);
  }
  return pairs;
}

class Upstream {
  constructor() {
    this.agents = {
      http: new http.Agent({ keepAlive: true, maxSockets: 256 }),
      https: new https.Agent({ keepAlive: true, maxSockets: 256, secureContext: trust.secureContext() }),
      httpsInsecure: new https.Agent({ keepAlive: true, maxSockets: 256, rejectUnauthorized: false }),
    };
    this.sessions = new Map(); // key -> Promise<ClientHttp2Session|null>
    this.alpn = new Map();     // key -> 'h1' cuando el servidor no habla h2
  }

  closeAll() {
    for (const p of this.sessions.values()) p.then((sess) => sess && sess.destroy()).catch(() => {});
    this.sessions.clear();
    for (const a of Object.values(this.agents)) a.destroy();
  }

  // Devuelve una sesión HTTP/2 si el servidor la soporta; null si solo habla HTTP/1.1
  _h2Session(host, port, verify) {
    const key = `${host}:${port}:${verify ? 1 : 0}`;
    if (this.alpn.get(key) === 'h1') return Promise.resolve(null);
    const cached = this.sessions.get(key);
    if (cached) return cached;
    const p = new Promise((resolve, reject) => {
      const socket = tls.connect({
        host, port, servername: net.isIP(host) ? undefined : host,
        ALPNProtocols: ['h2', 'http/1.1'], rejectUnauthorized: verify, secureContext: verify ? trust.secureContext() : undefined,
      });
      socket.once('error', (e) => { this.sessions.delete(key); reject(e); });
      socket.once('secureConnect', () => {
        if (socket.alpnProtocol !== 'h2') {
          this.alpn.set(key, 'h1');
          this.sessions.delete(key);
          socket.destroy();
          return resolve(null);
        }
        const session = http2.connect(`https://${host}:${port}`, { createConnection: () => socket });
        const drop = () => { if (this.sessions.get(key) === p) this.sessions.delete(key); };
        session.on('close', drop);
        session.on('goaway', drop);
        session.on('error', drop);
        session.setTimeout(120000, () => session.close());
        resolve(session);
      });
    });
    this.sessions.set(key, p);
    return p;
  }

  /**
   * Abre un request hacia el servidor.
   * opts: { protocol: 'http:'|'https:', hostname, port, method, path, headers: [[k,v]], preferH2, verifyTLS }
   * Devuelve un EventEmitter con write/end/destroy que emite 'response' (meta, readable) y 'error'.
   * meta.trailers se completa cuando el stream termina.
   */
  request(opts) {
    const ee = new EventEmitter();
    const queue = [];
    let target = null;
    let ended = false;
    ee.write = (c) => { if (target) target.write(c); else queue.push(c); };
    ee.end = (c) => {
      if (c) ee.write(c);
      ended = true;
      if (target) target.end();
    };
    ee.destroy = () => { if (target) target.destroy(); ended = true; ee.destroyed = true; };
    const attach = (t) => {
      target = t;
      if (ee.destroyed) return t.destroy();
      for (const c of queue) t.write(c);
      queue.length = 0;
      if (ended) t.end();
    };

    const https_ = opts.protocol === 'https:';
    const start = async () => {
      if (https_ && opts.preferH2) {
        let session = null;
        try {
          session = await this._h2Session(opts.hostname, opts.port, opts.verifyTLS);
        } catch (e) {
          return ee.emit('error', e);
        }
        if (session) return this._h2Request(session, opts, ee, attach);
      }
      this._h1Request(opts, ee, attach);
    };
    start();
    return ee;
  }

  _h1Request(opts, ee, attach) {
    const isHttps = opts.protocol === 'https:';
    const flat = [];
    let hasHost = false;
    for (const [k, v] of opts.headers) {
      const lk = k.toLowerCase();
      if (lk.startsWith(':') || HOP_BY_HOP.has(lk)) continue;
      if (lk === 'host') hasHost = true;
      flat.push(k, v);
    }
    if (!hasHost) {
      const defPort = isHttps ? 443 : 80;
      flat.unshift('Host', opts.port === defPort ? opts.hostname : `${opts.hostname}:${opts.port}`);
    }
    const req = (isHttps ? https : http).request({
      method: opts.method,
      hostname: opts.hostname,
      port: opts.port,
      path: opts.path,
      headers: flat,
      setHost: false,
      servername: isHttps && !net.isIP(opts.hostname) ? opts.hostname : undefined,
      agent: isHttps ? (opts.verifyTLS ? this.agents.https : this.agents.httpsInsecure) : this.agents.http,
    });
    req.on('response', (res) => {
      const meta = {
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        httpVersion: res.httpVersion,
        headers: [],
        trailers: [],
      };
      for (let i = 0; i < res.rawHeaders.length; i += 2) meta.headers.push([res.rawHeaders[i], res.rawHeaders[i + 1]]);
      res.on('end', () => {
        for (let i = 0; i < res.rawTrailers.length; i += 2) meta.trailers.push([res.rawTrailers[i], res.rawTrailers[i + 1]]);
      });
      meta.serverIp = res.socket && res.socket.remoteAddress;
      ee.emit('response', meta, res);
    });
    req.on('error', (e) => ee.emit('error', e));
    attach(req);
  }

  _h2Request(session, opts, ee, attach) {
    const headers = {
      ':method': opts.method,
      ':path': opts.path,
      ':scheme': 'https',
      ':authority': opts.port === 443 ? opts.hostname : `${opts.hostname}:${opts.port}`,
      ...pairsToH2Headers(opts.headers),
    };
    let stream;
    try {
      stream = session.request(headers, { endStream: false });
    } catch (e) {
      return ee.emit('error', e);
    }
    stream.on('response', (h) => {
      const meta = {
        statusCode: Number(h[':status']),
        statusMessage: http.STATUS_CODES[h[':status']] || '',
        httpVersion: '2.0',
        headers: h2HeadersToPairs(h),
        trailers: [],
      };
      stream.on('trailers', (t) => { meta.trailers = h2HeadersToPairs(t); });
      try { meta.serverIp = session.socket && session.socket.remoteAddress; } catch { /* sesión cerrada */ }
      ee.emit('response', meta, stream);
    });
    stream.on('error', (e) => ee.emit('error', e));
    attach(stream);
  }
}

module.exports = { Upstream, HOP_BY_HOP, pairsToH2Headers };
