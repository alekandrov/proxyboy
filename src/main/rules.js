// Reglas: matching por comodines, Map Remote y ejecución de scripts.
const vm = require('vm');
const { URL } = require('url');

const reCache = new Map();
function wildcardToRegExp(pattern) {
  let re = reCache.get(pattern);
  if (!re) {
    const esc = String(pattern).trim().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    re = new RegExp(`^${esc}$`, 'i');
    if (reCache.size > 2000) reCache.clear();
    reCache.set(pattern, re);
  }
  return re;
}

function hostMatches(host, patterns) {
  return (patterns || []).some((p) => p && wildcardToRegExp(p).test(host));
}

// Una regla coincide si está habilitada, el método coincide (o es * / vacío) y la URL matchea el patrón
function ruleMatches(rule, method, url) {
  if (!rule || !rule.enabled || !rule.url) return false;
  const m = (rule.method || '*').toUpperCase();
  if (m !== '*' && m !== '' && m !== method.toUpperCase()) return false;
  return wildcardToRegExp(rule.url).test(url);
}

function findRule(rules, method, url) {
  return (rules || []).find((r) => ruleMatches(r, method, url));
}

// Map Remote: reemplaza esquema/host/puerto (y path si el destino lo define) conservando el query
function applyMapRemote(rule, url) {
  const src = new URL(url);
  const dst = new URL(rule.to);
  const out = new URL(src.toString());
  out.protocol = dst.protocol;
  out.hostname = dst.hostname;
  out.port = dst.port;
  if (dst.pathname && dst.pathname !== '/') {
    out.pathname = dst.pathname;
  }
  if (dst.search) out.search = dst.search;
  return out;
}

// ---------------- Scripts ----------------
// Cada script define (opcionalmente) onRequest(context, url, request) y onResponse(context, url, request, response),
// que reciben/devuelven objetos planos { method, url, headers, body } / { statusCode, headers, body }.
// `headers` es un objeto { nombre: valor }; `body` es string (o null).
const scriptCache = new Map(); // code -> { onRequest, onResponse, sandbox }
const SCRIPT_TIMEOUT = 2000;

function compileScript(rule, log) {
  const key = `${rule.id}:${rule.code}`;
  let c = scriptCache.get(key);
  if (c) { c.sandbox.__log = log; return c; }
  const sandbox = {
    __log: log,
    console: {},
    JSON, URL, URLSearchParams, Math, Date, encodeURIComponent, decodeURIComponent, escape, unescape,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    sharedState: {},
  };
  for (const lvl of ['log', 'info', 'warn', 'error', 'debug']) {
    sandbox.console[lvl] = (...args) => sandbox.__log(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
  }
  vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  const script = new vm.Script(`${rule.code}
;({ onRequest: typeof onRequest === 'function' ? onRequest : null,
   onResponse: typeof onResponse === 'function' ? onResponse : null })`, { filename: `script-${rule.name || rule.id}.js` });
  const fns = script.runInContext(sandbox, { timeout: SCRIPT_TIMEOUT });
  c = { ...fns, sandbox };
  if (scriptCache.size > 200) scriptCache.clear();
  scriptCache.set(key, c);
  return c;
}

function withTimeout(p, ms, label) {
  let t;
  return Promise.race([
    Promise.resolve(p).finally(() => clearTimeout(t)),
    new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${label}: timeout de ${ms} ms`)), ms); }),
  ]);
}

async function runScriptHook(rule, hook, args, log) {
  const c = compileScript(rule, log);
  const fn = c[hook];
  if (!fn) return undefined;
  const context = { scriptName: rule.name || `#${rule.id}`, sharedState: c.sandbox.sharedState };
  // Copia profunda para que el script no comparta referencias con el proxy
  const plain = JSON.parse(JSON.stringify(args));
  return withTimeout(fn(context, ...plain), SCRIPT_TIMEOUT, rule.name || 'script');
}

module.exports = {
  wildcardToRegExp, hostMatches, ruleMatches, findRule, applyMapRemote, runScriptHook,
};
