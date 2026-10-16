'use strict';
// Local reverse proxy. Claude Code -> 127.0.0.1:port -> upstream (api.anthropic.com).
// Every JSON request body is deep-walked and secrets are replaced with placeholders
// before leaving the machine. Responses are streamed back untouched.
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const fs = require('fs');
const { URL } = require('url');
const { paths, ensureHome } = require('./paths');
const config = require('./config');
const { redactDeep } = require('./redact');
const vault = require('./vault');

const SYSTEM_NOTICE =
  'KEYFENCE: This session runs behind a local secret-redaction proxy. Credentials appear to you only as ' +
  'placeholders like {{KF_STRIPE_SECRET_KEY_1a2b3c4d}}. Use a placeholder verbatim wherever the real value ' +
  'belongs (shell commands, file contents, headers, env files); it is substituted with the real secret on the ' +
  "user's machine at execution time, and command output is redacted the same way. In shell commands " +
  '$KF_NAME_hash also works. Never ask the user to paste a secret in another form, never try to reconstruct, ' +
  'decode or guess a placeholder, and treat placeholders in output as expected rather than as errors.';

const stats = { started: new Date().toISOString(), requests: 0, redactions: 0, fresh: 0, errors: 0 };

function log(line) {
  try {
    ensureHome();
    fs.appendFileSync(paths.log, `${new Date().toISOString()} ${line}\n`);
  } catch (_) { /* ignore */ }
}

function decodeBody(buf, encoding) {
  if (!encoding || encoding === 'identity') return buf;
  if (encoding === 'gzip') return zlib.gunzipSync(buf);
  if (encoding === 'deflate') return zlib.inflateSync(buf);
  if (encoding === 'br') return zlib.brotliDecompressSync(buf);
  throw new Error(`unsupported content-encoding ${encoding}`);
}

// Returns true if the notice was added.
function addSystemNotice(body) {
  if (!body || typeof body !== 'object') return false;
  if (Array.isArray(body.system)) {
    if (body.system.some((b) => b && typeof b.text === 'string' && b.text.startsWith('KEYFENCE:'))) return false;
    body.system.push({ type: 'text', text: SYSTEM_NOTICE });
    return true;
  }
  if (typeof body.system === 'string') {
    if (body.system.includes('KEYFENCE:')) return false;
    body.system = body.system + '\n\n' + SYSTEM_NOTICE;
    return true;
  }
  if (body.messages) { body.system = SYSTEM_NOTICE; return true; }
  return false;
}

// Control endpoints are protected by a per-install token file so a web page on the
// same machine can't shut the proxy down with a cross-origin POST.
const crypto = require('crypto');
function controlToken() {
  ensureHome();
  const file = paths.token;
  try { return fs.readFileSync(file, 'utf8').trim(); }
  catch (_) {
    const t = crypto.randomBytes(24).toString('hex');
    fs.writeFileSync(file, t, { mode: 0o600 });
    return t;
  }
}

function processBody(raw, headers, cfg) {
  const ct = String(headers['content-type'] || '');
  if (!/json/i.test(ct) || raw.length === 0) return { body: raw, changed: false, found: [] };
  let decoded;
  try { decoded = decodeBody(raw, String(headers['content-encoding'] || '').toLowerCase()); }
  catch (e) { log(`warn: ${e.message}; forwarding body unmodified`); return { body: raw, changed: false, found: [] }; }
  let json;
  try { json = JSON.parse(decoded.toString('utf8')); }
  catch (_) { return { body: raw, changed: false, found: [] }; }

  const { value, found } = redactDeep(json, { register: true });
  if (found.length) {
    stats.redactions += found.length;
    const fresh = found.filter((f) => f.fresh);
    stats.fresh += fresh.length;
    if (fresh.length) log(`registered ${fresh.length} new secret(s): ${fresh.map((f) => f.placeholder).join(' ')}`);
  }
  const out = value;
  const noticeAdded = cfg.systemNotice && out && out.messages ? addSystemNotice(out) : false;
  if (!found.length && !noticeAdded) return { body: raw, changed: false, found };
  return { body: Buffer.from(JSON.stringify(out), 'utf8'), changed: true, found };
}

function statusPayload() {
  return { ok: true, pid: process.pid, ...stats, secrets: vault.entries().length, upstream: config.load().upstream };
}

function createServer(cfg) {
  const upstream = new URL(cfg.upstream);
  const isHttps = upstream.protocol === 'https:';
  const agent = isHttps ? new https.Agent({ keepAlive: true }) : new http.Agent({ keepAlive: true });
  const client = isHttps ? https : http;

  return http.createServer((req, res) => {
    if (req.url.startsWith('/_keyfence/')) {
      if (req.url === '/_keyfence/status') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify(statusPayload()));
      }
      if (req.url === '/_keyfence/shutdown' && req.method === 'POST') {
        if (req.headers.origin || req.headers['x-keyfence-token'] !== controlToken()) {
          res.writeHead(403); return res.end('forbidden');
        }
        res.writeHead(200); res.end('bye');
        setTimeout(() => process.exit(0), 50);
        return;
      }
      res.writeHead(404); return res.end();
    }

    stats.requests++;
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks);
      const headers = { ...req.headers };
      let processed;
      try { processed = processBody(raw, headers, cfg); }
      catch (e) { stats.errors++; log(`error processing body: ${e.message}`); processed = { body: raw, changed: false }; }
      if (processed.changed) delete headers['content-encoding'];
      headers.host = upstream.host;
      delete headers['transfer-encoding'];
      headers['content-length'] = String(processed.body.length);

      const basePath = upstream.pathname.replace(/\/$/, '');
      const up = client.request({
        protocol: upstream.protocol, hostname: upstream.hostname, port: upstream.port || undefined,
        path: basePath + req.url, method: req.method, headers, agent,
      }, (ur) => {
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res);
      });
      up.on('error', (e) => {
        stats.errors++;
        log(`upstream error: ${e.message}`);
        if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'keyfence_upstream_error', message: `keyfence could not reach ${cfg.upstream}: ${e.message}` } }));
      });
      req.on('aborted', () => up.destroy());
      up.end(processed.body);
    });
  });
}

function start(opts = {}) {
  const cfg = { ...config.load(), ...opts };
  ensureHome();
  const server = createServer(cfg);
  server.keepAliveTimeout = 65000;
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(cfg.port, '127.0.0.1', () => {
      try { fs.writeFileSync(paths.pid, String(process.pid)); } catch (_) { /* ignore */ }
      log(`listening on 127.0.0.1:${cfg.port} -> ${cfg.upstream}`);
      resolve({ server, cfg });
    });
  });
}

module.exports = { start, createServer, processBody, controlToken, SYSTEM_NOTICE, stats };
