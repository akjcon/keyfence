'use strict';
// The vault maps placeholders -> real secret values. It lives only on this machine.
// Placeholders are deterministic (HMAC of the value with a per-install salt) so the
// same secret always gets the same placeholder, which keeps prompt caching stable.
const fs = require('fs');
const crypto = require('crypto');
const { paths, ensureHome } = require('./paths');

const PLACEHOLDER_RE = /\{\{KF_[A-Z0-9_]+_[a-f0-9]{8}\}\}/g;

let _salt = null;
function salt() {
  if (_salt) return _salt;
  ensureHome();
  try {
    _salt = fs.readFileSync(paths.salt, 'utf8').trim();
  } catch (_) {
    _salt = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(paths.salt, _salt, { mode: 0o600 });
  }
  return _salt;
}

function sanitizeKind(kind) {
  const k = String(kind || 'SECRET').toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return (k || 'SECRET').slice(0, 40);
}

function placeholderFor(kind, value) {
  const h = crypto.createHmac('sha256', salt()).update(value).digest('hex').slice(0, 8);
  return `{{KF_${sanitizeKind(kind)}_${h}}}`;
}

function read() {
  try {
    const v = JSON.parse(fs.readFileSync(paths.vault, 'utf8'));
    if (v && v.secrets) return v;
  } catch (_) { /* fresh */ }
  return { version: 1, secrets: {} };
}

function write(v) {
  ensureHome();
  v.rev = (v.rev || 0) + 1; // monotonic revision so caches don't depend on mtime granularity
  const tmp = paths.vault + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(v, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, paths.vault);
}

function mtime() {
  try { return fs.statSync(paths.vault).mtimeMs; } catch (_) { return 0; }
}

// Cache key for the vault's contents: revision + size + mtime.
function version() {
  try {
    const st = fs.statSync(paths.vault);
    return `${read().rev || 0}:${st.size}:${st.mtimeMs}`;
  } catch (_) { return '0'; }
}

// Register a secret. Returns its placeholder. Idempotent.
function register(kind, value) {
  const ph = placeholderFor(kind, value);
  const v = read();
  if (!v.secrets[ph]) {
    v.secrets[ph] = { value, kind: sanitizeKind(kind), created: new Date().toISOString() };
    write(v);
  }
  return ph;
}

// Array of { placeholder, value, kind }, longest values first (so longer secrets
// that contain shorter ones get replaced first).
function entries() {
  const v = read();
  return Object.entries(v.secrets)
    .map(([placeholder, s]) => ({ placeholder, value: s.value, kind: s.kind, created: s.created }))
    .filter((e) => typeof e.value === 'string' && e.value.length > 0)
    .sort((a, b) => b.value.length - a.value.length);
}

function lookup(placeholder) {
  const v = read();
  const s = v.secrets[placeholder];
  return s ? s.value : undefined;
}

function remove(placeholder) {
  const v = read();
  const existed = !!v.secrets[placeholder];
  if (existed) { delete v.secrets[placeholder]; write(v); }
  return existed;
}

module.exports = { register, entries, lookup, remove, placeholderFor, read, mtime, version, PLACEHOLDER_RE, sanitizeKind };
