'use strict';
const vault = require('./vault');
const { detect } = require('./detect');

// ---- Known-value matching ------------------------------------------------
// Build a single alternation regex of every known secret value (and common
// encodings of it), longest first. Cached by vault mtime.

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function variants(value) {
  const set = new Set([value]);
  try {
    const b64 = Buffer.from(value, 'utf8').toString('base64');
    set.add(b64);
    set.add(b64.replace(/=+$/, ''));
    set.add(b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  } catch (_) { /* ignore */ }
  const enc = encodeURIComponent(value);
  if (enc !== value) set.add(enc);
  // JSON-escaped form (as it appears inside a JSON string literal)
  const js = JSON.stringify(value).slice(1, -1);
  if (js !== value) set.add(js);
  // Shell-escaped single quotes
  if (value.includes("'")) set.add(value.replace(/'/g, "'\\''"));
  return [...set].filter((v) => v.length >= 6);
}

let cache = { mtime: -1, re: null, map: null };
function knownMatcher() {
  const mt = vault.version();
  if (cache.mtime === mt && cache.re) return cache;
  const map = new Map();
  const alts = [];
  for (const e of vault.entries()) {
    for (const v of variants(e.value)) {
      if (!map.has(v)) { map.set(v, e.placeholder); alts.push(v); }
    }
  }
  alts.sort((a, b) => b.length - a.length);
  const re = alts.length ? new RegExp(alts.map(escapeRe).join('|'), 'g') : null;
  cache = { mtime: mt, re, map };
  return cache;
}

function invalidateCache() { cache = { mtime: -1, re: null, map: null }; }

// ---- Public API ----------------------------------------------------------

/**
 * Replace secrets in text with placeholders.
 * @param {string} text
 * @param {{register?: boolean}} opts  register=false -> only known values are replaced
 * @returns {{text: string, found: Array<{placeholder: string, kind: string, fresh: boolean}>}}
 */
function redactText(text, opts = {}) {
  if (typeof text !== 'string' || !text) return { text, found: [] };
  const register = opts.register !== false;
  const found = [];
  let out = text;

  // 1. Known values first.
  const k = knownMatcher();
  if (k.re) {
    out = out.replace(k.re, (m) => {
      const ph = k.map.get(m);
      found.push({ placeholder: ph, kind: ph.slice(5, -11), fresh: false });
      return ph;
    });
  }

  // 2. Fresh detections.
  if (register) {
    const hits = detect(out);
    if (hits.length) {
      let rebuilt = '';
      let cursor = 0;
      for (const h of hits) {
        const ph = vault.register(h.kind, h.value);
        found.push({ placeholder: ph, kind: h.kind, fresh: true });
        rebuilt += out.slice(cursor, h.start) + ph;
        cursor = h.end;
      }
      out = rebuilt + out.slice(cursor);
      invalidateCache();
    }
  }
  return { text: out, found };
}

// Placeholders the model may write: {{KF_X_hash}}, $KF_X_hash, ${KF_X_hash}
const EXPAND_RE = /\{\{(KF_[A-Z0-9_]+_[a-f0-9]{8})\}\}|\$\{(KF_[A-Z0-9_]+_[a-f0-9]{8})\}|\$(KF_[A-Z0-9_]+_[a-f0-9]{8})\b/g;

/** Replace placeholders with real values. Unknown placeholders are left as-is. */
function expandText(text) {
  if (typeof text !== 'string' || !text.includes('KF_')) return { text, expanded: 0 };
  let expanded = 0;
  const out = text.replace(EXPAND_RE, (m, a, b, c) => {
    const name = a || b || c;
    const val = vault.lookup(`{{${name}}}`);
    if (val === undefined) return m;
    expanded++;
    return val;
  });
  return { text: out, expanded };
}

/** Deep-walk any JSON-ish value, applying fn to every string. Returns [newValue, changed]. */
function mapStrings(value, fn) {
  let changed = false;
  const walk = (v) => {
    if (typeof v === 'string') {
      const r = fn(v);
      if (r !== v) changed = true;
      return r;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const o = {};
      for (const [k, x] of Object.entries(v)) o[k] = walk(x);
      return o;
    }
    return v;
  };
  const out = walk(value);
  return [out, changed];
}

function redactDeep(value, opts) {
  const found = [];
  const [out, changed] = mapStrings(value, (s) => {
    const r = redactText(s, opts);
    found.push(...r.found);
    return r.text;
  });
  return { value: out, changed, found };
}

function expandDeep(value) {
  let expanded = 0;
  const [out, changed] = mapStrings(value, (s) => {
    const r = expandText(s);
    expanded += r.expanded;
    return r.text;
  });
  return { value: out, changed, expanded };
}

module.exports = { redactText, expandText, redactDeep, expandDeep, variants, invalidateCache };
