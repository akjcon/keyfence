'use strict';
require('./_helpers').isolate('redact');
const test = require('node:test');
const assert = require('node:assert');
const { SECRETS } = require('./_helpers');
const vault = require('../src/vault');
const { redactText, expandText, redactDeep, expandDeep, variants } = require('../src/redact');

test('redactText registers fresh secrets and replaces them', () => {
  const r = redactText(`export STRIPE=${SECRETS.stripe}`);
  assert.ok(!r.text.includes(SECRETS.stripe));
  assert.strictEqual(r.found.length, 1);
  assert.strictEqual(r.found[0].fresh, true);
  assert.match(r.text, /^export STRIPE=\{\{KF_SECRET_KEY_LIVE_[a-f0-9]{8}\}\}$/);
  assert.strictEqual(vault.lookup(r.found[0].placeholder), SECRETS.stripe);
});

test('known values are replaced even without context, and marked not fresh', () => {
  const ph = vault.register('CUSTOM', 'plainOpaqueValue9');
  const r = redactText('the value plainOpaqueValue9 appears bare', { register: false });
  assert.strictEqual(r.text, `the value ${ph} appears bare`);
  assert.deepStrictEqual(r.found.map((f) => f.fresh), [false]);
});

test('encoded variants of known values are replaced', () => {
  const value = 'p@ss/word+with=chars"q';
  const ph = vault.register('PW', value);
  const b64 = Buffer.from(value).toString('base64');
  const b64url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const urlenc = encodeURIComponent(value);
  const jsonEsc = JSON.stringify(value).slice(1, -1);
  for (const v of [b64, b64url, urlenc, jsonEsc]) {
    assert.ok(variants(value).includes(v), `variants() missing ${v}`);
    assert.strictEqual(redactText(`x ${v} y`, { register: false }).text, `x ${ph} y`, `variant not redacted: ${v}`);
  }
});

test('register:false does not store new secrets', () => {
  const before = vault.entries().length;
  const r = redactText(`token ${SECRETS.slack}`, { register: false });
  assert.ok(r.text.includes(SECRETS.slack));
  assert.strictEqual(vault.entries().length, before);
});

test('expandText handles all three placeholder syntaxes and leaves unknown ones', () => {
  const ph = vault.register('GITHUB_TOKEN', SECRETS.github);
  const name = ph.slice(2, -2);
  const r = expandText(`a ${ph} b \${${name}} c $${name} d {{KF_NOPE_deadbeef}}`);
  assert.strictEqual(r.text, `a ${SECRETS.github} b ${SECRETS.github} c ${SECRETS.github} d {{KF_NOPE_deadbeef}}`);
  assert.strictEqual(r.expanded, 3);
});

test('redact -> expand round-trips', () => {
  const original = `AWS_ACCESS_KEY_ID=${SECRETS.aws}\nGOOGLE=${SECRETS.google}`;
  const red = redactText(original).text;
  assert.ok(!red.includes(SECRETS.aws) && !red.includes(SECRETS.google));
  assert.strictEqual(expandText(red).text, original);
});

test('redactDeep / expandDeep walk nested JSON and keep non-strings', () => {
  const input = { a: [1, true, null, { b: `jwt ${SECRETS.jwt}` }], n: 42 };
  const r = redactDeep(input, { register: true });
  assert.strictEqual(r.changed, true);
  assert.ok(!JSON.stringify(r.value).includes(SECRETS.jwt));
  assert.deepStrictEqual(r.value.a.slice(0, 3), [1, true, null]);
  assert.strictEqual(r.value.n, 42);
  assert.deepStrictEqual(expandDeep(r.value).value, input);
  assert.strictEqual(redactDeep({ x: 'nothing to see' }).changed, false);
});
