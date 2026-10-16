'use strict';
require('./_helpers').isolate('detect');
const test = require('node:test');
const assert = require('node:assert');
const { SECRETS } = require('./_helpers');
const { detect } = require('../src/detect');

const values = (text) => detect(text).map((d) => d.value);
const kinds = (text) => detect(text).map((d) => d.kind);

test('provider token shapes are detected without context', () => {
  assert.deepStrictEqual(kinds(`here: ${SECRETS.stripe}`), ['SECRET_KEY_LIVE']);
  assert.deepStrictEqual(kinds(`aws ${SECRETS.aws} done`), ['AWS_ACCESS_KEY_ID']);
  assert.deepStrictEqual(kinds(SECRETS.github), ['GITHUB_TOKEN']);
  assert.deepStrictEqual(kinds(SECRETS.slack), ['SLACK_TOKEN']);
  assert.deepStrictEqual(kinds(SECRETS.google), ['GOOGLE_API_KEY']);
  assert.deepStrictEqual(kinds(SECRETS.jwt), ['JWT']);
});

test('detections report exact offsets', () => {
  const text = `key is ${SECRETS.stripe}.`;
  const [d] = detect(text);
  assert.strictEqual(text.slice(d.start, d.end), SECRETS.stripe);
});

test('PEM private keys, raw and JSON-escaped', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\nabcd\n-----END RSA PRIVATE KEY-----';
  assert.deepStrictEqual(values(`file:\n${pem}\n`), [pem]);
  const escaped = pem.replace(/\n/g, '\\n');
  const hits = detect(`cert = '${escaped}'`);
  assert.strictEqual(hits.length, 1);
  assert.ok(hits[0].value.startsWith('-----BEGIN RSA PRIVATE KEY-----'));
  assert.ok(hits[0].value.endsWith('-----END RSA PRIVATE KEY-----'));
});

test('contextual rules: assignments, JSON keys, Bearer, URL passwords, CLI flags', () => {
  assert.deepStrictEqual(values('DB_PASSWORD=hunter2hunter2'), ['hunter2hunter2']);
  assert.deepStrictEqual(values('{"client_secret": "q8w7e6r5t4y3u2i1"}'), ['q8w7e6r5t4y3u2i1']);
  assert.deepStrictEqual(values('curl -H "Authorization: Bearer abcdefghijklmnop1234567890"'), ['abcdefghijklmnop1234567890']);
  assert.deepStrictEqual(values('postgres://admin:s3cretPassw0rd@db.internal:5432/app'), ['s3cretPassw0rd']);
  assert.deepStrictEqual(values('mytool --password Zx9vQ2mN8kL4'), ['Zx9vQ2mN8kL4']);
});

test('public and placeholder-ish values are ignored', () => {
  const clean = [
    'NEXT_PUBLIC_STRIPE_KEY=pk_live_51HxAbCdEfGhIjKlMnOp',
    'PORT=3000',
    'NODE_ENV=production',
    'TIMEOUT=12345678',
    'fixed in commit 3f2a1bc',
    'see https://example.com/docs?page=2',
    'API_KEY=changeme',
    'API_KEY=<your-key>',
    'API_KEY=${STRIPE_KEY}',
    'apiKey: process.env.STRIPE_KEY',
    'API_KEY={{KF_API_KEY_1a2b3c4d}}',
  ];
  for (const text of clean) assert.deepStrictEqual(detect(text), [], `false positive on: ${text}`);
});

test('overlapping hits are de-duplicated', () => {
  const hits = detect(`STRIPE_SECRET_KEY=${SECRETS.stripe}`);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].value, SECRETS.stripe);
});
