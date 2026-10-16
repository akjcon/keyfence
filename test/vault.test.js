'use strict';
require('./_helpers').isolate('vault');
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { SECRETS } = require('./_helpers');
const { paths } = require('../src/paths');
const vault = require('../src/vault');

test('register returns a well-formed, deterministic placeholder', () => {
  const ph = vault.register('stripe secret', SECRETS.stripe);
  assert.match(ph, /^\{\{KF_STRIPE_SECRET_[a-f0-9]{8}\}\}$/);
  assert.strictEqual(vault.register('stripe secret', SECRETS.stripe), ph);
  assert.strictEqual(vault.placeholderFor('stripe secret', SECRETS.stripe), ph);
  assert.notStrictEqual(vault.register('stripe secret', SECRETS.stripe + 'x'), ph);
});

test('lookup, entries and remove', () => {
  const ph = vault.register('AWS', SECRETS.aws);
  assert.strictEqual(vault.lookup(ph), SECRETS.aws);
  assert.ok(vault.entries().some((e) => e.placeholder === ph && e.kind === 'AWS'));
  const lens = vault.entries().map((e) => e.value.length);
  assert.deepStrictEqual(lens, [...lens].sort((a, b) => b - a), 'entries are longest-first');
  assert.strictEqual(vault.remove(ph), true);
  assert.strictEqual(vault.lookup(ph), undefined);
  assert.strictEqual(vault.remove(ph), false);
});

test('vault and salt live in KEYFENCE_HOME with 0600 perms', { skip: process.platform === 'win32' }, () => {
  vault.register('X', SECRETS.github);
  assert.ok(paths.vault.startsWith(process.env.KEYFENCE_HOME));
  assert.strictEqual(fs.statSync(paths.vault).mode & 0o777, 0o600);
  assert.strictEqual(fs.statSync(paths.salt).mode & 0o777, 0o600);
});

test('PLACEHOLDER_RE matches generated placeholders', () => {
  const ph = vault.register('GITHUB_TOKEN', SECRETS.github);
  const re = new RegExp(vault.PLACEHOLDER_RE.source);
  assert.ok(re.test(`use ${ph} here`));
});
