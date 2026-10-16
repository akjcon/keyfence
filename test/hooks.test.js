'use strict';
require('./_helpers').isolate('hooks');
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');
const { SECRETS } = require('./_helpers');
const vault = require('../src/vault');

const BIN = path.join(__dirname, '..', 'bin', 'keyfence.js');

function hook(event, input, extraEnv = {}) {
  const r = spawnSync(process.execPath, [BIN, 'hook', event], {
    input: JSON.stringify(input), encoding: 'utf8', env: { ...process.env, ...extraEnv }, timeout: 10000,
  });
  assert.strictEqual(r.status, 0, r.stderr);
  return r.stdout ? JSON.parse(r.stdout) : null;
}

test('pretool never rewrites Bash commands (secrets reach shells as env vars)', () => {
  const ph = vault.register('GITHUB_TOKEN', SECRETS.github);
  assert.strictEqual(hook('pretool', { tool_name: 'Bash', tool_input: { command: `echo ${ph} $${ph.slice(2, -2)}` } }), null);
});

test('sessionstart exports vault secrets into CLAUDE_ENV_FILE and watches the vault', () => {
  const ph = vault.register('GITHUB_TOKEN', SECRETS.github);
  const envFile = path.join(process.env.KEYFENCE_HOME, 'env.sh');
  fs.writeFileSync(envFile, '');
  const cfgPath = path.join(process.env.KEYFENCE_HOME, 'config.json');
  // Point the daemon at a port nothing listens on and give it a short wait so the test stays fast.
  fs.writeFileSync(cfgPath, JSON.stringify({ port: 1, upstream: 'http://127.0.0.1:9' }));
  const out = hook('sessionstart', {}, { CLAUDE_ENV_FILE: envFile });
  const env = fs.readFileSync(envFile, 'utf8');
  assert.match(env, new RegExp(`^export ${ph.slice(2, -2)}='${SECRETS.github}'$`, 'm'));
  assert.deepStrictEqual(out.hookSpecificOutput.watchPaths, [path.join(process.env.KEYFENCE_HOME, 'vault.json')]);
  const r = spawnSync(process.execPath, [BIN, 'hook', 'filechanged'], { input: '{}', encoding: 'utf8', env: { ...process.env, CLAUDE_ENV_FILE: envFile } });
  assert.strictEqual(r.status, 0, r.stderr);
  assert.strictEqual((fs.readFileSync(envFile, 'utf8').match(/^export KF_/gm) || []).length, 2);
});

test('pretool expands $KF_ syntax inside Write content', () => {
  const ph = vault.register('AWS', SECRETS.aws);
  const out = hook('pretool', { tool_name: 'Write', tool_input: { file_path: '/x/.env', content: `KEY=$${ph.slice(2, -2)}\n` } });
  assert.strictEqual(out.hookSpecificOutput.updatedInput.content, `KEY=${SECRETS.aws}\n`);
  assert.strictEqual(out.hookSpecificOutput.updatedInput.file_path, '/x/.env');
});

test('pretool prints nothing without placeholders or for non-expanding tools', () => {
  const ph = vault.register('GITHUB_TOKEN', SECRETS.github);
  assert.strictEqual(hook('pretool', { tool_name: 'Bash', tool_input: { command: 'ls -la' } }), null);
  assert.strictEqual(hook('pretool', { tool_name: 'WebFetch', tool_input: { url: `https://x/${ph}` } }), null);
});

test('posttool redacts secrets in tool output and keeps its shape', () => {
  const out = hook('posttool', {
    tool_name: 'Bash',
    tool_response: { stdout: `SLACK_BOT_TOKEN=${SECRETS.slack}\n`, stderr: '', interrupted: false, isImage: false },
  });
  const o = out.hookSpecificOutput;
  assert.strictEqual(o.hookEventName, 'PostToolUse');
  assert.deepStrictEqual(Object.keys(o.updatedToolOutput).sort(), ['interrupted', 'isImage', 'stderr', 'stdout']);
  assert.strictEqual(o.updatedToolOutput.interrupted, false);
  assert.ok(!o.updatedToolOutput.stdout.includes(SECRETS.slack));
  const [ph] = o.updatedToolOutput.stdout.match(/\{\{KF_[A-Z0-9_]+_[a-f0-9]{8}\}\}/);
  assert.strictEqual(vault.lookup(ph), SECRETS.slack, 'hook registered the secret in the shared vault');
  assert.ok(o.additionalContext.includes(ph));
});

test('posttool prints nothing for clean output', () => {
  assert.strictEqual(hook('posttool', { tool_name: 'Bash', tool_response: { stdout: 'ok\n', stderr: '', interrupted: false, isImage: false } }), null);
});
