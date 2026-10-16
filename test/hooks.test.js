'use strict';
require('./_helpers').isolate('hooks');
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { spawnSync } = require('child_process');
const { SECRETS } = require('./_helpers');
const vault = require('../src/vault');

const BIN = path.join(__dirname, '..', 'bin', 'keyfence.js');

function hook(event, input) {
  const r = spawnSync(process.execPath, [BIN, 'hook', event], {
    input: JSON.stringify(input), encoding: 'utf8', env: process.env, timeout: 10000,
  });
  assert.strictEqual(r.status, 0, r.stderr);
  return r.stdout ? JSON.parse(r.stdout) : null;
}

test('pretool expands placeholders in Bash commands', () => {
  const ph = vault.register('GITHUB_TOKEN', SECRETS.github);
  const out = hook('pretool', { tool_name: 'Bash', tool_input: { command: `echo ${ph}` } });
  assert.deepStrictEqual(out, {
    hookSpecificOutput: { hookEventName: 'PreToolUse', updatedInput: { command: `echo ${SECRETS.github}` } },
  });
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
