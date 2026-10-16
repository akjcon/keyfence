'use strict';
require('./_helpers').isolate('install');
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { paths } = require('../src/paths');
const config = require('../src/config');
const { install, uninstall, isInstalled, readSettings, MARKER } = require('../src/install');

// A port nothing listens on, so uninstall()'s daemon.stop() never touches a real proxy.
function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const ours = (s) => Object.values(s.hooks || {}).flat().filter((g) => g.hooks.some((h) => h.command.includes(MARKER)));
const groupCount = (s) => Object.values(s.hooks || {}).flat().length;

function seed(settings) {
  fs.mkdirSync(paths.claudeDir, { recursive: true });
  fs.writeFileSync(paths.claudeSettings, JSON.stringify(settings));
}

const USER_HOOK = { matcher: 'Bash', hooks: [{ type: 'command', command: 'echo user-hook' }] };

test('install wires base URL and six hook groups, preserving user settings', async () => {
  const port = await freePort();
  seed({ model: 'opus', env: { FOO: 'bar' }, hooks: { PreToolUse: [USER_HOOK] } });
  const { entry } = install({ port });

  assert.ok(entry.startsWith(paths.app) && fs.existsSync(entry), 'package copied to KEYFENCE_HOME/app');
  const s = readSettings();
  assert.strictEqual(s.env.ANTHROPIC_BASE_URL, `http://127.0.0.1:${port}`);
  assert.strictEqual(s.env.FOO, 'bar');
  assert.strictEqual(s.model, 'opus');
  assert.strictEqual(ours(s).length, 6);
  assert.deepStrictEqual(Object.keys(s.hooks).sort(), ['CwdChanged', 'FileChanged', 'PostToolUse', 'PreToolUse', 'SessionStart', 'UserPromptSubmit']);
  assert.ok(s.hooks.PreToolUse.some((g) => g.hooks[0].command === 'echo user-hook'));
  assert.ok(fs.existsSync(paths.claudeSettings + '.keyfence-backup'));
  assert.strictEqual(isInstalled(), true);
});

test('install is idempotent', async () => {
  const port = await freePort();
  install({ port });
  const n = groupCount(readSettings());
  install({ port });
  assert.strictEqual(groupCount(readSettings()), n);
  assert.strictEqual(ours(readSettings()).length, 6);
});

test('existing non-local ANTHROPIC_BASE_URL becomes the upstream and is restored on uninstall', async () => {
  const port = await freePort();
  seed({ env: { ANTHROPIC_BASE_URL: 'https://gateway.example.com/anthropic' }, hooks: { PreToolUse: [USER_HOOK] } });
  install({ port });
  assert.strictEqual(config.load().upstream, 'https://gateway.example.com/anthropic');
  assert.strictEqual(readSettings().env.ANTHROPIC_BASE_URL, `http://127.0.0.1:${port}`);

  await uninstall();
  const s = readSettings();
  assert.strictEqual(s.env.ANTHROPIC_BASE_URL, 'https://gateway.example.com/anthropic');
  assert.strictEqual(ours(s).length, 0);
  assert.deepStrictEqual(s.hooks.PreToolUse, [USER_HOOK]);
  assert.strictEqual(isInstalled(), false);
});

test('uninstall from a clean install removes base URL and empty sections', async () => {
  const port = await freePort();
  seed({ theme: 'dark' });
  config.save({ ...config.DEFAULTS, port });
  install({ port });
  await uninstall();
  assert.deepStrictEqual(readSettings(), { theme: 'dark' });
  assert.ok(path.dirname(paths.claudeSettings).startsWith(process.env.CLAUDE_CONFIG_DIR));
});
