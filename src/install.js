'use strict';
// One-shot setup: copy ourselves to ~/.keyfence/app, wire hooks + ANTHROPIC_BASE_URL
// into ~/.claude/settings.json, start the proxy. Idempotent; re-run to upgrade.
// A backup of settings.json is written next to it before any change.
const fs = require('fs');
const path = require('path');
const { paths, ensureHome } = require('./paths');
const config = require('./config');
const daemon = require('./daemon');

const MARKER = 'keyfence.js hook';

function readSettings() {
  try { return JSON.parse(fs.readFileSync(paths.claudeSettings, 'utf8')); }
  catch (e) {
    if (e.code === 'ENOENT') return {};
    throw new Error(`could not parse ${paths.claudeSettings}: ${e.message}`);
  }
}

function writeSettings(s) {
  fs.mkdirSync(path.dirname(paths.claudeSettings), { recursive: true });
  // Keep the first (pre-keyfence) backup; never overwrite it with a keyfence-modified file.
  const backup = paths.claudeSettings + '.keyfence-backup';
  if (fs.existsSync(paths.claudeSettings) && !fs.existsSync(backup)) {
    fs.copyFileSync(paths.claudeSettings, backup);
  }
  const tmp = paths.claudeSettings + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2) + '\n');
  fs.renameSync(tmp, paths.claudeSettings);
}

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    if (e.isDirectory()) copyDir(s, d); else fs.copyFileSync(s, d);
  }
}

function installApp() {
  const pkgRoot = path.join(__dirname, '..');
  const dst = paths.app;
  fs.rmSync(dst, { recursive: true, force: true });
  fs.mkdirSync(dst, { recursive: true });
  for (const name of ['bin', 'src', 'package.json']) {
    const s = path.join(pkgRoot, name);
    if (fs.statSync(s).isDirectory()) copyDir(s, path.join(dst, name)); else fs.copyFileSync(s, path.join(dst, name));
  }
  return path.join(dst, 'bin', 'keyfence.js');
}

function q(p) { return /[\s"]/.test(p) ? `"${p.replace(/"/g, '\\"')}"` : p; }

function hookCmd(entry, event) { return `${q(process.execPath)} ${q(entry)} hook ${event}`; }

function isOurs(group) {
  return (group.hooks || []).some((h) => typeof h.command === 'string' && h.command.includes(MARKER));
}

function stripOurHooks(hooks) {
  const out = {};
  for (const [event, groups] of Object.entries(hooks || {})) {
    const kept = (Array.isArray(groups) ? groups : []).filter((g) => !isOurs(g));
    if (kept.length) out[event] = kept;
  }
  return out;
}

function install({ port, upstream } = {}) {
  ensureHome();
  const entry = installApp();
  const settings = readSettings();
  const cfg = config.load();
  if (port) cfg.port = Number(port);

  // If the user already routes through a gateway, keep it as our upstream.
  const settingsBase = settings.env && settings.env.ANTHROPIC_BASE_URL;
  const existingBase = settingsBase || process.env.ANTHROPIC_BASE_URL;
  const isOurs = (u) => /^http:\/\/127\.0\.0\.1:\d+$/.test(u || '');
  if (upstream) cfg.upstream = upstream;
  else if (existingBase && !isOurs(existingBase) && !/localhost/.test(existingBase)) cfg.upstream = existingBase;
  // Remember exactly what settings.json had so uninstall can put it back (null = nothing).
  // On a re-install settings.json already points at us, so keep what we recorded before.
  if (!isOurs(settingsBase)) cfg.restoreBaseUrl = settingsBase || null;
  config.save(cfg);

  settings.env = { ...(settings.env || {}), ANTHROPIC_BASE_URL: `http://127.0.0.1:${cfg.port}` };
  const hooks = stripOurHooks(settings.hooks);
  const add = (event, matcher, name, timeout) => {
    const h = { type: 'command', command: hookCmd(entry, name) };
    if (timeout) h.timeout = timeout;
    const group = matcher === undefined ? { hooks: [h] } : { matcher, hooks: [h] };
    hooks[event] = [...(hooks[event] || []), group];
  };
  add('SessionStart', undefined, 'sessionstart', 10);
  add('UserPromptSubmit', undefined, 'prompt', 10);
  add('PreToolUse', 'Bash|Write|Edit|MultiEdit|NotebookEdit', 'pretool', 10);
  add('PostToolUse', '', 'posttool', 10);
  settings.hooks = hooks;
  writeSettings(settings);
  return { entry, cfg };
}

function uninstall() {
  const settings = readSettings();
  const cfg = config.load();
  if (settings.env && /^http:\/\/127\.0\.0\.1:\d+$/.test(settings.env.ANTHROPIC_BASE_URL || '')) {
    if (cfg.restoreBaseUrl) settings.env.ANTHROPIC_BASE_URL = cfg.restoreBaseUrl;
    else delete settings.env.ANTHROPIC_BASE_URL;
    if (!Object.keys(settings.env).length) delete settings.env;
  }
  settings.hooks = stripOurHooks(settings.hooks);
  if (!Object.keys(settings.hooks).length) delete settings.hooks;
  writeSettings(settings);
  delete cfg.restoreBaseUrl;
  config.save(cfg);
  return daemon.stop();
}

function isInstalled() {
  const s = readSettings();
  return !!(s.env && /127\.0\.0\.1/.test(s.env.ANTHROPIC_BASE_URL || '')) &&
    Object.values(s.hooks || {}).some((gs) => Array.isArray(gs) && gs.some(isOurs));
}

module.exports = { install, uninstall, isInstalled, readSettings, MARKER };
