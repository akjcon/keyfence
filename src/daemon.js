'use strict';
const http = require('http');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const { paths, ensureHome } = require('./paths');
const config = require('./config');

function status(port, timeoutMs = 400) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/_keyfence/status', timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (_) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

// Path to the CLI entry that hooks and the daemon should use. Prefer the installed
// copy under ~/.keyfence/app so npx cache eviction can't break anything.
function entryPoint() {
  const installed = path.join(paths.app, 'bin', 'keyfence.js');
  if (fs.existsSync(installed)) return installed;
  return path.join(__dirname, '..', 'bin', 'keyfence.js');
}

function spawnDetached() {
  ensureHome();
  const out = fs.openSync(paths.log, 'a');
  const child = spawn(process.execPath, [entryPoint(), 'proxy'], {
    detached: true, stdio: ['ignore', out, out], windowsHide: true,
    env: { ...process.env, KEYFENCE_DAEMON: '1' },
  });
  child.unref();
  return child.pid;
}

async function ensureRunning({ waitMs = 2500 } = {}) {
  const cfg = config.load();
  const s = await status(cfg.port);
  if (s) return { running: true, started: false, status: s };
  spawnDetached();
  const deadline = Date.now() + waitMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 120));
    const s2 = await status(cfg.port);
    if (s2) return { running: true, started: true, status: s2 };
  }
  return { running: false, started: true, status: null };
}

async function stop() {
  const cfg = config.load();
  const s = await status(cfg.port);
  if (!s) return false;
  await new Promise((resolve) => {
    let token = '';
    try { token = fs.readFileSync(paths.token, 'utf8').trim(); } catch (_) { /* no token yet */ }
    const req = http.request({ host: '127.0.0.1', port: cfg.port, path: '/_keyfence/shutdown', method: 'POST', headers: { 'x-keyfence-token': token } }, (res) => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve);
    req.end();
  });
  // Wait for the port to actually close so a following start/status is accurate.
  const deadline = Date.now() + 1500;
  while (Date.now() < deadline && (await status(cfg.port, 150))) {
    await new Promise((r) => setTimeout(r, 60));
  }
  try { fs.unlinkSync(paths.pid); } catch (_) { /* ignore */ }
  return true;
}

module.exports = { status, ensureRunning, stop, entryPoint, spawnDetached };
