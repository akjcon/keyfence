'use strict';
const os = require('os');
const path = require('path');
const fs = require('fs');

const HOME = os.homedir();
const KF_DIR = process.env.KEYFENCE_HOME || path.join(HOME, '.keyfence');
const CLAUDE_DIR = process.env.CLAUDE_CONFIG_DIR || path.join(HOME, '.claude');

const paths = {
  home: KF_DIR,
  vault: path.join(KF_DIR, 'vault.json'),
  salt: path.join(KF_DIR, 'salt'),
  config: path.join(KF_DIR, 'config.json'),
  pid: path.join(KF_DIR, 'proxy.pid'),
  token: path.join(KF_DIR, 'proxy.token'),
  envsh: path.join(KF_DIR, 'env.sh'),
  log: path.join(KF_DIR, 'proxy.log'),
  app: path.join(KF_DIR, 'app'),
  claudeDir: CLAUDE_DIR,
  claudeSettings: path.join(CLAUDE_DIR, 'settings.json'),
  claudeProjects: path.join(CLAUDE_DIR, 'projects'),
  claudeHistory: path.join(CLAUDE_DIR, 'history.jsonl'),
};

function ensureHome() {
  if (!fs.existsSync(KF_DIR)) fs.mkdirSync(KF_DIR, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(KF_DIR, 0o700); } catch (_) { /* windows */ }
}

module.exports = { paths, ensureHome };
