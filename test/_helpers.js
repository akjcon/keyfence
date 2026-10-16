'use strict';
// Shared test helpers. Every test file calls isolate() BEFORE requiring anything
// from src/, because src/paths.js reads KEYFENCE_HOME / CLAUDE_CONFIG_DIR at
// require time.
const fs = require('fs');
const os = require('os');
const path = require('path');

const BASE = process.env.KEYFENCE_TEST_TMP || path.join(os.tmpdir(), 'keyfence-tests');

function tmpdir(prefix) {
  fs.mkdirSync(BASE, { recursive: true });
  return fs.mkdtempSync(path.join(BASE, `${prefix}-`));
}

function isolate(prefix) {
  const dir = tmpdir(prefix);
  process.env.KEYFENCE_HOME = path.join(dir, 'kf');
  process.env.CLAUDE_CONFIG_DIR = path.join(dir, 'claude');
  delete process.env.ANTHROPIC_BASE_URL;
  return dir;
}

// Fake-but-shaped secrets. Assembled at runtime so the source never contains
// a literal that a secret scanner would flag.
const SECRETS = {
  stripe: 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc',
  aws: 'AKIA' + 'IOSFODNN7EXAMPLE',
  github: 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
  slack: 'xoxb-' + '1234567890-0987654321-AbCdEfGhIjKlMnOp',
  google: 'AIza' + 'SyD3x4mpl3K3yV4lu3F0rT3st1ngABCDEF0',
  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
};

module.exports = { tmpdir, isolate, SECRETS, BASE };
