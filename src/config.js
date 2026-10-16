'use strict';
const fs = require('fs');
const { paths, ensureHome } = require('./paths');

const DEFAULTS = {
  port: 47117,
  upstream: 'https://api.anthropic.com',
  // Append a short note to the system prompt explaining placeholders to the model.
  systemNotice: true,
};

function load() {
  try {
    const raw = JSON.parse(fs.readFileSync(paths.config, 'utf8'));
    return { ...DEFAULTS, ...raw };
  } catch (_) {
    return { ...DEFAULTS };
  }
}

function save(cfg) {
  ensureHome();
  const tmp = paths.config + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, paths.config);
}

module.exports = { load, save, DEFAULTS };
