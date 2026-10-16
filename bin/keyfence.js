#!/usr/bin/env node
'use strict';
require('../src/cli.js').main(process.argv.slice(2)).catch((err) => {
  process.stderr.write(`keyfence: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
