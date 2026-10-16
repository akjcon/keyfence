'use strict';
module.exports = {
  ...require('./redact'),
  detect: require('./detect').detect,
  vault: require('./vault'),
  proxy: require('./proxy'),
};
