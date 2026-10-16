'use strict';
require('./_helpers').isolate('proxy');
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const zlib = require('zlib');
const { SECRETS } = require('./_helpers');
const { processBody, createServer } = require('../src/proxy');

const JSON_CT = { 'content-type': 'application/json' };
const CFG = { systemNotice: true };

function claudeBody() {
  return {
    model: 'claude-test',
    messages: [
      { role: 'user', content: `deploy with ${SECRETS.stripe}` },
      { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'Bash', input: { command: 'cat .env' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: `GITHUB_TOKEN=${SECRETS.github}` }] },
    ],
  };
}

test('processBody redacts JSON bodies and adds the system notice', () => {
  const r = processBody(Buffer.from(JSON.stringify(claudeBody())), JSON_CT, CFG);
  const s = r.body.toString();
  assert.strictEqual(r.changed, true);
  assert.ok(!s.includes(SECRETS.stripe) && !s.includes(SECRETS.github));
  assert.strictEqual(r.found.length, 2);
  assert.ok(JSON.parse(s).system.startsWith('KEYFENCE:'));
});

test('processBody appends to an existing system array once', () => {
  const body = { ...claudeBody(), system: [{ type: 'text', text: 'You are helpful.' }] };
  const once = JSON.parse(processBody(Buffer.from(JSON.stringify(body)), JSON_CT, CFG).body);
  assert.strictEqual(once.system.length, 2);
  assert.ok(once.system[1].text.startsWith('KEYFENCE:'));
  const twice = JSON.parse(processBody(Buffer.from(JSON.stringify(once)), JSON_CT, CFG).body);
  assert.strictEqual(twice.system.length, 2);
});

test('processBody decodes gzip bodies', () => {
  const gz = zlib.gzipSync(Buffer.from(JSON.stringify(claudeBody())));
  const r = processBody(gz, { ...JSON_CT, 'content-encoding': 'gzip' }, CFG);
  assert.ok(!r.body.toString().includes(SECRETS.stripe));
  assert.doesNotThrow(() => JSON.parse(r.body.toString()));
});

test('processBody leaves non-JSON and invalid JSON untouched', () => {
  const raw = Buffer.from(`not json ${SECRETS.stripe}`);
  assert.strictEqual(processBody(raw, { 'content-type': 'text/plain' }, CFG).body, raw);
  assert.strictEqual(processBody(raw, JSON_CT, CFG).changed, false);
});

test('processBody skips the notice when systemNotice is off or there are no messages', () => {
  const off = JSON.parse(processBody(Buffer.from(JSON.stringify(claudeBody())), JSON_CT, { systemNotice: false }).body);
  assert.strictEqual(off.system, undefined);
  const noMsgs = JSON.parse(processBody(Buffer.from('{"a":1}'), JSON_CT, CFG).body);
  assert.strictEqual(noMsgs.system, undefined);
});

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

test('integration: upstream sees placeholders only; response passes through', async (t) => {
  let seen = null;
  const upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen = { url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() };
      res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': 'yes' });
      res.end('{"id":"msg_1","echo":"sk_live_in_response_is_not_touched"}');
    });
  });
  const upPort = await listen(upstream);
  const proxy = createServer({ upstream: `http://127.0.0.1:${upPort}`, systemNotice: true });
  const pxPort = await listen(proxy);
  t.after(() => { proxy.close(); upstream.close(); });
  proxy.unref(); upstream.unref();

  const payload = JSON.stringify(claudeBody());
  const res = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: pxPort, path: '/v1/messages', method: 'POST',
      headers: { ...JSON_CT, 'content-length': Buffer.byteLength(payload), connection: 'close' } }, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(payload);
  });

  assert.strictEqual(seen.url, '/v1/messages');
  assert.ok(!seen.body.includes(SECRETS.stripe), 'raw secret in user message reached upstream');
  assert.ok(!seen.body.includes(SECRETS.github), 'raw secret in tool_result reached upstream');
  const sent = JSON.parse(seen.body);
  assert.match(sent.messages[0].content, /\{\{KF_SECRET_KEY_LIVE_[a-f0-9]{8}\}\}/);
  assert.match(sent.messages[2].content[0].content, /\{\{KF_GITHUB_TOKEN_[a-f0-9]{8}\}\}/);
  assert.ok(sent.system.startsWith('KEYFENCE:'));
  assert.strictEqual(Number(seen.headers['content-length']), Buffer.byteLength(seen.body));

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers['x-upstream'], 'yes');
  assert.strictEqual(res.body, '{"id":"msg_1","echo":"sk_live_in_response_is_not_touched"}');
});

test('integration: status endpoint answers locally', async (t) => {
  const proxy = createServer({ upstream: 'http://127.0.0.1:9', systemNotice: true });
  const port = await listen(proxy);
  t.after(() => proxy.close());
  const body = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/_keyfence/status', headers: { connection: 'close' } }, (r) => {
      let d = ''; r.on('data', (c) => { d += c; }); r.on('end', () => resolve(d));
    }).on('error', reject);
  });
  assert.strictEqual(JSON.parse(body).ok, true);
});
