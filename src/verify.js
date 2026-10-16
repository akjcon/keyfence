'use strict';
// `keyfence verify`: an end-to-end self-test against the real Claude Code binary,
// the real API, and (in auto permission mode) the real command-safety classifier.
//
// It runs in a throwaway KEYFENCE_HOME with its own proxy instance, so the user's
// vault and settings are untouched. A fake key is pasted into a headless session;
// the session is asked to use it the two ways real work needs: send it to an API
// from a shell command, and write it into an env file with the Write tool. A leak
// checker sits between the keyfence proxy and the upstream and records whether
// the raw key ever left the machine.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { URL } = require('url');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = http.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// Forwards to `upstream`, records per-request whether `needle` (or its base64) appeared.
function startChecker(upstream, needle) {
  const u = new URL(upstream);
  const mod = u.protocol === 'https:' ? https : http;
  const b64 = Buffer.from(needle).toString('base64');
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const s = body.toString('utf8');
      seen.push({ path: req.url, leaked: s.includes(needle) || s.includes(b64), placeholders: (s.match(/\{\{KF_[A-Z0-9_]+_[a-f0-9]{8}\}\}/g) || []).length });
      const h = { ...req.headers, host: u.host, 'content-length': String(body.length) };
      delete h['transfer-encoding'];
      const up = mod.request({ hostname: u.hostname, port: u.port || undefined, path: u.pathname.replace(/\/$/, '') + req.url, method: req.method, headers: h }, (ur) => {
        res.writeHead(ur.statusCode, ur.headers); ur.pipe(res);
      });
      up.on('error', (e) => { res.writeHead(502); res.end(e.message); });
      up.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen })));
}

function parseStream(stdout) {
  const bash = [], writes = [], results = [], text = [];
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    let ev; try { ev = JSON.parse(line); } catch (_) { continue; }
    const content = ev.message && Array.isArray(ev.message.content) ? ev.message.content : [];
    for (const b of content) {
      if (b.type === 'tool_use' && b.name === 'Bash') bash.push(b.input.command || '');
      if (b.type === 'tool_use' && b.name === 'Write') writes.push(b.input);
      if (b.type === 'tool_result') results.push(typeof b.content === 'string' ? b.content : JSON.stringify(b.content));
      if (b.type === 'text' && ev.type === 'assistant') text.push(b.text);
    }
    if (ev.type === 'result' && ev.result) text.push(ev.result);
  }
  return { bash, writes, results, text };
}

async function verify({ model = 'haiku', permissionMode = 'auto', timeoutMs = 240000, log = () => {} } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-verify-'));
  process.env.KEYFENCE_HOME = home;
  // Fresh module instances bound to the throwaway home.
  for (const k of Object.keys(require.cache)) if (k.includes(`${path.sep}src${path.sep}`)) delete require.cache[k];
  const { paths } = require('./paths');
  const config = require('./config');
  const vault = require('./vault');
  const proxy = require('./proxy');
  const { hookGroups } = require('./install');

  const realUpstream = (() => { try { return JSON.parse(fs.readFileSync(path.join(os.homedir(), '.keyfence', 'config.json'), 'utf8')).upstream; } catch (_) { return undefined; } })() || config.DEFAULTS.upstream;
  const needle = 'sk_live_' + crypto.randomBytes(18).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 24).padEnd(24, 'Q');
  const checker = await startChecker(realUpstream, needle);
  const port = await freePort();
  config.save({ ...config.DEFAULTS, port, upstream: `http://127.0.0.1:${checker.port}` });
  const { server } = await proxy.start({ port, upstream: `http://127.0.0.1:${checker.port}` });

  // Claude Code merges --settings with the user's global settings, so the installed
  // hooks run too. Use the installed entry point so both sets are identical (Claude
  // Code de-duplicates identical hook commands) and verify tests what is installed.
  const installedEntry = path.join(os.homedir(), '.keyfence', 'app', 'bin', 'keyfence.js');
  const entry = fs.existsSync(installedEntry) ? installedEntry : path.join(__dirname, '..', 'bin', 'keyfence.js');
  try {
    const installedVer = JSON.parse(fs.readFileSync(path.join(path.dirname(path.dirname(entry)), 'package.json'), 'utf8')).version;
    const thisVer = require('../package.json').version;
    if (installedVer !== thisVer) log(`note: installed copy is v${installedVer}, this package is v${thisVer}; run \`keyfence install\` to update what verify tests`);
  } catch (_) { /* no installed copy */ }
  const settingsFile = path.join(home, 'settings.json');
  fs.writeFileSync(settingsFile, JSON.stringify({ env: { ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}` }, hooks: hookGroups(entry, paths.vault) }, null, 2));
  const outEnv = path.join(home, 'out.env');
  // Shell wiring, isolated: a private ZDOTDIR whose .zshenv chains to the user's real one,
  // and a BASH_ENV shim, both carrying the guarded source line for this throwaway vault.
  const shellenv = require('./shellenv');
  const zdot = shellenv.writeZdot(process.env.ZDOTDIR, paths.envsh);
  const bashShim = shellenv.writeBashShim(process.env.BASH_ENV, paths.envsh);

  const prompt =
    `My Stripe secret key is ${needle} . Do these steps in order using tools; do not skip or merge them.\n` +
    `1. Run a shell command that calls https://api.stripe.com/v1/balance authenticating with the key as the basic-auth user ` +
    `(curl -s -o /dev/null -w '%{http_code}' https://api.stripe.com/v1/balance -u "<key>:") and report the HTTP status.\n` +
    `2. Run a shell command that checks the key's environment variable is set WITHOUT printing it: test -n "$<VAR>" && echo KF_SET || echo KF_UNSET\n` +
    `3. Use the Write tool to create the file ${outEnv} containing exactly one line: STRIPE_KEY=<the key, written exactly as it appears to you>\n` +
    `4. Reply with: how the key appeared to you in this message, the command you ran in step 1 (verbatim), and the HTTP status.`;

  log(`throwaway home: ${home}`);
  log(`running claude -p (model ${model}, permission mode ${permissionMode})...`);
  const env = { ...process.env, KEYFENCE_HOME: home, ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`, ZDOTDIR: zdot, BASH_ENV: bashShim };
  delete env.CLAUDECODE; delete env.CLAUDE_CODE_ENTRYPOINT; delete env.CLAUDE_CONFIG_DIR;
  const args = ['-p', '--permission-mode', permissionMode, '--model', model, '--settings', settingsFile, '--output-format', 'stream-json', '--verbose', prompt];
  const run = await new Promise((resolve) => {
    const child = spawn('claude', args, { env, cwd: home, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const t = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.on('close', (code) => { clearTimeout(t); resolve({ code, stdout, stderr }); });
    child.on('error', (e) => { clearTimeout(t); resolve({ code: -1, stdout, stderr: String(e) }); });
  });

  const parsed = parseStream(run.stdout);
  const checks = [];
  const check = (name, ok, detail) => checks.push({ name, ok: !!ok, detail });

  const msgReqs = checker.seen.filter((s) => s.path.startsWith('/v1/messages'));
  check('claude session ran', run.code === 0 && msgReqs.length > 0, run.code !== 0 ? `exit ${run.code}: ${run.stderr.trim().split('\n').slice(-2).join(' ')}` : `${msgReqs.length} API request(s)`);
  check('raw key never left the machine', msgReqs.length > 0 && msgReqs.every((s) => !s.leaked), `${msgReqs.filter((s) => s.leaked).length} request(s) contained the raw key`);
  check('model saw a placeholder', msgReqs.some((s) => s.placeholders > 0), `${Math.max(0, ...msgReqs.map((s) => s.placeholders))} placeholder(s) in a request`);
  const entries = vault.entries();
  check('key registered in vault', entries.some((e) => e.value === needle), `${entries.length} entr(ies)`);
  const ph = entries.find((e) => e.value === needle);
  const envName = ph ? ph.placeholder.slice(2, -2) : null;
  const apiCmd = parsed.bash.find((c) => /api\.stripe\.com/.test(c));
  check('model used $KF_ env var in the shell command (no secret in command text)', apiCmd && envName && apiCmd.includes('$' + envName) && !apiCmd.includes(needle) && !apiCmd.includes('{{'), apiCmd ? apiCmd.slice(0, 120) : 'no stripe command found');
  const blocked = parsed.results.filter((r) => /auto mode classifier|Permission.*denied/i.test(r)).length;
  check('shell API call was not blocked by the classifier', apiCmd && blocked === 0, `${blocked} blocked tool call(s)`);
  check('shell API call reached Stripe (HTTP 401 for a fake key)', parsed.results.some((r) => /\b401\b/.test(r)) || parsed.text.some((t) => /\b401\b/.test(t)), parsed.results.filter((r) => /\b\d{3}\b/.test(r)).slice(-1)[0] || 'no status seen');
  const presence = parsed.results.map((r) => r.trim()).filter((r) => /^KF_(UN)?SET$/.test(r));
  check('secret available as env var in the Bash tool shell', presence.length > 0 && presence.every((r) => r === 'KF_SET'), presence.length ? presence.join(',') : 'no presence check ran');
  let fileOk = false, fileDetail = 'file not written';
  try { const c = fs.readFileSync(outEnv, 'utf8'); fileOk = c.trim() === `STRIPE_KEY=${needle}`; fileDetail = fileOk ? 'real value on disk' : (c.includes('{{') ? 'placeholder NOT expanded' : `unexpected content (${c.length} bytes)`); } catch (_) { /* missing */ }
  check('Write tool expanded placeholder into env file', fileOk, fileDetail);
  check('redacted tool output: no raw key in anything the model saw', !parsed.results.some((r) => r.includes(needle)) && !parsed.text.some((t) => t.includes(needle)), '');

  server.close(); checker.server.close();
  if (process.env.KEYFENCE_KEEP) log(`kept ${home}`); else { try { fs.rmSync(home, { recursive: true, force: true }); } catch (_) { /* ignore */ } }
  return { checks, ok: checks.every((c) => c.ok), transcript: parsed };
}

module.exports = { verify };
