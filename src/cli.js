'use strict';
const fs = require('fs');
const { paths } = require('./paths');
const config = require('./config');
const vault = require('./vault');
const daemon = require('./daemon');
const { redactText } = require('./redact');

const HELP = `keyfence — secrets never leave your machine (for Claude Code)

  keyfence install [--port N] [--upstream URL]   wire into Claude Code and start the proxy
  keyfence uninstall                             remove hooks + base URL, stop proxy (vault is kept)
  keyfence status                                proxy health, counts, config
  keyfence doctor                                diagnose a broken setup
  keyfence verify [--model M] [--permission-mode auto]   live end-to-end test (fake key, real API, real classifier)
  keyfence list                                  placeholders in the vault (never values)
  keyfence forget <placeholder>                  remove one secret from the vault
  keyfence test [text]                           show how text would be redacted (dry run)
  keyfence start | stop | restart                control the proxy daemon
  keyfence proxy                                 run the proxy in the foreground
  keyfence hook <event>                          (used by Claude Code hooks)
`;

function arg(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
const out = (s) => process.stdout.write(s + '\n');

async function main(args) {
  const cmd = args[0] || 'help';
  switch (cmd) {
    case 'help': case '--help': case '-h': out(HELP); return;
    case 'version': case '--version': case '-v': out(require('../package.json').version); return;

    case 'hook': return require('./hooks').run(args[1]);

    case 'proxy': {
      const { cfg } = await require('./proxy').start();
      if (!process.env.KEYFENCE_DAEMON) out(`keyfence proxy listening on http://127.0.0.1:${cfg.port} -> ${cfg.upstream}`);
      return new Promise(() => {});
    }

    case 'install': {
      const { install } = require('./install');
      const { cfg, entry, zdot, bashShim } = install({ port: arg(args, '--port'), upstream: arg(args, '--upstream') });
      await daemon.stop();
      const r = await daemon.ensureRunning();
      out('keyfence installed.');
      out(`  proxy      http://127.0.0.1:${cfg.port} -> ${cfg.upstream}  (${r.running ? 'running' : 'FAILED TO START'})`);
      out(`  hooks      ${entry}`);
      out(`  settings   ${paths.claudeSettings}  (backup: settings.json.keyfence-backup)`);
      out(`  vault      ${paths.vault}`);
      out(`  shell      ZDOTDIR=${zdot} (zsh), BASH_ENV=${bashShim} (bash); set only for Claude Code, no dotfiles edited`);
      out('\nRestart any open Claude Code sessions. Paste keys freely; the model only ever sees placeholders.');
      return;
    }

    case 'uninstall': {
      const { uninstall } = require('./install');
      await uninstall();
      out(`keyfence removed from Claude Code. Vault kept at ${paths.vault} (delete it yourself if you want).`);
      return;
    }

    case 'start': { const r = await daemon.ensureRunning(); out(r.running ? (r.started ? 'started' : 'already running') : 'failed to start; see ' + paths.log); return; }
    case 'stop': { out((await daemon.stop()) ? 'stopped' : 'not running'); return; }
    case 'restart': { await daemon.stop(); const r = await daemon.ensureRunning(); out(r.running ? 'restarted' : 'failed to start; see ' + paths.log); return; }

    case 'status': {
      const cfg = config.load();
      const s = await daemon.status(cfg.port);
      const { isInstalled } = require('./install');
      out(`installed in Claude Code: ${isInstalled() ? 'yes' : 'no'}`);
      out(`proxy: ${s ? `running (pid ${s.pid}) on 127.0.0.1:${cfg.port} -> ${s.upstream}` : `NOT running (expected on 127.0.0.1:${cfg.port})`}`);
      if (s) out(`requests: ${s.requests}   redactions: ${s.redactions}   new secrets this run: ${s.fresh}   errors: ${s.errors}`);
      out(`vault: ${vault.entries().length} secret(s) at ${paths.vault}`);
      return;
    }

    case 'verify': {
      const { verify } = require('./verify');
      const model = arg(args, '--model') || 'haiku';
      const permissionMode = arg(args, '--permission-mode') || 'auto';
      out('keyfence verify: end-to-end test with a fake key, a throwaway vault, the real API and the real classifier.');
      const r = await verify({ model, permissionMode, log: out });
      out('');
      for (const c of r.checks) out(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
      out('');
      out(r.ok ? 'All checks passed.' : 'Some checks FAILED. Run with --show-transcript to see what the model did.');
      if (args.includes('--show-transcript')) {
        out('\n--- bash commands:'); r.transcript.bash.forEach((c) => out('  ' + c));
        out('--- tool results:'); r.transcript.results.forEach((c) => out('  ' + c.replace(/\n/g, ' ').slice(0, 300)));
        out('--- model text:'); r.transcript.text.forEach((c) => out('  ' + c.replace(/\n/g, ' ').slice(0, 500)));
      }
      if (!r.ok) process.exitCode = 1;
      return;
    }

    case 'doctor': {
      const cfg = config.load();
      const { readSettings, isInstalled } = require('./install');
      const problems = [];
      const s = readSettings();
      const base = s.env && s.env.ANTHROPIC_BASE_URL;
      out(`node: ${process.version} (${process.execPath})`);
      out(`settings: ${paths.claudeSettings}`);
      out(`  env.ANTHROPIC_BASE_URL = ${base || '(unset)'}`);
      if (base !== `http://127.0.0.1:${cfg.port}`) problems.push(`ANTHROPIC_BASE_URL should be http://127.0.0.1:${cfg.port}; run \`keyfence install\``);
      if (!isInstalled()) problems.push('hooks not found in settings; run `keyfence install`');
      const entry = daemon.entryPoint();
      out(`entry: ${entry} ${fs.existsSync(entry) ? '(ok)' : '(MISSING)'}`);
      if (!fs.existsSync(entry)) problems.push('installed copy missing; run `keyfence install`');
      // Hooks hard-code the node binary that ran install; detect a moved/upgraded node.
      const hookCmds = Object.values(s.hooks || {}).flat().flatMap((g) => (g && g.hooks) || []).map((h) => String(h.command || '')).filter((c) => c.includes('keyfence.js hook'));
      const nodeBin = hookCmds.length ? (hookCmds[0].match(/^"([^"]+)"|^(\S+)/) || []).slice(1).find(Boolean) : null;
      if (nodeBin && !fs.existsSync(nodeBin)) problems.push(`hooks point at a node binary that no longer exists (${nodeBin}); run \`keyfence install\` again`);
      const st = await daemon.status(cfg.port);
      out(`proxy: ${st ? 'running' : 'not running'}`);
      if (!st) {
        const r = await daemon.ensureRunning();
        out(`  tried to start: ${r.running ? 'ok' : 'FAILED'}`);
        if (!r.running) problems.push(`proxy will not start; check ${paths.log}`);
      }
      try {
        const u = new URL(cfg.upstream);
        await new Promise((resolve, reject) => {
          const mod = u.protocol === 'https:' ? require('https') : require('http');
          const req = mod.request({ host: u.hostname, port: u.port || undefined, path: '/', method: 'HEAD', timeout: 5000 }, (res) => { res.resume(); resolve(); });
          req.on('error', reject); req.on('timeout', () => reject(new Error('timeout'))); req.end();
        });
        out(`upstream ${cfg.upstream}: reachable`);
      } catch (e) { problems.push(`upstream ${cfg.upstream} unreachable: ${e.message}`); }
      out(problems.length ? `\nPROBLEMS:\n  - ${problems.join('\n  - ')}` : '\nAll good.');
      if (problems.length) process.exitCode = 1;
      return;
    }

    case 'list': {
      const es = vault.entries().sort((a, b) => String(a.created).localeCompare(String(b.created)));
      if (!es.length) return out('vault is empty');
      for (const e of es) out(`${e.placeholder}\t${e.kind}\tlen=${e.value.length}\t${e.created || ''}`);
      return;
    }

    case 'forget': {
      const ph = args[1];
      if (!ph) throw new Error('usage: keyfence forget <placeholder>');
      out(vault.remove(ph) ? `removed ${ph}` : `not found: ${ph}`);
      return;
    }

    case 'test': {
      const register = args.includes('--register');
      const text = args.slice(1).filter((a) => a !== '--register').join(' ') || fs.readFileSync(0, 'utf8');
      if (register) {
        const r = redactText(text, { register: true });
        out(r.text);
        out(`\n-- ${r.found.length} redaction(s)`);
      } else {
        // Dry run: show detections without storing anything.
        const { detect } = require('./detect');
        const known = redactText(text, { register: false });
        const hits = detect(known.text);
        let s = known.text;
        for (const h of [...hits].reverse()) s = s.slice(0, h.start) + vault.placeholderFor(h.kind, h.value) + s.slice(h.end);
        out(s);
        out(`\n-- ${hits.length + known.found.length} detection(s): ${[...known.found.map((f) => f.kind), ...hits.map((h) => h.kind)].join(', ') || 'none'}`);
      }
      return;
    }

    default:
      out(HELP);
      throw new Error(`unknown command: ${cmd}`);
  }
}

module.exports = { main };
