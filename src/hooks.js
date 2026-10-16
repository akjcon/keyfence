'use strict';
// Claude Code hook handlers. Each reads the hook's JSON from stdin and prints JSON
// (or nothing) to stdout. They must be fast and must never throw.
//
// Design: secrets reach shell commands as real environment variables (KF_NAME_hash),
// never as text spliced into the command string. Claude Code's CLAUDE_ENV_FILE
// persists exports into later Bash tool calls; SessionStart writes it and registers
// the vault as a watch path so FileChanged re-exports when a new secret is captured.
const fs = require('fs');
const { redactDeep, expandDeep } = require('./redact');
const vault = require('./vault');
const daemon = require('./daemon');
const { paths } = require('./paths');
const { SYSTEM_NOTICE } = require('./proxy');

// Text expansion is only for file contents, where no env var can help.
const EXPAND_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(data));
    setTimeout(() => resolve(data), 3000).unref();
  });
}

function emit(obj) { process.stdout.write(JSON.stringify(obj)); }

function shellQuote(s) { return `'${String(s).replace(/'/g, `'\\''`)}'`; }

// Append `export KF_X=...` for every vault entry to CLAUDE_ENV_FILE. Returns count.
function exportEnv() {
  const file = process.env.CLAUDE_ENV_FILE;
  if (!file) return 0;
  const lines = vault.entries().map((e) => `export ${e.placeholder.slice(2, -2)}=${shellQuote(e.value)}`);
  if (!lines.length) return 0;
  fs.appendFileSync(file, lines.join('\n') + '\n');
  return lines.length;
}

// PreToolUse: for file-writing tools only, {{KF_X}} -> real value in the content.
async function preToolUse(input) {
  if (!EXPAND_TOOLS.has(input.tool_name) || !input.tool_input) return;
  const { value, changed } = expandDeep(input.tool_input);
  if (!changed) return;
  emit({ hookSpecificOutput: { hookEventName: 'PreToolUse', updatedInput: value } });
}

// PostToolUse: real values -> placeholders in what the model sees.
async function postToolUse(input) {
  if (input.tool_response === undefined) return;
  const { value, changed, found } = redactDeep(input.tool_response, { register: true });
  if (!changed) return;
  const fresh = [...new Set(found.filter((f) => f.fresh).map((f) => f.placeholder))];
  const out = { hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: value } };
  if (fresh.length) {
    out.hookSpecificOutput.additionalContext =
      `keyfence redacted ${fresh.length} new secret(s) from this output: ${fresh.join(' ')}. ` +
      `Each is available in shell commands as an env var of the same name, e.g. $${fresh[0].slice(2, -2)}.`;
  }
  emit(out);
}

// UserPromptSubmit: ensure the proxy is up; pre-register secrets in the prompt so the
// vault watcher exports them before the model's first command.
async function userPromptSubmit(input) {
  const ensure = await daemon.ensureRunning();
  const { found } = redactDeep(input.prompt || '', { register: true });
  const phs = [...new Set(found.map((f) => f.placeholder))];
  const notes = [];
  if (!ensure.running) notes.push('WARNING: keyfence proxy failed to start; API requests may fail. Run `keyfence doctor`.');
  if (phs.length) {
    notes.push(`keyfence: ${phs.length} secret(s) in this prompt appear to you as placeholders: ${phs.join(' ')}. ` +
      `In shell commands use them as env vars: ${phs.map((p) => '$' + p.slice(2, -2)).join(' ')}.`);
  }
  if (notes.length) emit({ hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: notes.join('\n') } });
}

async function sessionStart() {
  const ensure = await daemon.ensureRunning();
  const n = exportEnv();
  const ctx = ensure.running
    ? SYSTEM_NOTICE + (n ? ` (${n} secret(s) currently exported.)` : '')
    : 'WARNING: keyfence proxy is not running and could not be started. Run `keyfence doctor`.';
  emit({ hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: ctx, watchPaths: [paths.vault] } });
}

// FileChanged (vault.json) and CwdChanged (Claude Code clears env on cd): re-export.
async function reexport() {
  exportEnv();
}

const HANDLERS = {
  pretool: preToolUse, posttool: postToolUse, prompt: userPromptSubmit,
  sessionstart: sessionStart, filechanged: reexport, cwdchanged: reexport,
};

async function run(event) {
  const handler = HANDLERS[event];
  if (!handler) { process.stderr.write(`keyfence: unknown hook event ${event}\n`); return; }
  let input = {};
  try { input = JSON.parse((await readStdin()) || '{}'); } catch (_) { /* ignore */ }
  try { await handler(input); }
  catch (e) { process.stderr.write(`keyfence hook ${event}: ${e.message}\n`); }
}

module.exports = { run, HANDLERS, EXPAND_TOOLS, exportEnv };
