'use strict';
// Claude Code hook handlers. Each reads the hook's JSON from stdin and prints JSON
// (or nothing) to stdout. They must be fast and must never throw.
const { redactDeep, expandDeep } = require('./redact');
const daemon = require('./daemon');
const { SYSTEM_NOTICE } = require('./proxy');

const EXPAND_TOOLS = new Set(['Bash', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

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

// PreToolUse: placeholders -> real values, so commands and file writes actually work.
async function preToolUse(input) {
  if (!EXPAND_TOOLS.has(input.tool_name) || !input.tool_input) return;
  const { value, changed } = expandDeep(input.tool_input);
  if (!changed) return;
  emit({ hookSpecificOutput: { hookEventName: 'PreToolUse', updatedInput: value } });
}

// PostToolUse: real values -> placeholders in what the model sees. The proxy would
// catch these anyway on the way out; doing it here keeps the local transcript clean too.
async function postToolUse(input) {
  if (input.tool_response === undefined) return;
  const { value, changed, found } = redactDeep(input.tool_response, { register: true });
  if (!changed) return;
  const fresh = [...new Set(found.filter((f) => f.fresh).map((f) => f.placeholder))];
  const out = { hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: value } };
  if (fresh.length) {
    out.hookSpecificOutput.additionalContext =
      `keyfence redacted ${fresh.length} new secret(s) from this output: ${fresh.join(' ')}. Use the placeholders verbatim where the values are needed.`;
  }
  emit(out);
}

// UserPromptSubmit: make sure the proxy is up before the request goes out, and
// pre-register anything secret-looking in the prompt so the model gets told about it.
async function userPromptSubmit(input) {
  const ensure = await daemon.ensureRunning();
  const { found } = redactDeep(input.prompt || '', { register: true });
  const phs = [...new Set(found.map((f) => f.placeholder))];
  const notes = [];
  if (!ensure.running) notes.push('WARNING: keyfence proxy failed to start; API requests may fail. Run `keyfence doctor`.');
  if (phs.length) notes.push(`keyfence: ${phs.length} secret(s) in this prompt will appear to you as placeholders: ${phs.join(' ')}. Use them verbatim.`);
  if (notes.length) emit({ hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: notes.join('\n') } });
}

async function sessionStart() {
  const ensure = await daemon.ensureRunning();
  const ctx = ensure.running ? SYSTEM_NOTICE : 'WARNING: keyfence proxy is not running and could not be started. Run `keyfence doctor`.';
  emit({ hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: ctx } });
}

const HANDLERS = { pretool: preToolUse, posttool: postToolUse, prompt: userPromptSubmit, sessionstart: sessionStart };

async function run(event) {
  const handler = HANDLERS[event];
  if (!handler) { process.stderr.write(`keyfence: unknown hook event ${event}\n`); return; }
  let input = {};
  try { input = JSON.parse((await readStdin()) || '{}'); } catch (_) { /* ignore */ }
  try { await handler(input); }
  catch (e) { process.stderr.write(`keyfence hook ${event}: ${e.message}\n`); }
}

module.exports = { run, HANDLERS, EXPAND_TOOLS };
