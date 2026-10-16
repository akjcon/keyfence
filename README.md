# keyfence

If you paste an API key into Claude Code, or a command prints one, that key goes into the transcript and gets sent to the model provider. keyfence stops it from leaving your machine. A small local proxy sits between Claude Code and the API and swaps every secret it finds for a placeholder like `{{KF_STRIPE_SECRET_KEY_1a2b3c4d}}`. When Claude runs a command or writes a file that uses a placeholder, Claude Code hooks put the real value back just before it runs. The model only ever sees placeholders and your commands still work, so you don't have to change how you use Claude Code.

## Install

```sh
npm i -g keyfence && keyfence install
# or, without a global install
npx keyfence install
```

Then restart any open Claude Code sessions.

`install` copies keyfence to `~/.keyfence/app`, so hooks keep working even if the npx cache is cleared. It also edits `~/.claude/settings.json` and starts the proxy. You can run it again to upgrade.

Options: `--port N` (default `47117`) and `--upstream URL` (default `https://api.anthropic.com`).

## How it works

```
 Claude Code                keyfence proxy                 upstream
 ───────────   HTTP    ┌────────────────────────┐  HTTPS   ─────────────────
  requests  ─────────▶ │ 127.0.0.1:47117        │ ───────▶ api.anthropic.com
            ◀───────── │ redact JSON bodies     │ ◀─────── (or your gateway)
  responses  untouched │ add KEYFENCE: notice   │
                       └───────────┬────────────┘
                                   │
                         ~/.keyfence/vault.json
                       (placeholder -> real value)
```

`install` sets `env.ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`, so every Claude Code API request goes through the proxy. For each JSON request body, the proxy:

1. Walks every string (messages, tool results, system prompt, and so on).
2. Replaces values already in the vault, including their base64, base64url, URL-encoded and JSON-escaped forms.
3. Detects new secrets, saves them to the vault and replaces them.
4. Adds a short system note, starting with `KEYFENCE:`, telling the model that placeholders are expected and should be used as-is.

Responses come back unchanged. gzip, deflate and brotli request bodies are supported.

Placeholders are deterministic: each one is an HMAC of the value with a salt unique to your install. The same secret always gets the same placeholder, so prompt caching keeps working.

Four hooks are added to `settings.json`:

| Hook               | What it does |
|--------------------|--------------|
| `SessionStart`     | Starts the proxy if it isn't running and tells the model about placeholders. |
| `UserPromptSubmit` | Makes sure the proxy is up before the request goes out. Saves any secrets in your prompt to the vault and tells the model which placeholders it will see. |
| `PreToolUse`       | For `Bash`, `Write`, `Edit`, `MultiEdit` and `NotebookEdit`, replaces `{{KF_...}}`, `${KF_...}` and `$KF_...` with the real values so the command or file write uses the actual secret. |
| `PostToolUse`      | Replaces secrets in tool output (`cat .env`, `printenv`, ...) with placeholders before the model sees it, and saves new ones. |

## What it catches

**Provider token formats** (matched without any surrounding context):

- Anthropic (`sk-ant-`), OpenAI (`sk-proj-`, legacy `sk-...T3BlbkFJ...`)
- Stripe-style `sk_live_` / `sk_test_` / `rk_live_`, Stripe webhook `whsec_`
- AWS access key IDs (`AKIA`, `ASIA`, `ABIA`, `ACCA`)
- GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab (`glpat-`)
- Slack tokens (`xoxb-`, `xoxp-`, ...) and webhook URLs, Discord bot tokens and webhook URLs
- Google API keys (`AIza`), OAuth client secrets (`GOCSPX-`), OAuth access tokens (`ya29.`)
- SendGrid, Mailgun, Resend, Twilio
- npm, PyPI
- DigitalOcean, Vercel Blob, Supabase, Cloudflare, Hugging Face, Replicate, Linear, Figma, Shopify, Square, Notion, Telegram bots, PlanetScale, Datadog
- JWTs (`eyJ...eyJ...sig`)
- PEM private key blocks, including the `\n`-escaped form found inside JSON files such as service-account keys

**Contextual rules** (where the name next to a value marks it as a credential):

- Assignments in env files, YAML and code: `DB_PASSWORD=...`, `apiKey: "..."`, `secret := ...`, `token => ...`. A name counts as sensitive if it contains words like secret, token, password, api key, private key, credential, auth, access key, client secret, signing or encryption key, DSN or license.
- JSON keys: `"client_secret": "..."`
- `Authorization: Bearer ...` / `Basic ...` / `Token ...`, and headers like `x-api-key:`, `private-token:`
- Passwords in URLs: `postgres://user:PASSWORD@host`
- CLI flags: `--token X`, `--password=X`, `--api-key X`, `--secret`, `--auth`, `--key`, `--client-secret` (single or double dash)

Once a value is in the vault, it is replaced wherever it appears, even with no context around it.

## What it deliberately ignores

- Keys that are public by design: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` and similar when the value is a publishable key (`pk_live_`, `pk_test_`, Mapbox `pk.`, PostHog `phc_`)
- Plain numbers and short plain words: `PORT=3000`, `NODE_ENV=production`
- Values shorter than 8 characters, which covers short commit hashes
- URLs without credentials, and file paths
- Values that look like placeholders: `changeme`, `<your-key>`, `your_key_here`, `xxx`, `${VAR}`, `process.env.X`, `env(...)`, `...`, `***`
- Existing `{{KF_...}}` placeholders

## Commands

| Command | What it does |
|---|---|
| `keyfence install [--port N] [--upstream URL]` | Wire into Claude Code and start the proxy |
| `keyfence uninstall` | Remove the hooks and base URL and stop the proxy. The vault is kept. |
| `keyfence status` | Whether it is installed, proxy health, request/redaction counts, vault size |
| `keyfence doctor` | Check settings, the hook entry point, the proxy and upstream reachability. Tries to start the proxy if it is down. |
| `keyfence list` | List vault placeholders with kind and length (never the values) |
| `keyfence forget <placeholder>` | Remove one secret from the vault |
| `keyfence test 'text'` | Dry run: show how text would be redacted, without saving anything. Reads stdin if no text is given. Add `--register` to save the results. |
| `keyfence start` / `stop` / `restart` | Control the background proxy |
| `keyfence proxy` | Run the proxy in the foreground |
| `keyfence hook <event>` | Entry point used by the Claude Code hooks |

## Where things live

| Path | Contents |
|---|---|
| `~/.keyfence/vault.json` | Placeholder to real value map. Mode `0600`, directory `0700`. |
| `~/.keyfence/salt` | Per-install HMAC salt used to generate placeholders (`0600`) |
| `~/.keyfence/config.json` | `port`, `upstream`, `systemNotice` |
| `~/.keyfence/proxy.log` | Proxy log. Contains placeholders, never values. |
| `~/.keyfence/proxy.pid` | PID of the background proxy |
| `~/.keyfence/app/` | The installed copy that the hooks and daemon run |
| `~/.claude/settings.json` | Gets `env.ANTHROPIC_BASE_URL` and the four hooks. Before each write, the previous file is copied to `settings.json.keyfence-backup`. |

`KEYFENCE_HOME` overrides `~/.keyfence`. `CLAUDE_CONFIG_DIR` overrides `~/.claude`.

## Using it with an existing gateway

If `ANTHROPIC_BASE_URL` already points somewhere other than localhost (a corporate gateway, LiteLLM, Bedrock or Vertex shim, and so on), `install` keeps that URL as keyfence's upstream and puts the proxy in front of it. To set it explicitly:

```sh
keyfence install --upstream https://llm-gateway.internal.example.com/anthropic
```

The URL path is kept, so `/v1/messages` is forwarded to `<upstream>/v1/messages`. `uninstall` sets `ANTHROPIC_BASE_URL` back to that upstream.

## Limitations and honest caveats

- **The local transcript still has the raw text.** Claude Code writes your prompt to `~/.claude/projects/...` before the proxy sees the request. The `PostToolUse` hook keeps tool output clean, but a secret you type or paste yourself is on local disk. keyfence protects what leaves the machine, not what is stored on it.
- **The vault is plaintext.** Secrets in `~/.keyfence/vault.json` are protected only by `0600` file permissions. That's the same trust level as `~/.aws/credentials` or a `.env` file: anything running as your user can read it.
- **Detection is pattern-based.** A secret with an unrecognized format and no clue nearby (for example, a random string pasted on its own line) can slip through. Run `keyfence test 'your text'` to see what would be caught. Once a value is in the vault, it is caught everywhere.
- **False positives are harmless.** If something that isn't a secret gets replaced, the placeholder still expands back to the original string when commands run or files are written. The model just sees a placeholder instead of the literal.
- **Only JSON request bodies are redacted.** Responses and non-JSON uploads pass through unchanged.
- **If the proxy is down, Claude Code requests fail**, because `ANTHROPIC_BASE_URL` points at it. The hooks restart it at session start and on each prompt. If it still won't start, run `keyfence doctor`.
- **Platforms:** macOS, Linux and Windows. Node 18 or newer, no dependencies.

## Uninstall

```sh
keyfence uninstall          # removes our hooks and base URL, stops the proxy
npm rm -g keyfence          # if installed globally
rm -rf ~/.keyfence          # optional: deletes the vault, salt, config and logs
```

`uninstall` removes only keyfence's own hook groups and leaves your other hooks and settings alone. If you had a gateway URL before installing, it is restored.

## Development

```sh
npm test    # node:test, no dependencies
```

Tests use temporary `KEYFENCE_HOME` and `CLAUDE_CONFIG_DIR` directories and never touch your real `~/.keyfence` or `~/.claude`. Set `KEYFENCE_TEST_TMP` to choose where those directories are created.

## License

MIT
