'use strict';
// Secret detection. Two families:
//   1. Provider-specific token shapes (high confidence, no context needed).
//   2. Contextual rules: KEY=value / "key": "value" / Bearer / URL passwords,
//      where the key name tells us it's a credential.
// A false positive is cheap here: the placeholder still expands back to the real
// string at execution time, so over-matching only hides a literal from the model.

const PROVIDER_RULES = [
  // Anthropic / OpenAI
  { id: 'anthropic', kind: 'ANTHROPIC_API_KEY', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { id: 'openai-proj', kind: 'OPENAI_API_KEY', re: /\bsk-proj-[A-Za-z0-9_-]{20,}/g },
  { id: 'openai', kind: 'OPENAI_API_KEY', re: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/g },
  // Stripe-shaped (also Clerk and others use sk_live/sk_test)
  { id: 'sk-live', kind: 'SECRET_KEY_LIVE', re: /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g },
  { id: 'sk-test', kind: 'SECRET_KEY_TEST', re: /\b[sr]k_test_[A-Za-z0-9]{16,}\b/g },
  { id: 'stripe-whsec', kind: 'STRIPE_WEBHOOK_SECRET', re: /\bwhsec_[A-Za-z0-9]{24,}\b/g },
  // AWS
  { id: 'aws-akid', kind: 'AWS_ACCESS_KEY_ID', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  // GitHub / GitLab
  { id: 'github', kind: 'GITHUB_TOKEN', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: 'github-pat', kind: 'GITHUB_TOKEN', re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g },
  { id: 'gitlab', kind: 'GITLAB_TOKEN', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  // Slack / Discord
  { id: 'slack', kind: 'SLACK_TOKEN', re: /\bxox[abprse]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'slack-webhook', kind: 'SLACK_WEBHOOK', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g },
  { id: 'discord-bot', kind: 'DISCORD_TOKEN', re: /\b[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/g },
  { id: 'discord-webhook', kind: 'DISCORD_WEBHOOK', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
  // Google
  { id: 'google-api', kind: 'GOOGLE_API_KEY', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'google-oauth-secret', kind: 'GOOGLE_CLIENT_SECRET', re: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'google-oauth-token', kind: 'GOOGLE_OAUTH_TOKEN', re: /\bya29\.[A-Za-z0-9_-]{30,}\b/g },
  // Email / SMS
  { id: 'sendgrid', kind: 'SENDGRID_API_KEY', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
  { id: 'mailgun', kind: 'MAILGUN_API_KEY', re: /\bkey-[0-9a-f]{32}\b/g },
  { id: 'resend', kind: 'RESEND_API_KEY', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}\b/g },
  { id: 'twilio', kind: 'TWILIO_API_KEY', re: /\bSK[0-9a-f]{32}\b/g },
  // Package registries
  { id: 'npm', kind: 'NPM_TOKEN', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'pypi', kind: 'PYPI_TOKEN', re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g },
  // Cloud / infra
  { id: 'digitalocean', kind: 'DIGITALOCEAN_TOKEN', re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g },
  { id: 'vercel-blob', kind: 'VERCEL_BLOB_TOKEN', re: /\bvercel_blob_rw_[A-Za-z0-9_]{20,}\b/g },
  { id: 'supabase', kind: 'SUPABASE_TOKEN', re: /\bsbp_[a-f0-9]{40}\b/g },
  { id: 'cloudflare', kind: 'CLOUDFLARE_TOKEN', re: /\bcfut_[A-Za-z0-9_-]{30,}\b/g },
  { id: 'huggingface', kind: 'HF_TOKEN', re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { id: 'replicate', kind: 'REPLICATE_API_TOKEN', re: /\br8_[A-Za-z0-9]{30,}\b/g },
  { id: 'linear', kind: 'LINEAR_API_KEY', re: /\blin_api_[A-Za-z0-9]{30,}\b/g },
  { id: 'figma', kind: 'FIGMA_TOKEN', re: /\bfigd_[A-Za-z0-9_-]{30,}\b/g },
  { id: 'shopify', kind: 'SHOPIFY_TOKEN', re: /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/g },
  { id: 'square', kind: 'SQUARE_TOKEN', re: /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}\b/g },
  { id: 'notion', kind: 'NOTION_TOKEN', re: /\b(?:secret|ntn)_[A-Za-z0-9]{40,}\b/g },
  { id: 'telegram', kind: 'TELEGRAM_BOT_TOKEN', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b/g },
  { id: 'planetscale', kind: 'PLANETSCALE_TOKEN', re: /\bpscale_(?:pw|tkn|oauth)_[A-Za-z0-9_.-]{30,}\b/g },
  { id: 'datadog-app', kind: 'DATADOG_TOKEN', re: /\bdd[a-z]{0,6}_[a-f0-9]{32,}\b/g },
  // Structural
  { id: 'jwt', kind: 'JWT', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: 'pem', kind: 'PRIVATE_KEY', re: /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/g },
  // PEM as it appears inside JSON strings (escaped newlines), e.g. Firebase service accounts
  { id: 'pem-escaped', kind: 'PRIVATE_KEY', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\\\n|\\n|[^"'])*?-----END [A-Z ]*PRIVATE KEY-----/g },
];

// Key names that mean "the value next to me is a credential".
const SENSITIVE_KEY = /(secret|token|passw(?:or)?d|pwd|api[_-]?key|apikey|private[_-]?key|credential|auth(?:orization)?|access[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key|session[_-]?key|service[_-]?account|_key$|^key$|_dsn$|license)/i;
// Keys that look sensitive but are public by design.
const PUBLIC_KEY_NAME = /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)/i;
const PUBLIC_VALUE = /^(?:pk_(?:live|test)_|pk\.|phc_)/; // publishable keys (Stripe/Clerk, Mapbox, PostHog)

// Values that are obviously not real secrets.
const PLACEHOLDER_VALUE = /^(?:\$\{?[A-Z_][A-Z0-9_]*\}?$|<[^>]+>$|\[[^\]]+\]$|x{3,}$|your[_-]|changeme$|change[_-]me$|(?:example|placeholder|dummy|test|none|null|undefined|true|false)$|\.\.\.$|\*+$|process\.env\.|env\(|\{\{)/i;
const MIN_VALUE_LEN = 8;

function plausibleSecretValue(val, keyName) {
  if (!val || val.length < MIN_VALUE_LEN || val.length > 8192) return false;
  if (PLACEHOLDER_VALUE.test(val)) return false;
  if (/^\{\{KF_/.test(val)) return false;
  if (/^\d+(\.\d+)?$/.test(val)) return false; // plain numbers
  if (/^[a-z]+(?:[-_ ][a-z]+)*$/i.test(val) && !/\d/.test(val) && val.length < 16) return false; // plain words
  if (/^(?:https?|wss?):\/\/[^@]*$/i.test(val)) return false; // URL without credentials
  if (/^[./~][^\s]*$/.test(val) && !/[A-Za-z0-9]{24,}/.test(val)) return false; // file paths
  if (keyName && PUBLIC_KEY_NAME.test(keyName) && PUBLIC_VALUE.test(val)) return false;
  if (PUBLIC_VALUE.test(val)) return false;
  return true;
}

// Contextual rules return [{ start, end, value, kind }] for a text.
const ASSIGN_RE = /(^|[\s,;{(])([A-Za-z_][A-Za-z0-9_.-]{1,80})\s*(?::|=|:=|=>)\s*(?:"((?:[^"\\]|\\.){1,8192})"|'([^']{1,8192})'|`([^`]{1,8192})`|([^\s"'`,;)}&|<>]{1,8192}))/gm;
const JSONKEY_RE = /"([A-Za-z_][A-Za-z0-9_.-]{1,80})"\s*:\s*"((?:[^"\\]|\\.){1,8192})"/g;
const BEARER_RE = /\b(?:Bearer|Basic)\s+([A-Za-z0-9\-._~+/=]{16,})/g;
// Values assigned to names that are public by design (NEXT_PUBLIC_*, etc.). Provider
// hits (e.g. a Supabase anon JWT) inside these spans are not secrets.
const PUBLIC_ASSIGN_RE = /\b((?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)[A-Za-z0-9_]*)\s*(?::|=)\s*["']?([^\s"',;]{8,})/g;
function publicSpans(text) {
  const spans = [];
  PUBLIC_ASSIGN_RE.lastIndex = 0;
  let m;
  while ((m = PUBLIC_ASSIGN_RE.exec(text))) {
    if (/secret|token|private/i.test(m[1])) continue;
    const start = m.index + m[0].lastIndexOf(m[2]);
    spans.push([start, start + m[2].length]);
  }
  return spans;
}
const HEADER_RE = /\b(x-api-key|api-key|apikey|x-auth-token|x-access-token|authorization|private-token)\s*[:=]\s*["']?([A-Za-z0-9\-._~+/=]{12,})/gi;
const URL_CRED_RE = /\b[a-z][a-z0-9+.-]*:\/\/([^\s/:@"']+):([^\s/@"']{3,})@/gi;
const CLI_FLAG_RE = /(?:--?(?:token|password|passwd|pwd|api[-_]?key|secret|auth|key|access[-_]?key|client[-_]?secret)(?:=|\s+))(?:"([^"]{8,})"|'([^']{8,})'|([^\s"']{8,}))/gi;

function contextual(text) {
  const out = [];
  const push = (start, value, kind) => {
    if (value && plausibleSecretValue(value)) out.push({ start, end: start + value.length, value, kind });
  };
  let m;
  ASSIGN_RE.lastIndex = 0;
  while ((m = ASSIGN_RE.exec(text))) {
    const key = m[2];
    if (!SENSITIVE_KEY.test(key)) continue;
    if (PUBLIC_KEY_NAME.test(key) && !/secret|token|private/i.test(key)) continue;
    const val = m[3] ?? m[4] ?? m[5] ?? m[6];
    if (!val || !plausibleSecretValue(val, key)) continue;
    const start = m.index + m[0].lastIndexOf(val);
    push(start, val, key.replace(/^.*\./, ''));
  }
  JSONKEY_RE.lastIndex = 0;
  while ((m = JSONKEY_RE.exec(text))) {
    if (!SENSITIVE_KEY.test(m[1]) || !plausibleSecretValue(m[2], m[1])) continue;
    push(m.index + m[0].lastIndexOf(m[2]), m[2], m[1]);
  }
  BEARER_RE.lastIndex = 0;
  while ((m = BEARER_RE.exec(text))) push(m.index + m[0].length - m[1].length, m[1], 'BEARER_TOKEN');
  HEADER_RE.lastIndex = 0;
  while ((m = HEADER_RE.exec(text))) push(m.index + m[0].length - m[2].length, m[2], m[1].replace(/^x-/i, ''));
  URL_CRED_RE.lastIndex = 0;
  while ((m = URL_CRED_RE.exec(text))) {
    const pw = m[2];
    if (pw.length >= 3 && !PLACEHOLDER_VALUE.test(pw)) {
      const start = m.index + m[0].lastIndexOf(':' + pw + '@') + 1;
      out.push({ start, end: start + pw.length, value: pw, kind: 'URL_PASSWORD' });
    }
  }
  CLI_FLAG_RE.lastIndex = 0;
  while ((m = CLI_FLAG_RE.exec(text))) {
    const val = m[1] ?? m[2] ?? m[3];
    push(m.index + m[0].lastIndexOf(val), val, 'CLI_SECRET');
  }
  return out;
}

function providerMatches(text) {
  const out = [];
  for (const rule of PROVIDER_RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text))) {
      out.push({ start: m.index, end: m.index + m[0].length, value: m[0], kind: rule.kind, id: rule.id });
      if (m[0].length === 0) rule.re.lastIndex++;
    }
  }
  return out;
}

// All detections in a text, de-overlapped (earliest start wins; longer wins on tie).
function detect(text) {
  if (!text || text.length < MIN_VALUE_LEN) return [];
  const pub = publicSpans(text);
  const isPublic = (d) => pub.some(([s, e]) => d.start >= s && d.end <= e);
  const all = providerMatches(text).concat(contextual(text)).filter((d) => !isPublic(d));
  all.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let cursor = -1;
  for (const d of all) {
    if (d.start < cursor) continue;
    out.push(d);
    cursor = d.end;
  }
  return out;
}

module.exports = { detect, PROVIDER_RULES, plausibleSecretValue, SENSITIVE_KEY };
