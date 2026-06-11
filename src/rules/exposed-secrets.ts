import { Finding, Rule, RuleContext } from "../types.js";

/**
 * Patterns for well-known secret formats. Order matters only insofar as we
 * report the first match — we don't double-flag the same string.
 */
const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "Stripe live key", re: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
  { name: "Stripe test key", re: /\bsk_test_[A-Za-z0-9]{16,}\b/ },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/ },
  { name: "OpenAI API key", re: /\bsk-[A-Za-z0-9]{32,}\b/ },
  { name: "Slack bot token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "GitHub PAT", re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: "GitHub OAuth token", re: /\bgho_[A-Za-z0-9]{36}\b/ },
  { name: "GitHub fine-grained token", re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/ },
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

/** Names that are meant to look like secrets but aren't (env-var references). */
const PLACEHOLDER_RE = /^\$\{?[A-Z0-9_]+\}?$|^<[^>]+>$|^YOUR_.*_HERE$|^xxx+$|^changeme$/i;

/**
 * Shannon entropy in bits/char. Useful proxy for "looks like a base64/hex token"
 * vs. "looks like English."
 */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts: Record<string, number> = {};
  for (const ch of s) counts[ch] = (counts[ch] ?? 0) + 1;
  let h = 0;
  const n = s.length;
  for (const c of Object.values(counts)) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Mask a secret for display. Keep just enough context to be useful in triage
 * without leaking the value.
 */
export function maskSecret(value: string): string {
  if (value.length <= 8) return "***";
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`;
}

/**
 * Return a masked form of `value` when it looks like a secret (known token
 * format or the same high-entropy heuristic the exposed-secrets rule uses),
 * otherwise the original string. Used when persisting redacted config
 * snapshots for drift diffs — anything the rule would flag never lands on
 * disk or in diff output in full.
 */
export function redactIfSecret(value: string): string {
  if (!value || PLACEHOLDER_RE.test(value.trim())) return value;
  for (const { re } of SECRET_PATTERNS) {
    if (re.test(value)) return maskSecret(value);
  }
  const trimmed = value.trim();
  if (
    trimmed.length >= 30 &&
    !/\s/.test(trimmed) &&
    !trimmed.includes("/") &&
    shannonEntropy(trimmed) >= 4.0
  ) {
    return maskSecret(value);
  }
  return value;
}

interface Hit {
  pattern: string;
  masked: string;
  location: string;
}

function inspectString(value: string, location: string, hits: Hit[]): void {
  if (typeof value !== "string" || !value) return;
  if (PLACEHOLDER_RE.test(value.trim())) return;

  for (const { name, re } of SECRET_PATTERNS) {
    const m = value.match(re);
    if (m) {
      hits.push({ pattern: name, masked: maskSecret(m[0]), location });
      return;
    }
  }
  // Generic high-entropy heuristic for tokens we don't have a regex for.
  // Threshold tuned to avoid flagging long file paths and URLs while catching
  // typical 32+ char base64/hex secrets.
  const trimmed = value.trim();
  if (trimmed.length >= 30 && !/\s/.test(trimmed) && !trimmed.includes("/")) {
    const h = shannonEntropy(trimmed);
    if (h >= 4.0) {
      hits.push({
        pattern: "high-entropy string",
        masked: maskSecret(trimmed),
        location,
      });
    }
  }
}

export const exposedSecretsRule: Rule = {
  id: "exposed-secrets",
  defaultSeverity: "critical",
  description:
    "Detects credentials embedded in MCP server configs (env blocks, command args, URLs). Inline secrets cannot be rotated without editing the config and are leaked to anyone with read access to the file.",

  check(ctx: RuleContext): Finding[] {
    const hits: Hit[] = [];
    const { server, serverName } = ctx;

    if (server.env) {
      for (const [k, v] of Object.entries(server.env)) {
        inspectString(String(v), `env.${k}`, hits);
      }
    }
    if (Array.isArray(server.args)) {
      server.args.forEach((arg, i) => {
        inspectString(String(arg), `args[${i}]`, hits);
      });
    }
    if (typeof server.url === "string") {
      inspectString(server.url, "url", hits);
    }
    if (typeof server.command === "string") {
      inspectString(server.command, "command", hits);
    }

    return hits.map((h) => ({
      rule: exposedSecretsRule.id,
      severity: exposedSecretsRule.defaultSeverity,
      file: ctx.config.path,
      server: serverName,
      message: `Likely ${h.pattern} embedded in ${h.location}. Move to a secret manager and reference via env-var indirection.`,
      evidence: `${h.location} = ${h.masked}`,
    }));
  },
};
