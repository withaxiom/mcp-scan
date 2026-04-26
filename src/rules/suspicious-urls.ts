import { Finding, Rule, RuleContext } from "../types.js";

const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "goo.gl",
  "ow.ly",
  "t.co",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
]);

const IP_LITERAL_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const URL_RE = /\bhttps?:\/\/[^\s'"`]+/gi;
const GIST_RAW_RE = /gist\.githubusercontent\.com\/[^\/]+\/[a-f0-9]+\/raw/i;

interface UrlIssue {
  kind: string;
  url: string;
  location: string;
}

function inspect(url: string, location: string, out: UrlIssue[]): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return;
  }

  if (parsed.protocol === "http:" && !["localhost", "127.0.0.1"].includes(parsed.hostname)) {
    out.push({ kind: "non-HTTPS endpoint", url, location });
  }
  if (URL_SHORTENERS.has(parsed.hostname.toLowerCase())) {
    out.push({ kind: "URL shortener", url, location });
  }
  if (IP_LITERAL_RE.test(parsed.hostname)) {
    // Loopback is fine; flag everything else.
    if (!parsed.hostname.startsWith("127.") && parsed.hostname !== "0.0.0.0") {
      out.push({ kind: "raw IP literal", url, location });
    }
  }
  if (GIST_RAW_RE.test(url)) {
    out.push({ kind: "raw GitHub gist", url, location });
  }
}

function scanString(s: string, location: string, out: UrlIssue[]): void {
  if (typeof s !== "string") return;
  // Direct URL field (no protocol prefix needed for parsing)
  if (/^[a-z]+:\/\//i.test(s)) inspect(s, location, out);
  // URLs embedded in larger strings
  const matches = s.match(URL_RE);
  if (matches) {
    for (const m of matches) inspect(m, location, out);
  }
}

export const suspiciousUrlsRule: Rule = {
  id: "suspicious-urls",
  defaultSeverity: "medium",
  description:
    "Flags URLs in MCP configs that exhibit risky patterns: URL shorteners, raw IP literals, plain HTTP, or raw GitHub gists pulled at runtime.",

  check(ctx: RuleContext): Finding[] {
    const issues: UrlIssue[] = [];
    const { server, serverName } = ctx;

    if (typeof server.url === "string") scanString(server.url, "url", issues);
    if (typeof server.command === "string") scanString(server.command, "command", issues);
    if (Array.isArray(server.args)) {
      server.args.forEach((a, i) => scanString(String(a), `args[${i}]`, issues));
    }
    if (server.env) {
      for (const [k, v] of Object.entries(server.env)) {
        scanString(String(v), `env.${k}`, issues);
      }
    }

    return issues.map((i) => ({
      rule: suspiciousUrlsRule.id,
      severity: suspiciousUrlsRule.defaultSeverity,
      file: ctx.config.path,
      server: serverName,
      message: `Server "${serverName}" references a ${i.kind} (${i.url}). This is a common vector for MCP supply-chain attacks.`,
      evidence: `${i.location} → ${i.url}`,
    }));
  },
};
