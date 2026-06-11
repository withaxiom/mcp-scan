import chalk from "chalk";
import { Finding, ScanResult, Severity } from "./types.js";

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(` ${s} `),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.cyan(s),
  info: (s) => chalk.gray(s),
};

export function renderPretty(result: ScanResult): string {
  const lines: string[] = [];
  const { findings, configsScanned } = result;

  lines.push("");
  lines.push(chalk.bold.white("mcp-scan ") + chalk.gray("v0.1.0"));
  lines.push("");

  if (configsScanned.length === 0) {
    lines.push(
      chalk.yellow(
        "  No MCP configs found in standard locations. Pass --config <path> to scan a custom file.",
      ),
    );
    lines.push("");
    return lines.join("\n");
  }

  lines.push(chalk.gray(`Scanned ${configsScanned.length} config file(s):`));
  for (const cfg of configsScanned) {
    const serverCount = Object.keys(cfg.servers).length;
    lines.push(
      chalk.gray(
        `  - ${cfg.path}  ${chalk.dim(`[${cfg.client}, ${serverCount} server(s)]`)}`,
      ),
    );
  }
  lines.push("");

  if (findings.length === 0) {
    lines.push(chalk.green.bold("OK  No issues found."));
    lines.push("");
    return lines.join("\n");
  }

  // Group by file then server for readability
  const grouped = groupFindings(findings);
  for (const [file, byServer] of grouped) {
    lines.push(chalk.bold.underline(file));
    for (const [server, items] of byServer) {
      lines.push(
        chalk.bold(`  ${server === null ? "(file)" : server}`) +
          chalk.gray(`  ${items.length} finding(s)`),
      );
      for (const f of items) {
        lines.push(`    ${SEV_COLOR[f.severity](f.severity.toUpperCase())} ${chalk.bold(f.rule)}`);
        lines.push(`      ${f.message}`);
        if (f.evidence) {
          lines.push(chalk.gray(`      evidence: ${f.evidence}`));
        }
        if (f.diff) {
          lines.push(...renderDiff(f.diff, "      "));
        }
      }
      lines.push("");
    }
  }

  lines.push(summaryLine(findings));
  lines.push("");
  return lines.join("\n");
}

/**
 * Quiet report (--quiet): critical findings only, one block per finding,
 * no banner, no config inventory. Prints nothing when there are no critical
 * findings — classic quiet semantics. Exit-code gating is unaffected (it is
 * computed from the full finding set in the CLI).
 */
export function renderQuiet(result: ScanResult): string {
  const criticals = result.findings.filter((f) => f.severity === "critical");
  if (criticals.length === 0) return "";

  const lines: string[] = [];
  for (const f of criticals) {
    lines.push(
      `${SEV_COLOR.critical("CRITICAL")} ${chalk.bold(f.rule)}  ${f.file}${f.server ? chalk.gray(` :: ${f.server}`) : ""}`,
    );
    lines.push(`  ${f.message}`);
    if (f.evidence) lines.push(chalk.gray(`  evidence: ${f.evidence}`));
  }
  lines.push("");
  return lines.join("\n");
}

/**
 * Color a unified-style diff (see Finding.diff): removed lines red, added
 * lines green, context dim. Chalk handles NO_COLOR / non-TTY downgrade
 * automatically, so piped output stays plain text.
 */
function renderDiff(diff: string[], indent: string): string[] {
  const changed = diff.some((l) => l.startsWith("+ ") || l.startsWith("- "));
  if (!changed) {
    // Possible when the only change is inside a redacted (masked) value.
    return [chalk.gray(`${indent}(change is within redacted values — no visible diff)`)];
  }
  return diff.map((l) => {
    if (l.startsWith("+ ")) return chalk.green(`${indent}${l}`);
    if (l.startsWith("- ")) return chalk.red(`${indent}${l}`);
    return chalk.dim(`${indent}${l}`);
  });
}

function groupFindings(
  findings: Finding[],
): Map<string, Map<string | null, Finding[]>> {
  const out = new Map<string, Map<string | null, Finding[]>>();
  for (const f of findings) {
    let byServer = out.get(f.file);
    if (!byServer) {
      byServer = new Map();
      out.set(f.file, byServer);
    }
    let arr = byServer.get(f.server);
    if (!arr) {
      arr = [];
      byServer.set(f.server, arr);
    }
    arr.push(f);
  }
  return out;
}

function summaryLine(findings: Finding[]): string {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) counts[f.severity]++;

  const parts: string[] = [];
  if (counts.critical) parts.push(chalk.bgRed.white.bold(` ${counts.critical} CRITICAL `));
  if (counts.high) parts.push(chalk.red.bold(`${counts.high} high`));
  if (counts.medium) parts.push(chalk.yellow(`${counts.medium} medium`));
  if (counts.low) parts.push(chalk.cyan(`${counts.low} low`));
  if (counts.info) parts.push(chalk.gray(`${counts.info} info`));

  return chalk.bold(`Summary: ${findings.length} finding(s)  `) + parts.join("  ");
}

/**
 * JSON report. Compact (single-line) by default for piping into jq / log
 * aggregation; pass `pretty` (--json-pretty) for human-diffable 2-space
 * indentation. Content is identical either way.
 */
export function renderJson(result: ScanResult, pretty = false): string {
  return JSON.stringify(
    {
      version: "0.1.0",
      startedAt: result.startedAt,
      finishedAt: result.finishedAt,
      configsScanned: result.configsScanned.map((c) => ({
        path: c.path,
        client: c.client,
        serverCount: Object.keys(c.servers).length,
      })),
      findings: result.findings,
    },
    null,
    pretty ? 2 : undefined,
  );
}

/**
 * SARIF 2.1.0 output for CI integration (GitHub code scanning, etc.).
 * Minimal but valid — we emit one rule per unique rule id and one result per
 * finding.
 */
export function renderSarif(result: ScanResult): string {
  const sevToLevel: Record<Severity, "error" | "warning" | "note"> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
    info: "note",
  };

  const ruleIds = Array.from(new Set(result.findings.map((f) => f.rule)));
  const rules = ruleIds.map((id) => ({
    id,
    name: id,
    shortDescription: { text: id },
    fullDescription: { text: id },
    helpUri: `https://github.com/withaxiom/mcp-scan#${id}`,
  }));

  const results = result.findings.map((f) => ({
    ruleId: f.rule,
    level: sevToLevel[f.severity],
    message: { text: f.message + (f.evidence ? ` (${f.evidence})` : "") },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
        },
        logicalLocations: f.server
          ? [{ name: f.server, kind: "module" }]
          : undefined,
      },
    ],
    properties: { severity: f.severity, server: f.server },
  }));

  return JSON.stringify(
    {
      $schema:
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "mcp-scan",
              version: "0.1.0",
              informationUri: "https://github.com/withaxiom/mcp-scan",
              rules,
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  );
}
