import { discoverConfigs } from "./discovery.js";
import { detectAndRecordChanges } from "./state.js";
import { ALL_RULES } from "./rules/index.js";
import {
  DiscoveredConfig,
  Finding,
  Rule,
  ScanResult,
  SEVERITY_RANK,
} from "./types.js";

export interface ScanOptions {
  /** Extra config paths to scan (in addition to standard locations). */
  configPaths?: string[];
  /** Override the default rule set. */
  rules?: Rule[];
  /** Override the state directory (used by tests). */
  stateDir?: string;
  /** Skip the on-disk state update (used by tests). */
  noState?: boolean;
}

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const rules = options.rules ?? ALL_RULES;
  const configs = await discoverConfigs(options.configPaths ?? []);
  const findings = runRules(configs, rules);

  // Rug-pull / drift detection runs as a special-case "rule" because it's
  // stateful — it reads/writes ~/.mcp-scan/state.json.
  const driftFindings = await detectAndRecordChanges(configs, {
    dir: options.stateDir,
    dryRun: options.noState,
  });
  findings.push(...driftFindings);

  // Deterministic order: severity desc, then file, then server, then rule.
  findings.sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    if ((a.server ?? "") !== (b.server ?? ""))
      return (a.server ?? "").localeCompare(b.server ?? "");
    return a.rule.localeCompare(b.rule);
  });

  return {
    findings,
    configsScanned: configs,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

export function runRules(
  configs: DiscoveredConfig[],
  rules: Rule[],
): Finding[] {
  const findings: Finding[] = [];
  for (const cfg of configs) {
    for (const [serverName, server] of Object.entries(cfg.servers)) {
      for (const rule of rules) {
        try {
          const out = rule.check({ config: cfg, serverName, server });
          findings.push(...out);
        } catch (err) {
          findings.push({
            rule: rule.id,
            severity: "low",
            file: cfg.path,
            server: serverName,
            message: `Rule "${rule.id}" threw while scanning: ${(err as Error).message}`,
          });
        }
      }
    }
  }
  return findings;
}

/** True if any finding warrants a non-zero exit code (Snyk-style gating). */
export function hasGatingFindings(findings: Finding[]): boolean {
  return findings.some(
    (f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high,
  );
}
