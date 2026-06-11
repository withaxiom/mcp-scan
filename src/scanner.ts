import { discoverConfigs } from "./discovery.js";
import { detectAndRecordChanges } from "./state.js";
import { ALL_RULES } from "./rules/index.js";
import {
  DiscoveredConfig,
  Finding,
  Rule,
  ScanLogger,
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
  /** Verbose diagnostics sink (--verbose). Never affects scan results. */
  log?: ScanLogger;
}

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const { log } = options;
  const t0 = performance.now();
  const rules = options.rules ?? ALL_RULES;

  const configs = await discoverConfigs(options.configPaths ?? [], log);
  const tDiscovery = performance.now();
  log?.(
    `discovery: ${configs.length} config(s) loaded in ${(tDiscovery - t0).toFixed(1)}ms`,
  );

  const findings = runRules(configs, rules, log);
  const tRules = performance.now();
  log?.(
    `rules: ${rules.length} rule(s) over ${countServers(configs)} server(s) in ${(tRules - tDiscovery).toFixed(1)}ms`,
  );

  // Rug-pull / drift detection runs as a special-case "rule" because it's
  // stateful — it reads/writes ~/.mcp-scan/state.json.
  const driftFindings = await detectAndRecordChanges(configs, {
    dir: options.stateDir,
    dryRun: options.noState,
  });
  const tDrift = performance.now();
  log?.(
    `drift: ${driftFindings.length} changed server(s) in ${(tDrift - tRules).toFixed(1)}ms`,
  );
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

  log?.(`scan: ${findings.length} finding(s) total in ${(performance.now() - t0).toFixed(1)}ms`);

  return {
    findings,
    configsScanned: configs,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

function countServers(configs: DiscoveredConfig[]): number {
  return configs.reduce((n, c) => n + Object.keys(c.servers).length, 0);
}

export function runRules(
  configs: DiscoveredConfig[],
  rules: Rule[],
  log?: ScanLogger,
): Finding[] {
  const findings: Finding[] = [];
  // Per-rule progress accounting for --verbose. Aggregated across all
  // configs/servers so the log stays readable on large setups.
  const perRule = new Map<string, { ms: number; findings: number }>();

  for (const cfg of configs) {
    for (const [serverName, server] of Object.entries(cfg.servers)) {
      for (const rule of rules) {
        const ruleStart = log ? performance.now() : 0;
        let produced = 0;
        try {
          const out = rule.check({ config: cfg, serverName, server });
          produced = out.length;
          findings.push(...out);
        } catch (err) {
          produced = 1;
          findings.push({
            rule: rule.id,
            severity: "low",
            file: cfg.path,
            server: serverName,
            message: `Rule "${rule.id}" threw while scanning: ${(err as Error).message}`,
          });
        }
        if (log) {
          const agg = perRule.get(rule.id) ?? { ms: 0, findings: 0 };
          agg.ms += performance.now() - ruleStart;
          agg.findings += produced;
          perRule.set(rule.id, agg);
        }
      }
    }
  }

  if (log) {
    for (const rule of rules) {
      const agg = perRule.get(rule.id);
      if (agg) {
        log(`rule ${rule.id}: ${agg.findings} finding(s) in ${agg.ms.toFixed(1)}ms`);
      } else {
        log(`rule ${rule.id}: not evaluated (no servers discovered)`);
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
