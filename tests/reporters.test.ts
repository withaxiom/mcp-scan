import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../src/discovery.js";
import { runRules } from "../src/scanner.js";
import { ALL_RULES } from "../src/rules/index.js";
import {
  renderFooter,
  renderPretty,
  renderQuiet,
  renderJson,
  renderSarif,
} from "../src/reporters.js";
import { Finding, ScanResult } from "../src/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, "fixtures");

const FOOTER_RE = /Scanned (\d+) servers · (\d+) issues · (\d+) regressions/;

async function fixtureResult(): Promise<ScanResult> {
  const cfg = await loadConfig(
    path.join(fixturesDir, "dangerous-auto-approve.json"),
    "test",
  );
  if (!cfg) throw new Error("fixture missing");
  const findings = runRules([cfg], ALL_RULES);
  // Synthetic drift finding, as state.detectAndRecordChanges would emit it.
  const regression: Finding = {
    rule: "changed-server-config",
    severity: "medium",
    file: cfg.path,
    server: "wildcard-approver",
    message: "changed since last scan",
    evidence: "prev=aaaaaaaaaaaa now=bbbbbbbbbbbb",
  };
  return {
    findings: [...findings, regression],
    configsScanned: [cfg],
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
  };
}

describe("scan summary footer (SCN-5)", () => {
  it("reports accurate server / issue / regression counts from a fixture scan", async () => {
    const result = await fixtureResult();
    const servers = Object.keys(result.configsScanned[0].servers).length;
    const issues = result.findings.filter(
      (f) => f.rule !== "changed-server-config",
    ).length;

    const m = renderFooter(result).match(FOOTER_RE);
    expect(m).not.toBeNull();
    expect(Number(m![1])).toBe(servers);
    expect(Number(m![2])).toBe(issues);
    expect(Number(m![3])).toBe(1);
    // Sanity: issues + regressions partition the finding total.
    expect(Number(m![2]) + Number(m![3])).toBe(result.findings.length);
  });

  it("appears in pretty and quiet output, never in JSON/SARIF", async () => {
    const result = await fixtureResult();
    expect(renderPretty(result)).toMatch(FOOTER_RE);
    expect(renderQuiet(result)).toMatch(FOOTER_RE);
    expect(renderJson(result)).not.toMatch(FOOTER_RE);
    expect(renderJson(result, true)).not.toMatch(FOOTER_RE);
    expect(renderSarif(result)).not.toMatch(FOOTER_RE);
    // JSON stays valid JSON.
    expect(() => JSON.parse(renderJson(result))).not.toThrow();
  });

  it("shows zero counts on an empty scan (footer after every scan)", () => {
    const empty: ScanResult = {
      findings: [],
      configsScanned: [],
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
    };
    expect(renderFooter(empty)).toMatch(/Scanned 0 servers · 0 issues · 0 regressions/);
    expect(renderPretty(empty)).toMatch(FOOTER_RE);
    expect(renderQuiet(empty)).toMatch(FOOTER_RE);
  });
});
