import { describe, it, expect } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../src/discovery.js";
import { runRules } from "../src/scanner.js";
import { ALL_RULES } from "../src/rules/index.js";
import {
  exposedSecretsRule,
  dangerousAutoApproveRule,
  suspiciousUrlsRule,
  shellInjectionRiskRule,
} from "../src/rules/index.js";
import { shannonEntropy, maskSecret } from "../src/rules/exposed-secrets.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, "fixtures");

async function loadFixture(name: string) {
  const cfg = await loadConfig(path.join(fixturesDir, name), "test");
  if (!cfg) throw new Error(`fixture missing: ${name}`);
  return cfg;
}

/**
 * Assemble realistic-looking test secrets at runtime from parts. We avoid
 * committing real-looking secret strings to the repo so GitHub's push
 * protection doesn't (correctly!) reject the push.
 */
const FAKE_STRIPE = ["sk", "live", "51HxYzABCDEFGhijklmnopqrstuvwxyz1234"].join("_");
const FAKE_GH_PAT = "ghp" + "_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";

function injectFakeSecrets(cfg: Awaited<ReturnType<typeof loadFixture>>) {
  const stripeBad = (cfg.servers as any)["stripe-bad"];
  if (stripeBad?.env) {
    if (stripeBad.env.STRIPE_KEY === "__STRIPE_LIVE_KEY_PLACEHOLDER__") {
      stripeBad.env.STRIPE_KEY = FAKE_STRIPE;
    }
    if (stripeBad.env.GITHUB_TOKEN === "__GITHUB_PAT_PLACEHOLDER__") {
      stripeBad.env.GITHUB_TOKEN = FAKE_GH_PAT;
    }
  }
  return cfg;
}

describe("exposed-secrets rule", () => {
  it("flags Stripe and GitHub tokens but not env-var placeholders", async () => {
    const cfg = injectFakeSecrets(await loadFixture("exposed-secrets.json"));
    const findings = runRules([cfg], [exposedSecretsRule]);

    const byServer = (s: string) => findings.filter((f) => f.server === s);
    expect(byServer("stripe-bad")).toHaveLength(2);
    expect(byServer("ok-server")).toHaveLength(0);

    // Evidence is masked, never contains the full secret
    for (const f of findings) {
      expect(f.evidence).toBeDefined();
      expect(f.evidence!).not.toContain(FAKE_STRIPE);
      expect(f.evidence!).not.toContain(FAKE_GH_PAT);
    }
    expect(findings.every((f) => f.severity === "critical")).toBe(true);
  });

  it("Shannon entropy and masking helpers work", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
    expect(shannonEntropy("abcdefgh")).toBeGreaterThan(2);
    expect(maskSecret("supersecretvalue123")).toMatch(/^supe…23 \(19 chars\)$/);
    expect(maskSecret("short")).toBe("***");
  });
});

describe("dangerous-auto-approve rule", () => {
  it("escalates wildcard, flags risky tool names, audits harmless lists", async () => {
    const cfg = await loadFixture("dangerous-auto-approve.json");
    const findings = runRules([cfg], [dangerousAutoApproveRule]);

    const wildcard = findings.find((f) => f.server === "wildcard-approver");
    expect(wildcard?.severity).toBe("critical");

    const risky = findings.find((f) => f.server === "risky-tools");
    expect(risky?.severity).toBe("high");
    expect(risky?.message).toMatch(/execute_shell|delete_file/);

    const harmless = findings.find((f) => f.server === "harmless-list");
    expect(harmless?.severity).toBe("medium");

    expect(findings.find((f) => f.server === "no-list")).toBeUndefined();
  });
});

describe("suspicious-urls rule", () => {
  it("flags shorteners, raw IPs, plain HTTP, and raw gists", async () => {
    const cfg = await loadFixture("suspicious-urls.json");
    const findings = runRules([cfg], [suspiciousUrlsRule]);

    expect(
      findings.find(
        (f) => f.server === "shortened" && /shortener/i.test(f.message),
      ),
    ).toBeDefined();
    expect(
      findings.find(
        (f) => f.server === "raw-ip" && /IP literal/i.test(f.message),
      ),
    ).toBeDefined();
    expect(
      findings.find(
        (f) => f.server === "raw-ip" && /non-HTTPS/i.test(f.message),
      ),
    ).toBeDefined();
    expect(
      findings.find(
        (f) => f.server === "gist" && /gist/i.test(f.message),
      ),
    ).toBeDefined();
    expect(findings.find((f) => f.server === "fine")).toBeUndefined();
  });
});

describe("shell-injection-risk rule", () => {
  it("flags bash -c, &&, |, and command substitution", async () => {
    const cfg = await loadFixture("shell-injection-risk.json");
    const findings = runRules([cfg], [shellInjectionRiskRule]);

    expect(findings.find((f) => f.server === "shell-chained")).toBeDefined();
    expect(
      findings.find(
        (f) =>
          f.server === "command-substitution" &&
          /command substitution/i.test(f.message),
      ),
    ).toBeDefined();
    expect(findings.find((f) => f.server === "clean")).toBeUndefined();
  });
});

describe("ALL_RULES exports + scanner orchestration", () => {
  it("includes the four v0.1 rules", () => {
    const ids = ALL_RULES.map((r) => r.id).sort();
    expect(ids).toEqual([
      "dangerous-auto-approve",
      "exposed-secrets",
      "shell-injection-risk",
      "suspicious-urls",
    ]);
  });

  it("runs every rule against every fixture without throwing", async () => {
    const fixtures = await Promise.all(
      [
        "exposed-secrets.json",
        "dangerous-auto-approve.json",
        "suspicious-urls.json",
        "shell-injection-risk.json",
      ].map((f) => loadFixture(f)),
    );
    expect(() => runRules(fixtures, ALL_RULES)).not.toThrow();
    const all = runRules(fixtures, ALL_RULES);
    expect(all.length).toBeGreaterThan(0);
  });
});
