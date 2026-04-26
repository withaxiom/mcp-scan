import { Finding, Rule, RuleContext } from "../types.js";

/**
 * Heuristic patterns that indicate the value is being interpreted by a shell
 * (rather than exec'd directly with argv). MCP servers should always be
 * launched with `command` + `args` separately so arguments are not subject
 * to word-splitting or expansion.
 */
const SHELL_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "command chaining (&&)", re: /&&/ },
  { name: "command chaining (||)", re: /\|\|/ },
  { name: "command chaining (;)", re: /;\s*\S/ },
  { name: "pipe (|)", re: /(?<![|])\|(?![|])/ },
  { name: "command substitution $( )", re: /\$\([^)]*\)/ },
  { name: "command substitution backticks", re: /`[^`]+`/ },
  { name: "redirection", re: /(^|\s)(>>?|<<?)\s*\S/ },
  { name: "background operator (&)", re: /\s&\s*$/ },
];

/** Common shells, when used as `command`, suggest the real payload is in args. */
const SHELL_BINARIES = new Set(["sh", "bash", "zsh", "ksh", "dash", "fish", "/bin/sh", "/bin/bash", "/usr/bin/env"]);

function scan(value: string, location: string): { name: string; snippet: string }[] {
  const hits: { name: string; snippet: string }[] = [];
  for (const { name, re } of SHELL_PATTERNS) {
    const m = value.match(re);
    if (m) {
      const idx = m.index ?? 0;
      const start = Math.max(0, idx - 10);
      const end = Math.min(value.length, idx + (m[0]?.length ?? 1) + 10);
      hits.push({ name, snippet: `…${value.slice(start, end)}…` });
    }
  }
  return hits.map((h) => ({ name: `${h.name} in ${location}`, snippet: h.snippet }));
}

export const shellInjectionRiskRule: Rule = {
  id: "shell-injection-risk",
  defaultSeverity: "high",
  description:
    "Detects MCP server commands that use shell metacharacters (&&, |, ;, $(...), backticks). Shell-interpreted commands open the door to argument injection if any value is attacker-influenced.",

  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { server, serverName } = ctx;

    if (typeof server.command === "string") {
      const cmd = server.command;
      const cmdHits = scan(cmd, "command");
      for (const h of cmdHits) {
        findings.push({
          rule: shellInjectionRiskRule.id,
          severity: shellInjectionRiskRule.defaultSeverity,
          file: ctx.config.path,
          server: serverName,
          message: `Server "${serverName}" command contains shell metacharacters (${h.name}). Use argv-style command + args separation.`,
          evidence: h.snippet,
        });
      }
      // If the launcher itself is a shell, the args are almost certainly
      // shell-interpreted — flag the pattern even without metacharacters.
      const base = cmd.split("/").pop() ?? cmd;
      if (
        SHELL_BINARIES.has(cmd) ||
        SHELL_BINARIES.has(base) ||
        (base === "env" && Array.isArray(server.args) && server.args.some((a) => SHELL_BINARIES.has(a)))
      ) {
        const flagIdx = (server.args ?? []).findIndex((a) => a === "-c");
        if (flagIdx !== -1) {
          findings.push({
            rule: shellInjectionRiskRule.id,
            severity: shellInjectionRiskRule.defaultSeverity,
            file: ctx.config.path,
            server: serverName,
            message: `Server "${serverName}" launches via "${cmd} -c", running args through a shell. Replace with a direct binary invocation.`,
            evidence: `command=${cmd} args=${JSON.stringify(server.args ?? [])}`,
          });
        }
      }
    }

    if (Array.isArray(server.args)) {
      server.args.forEach((arg, i) => {
        const hits = scan(String(arg), `args[${i}]`);
        for (const h of hits) {
          findings.push({
            rule: shellInjectionRiskRule.id,
            severity: shellInjectionRiskRule.defaultSeverity,
            file: ctx.config.path,
            server: serverName,
            message: `Server "${serverName}" argument contains shell metacharacters (${h.name}).`,
            evidence: h.snippet,
          });
        }
      });
    }

    return findings;
  },
};
