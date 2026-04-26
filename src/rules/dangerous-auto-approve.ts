import { Finding, Rule, RuleContext } from "../types.js";

/**
 * Tool names that should NEVER be silently auto-approved. Wildcard auto-approve
 * (`["*"]`) is also flagged regardless of contents.
 */
const HIGH_RISK_TOOLS = [
  "execute",
  "exec",
  "shell",
  "run",
  "run_command",
  "bash",
  "write_file",
  "delete",
  "delete_file",
  "rm",
  "send_email",
  "transfer",
  "pay",
  "create_payment",
];

/**
 * Pull all auto-approve list candidates off a server entry. Different clients
 * use different keys (`autoApprove`, `auto_approve`, `alwaysAllow`,
 * `always_allow`).
 */
function collectAutoApproveLists(server: Record<string, unknown>): {
  field: string;
  values: string[];
}[] {
  const fields = ["autoApprove", "auto_approve", "alwaysAllow", "always_allow"];
  const out: { field: string; values: string[] }[] = [];
  for (const f of fields) {
    const v = server[f];
    if (Array.isArray(v) && v.length > 0) {
      out.push({ field: f, values: v.map(String) });
    }
  }
  return out;
}

export const dangerousAutoApproveRule: Rule = {
  id: "dangerous-auto-approve",
  defaultSeverity: "high",
  description:
    "Detects MCP servers with auto-approve / always-allow lists that bypass the user prompt for destructive or high-risk tools. Wildcards are always flagged.",

  check(ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const lists = collectAutoApproveLists(ctx.server as Record<string, unknown>);

    for (const { field, values } of lists) {
      const wildcards = values.filter((v) => v === "*" || v === "all");
      if (wildcards.length > 0) {
        findings.push({
          rule: dangerousAutoApproveRule.id,
          severity: "critical",
          file: ctx.config.path,
          server: ctx.serverName,
          message: `Server "${ctx.serverName}" auto-approves ALL tools via wildcard. Every tool call from this server runs without user confirmation.`,
          evidence: `${field} = ${JSON.stringify(values)}`,
        });
        continue;
      }
      const risky = values.filter((v) =>
        HIGH_RISK_TOOLS.some((tool) => v.toLowerCase().includes(tool)),
      );
      if (risky.length > 0) {
        findings.push({
          rule: dangerousAutoApproveRule.id,
          severity: dangerousAutoApproveRule.defaultSeverity,
          file: ctx.config.path,
          server: ctx.serverName,
          message: `Server "${ctx.serverName}" auto-approves high-risk tools: ${risky.join(", ")}.`,
          evidence: `${field} = ${JSON.stringify(values)}`,
        });
      } else if (values.length > 0) {
        findings.push({
          rule: dangerousAutoApproveRule.id,
          severity: "medium",
          file: ctx.config.path,
          server: ctx.serverName,
          message: `Server "${ctx.serverName}" has ${values.length} auto-approved tool(s). Review whether each is safe to run unattended.`,
          evidence: `${field} = ${JSON.stringify(values)}`,
        });
      }
    }
    return findings;
  },
};
