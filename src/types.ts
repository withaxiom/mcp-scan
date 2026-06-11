import { z } from "zod";

/**
 * MCP server entry as it appears in client config files.
 * Different clients use slightly different shapes; we accept a permissive
 * superset and let rules inspect what they care about.
 */
export const McpServerEntrySchema = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string()).optional(),
    url: z.string().optional(),
    type: z.string().optional(),
    // Auto-approve / always-allow flags vary by client
    autoApprove: z.array(z.string()).optional(),
    auto_approve: z.array(z.string()).optional(),
    alwaysAllow: z.array(z.string()).optional(),
    always_allow: z.array(z.string()).optional(),
    disabled: z.boolean().optional(),
  })
  .passthrough();

export type McpServerEntry = z.infer<typeof McpServerEntrySchema>;

/**
 * A discovered config file with its parsed `mcpServers` map.
 */
export interface DiscoveredConfig {
  /** Absolute path to the config file. */
  path: string;
  /** Friendly client label (e.g. "claude-desktop", "cursor"). */
  client: string;
  /** Parsed mcp server map. Keys are server names. */
  servers: Record<string, McpServerEntry>;
  /** Raw parsed JSON for whole-file rules. */
  raw: unknown;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  rule: string;
  severity: Severity;
  /** Absolute path to the offending config file. */
  file: string;
  /** Server name within the file, or `null` for whole-file findings. */
  server: string | null;
  /** Human-readable explanation. */
  message: string;
  /**
   * Redacted evidence (key path, snippet) for the user. Never include
   * full secret values — rules that detect secrets should mask them.
   */
  evidence?: string;
}

export interface ScanResult {
  findings: Finding[];
  configsScanned: DiscoveredConfig[];
  startedAt: string;
  finishedAt: string;
}

export interface RuleContext {
  config: DiscoveredConfig;
  serverName: string;
  server: McpServerEntry;
}

export interface Rule {
  id: string;
  defaultSeverity: Severity;
  description: string;
  /** Per-server check. Rules return zero or more findings. */
  check(ctx: RuleContext): Finding[];
}

/**
 * Sink for verbose diagnostics (--verbose). Implementations decide where the
 * lines go (the CLI writes them to stderr so stdout stays machine-parseable).
 */
export type ScanLogger = (line: string) => void;

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
