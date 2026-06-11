import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DiscoveredConfig, McpServerEntry, ScanLogger } from "./types.js";

interface KnownLocation {
  client: string;
  /** Resolves to an absolute path; may not exist. */
  resolve: () => string;
}

/**
 * Standard locations we look at out-of-the-box. All paths are best-effort:
 * non-existent files are silently skipped during discovery.
 */
export const KNOWN_LOCATIONS: KnownLocation[] = [
  {
    client: "claude-desktop",
    resolve: () =>
      path.join(
        os.homedir(),
        "Library",
        "Application Support",
        "Claude",
        "claude_desktop_config.json",
      ),
  },
  {
    client: "claude-desktop",
    resolve: () =>
      path.join(
        os.homedir(),
        ".config",
        "Claude",
        "claude_desktop_config.json",
      ),
  },
  {
    client: "cursor",
    resolve: () => path.join(os.homedir(), ".cursor", "mcp.json"),
  },
  {
    client: "cursor",
    resolve: () => path.join(os.homedir(), ".cursor", "config.json"),
  },
  {
    client: "windsurf",
    resolve: () =>
      path.join(os.homedir(), ".codeium", "windsurf", "mcp_config.json"),
  },
  {
    client: "claude-code",
    resolve: () => path.join(os.homedir(), ".claude", "settings.json"),
  },
  {
    client: "claude-code",
    resolve: () =>
      path.join(os.homedir(), ".config", "claude-code", "settings.json"),
  },
];

async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Pull the `mcpServers` (or equivalent) map out of a parsed config file.
 * Different clients nest it differently; we try a few common shapes.
 */
function extractServers(raw: unknown): Record<string, McpServerEntry> {
  if (!raw || typeof raw !== "object") return {};
  const obj = raw as Record<string, unknown>;

  // Most common: { "mcpServers": { name: {...} } }
  if (obj.mcpServers && typeof obj.mcpServers === "object") {
    return obj.mcpServers as Record<string, McpServerEntry>;
  }
  // Cursor sometimes uses "servers"
  if (obj.servers && typeof obj.servers === "object") {
    return obj.servers as Record<string, McpServerEntry>;
  }
  // Windsurf nests under "mcp"
  if (obj.mcp && typeof obj.mcp === "object") {
    const mcp = obj.mcp as Record<string, unknown>;
    if (mcp.servers && typeof mcp.servers === "object") {
      return mcp.servers as Record<string, McpServerEntry>;
    }
    if (mcp.mcpServers && typeof mcp.mcpServers === "object") {
      return mcp.mcpServers as Record<string, McpServerEntry>;
    }
  }
  return {};
}

/**
 * Read and parse a single config file. Returns `null` if the file is unreadable
 * or not valid JSON — we never throw, so one bad config can't kill a scan.
 */
export async function loadConfig(
  filePath: string,
  client = "custom",
): Promise<DiscoveredConfig | null> {
  if (!(await fileExists(filePath))) return null;
  let raw: unknown;
  try {
    const text = await fs.readFile(filePath, "utf8");
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  const servers = extractServers(raw);
  return {
    path: path.resolve(filePath),
    client,
    servers,
    raw,
  };
}

/**
 * Walk all known locations + any user-supplied paths, returning every config
 * we could parse. Missing files are silently dropped.
 *
 * When a `log` sink is provided (--verbose) every candidate path is reported,
 * including the ones that were skipped. Logging never changes discovery
 * behavior — the extra existence probe only runs to label skips accurately.
 */
export async function discoverConfigs(
  extraPaths: string[] = [],
  log?: ScanLogger,
): Promise<DiscoveredConfig[]> {
  const results: DiscoveredConfig[] = [];

  const probe = async (p: string, client: string): Promise<void> => {
    const cfg = await loadConfig(p, client);
    if (cfg) {
      results.push(cfg);
      log?.(
        `discovery: ${p} [${client}] — ${Object.keys(cfg.servers).length} server(s)`,
      );
    } else if (log) {
      const reason = (await fileExists(p)) ? "unparsable JSON" : "not found";
      log(`discovery: ${p} [${client}] — skipped (${reason})`);
    }
  };

  for (const loc of KNOWN_LOCATIONS) {
    await probe(loc.resolve(), loc.client);
  }

  for (const p of extraPaths) {
    await probe(path.resolve(p), "custom");
  }

  return results;
}
