import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { DiscoveredConfig, Finding } from "./types.js";

interface ServerHashEntry {
  hash: string;
  /** ISO timestamp of the run that recorded this hash. */
  seenAt: string;
}

interface StateFile {
  version: 1;
  /** Keyed by `${configPath}::${serverName}`. */
  servers: Record<string, ServerHashEntry>;
}

const DEFAULT_STATE_DIR = path.join(os.homedir(), ".mcp-scan");
const STATE_FILE_NAME = "state.json";

function stateFilePath(dir = DEFAULT_STATE_DIR): string {
  return path.join(dir, STATE_FILE_NAME);
}

function hashServer(server: unknown): string {
  // Stable JSON stringify — sort keys so reordered fields don't churn the hash.
  const stable = stableStringify(server);
  return crypto.createHash("sha256").update(stable).digest("hex");
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k]))
      .join(",") +
    "}"
  );
}

async function readState(dir: string): Promise<StateFile> {
  try {
    const text = await fs.readFile(stateFilePath(dir), "utf8");
    const parsed = JSON.parse(text);
    if (parsed && parsed.version === 1 && parsed.servers) return parsed;
  } catch {
    /* fall through to empty state */
  }
  return { version: 1, servers: {} };
}

async function writeState(dir: string, state: StateFile): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(stateFilePath(dir), JSON.stringify(state, null, 2), "utf8");
}

/**
 * Compare each server's current hash against the prior run and emit a
 * `changed-server-config` finding for any server whose config drifted.
 *
 * Always updates the on-disk state to reflect the current run, unless
 * `dryRun` is true (used in tests).
 */
export async function detectAndRecordChanges(
  configs: DiscoveredConfig[],
  options: { dir?: string; dryRun?: boolean } = {},
): Promise<Finding[]> {
  const dir = options.dir ?? DEFAULT_STATE_DIR;
  const prior = await readState(dir);
  const next: StateFile = { version: 1, servers: {} };
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  for (const cfg of configs) {
    for (const [name, server] of Object.entries(cfg.servers)) {
      const key = `${cfg.path}::${name}`;
      const hash = hashServer(server);
      next.servers[key] = { hash, seenAt: now };

      const previous = prior.servers[key];
      if (previous && previous.hash !== hash) {
        findings.push({
          rule: "changed-server-config",
          severity: "medium",
          file: cfg.path,
          server: name,
          message: `MCP server "${name}" config changed since last scan (possible rug-pull or unintended modification).`,
          evidence: `prev=${previous.hash.slice(0, 12)} now=${hash.slice(0, 12)} (last seen ${previous.seenAt})`,
        });
      }
    }
  }

  if (!options.dryRun) {
    await writeState(dir, next);
  }
  return findings;
}

// Exported for testing
export const _internal = { hashServer, stableStringify };
