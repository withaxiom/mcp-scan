import { describe, it, expect, beforeEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { detectAndRecordChanges } from "../src/state.js";
import { DiscoveredConfig } from "../src/types.js";

async function makeTmp(): Promise<string> {
  return await fs.mkdtemp(path.join(os.tmpdir(), "mcp-scan-state-"));
}

function buildConfig(servers: Record<string, unknown>): DiscoveredConfig {
  return {
    path: "/virtual/test-config.json",
    client: "test",
    servers: servers as DiscoveredConfig["servers"],
    raw: { mcpServers: servers },
  };
}

describe("state / drift detection", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await makeTmp();
  });

  it("emits no findings on first run, then flags changed servers on second run", async () => {
    const v1 = buildConfig({
      app: { command: "node", args: ["./app.js"] },
    });
    const first = await detectAndRecordChanges([v1], { dir });
    expect(first).toEqual([]);

    // Same config -> still no findings
    const second = await detectAndRecordChanges([v1], { dir });
    expect(second).toEqual([]);

    // Mutate the server's command
    const v2 = buildConfig({
      app: { command: "node", args: ["./app.js", "--evil"] },
    });
    const third = await detectAndRecordChanges([v2], { dir });
    expect(third).toHaveLength(1);
    expect(third[0].rule).toBe("changed-server-config");
    expect(third[0].severity).toBe("medium");
    expect(third[0].server).toBe("app");
  });

  it("dryRun does not write state to disk", async () => {
    const cfg = buildConfig({
      svc: { command: "node", args: ["./srv.js"] },
    });
    await detectAndRecordChanges([cfg], { dir, dryRun: true });
    const stateFile = path.join(dir, "state.json");
    const exists = await fs
      .access(stateFile)
      .then(() => true)
      .catch(() => false);
    expect(exists).toBe(false);
  });

  it("treats key-reordering as the same hash", async () => {
    const a = buildConfig({
      svc: { command: "node", args: ["./s.js"], env: { A: "1", B: "2" } },
    });
    const b = buildConfig({
      svc: { env: { B: "2", A: "1" }, args: ["./s.js"], command: "node" },
    });
    await detectAndRecordChanges([a], { dir });
    const result = await detectAndRecordChanges([b], { dir });
    expect(result).toEqual([]);
  });
});
