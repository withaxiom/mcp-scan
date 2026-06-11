import { describe, it, expect, beforeEach } from "vitest";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CLI_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../dist/index.js",
);

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Run the built CLI with HOME pointed at an isolated temp dir so the user's
 * real configs (~/Library, ~/.claude, ...) are never scanned and state lands
 * under the temp HOME, not the real one.
 */
function runCli(args: string[], home: string): Promise<CliRun> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      [CLI_PATH, ...args],
      { env: { ...process.env, HOME: home } },
      (err, stdout, stderr) => {
        if (err && typeof err.code !== "number") {
          reject(err); // spawn failure (e.g. dist not built), not a CLI exit
          return;
        }
        resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
      },
    );
  });
}

async function fileExists(p: string): Promise<boolean> {
  return fs
    .access(p)
    .then(() => true)
    .catch(() => false);
}

describe("cli --no-state", () => {
  let home: string;
  let fixture: string;
  let stateFile: string;

  beforeEach(async () => {
    home = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-scan-cli-home-"));
    fixture = path.join(home, "fixture-config.json");
    await fs.writeFile(
      fixture,
      JSON.stringify({
        mcpServers: { echo: { command: "node", args: ["server.js"] } },
      }),
      "utf8",
    );
    stateFile = path.join(home, ".mcp-scan", "state.json");
  });

  it("writes state.json by default (control run)", async () => {
    const run = await runCli(["--json", "-c", fixture], home);
    expect(run.code).toBe(0);
    expect(await fileExists(stateFile)).toBe(true);
  });

  it("does not write state.json when --no-state is passed", async () => {
    const run = await runCli(["--json", "--no-state", "-c", fixture], home);
    expect(run.code).toBe(0);
    expect(await fileExists(stateFile)).toBe(false);
  });
});
