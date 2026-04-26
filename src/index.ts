import { Command } from "commander";
import { scan, hasGatingFindings } from "./scanner.js";
import { renderJson, renderPretty, renderSarif } from "./reporters.js";

interface CliOpts {
  config?: string[];
  json?: boolean;
  sarif?: boolean;
  noState?: boolean;
  failOn?: string;
}

const program = new Command();

program
  .name("mcp-scan")
  .description(
    "Open-source security scanner for MCP server configurations. Detects exposed secrets, dangerous auto-approve patterns, suspicious URLs, and shell-injection risks.",
  )
  .version("0.1.0");

program
  .option(
    "-c, --config <path>",
    "Additional MCP config file(s) to scan (repeatable). Standard locations are always scanned too.",
    (value: string, prev: string[] = []) => prev.concat([value]),
    [] as string[],
  )
  .option("--json", "Emit findings as JSON instead of the pretty terminal report.")
  .option("--sarif", "Emit findings as SARIF 2.1.0 (for CI / GitHub code scanning).")
  .option(
    "--no-state",
    "Skip writing ~/.mcp-scan/state.json. Drift detection still runs against any prior state but won't update it.",
  )
  .action(async (opts: CliOpts) => {
    try {
      const result = await scan({
        configPaths: opts.config ?? [],
        noState: opts.noState,
      });

      if (opts.sarif) {
        process.stdout.write(renderSarif(result) + "\n");
      } else if (opts.json) {
        process.stdout.write(renderJson(result) + "\n");
      } else {
        process.stdout.write(renderPretty(result));
      }

      // Snyk-style: exit non-zero if anything high or critical was found.
      if (hasGatingFindings(result.findings)) {
        process.exit(1);
      }
      process.exit(0);
    } catch (err) {
      process.stderr.write(
        `mcp-scan: fatal error — ${(err as Error).message}\n`,
      );
      process.exit(2);
    }
  });

program.parseAsync(process.argv);
