import chalk from "chalk";
import { Command, Option } from "commander";
import { scan, hasGatingFindings } from "./scanner.js";
import {
  renderJson,
  renderPretty,
  renderQuiet,
  renderSarif,
} from "./reporters.js";

interface CliOpts {
  config?: string[];
  json?: boolean;
  jsonPretty?: boolean;
  sarif?: boolean;
  noState?: boolean;
  failOn?: string;
  verbose?: boolean;
  quiet?: boolean;
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
  .option(
    "--json",
    "Emit findings as compact JSON (one line, jq-friendly) instead of the pretty terminal report.",
  )
  .option(
    "--json-pretty",
    "Emit findings as 2-space-indented JSON. Same content as --json; implies JSON output.",
  )
  .option("--sarif", "Emit findings as SARIF 2.1.0 (for CI / GitHub code scanning).")
  .option(
    "--no-state",
    "Skip writing ~/.mcp-scan/state.json. Drift detection still runs against any prior state but won't update it.",
  )
  .option(
    "--verbose",
    "Log discovery paths, per-rule progress, and per-phase timing to stderr. Scan results are unaffected.",
  )
  .addOption(
    new Option(
      "--quiet",
      "Print critical findings and the one-line summary footer only. Affects the terminal report; --json/--sarif output is unchanged. Exit codes are unchanged. Mutually exclusive with --verbose.",
    ).conflicts("verbose"),
  )
  .action(async (opts: CliOpts) => {
    try {
      const result = await scan({
        configPaths: opts.config ?? [],
        noState: opts.noState,
        log: opts.verbose
          ? (line) => process.stderr.write(chalk.gray(`[verbose] ${line}`) + "\n")
          : undefined,
      });

      if (opts.sarif) {
        process.stdout.write(renderSarif(result) + "\n");
      } else if (opts.json || opts.jsonPretty) {
        // --json-pretty wins when both are given — it is the same content,
        // just indented.
        process.stdout.write(renderJson(result, opts.jsonPretty) + "\n");
      } else if (opts.quiet) {
        process.stdout.write(renderQuiet(result));
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
