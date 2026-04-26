# mcp-scan

Open-source security scanner for **MCP (Model Context Protocol) server configurations**.

`mcp-scan` reads the MCP configs you've already installed for Claude Desktop, Cursor, Windsurf, and Claude Code, then flags four classes of issue that show up constantly in the wild:

- **Exposed secrets** baked into `env` blocks or command args
- **Dangerous auto-approve** lists that bypass tool-call confirmation
- **Suspicious URLs** (shorteners, raw IPs, plain HTTP, raw GitHub gists)
- **Shell-injection risk** in `command` / `args`

It also remembers what your servers looked like last run and tells you if any of them silently changed — the foundation of **rug-pull detection** for MCP supply-chain attacks.

> Built by [AXIOM Collective](https://withaxiom.co). The cloud version (continuous monitoring, org-wide policy, SOC 2 evidence) lives at **MCPGuard** — coming soon.

---

## Install

```bash
npm install -g @withaxiom/mcp-scan
```

Requires Node 18 or newer.

## Quickstart

```bash
mcp-scan
```

That's it. `mcp-scan` auto-discovers configs in:

| Client          | Path                                                         |
| --------------- | ------------------------------------------------------------ |
| Claude Desktop  | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Claude Desktop  | `~/.config/Claude/claude_desktop_config.json` (Linux)        |
| Cursor          | `~/.cursor/mcp.json`, `~/.cursor/config.json`                |
| Windsurf        | `~/.codeium/windsurf/mcp_config.json`                        |
| Claude Code     | `~/.claude/settings.json`, `~/.config/claude-code/settings.json` |

Want to scan something else? Pass `--config`:

```bash
mcp-scan --config ./team-mcp-config.json --config ./other.json
```

## Output formats

```bash
mcp-scan            # Pretty terminal output (default)
mcp-scan --json     # Machine-readable JSON
mcp-scan --sarif    # SARIF 2.1.0 for CI / GitHub code scanning
```

Exit code is **non-zero** if any `high` or `critical` finding is reported (Snyk-style — drop it into CI with confidence).

## What each rule catches

### `exposed-secrets` — *critical*

Scans `env`, `args`, `command`, and `url` fields for embedded credentials. Detects:

- Stripe keys (`sk_live_*`, `sk_test_*`)
- Anthropic keys (`sk-ant-*`)
- OpenAI keys (`sk-…`)
- Slack tokens (`xoxb-`, `xoxp-`, …)
- GitHub PATs (`ghp_*`, `gho_*`, `github_pat_*`)
- Google API keys (`AIza…`)
- AWS access key IDs (`AKIA…`)
- JWTs (`eyJ…`)
- Generic high-entropy strings (≥30 chars, ≥4.0 bits/char Shannon entropy)

Placeholder strings like `${ENV_VAR}`, `<your-key-here>`, `YOUR_KEY_HERE`, etc. are **not** flagged.

### `dangerous-auto-approve` — *high* (escalates to *critical* on wildcard)

Detects servers that have an `autoApprove` / `auto_approve` / `alwaysAllow` / `always_allow` list. Wildcard auto-approve (`["*"]`) is reported as **critical**. Lists that include high-risk tool names (`execute`, `shell`, `delete`, `transfer`, `pay`, …) are reported as **high**. Other lists are reported as **medium** so you can audit them.

### `suspicious-urls` — *medium*

Flags URLs in any field that:

- Use a known URL shortener (`bit.ly`, `t.co`, `tinyurl.com`, …)
- Use a raw IP literal (other than loopback)
- Use plain `http://` (other than localhost)
- Pull from a raw GitHub gist (`gist.githubusercontent.com/…/raw`)

### `shell-injection-risk` — *high*

Flags `command` / `args` values that contain `&&`, `||`, `;`, `|`, `$(...)`, backticks, or shell redirection. Also flags MCP servers launched via `sh -c` / `bash -c`, which always run their args through a shell.

### `changed-server-config` — *medium* (stateful)

On every run, `mcp-scan` writes a hash of each server's config block to `~/.mcp-scan/state.json`. On the next run, any server whose hash changed is reported. This is a **rug-pull detector**: if a benign MCP server you installed last month silently swapped its `command` to download a payload, you find out on your next scan.

Pass `--no-state` to skip writing state (useful in CI).

## Use in CI

```yaml
# .github/workflows/mcp-scan.yml
- run: npx @withaxiom/mcp-scan --config ./mcp.json --sarif > mcp-scan.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-scan.sarif
```

## Roadmap

v0.1 (this release) is intentionally focused on local-first, four-rules-done-well. On deck:

- **v0.2**: more rules (manifest signature checks, package-pinning, prompt-injection patterns), CI workflow, JSON Schema for config files.
- **v0.3**: `mcp-scan watch` for live monitoring, sandboxed test-launch of servers.
- **MCPGuard (cloud)**: continuous scanning across an entire org, policy as code, SOC 2 / ISO 27001 evidence packs.

## Contributing

PRs welcome. The architecture is deliberately small:

```
src/
├── index.ts            # CLI entrypoint
├── scanner.ts          # Orchestrator
├── discovery.ts        # Config file location finder
├── state.ts            # Drift / rug-pull state tracking
├── reporters.ts        # pretty / json / sarif renderers
├── types.ts            # Shared types + Zod schemas
└── rules/
    ├── exposed-secrets.ts
    ├── dangerous-auto-approve.ts
    ├── suspicious-urls.ts
    └── shell-injection-risk.ts
```

To add a rule: drop a new file in `src/rules/`, export a `Rule` object, and register it in `src/rules/index.ts`. Add a fixture in `tests/fixtures/` and a test in `tests/`.

```bash
npm install
npm run build
npm test
```

## Security disclosure

Found a vulnerability in `mcp-scan` itself? Email **security@withaxiom.co** rather than opening a public issue.

## License

MIT © AXIOM Collective
