# Contributing to mcp-snitch

Thanks for helping make agent traffic observable.

## Development setup

```bash
git clone https://github.com/mcp-snitch/mcp-snitch
cd mcp-snitch
npm install
npm run build
npm test
```

| Script | What it does |
|---|---|
| `npm run build` | compile TypeScript to `dist/` |
| `npm run lint` | type-check only (no emit) |
| `npm test` | vitest unit tests |
| `npm run demo` | end-to-end: smoke client → proxy → demo server |

## Ground rules

1. **Zero runtime dependencies.** The proxy sits in the trust path; every dep is
   attack surface. Dev-deps (typescript, vitest) are fine.
2. **stdout is sacred.** Only MCP JSON-RPC may be written to stdout. Logs,
   banners, and prompts go to stderr (or `/dev/tty`).
3. **Fail closed in strict mode.** If the policy engine errors while
   `mode=strict`, deny.
4. **Redact before logging.** Anything entering `AuditLog` passes through
   `redactDeep`.
5. **No telemetry, no network calls** in the core (desktop notifications are
   local IPC only).

## Adding a detection rule

1. Heuristic lives in `classify.ts` (call-site risk) or `inject.ts`
   (injection text). Keep it a plain regex/string check — no ML.
2. Add a unit test in `tests/` covering both a hit and a clean pass.
3. Update the “What it catches” table in the README if it's user-visible.

## Adding a client config path

Known configs live in `src/paths.ts` → `knownClientConfigs()`. Add the label,
path, and the JSON keys that hold server maps (`mcpServers`, `servers`, …).
`install` / `uninstall` must be idempotent — running either twice changes nothing.

## Commit / PR style

- Conventional-ish commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`
- One behavior change per PR
- CI must be green (lint + test + build + e2e smoke on Linux & macOS, Node 20/22)

## Security issues

Please report vulnerabilities privately via GitHub Security Advisories on this
repo — **not** in a public issue.
