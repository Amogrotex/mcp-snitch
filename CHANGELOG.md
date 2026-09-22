# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/), versioning: [SemVer](https://semver.org/).

## [0.1.0] — 2026-09-22

### Added
- Transparent MCP proxy (`mcp-snitch run`) with allow/deny evaluation per `tools/call`
- Modes: `learn` (default), `strict` (fail closed), `off`
- Glob rule store with deny precedence and argument patterns (`rules add/list/remove/clear`)
- Plain-language risk classification (shell, delete, sensitive paths, external hosts)
- Behavioral baselines: new path roots, new domains, unknown tools → alerts
- Rug-pull detection: SHA-256 pin of tool definitions, diff on `tools/list`
- Tool-poisoning scan of descriptions and input schemas
- Inbound prompt-injection scan of tool results
- Interactive y/N prompts on `/dev/tty` (headless fallback per mode)
- JSONL audit log with secret redaction (`audit --tail`)
- `install` / `uninstall` for Claude Desktop, Cursor, Windsurf, VS Code, Zed
- Desktop notifications (osascript / notify-send), stderr alert banners
- Demo MCP server + smoke client (`npm run demo`)
- CI: lint, unit tests, build, end-to-end smoke on Linux/macOS × Node 20/22
