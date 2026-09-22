# Architecture

## Overview

`mcp-snitch` is a transparent MCP proxy. A client talks to it exactly as it
would talk to a real server; it spawns the real server as a child process and
forwards newline-delimited JSON-RPC between the two, inspecting messages on the
way.

```
client stdin ──► handleClientMessage ──► child.stdin
client stdout ◄── toClient ◄── handleServerMessage ◄── child.stdout
```

Nothing on stdout is ever polluted with log output — banners and prompts go to
stderr (and `/dev/tty` when interactive).

## Layers

| Layer | Module | Fires on | Produces |
|---|---|---|---|
| Framing | `rpc.ts` | raw bytes | `RpcMessage[]` |
| Rule engine | `rules.ts` | outgoing `tools/call` | allow/deny (deny precedence) |
| Classifier | `classify.ts` | outgoing `tools/call` | severity + plain-language summary |
| Baseline | `baseline.ts` | `tools/list` + calls | drift, new roots/domains/flags |
| Metadata scan | `inject.ts` | `tools/list` | poisoned-description flags |
| Inbound scan | `inject.ts` | `tools/call` results | injection findings |
| Policy | `policy.ts` | combines the above | final `Evaluation` |
| Prompting | `tty.ts` | high/critical in learn/strict | y / n / timeout |
| Audit | `audit.ts` | every decision | JSONL, redacted |
| Alerting | `notify.ts` | notable events | stderr banner + desktop notification |

## Decision flow (outgoing tools/call)

```
mode == off?                     ──► allow
deny rule matches?               ──► deny
allow rule matches?              ──► allow
classify + anomalies + flags
  severity critical/high         ──► TTY? ask user
                                    ├ y → allow
                                    ├ n/timeout → deny
                                    └ unavailable → mode fallback
                                        learn  → allow + alert
                                        strict → deny
  severity medium (strict only)  ──► same prompt path
  otherwise                      ──► allow (+ alert if medium)
```

Every path writes an audit event with the decision and its reason.

## Trust model

- **The client is trusted** (it is you, on your machine).
- **The upstream server is untrusted**: its descriptions, schemas, results, and
  arguments are all attacker-controlled input.
- **The proxy is the TCB**: it must never crash on malformed messages (bad JSON
  lines are dropped, never forwarded), and it must fail closed in `strict` mode.

## Threat mapping (partial OWASP MCP Top 10)

| OWASP-ish id | Covered by |
|---|---|
| Tool poisoning | metadata scan → flagged tools → escalated risk on call |
| Rug pull | SHA-256 manifest diff vs baseline |
| Prompt injection via tool output | inbound result scan |
| Exfiltration / over-permissioned tools | classifier (URLs, sensitive paths) + rules |
| Supply chain of the config itself | `install` only wraps, never downloads |

Not covered: process sandboxing (use `srt`/containers), server-side
vulnerabilities inside the upstream implementation, remote (SSE/HTTP)
bridging (see roadmap).

## Persistence

Everything lives in one directory (`MCP_SNITCH_HOME` or `~/.mcp-snitch/`):

```
rules.json        allow/deny rules
baseline.json     per-server tool hashes, path roots, domains
config.json       { "defaultMode": "learn" }
installed.json    files touched by `mcp-snitch install`
audit/*.jsonl     append-only daily audit logs
```

No network calls, ever — except best-effort OS notifications
(`osascript` / `notify-send`) which send nothing off-box.

## Roadmap

- [ ] `run --url <remote>` — bridge remote HTTP/SSE MCP servers through the same policy path
- [ ] Windows console prompts (currently: headless defaults apply)
- [ ] Session sharing: export/import rules for teams
- [ ] SIEM export (OpenTelemetry logs) for `audit/`
- [ ] Content blocking option: strip flagged spans from inbound results instead of only alerting
- [ ] VS Code extension UI for the live call timeline
