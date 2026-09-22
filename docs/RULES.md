# Rules reference

Rules live in `~/.mcp-snitch/rules.json` and are matched against every outgoing
`tools/call`. **Deny rules always win over allow rules.**

## Schema

```json
{
  "version": 1,
  "rules": [
    {
      "id": "a1b2c3d4",
      "server": "github",
      "tool": "delete_*",
      "action": "deny",
      "args": { "path": "~/projects/**" },
      "note": "never delete repos",
      "created": "2026-09-22T10:00:00.000Z"
    }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `server` | glob | matches the server name given via `--name` (or the config key when installed) |
| `tool` | glob | matches the tool name |
| `action` | `allow` \| `deny` | what to do on match |
| `args` | object of globs | **optional** — every listed key must exist in the call arguments as a string *and* match its glob |
| `note` | string | free text shown in `rules list` |
| `id` | string | random 8-char id, used by `rules remove` |

## Glob syntax

| Token | Meaning |
|---|---|
| `*` | any characters (including `/`) |
| `?` | exactly one character |
| everything else | literal (regex metacharacters are escaped) |

Examples:

```
read_*          read_file, read_note, …
*               everything
get?            getFile, get_it, …
```

## Argument patterns

```bash
mcp-snitch rules add --server fs --tool read_file --allow --arg 'path=~/projects/**'
```

- The call must include `path` as a **string** — if the key is missing or not a
  string, the rule does not match.
- All `--arg` patterns must match (logical AND).
- Non-URL/path strings work too: `--arg 'id=meeting'`.

## Precedence

1. First matching **deny** rule (across all rules, regardless of order added)
2. First matching **allow** rule
3. Policy engine (classification + baseline + mode)

So this is safe by construction:

```
allow  *            .read_*
deny   github       delete_*
```

`github.delete_repo` is denied even though the allow glob matches `github` +
`read_*`? — actually it doesn't match `read_*`; the point stands generally:
deny beats allow whenever both match.

## CLI cheat sheet

```bash
mcp-snitch rules list
mcp-snitch rules add --server github --tool 'delete_*' --deny --note "no deletions"
mcp-snitch rules add --server '*' --tool 'read_*' --allow
mcp-snitch rules add --server notes --tool send_note --deny
mcp-snitch rules remove a1b2c3d4
mcp-snitch rules clear
```
