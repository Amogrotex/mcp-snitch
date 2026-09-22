/** CLI entry: run / install / uninstall / rules / status / audit / help. */

import { readFileSync, existsSync } from 'node:fs';
import type { Decision, Mode, Rule } from './types.js';
import { RuleStore } from './rules.js';
import { BaselineStore } from './baseline.js';
import { AuditLog } from './audit.js';
import { McpProxy } from './proxy.js';
import { install, uninstall } from './config-install.js';
import { configPath, dataDir, knownClientConfigs, rulesPath } from './paths.js';

const VERSION = '0.1.0';

const HELP = `
mcp-snitch — Little Snitch for MCP

  Interactive runtime firewall for Model Context Protocol tool calls.
  Watches what your MCP servers actually do, alerts on anything unusual,
  and lets you allow/deny per call — with rules you keep.

USAGE
  mcp-snitch <command> [options]

COMMANDS
  run [options] -- <command> [args...]
      Wrap an MCP server. Used automatically after "install".
      --name <server>     Server name for rules/baselines (default: command)
      --mode <mode>       learn | strict | off  (default: learn, or config)

  install [--dry-run]
      Rewrite MCP client configs (Claude Desktop, Cursor, VS Code, ...)
      so every local server runs through mcp-snitch. Originals are backed up.

  uninstall [--dry-run]
      Restore original client configs.

  rules list
      Show all allow/deny rules.

  rules add --server <glob> --tool <glob> (--allow | --deny) [--arg key=glob ...] [--note text]
      Add a rule. Examples:
        mcp-snitch rules add --server github --tool delete_repo --deny
        mcp-snitch rules add --server '*' --tool 'read_*' --allow
        mcp-snitch rules add --server fs --tool read_file --allow --arg 'path=~/projects/**'

  rules remove <id> | rules clear
      Delete one rule or all rules.

  status
      Show data directory, rules, baselines, and client configs.

  audit [--tail N]
      Print recent audit events (default 20).

  version | --version | -v
  help   | --help    | -h

MODES
  learn    Baseline normal behavior, alert on anomalies, allow with warning (default)
  strict   Anything risky without an explicit allow rule is denied
  off      Pass everything through, audit only

FILES
  ${rulesPath()}
  ${dataDir()}/baseline.json
  ${dataDir()}/audit/audit-YYYY-MM-DD.jsonl
`;

interface ParsedRun {
  name?: string;
  mode?: Mode;
  command?: string;
  args: string[];
}

function parseRun(argv: string[]): ParsedRun {
  const out: ParsedRun = { args: [] };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i]!;
    if (a === '--') {
      out.command = argv[i + 1];
      out.args = argv.slice(i + 2);
      return out;
    }
    if (a === '--name') {
      out.name = argv[i + 1];
      i += 2;
      continue;
    }
    if (a === '--mode') {
      out.mode = argv[i + 1] as Mode;
      i += 2;
      continue;
    }
    if (a.startsWith('--mode=')) {
      out.mode = a.slice('--mode='.length) as Mode;
      i += 1;
      continue;
    }
    if (a.startsWith('--name=')) {
      out.name = a.slice('--name='.length);
      i += 1;
      continue;
    }
    i += 1;
  }
  return out;
}

function defaultMode(): Mode {
  const env = process.env['MCP_SNITCH_MODE'];
  if (env === 'learn' || env === 'strict' || env === 'off') return env;
  const file = configPath();
  if (existsSync(file)) {
    try {
      const cfg = JSON.parse(readFileSync(file, 'utf8')) as { defaultMode?: Mode };
      if (cfg.defaultMode) return cfg.defaultMode;
    } catch {
      /* fall through */
    }
  }
  return 'learn';
}

function printLines(lines: string[]): void {
  for (const line of lines) console.log(line);
}

function cmdRules(sub: string[], rules: RuleStore): void {
  const [action, ...rest] = sub;

  if (!action || action === 'list') {
    const list = rules.list();
    if (list.length === 0) {
      console.log('No rules yet. Add one:');
      console.log("  mcp-snitch rules add --server github --tool delete_repo --deny");
      return;
    }
    console.log(`Rules (${list.length}) in ${rules.file}:\n`);
    for (const r of list) {
      const args = r.args ? ' ' + Object.entries(r.args).map(([k, v]) => `${k}=${v}`).join(' ') : '';
      console.log(`  ${r.id}  ${r.action.padEnd(5)}  ${r.server}.${r.tool}${args}${r.note ? `  # ${r.note}` : ''}`);
    }
    return;
  }

  if (action === 'add') {
    let server: string | undefined;
    let tool: string | undefined;
    let decision: Decision | undefined;
    let note: string | undefined;
    const argPatterns: Record<string, string> = {};
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i]!;
      if (a === '--server') server = rest[++i];
      else if (a === '--tool') tool = rest[++i];
      else if (a === '--allow') decision = 'allow';
      else if (a === '--deny') decision = 'deny';
      else if (a === '--note') note = rest[++i];
      else if (a === '--arg') {
        const kv = rest[++i] ?? '';
        const eq = kv.indexOf('=');
        if (eq > 0) argPatterns[kv.slice(0, eq)] = kv.slice(eq + 1);
      }
    }
    if (!server || !tool || !decision) {
      console.error('rules add requires --server, --tool, and --allow or --deny');
      process.exit(2);
    }
    const rule = rules.add({
      server,
      tool,
      action: decision,
      ...(Object.keys(argPatterns).length ? { args: argPatterns } : {}),
      ...(note ? { note } : {}),
    });
    console.log(`Added rule ${rule.id}: ${rule.action} ${rule.server}.${rule.tool}`);
    return;
  }

  if (action === 'remove') {
    const id = rest[0];
    if (!id) {
      console.error('rules remove requires a rule id');
      process.exit(2);
    }
    console.log(rules.remove(id) ? `Removed ${id}` : `No rule with id ${id}`);
    return;
  }

  if (action === 'clear') {
    const n = rules.clear();
    console.log(`Cleared ${n} rule(s).`);
    return;
  }

  console.error(`Unknown rules subcommand: ${action}`);
  process.exit(2);
}

function cmdStatus(): void {
  const rules = new RuleStore();
  const baseline = new BaselineStore();
  const configs = knownClientConfigs();

  console.log(`mcp-snitch ${VERSION}`);
  console.log(`  data dir     ${dataDir()}`);
  console.log(`  default mode ${defaultMode()}`);
  console.log(`  rules        ${rules.list().length} (${rules.file})`);
  console.log(`  baselines    ${baseline.servers().length} server(s)`);
  for (const name of baseline.servers()) {
    const b = baseline.get(name);
    console.log(
      `      ${name}: ${b.tools.length} tools, ${b.pathRoots.length} path roots, ${b.domains.length} domains`,
    );
  }
  console.log('  client configs:');
  if (configs.length === 0) console.log('      (none found)');
  for (const c of configs) {
    const wrapped = (() => {
      try {
        const json = JSON.parse(readFileSync(c.path, 'utf8')) as Record<string, unknown>;
        for (const key of ['mcpServers', 'servers', 'context_servers']) {
          const map = json[key] as Record<string, { command?: string }> | undefined;
          if (map && typeof map === 'object') {
            const entries = Object.values(map);
            const wrappedCount = entries.filter((e) => e.command === 'mcp-snitch').length;
            if (entries.length > 0) return `${wrappedCount}/${entries.length} wrapped`;
          }
        }
        return 'no servers';
      } catch {
        return 'unreadable';
      }
    })();
    console.log(`      ${c.label}: ${c.path} (${wrapped})`);
  }
}

function cmdAudit(sub: string[]): void {
  let n = 20;
  const tailIdx = sub.indexOf('--tail');
  if (tailIdx !== -1 && sub[tailIdx + 1]) n = Number(sub[tailIdx + 1]) || 20;
  const audit = new AuditLog();
  const events = audit.tail(n);
  if (events.length === 0) {
    console.log('No audit events yet.');
    return;
  }
  for (const e of events) console.log(JSON.stringify(e));
}

export function main(argv: string[]): void {
  const [command, ...rest] = argv;

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP.trimStart());
    return;
  }
  if (command === 'version' || command === '--version' || command === '-v') {
    console.log(VERSION);
    return;
  }

  if (command === 'run') {
    const parsed = parseRun(rest);
    if (!parsed.command) {
      console.error('run requires an upstream command after `--`\n  e.g. mcp-snitch run --name fs -- npx -y @modelcontextprotocol/server-filesystem /tmp');
      process.exit(2);
    }
    const mode = parsed.mode ?? defaultMode();
    const serverName = parsed.name ?? parsed.command;
    const proxy = new McpProxy({
      serverName,
      command: parsed.command,
      args: parsed.args,
      mode,
      rules: new RuleStore(),
      baseline: new BaselineStore(),
      audit: new AuditLog(),
    });
    proxy.start();
    return;
  }

  if (command === 'install') {
    const dry = rest.includes('--dry-run');
    printLines(install(dry));
    if (!dry) {
      console.log('\nRestart your MCP clients to pick up the change. Verify with: mcp-snitch status');
    }
    return;
  }

  if (command === 'uninstall') {
    const dry = rest.includes('--dry-run');
    printLines(uninstall(dry));
    return;
  }

  if (command === 'rules') {
    cmdRules(rest, new RuleStore());
    return;
  }

  if (command === 'status') {
    cmdStatus();
    return;
  }

  if (command === 'audit') {
    cmdAudit(rest);
    return;
  }

  console.error(`Unknown command: ${command}\n`);
  console.log(HELP.trimStart());
  process.exit(2);
}
