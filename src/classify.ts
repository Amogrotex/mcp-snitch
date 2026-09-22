/** Heuristic risk classification: turns a tool call into plain language + severity. */

import type { RiskAssessment, Severity } from './types.js';
import { extractDomain, looksLikePath, pathRoot } from './baseline.js';

const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /\.ssh(\/|$)/i,
  /\.aws(\/|$)/i,
  /\.gnupg(\/|$)/i,
  /\.env(\.|$|\/)/i,
  /id_rsa/i,
  /id_ed25519/i,
  /\.npmrc/i,
  /\.netrc/i,
  /credentials/i,
  /secrets?\//i,
  /wallet/i,
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\.git-credentials/,
  /auth\.json/i,
];

const SHELL_PATTERNS =
  /\b(exec|shell|bash|sh_cmd|run_command|run command|spawn|child_process|child process|terminal|powershell|cmd)\b/i;
const DELETE_PATTERNS = /\b(delete|remove|destroy|drop|purge|wipe|erase|unlink|rmdir)\b/i;
const WRITE_PATTERNS =
  /\b(write|update|create|append|upload|publish|post|put|send|insert|patch|modify|move|rename|save)\b/i;
const READ_PATTERNS = /\b(read|get|list|fetch|search|query|find|lookup|show|describe|download)\b/i;

/** `_` and `-` are word characters, so `\bdelete\b` misses `delete_repository`.
 * Match against both the raw name and a separator-normalized form. */
function toolMatches(re: RegExp, tool: string): boolean {
  if (re.test(tool)) return true;
  return re.test(tool.replace(/[_-]+/g, ' '));
}

export function isSensitivePath(value: string): boolean {
  return SENSITIVE_PATH_PATTERNS.some((re) => re.test(value));
}

export function isShellTool(tool: string, args: Record<string, unknown>): boolean {
  if (toolMatches(SHELL_PATTERNS, tool)) return true;
  for (const key of Object.keys(args)) {
    if (/^(cmd|command|script|shell|bash|exec)$/i.test(key)) return true;
  }
  return false;
}

export function isDeleteTool(tool: string): boolean {
  return toolMatches(DELETE_PATTERNS, tool);
}

function severityRank(s: Severity): number {
  switch (s) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    case 'low':
      return 1;
    case 'info':
      return 0;
  }
}

function max(a: Severity, b: Severity): Severity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

/** Pull the most salient string argument out of a call. */
export function salientArg(args: Record<string, unknown>): { key: string; value: string } | undefined {
  const entries = Object.entries(args).filter(([, v]) => typeof v === 'string') as [string, string][];
  if (entries.length === 0) return undefined;
  const preferred = entries.find(([, v]) => /^https?:\/\//i.test(v));
  if (preferred) return { key: preferred[0], value: preferred[1] };
  const pathEntry = entries.find(([, v]) => looksLikePath(v));
  if (pathEntry) return { key: pathEntry[0], value: pathEntry[1] };
  return { key: entries[0]![0], value: entries[0]![1] };
}

export interface ClassifyOptions {
  /** True when the tool's description was flagged as injection-bearing. */
  flagged?: boolean;
  /** Baseline anomalies detected for this call. */
  anomalies?: string[];
}

export function classifyCall(
  server: string,
  tool: string,
  args: Record<string, unknown>,
  opts: ClassifyOptions = {},
): RiskAssessment {
  const tags: string[] = [];
  let severity: Severity = 'info';
  const salient = salientArg(args);
  let path: string | undefined;
  let domain: string | undefined;
  let command: string | undefined;

  // Gather signals from every string argument.
  for (const value of Object.values(args)) {
    if (typeof value !== 'string') continue;
    const d = extractDomain(value);
    if (d) domain = d;
    if (looksLikePath(value) && !path) path = value;
    if (isSensitivePath(value) && !path) path = value;
  }

  const shell = isShellTool(tool, args);
  const del = isDeleteTool(tool);
  const sensitive = (path !== undefined && isSensitivePath(path)) ||
    (salient !== undefined && looksLikePath(salient.value) && isSensitivePath(salient.value));
  const hasUrl = domain !== undefined || /\bhttps?:\/\//i.test(JSON.stringify(args));
  const write = toolMatches(WRITE_PATTERNS, tool);
  const read = toolMatches(READ_PATTERNS, tool) && !write && !del && !shell;

  if (salient && /^(cmd|command|script|shell|bash|exec)$/i.test(salient.key)) {
    command = salient.value;
  } else if (shell && salient) {
    command = salient.value;
  }

  if (shell) {
    tags.push('shell');
    severity = max(severity, 'critical');
  }
  if (del) {
    tags.push('delete');
    severity = max(severity, 'critical');
  }
  if (sensitive) {
    tags.push('sensitive-path');
    severity = max(severity, 'high');
  }
  if (hasUrl) {
    tags.push('network');
    severity = max(severity, 'high');
  }
  if (write) {
    tags.push('write');
    severity = max(severity, 'medium');
  }
  if (read) {
    tags.push('read');
    severity = max(severity, 'low');
  }
  if (opts.flagged) {
    tags.push('flagged-description');
    severity = max(severity, 'high');
  }
  if (opts.anomalies && opts.anomalies.length > 0) {
    tags.push('anomaly');
    severity = max(severity, 'medium');
  }
  if (tags.length === 0) tags.push('unknown');

  return {
    severity,
    summary: plainLanguage(server, tool, { path, domain, command, shell, del, sensitive, write, read, hasUrl, salient }),
    tags,
    path,
    domain,
    command,
  };
}

interface PlainCtx {
  path?: string;
  domain?: string;
  command?: string;
  shell: boolean;
  del: boolean;
  sensitive: boolean;
  write: boolean;
  read: boolean;
  hasUrl: boolean;
  salient?: { key: string; value: string };
}

function plainLanguage(server: string, tool: string, ctx: PlainCtx): string {
  const where = `“${server}”`;
  if (ctx.shell && ctx.command) return `${where} wants to run: ${truncate(ctx.command, 80)}`;
  if (ctx.shell) return `${where} wants to execute a shell command via ${tool}()`;
  if (ctx.del) return `${where} wants to DELETE data via ${tool}()`;
  if (ctx.sensitive && ctx.path) return `${where} wants to access a secrets path (${truncate(ctx.path, 60)})`;
  if (ctx.hasUrl && ctx.domain) return `${where} wants to call an external host (${ctx.domain})`;
  if (ctx.write) return `${where} wants to modify data via ${tool}()`;
  if (ctx.read && ctx.path) return `${where} wants to read ${truncate(ctx.path, 60)}`;
  if (ctx.read) return `${where} wants to read data via ${tool}()`;
  if (ctx.salient) return `${where} calls ${tool}() with ${ctx.salient.key}=${truncate(ctx.salient.value, 60)}`;
  return `${where} calls ${tool}()`;
}

function truncate(value: string, n: number): string {
  return value.length <= n ? value : value.slice(0, n - 1) + '…';
}

/** Redact obvious secrets before anything hits the audit log or terminal. */
export function redactDeep<T>(value: T): T {
  const patterns: RegExp[] = [
    /\bsk-[A-Za-z0-9_-]{10,}/g,
    /\bghp_[A-Za-z0-9]{20,}/g,
    /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
    /\bglpat-[A-Za-z0-9_-]{10,}/g,
    /\bBearer\s+[A-Za-z0-9._~+/=-]{10,}/g,
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  ];
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') {
      let out = v;
      for (const re of patterns) out = out.replace(re, '[REDACTED]');
      return out;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        if (/^(password|token|api_?key|secret|authorization)$/i.test(k) && typeof val === 'string') {
          out[k] = '[REDACTED]';
        } else {
          out[k] = walk(val);
        }
      }
      return out;
    }
    return v;
  };
  return walk(value) as T;
}
