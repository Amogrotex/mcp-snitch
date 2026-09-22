/** Behavioral baselines: what a server usually touches, plus manifest drift. */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname } from 'node:path';
import type { BaselineFile, ServerBaseline } from './types.js';
import { baselinePath } from './paths.js';

function emptyBaseline(): ServerBaseline {
  return {
    tools: [],
    descs: {},
    pathRoots: [],
    domains: [],
    established: false,
    updatedAt: new Date().toISOString(),
  };
}

export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function hashTool(tool: { name: string; description?: string; inputSchema?: unknown }): string {
  return sha256(
    JSON.stringify({
      name: tool.name,
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? {},
    }),
  );
}

/** True if the value looks like a filesystem path (not a URL). */
export function looksLikePath(value: string): boolean {
  if (value.length < 2 || /\s/.test(value)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return false; // URLs are not paths
  return (
    value.startsWith('/') ||
    value.startsWith('~') ||
    value.startsWith('./') ||
    value.startsWith('../') ||
    /^[A-Za-z]:[\\/]/.test(value) ||
    value.includes('/')
  );
}

/**
 * Normalize a path to a coarse root used for anomaly detection:
 * `~/.ssh/id_rsa` -> `~/.ssh`, `/etc/ssh/sshd_config` -> `/etc/ssh`.
 */
export function pathRoot(value: string): string | undefined {
  if (!looksLikePath(value)) return undefined;
  let norm = value.replace(/\\/g, '/');
  // Already tilde-qualified.
  if (norm === '~') return '~';
  if (norm.startsWith('~/')) {
    const parts = norm.slice(2).split('/').filter(Boolean);
    return parts.length > 0 ? `~/${parts[0]}` : '~';
  }
  const home = homedir();
  let underHome = false;
  if (norm === home || norm.startsWith(home + '/')) {
    norm = norm.slice(home.length) || '/';
    underHome = true;
  }
  const parts = norm.split('/').filter(Boolean);
  if (parts.length === 0) return underHome ? '~' : '/';
  if (underHome) return `~/${parts[0]}`;
  return '/' + parts.slice(0, Math.min(2, parts.length)).join('/');
}

export function extractDomain(value: string): string | undefined {
  if (!/^https?:\/\//i.test(value)) return undefined;
  try {
    return new URL(value).hostname;
  } catch {
    return undefined;
  }
}

export class BaselineStore {
  readonly file: string;
  private data: BaselineFile;

  constructor(file: string = baselinePath()) {
    this.file = file;
    if (existsSync(file)) {
      try {
        const parsed = JSON.parse(readFileSync(file, 'utf8')) as BaselineFile;
        this.data = { version: 1, servers: parsed.servers ?? {} };
      } catch {
        this.data = { version: 1, servers: {} };
      }
    } else {
      this.data = { version: 1, servers: {} };
    }
  }

  save(): void {
    mkdirSync(dirname(this.file), { recursive: true });
    writeFileSync(this.file, JSON.stringify(this.data, null, 2) + '\n', 'utf8');
  }

  get(server: string): ServerBaseline {
    this.data.servers[server] ??= emptyBaseline();
    return this.data.servers[server]!;
  }

  /**
   * Record a tools/list response. First sighting establishes the baseline;
   * later sightings are diffed to catch rug-pull drift.
   */
  recordToolList(
    server: string,
    tools: { name: string; description?: string; inputSchema?: unknown }[],
  ): { drift: string[] } {
    const base = this.get(server);
    const descs: Record<string, string> = {};
    for (const t of tools) descs[t.name] = hashTool(t);
    const names = tools.map((t) => t.name);

    const drift: string[] = [];
    if (base.established) {
      for (const name of names) {
        if (!(name in base.descs)) drift.push(`added tool: ${name}`);
        else if (base.descs[name] !== descs[name]) drift.push(`changed definition: ${name}`);
      }
      for (const name of Object.keys(base.descs)) {
        if (!(name in descs)) drift.push(`removed tool: ${name}`);
      }
    }
    base.established = true;
    base.tools = names;
    base.descs = descs;
    base.updatedAt = new Date().toISOString();
    this.save();
    return { drift };
  }

  /** Record path roots and domains observed in a call's arguments. */
  recordCallPaths(server: string, args: Record<string, unknown>): void {
    const base = this.get(server);
    let changed = false;
    for (const value of Object.values(args)) {
      if (typeof value !== 'string') continue;
      const root = pathRoot(value);
      if (root && !base.pathRoots.includes(root)) {
        base.pathRoots.push(root);
        changed = true;
      }
      const domain = extractDomain(value);
      if (domain && !base.domains.includes(domain)) {
        base.domains.push(domain);
        changed = true;
      }
    }
    if (changed) {
      base.updatedAt = new Date().toISOString();
      this.save();
    }
  }

  /** Anomalies relative to the established baseline. Empty on first contact. */
  anomalies(server: string, tool: string, args: Record<string, unknown>): string[] {
    const base = this.get(server);
    if (!base.established) return [];
    const out: string[] = [];
    if (base.tools.length > 0 && !base.tools.includes(tool)) {
      out.push(`unknown tool not in baseline: ${tool}`);
    }
    const seenRoots = new Set<string>();
    const seenDomains = new Set<string>();
    for (const value of Object.values(args)) {
      if (typeof value !== 'string') continue;
      const root = pathRoot(value);
      if (root && !base.pathRoots.includes(root) && !seenRoots.has(root)) {
        seenRoots.add(root);
        out.push(`new path root: ${root}`);
      }
      const domain = extractDomain(value);
      if (domain && !base.domains.includes(domain) && !seenDomains.has(domain)) {
        seenDomains.add(domain);
        out.push(`new domain: ${domain}`);
      }
    }
    return out;
  }

  servers(): string[] {
    return Object.keys(this.data.servers);
  }
}
