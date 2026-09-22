/**
 * Install / uninstall: wrap MCP client configs so every server runs through
 * `mcp-snitch run`. Originals are backed up next to the config file and
 * recorded in installed.json for clean removal.
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { KnownConfig } from './paths.js';
import { installedManifestPath, knownClientConfigs } from './paths.js';

interface ServerEntry {
  command?: string;
  args?: string[];
  url?: string;
  [key: string]: unknown;
}

interface Manifest {
  version: number;
  files: string[];
  installedAt: string;
}

const SERVER_MAP_KEYS = ['mcpServers', 'servers', 'context_servers'] as const;

function loadManifest(): Manifest | null {
  const file = installedManifestPath();
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Manifest;
  } catch {
    return null;
  }
}

function saveManifest(files: string[]): void {
  const file = installedManifestPath();
  mkdirSync(dirname(file), { recursive: true });
  const manifest: Manifest = { version: 1, files, installedAt: new Date().toISOString() };
  writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
}

function wrapEntry(name: string, entry: ServerEntry): ServerEntry | null {
  if (entry.command === 'mcp-snitch') return null; // already wrapped
  if (!entry.command) return null; // remote (url-based) server — not supported yet
  const wrapped: ServerEntry = {
    ...entry,
    command: 'mcp-snitch',
    args: ['run', '--name', name, '--', entry.command, ...(entry.args ?? [])],
  };
  return wrapped;
}

function unwrapEntry(entry: ServerEntry): ServerEntry | null {
  if (entry.command !== 'mcp-snitch') return null;
  const args = entry.args ?? [];
  const sep = args.indexOf('--');
  if (sep === -1 || sep + 1 >= args.length) return null;
  const { ['run']: _run, ...rest } = entry as ServerEntry & Record<string, unknown>;
  void _run;
  const out: ServerEntry = { ...rest, command: args[sep + 1]!, args: args.slice(sep + 2) };
  delete out['run'];
  return out;
}

function processConfig(
  config: KnownConfig,
  mode: 'install' | 'uninstall',
  dryRun: boolean,
): string[] {
  const notes: string[] = [];
  if (!existsSync(config.path)) return notes;

  let raw: string;
  try {
    raw = readFileSync(config.path, 'utf8');
  } catch (e) {
    return [`${config.label}: unreadable (${(e as Error).message})`];
  }

  let json: Record<string, unknown>;
  try {
    json = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return [`${config.label}: not valid JSON, skipped`];
  }

  let changed = false;
  const touchedKeys: string[] = [];

  for (const key of SERVER_MAP_KEYS) {
    const map = json[key];
    if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
    const servers = map as Record<string, ServerEntry>;
    for (const [name, entry] of Object.entries(servers)) {
      if (mode === 'install') {
        const wrapped = wrapEntry(name, entry);
        if (wrapped) {
          servers[name] = wrapped;
          changed = true;
          notes.push(`${config.label}: wrapped “${name}”`);
          touchedKeys.push(key);
        } else if (entry.command === 'mcp-snitch') {
          notes.push(`${config.label}: “${name}” already wrapped`);
        } else {
          notes.push(`${config.label}: “${name}” is a remote server — not supported yet, skipped`);
        }
      } else {
        const unwrapped = unwrapEntry(entry);
        if (unwrapped) {
          servers[name] = unwrapped;
          changed = true;
          notes.push(`${config.label}: restored “${name}”`);
          touchedKeys.push(key);
        }
      }
    }
  }

  if (!changed) return notes;

  if (!dryRun) {
    if (mode === 'install') {
      const backup = config.path + '.mcp-snitch.bak';
      if (!existsSync(backup)) copyFileSync(config.path, backup);
    }
    writeFileSync(config.path, JSON.stringify(json, null, 2) + '\n', 'utf8');
  } else {
    notes.push(`${config.label}: (dry-run — no changes written)`);
  }

  if (mode === 'install' && !dryRun) {
    const manifest = loadManifest() ?? { version: 1, files: [], installedAt: '' };
    if (!manifest.files.includes(config.path)) manifest.files.push(config.path);
    saveManifest(manifest.files);
  }

  void touchedKeys;
  return notes;
}

export function install(dryRun = false): string[] {
  const configs = knownClientConfigs();
  if (configs.length === 0) {
    return ['No MCP client config files found. Create one (e.g. ~/.cursor/mcp.json) and re-run.'];
  }
  const notes = configs.flatMap((c) => processConfig(c, 'install', dryRun));
  return notes.length > 0 ? notes : ['No server entries found to wrap.'];
}

export function uninstall(dryRun = false): string[] {
  const manifest = loadManifest();
  const notes: string[] = [];

  // Prefer the manifest; fall back to scanning known configs.
  const targets = manifest
    ? knownClientConfigs().filter((c) => manifest.files.includes(c.path))
    : knownClientConfigs();

  for (const config of targets) {
    notes.push(...processConfig(config, 'uninstall', dryRun));
  }

  if (manifest && !dryRun) {
    const file = installedManifestPath();
    if (existsSync(file)) {
      // Clear manifest so a later install re-wraps cleanly.
      writeFileSync(file, JSON.stringify({ version: 1, files: [], installedAt: '' }, null, 2) + '\n');
    }
    notes.push('Backups left in place (*.mcp-snitch.bak) — delete them if no longer needed.');
  }

  return notes.length > 0 ? notes : ['Nothing to uninstall.'];
}
