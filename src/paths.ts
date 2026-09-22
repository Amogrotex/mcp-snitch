/** Filesystem locations: mcp-snitch state lives in one directory. */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { existsSync } from 'node:fs';

export function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) return join(homedir(), p.slice(2));
  return p;
}

export function dataDir(): string {
  return expandHome(process.env['MCP_SNITCH_HOME'] ?? join(homedir(), '.mcp-snitch'));
}

export function rulesPath(): string {
  return join(dataDir(), 'rules.json');
}

export function baselinePath(): string {
  return join(dataDir(), 'baseline.json');
}

export function auditDir(): string {
  return join(dataDir(), 'audit');
}

export function configPath(): string {
  return join(dataDir(), 'config.json');
}

export function installedManifestPath(): string {
  return join(dataDir(), 'installed.json');
}

export interface KnownConfig {
  label: string;
  /** Absolute path with `~` expanded. */
  path: string;
  /** JSON keys that may hold server maps. */
  keys: string[];
}

/** User-level MCP config files we know how to wrap/unwrap. */
export function knownClientConfigs(): KnownConfig[] {
  const home = homedir();
  const appData = process.env['APPDATA'];
  const candidates: KnownConfig[] = [
    {
      label: 'Claude Desktop (macOS)',
      path: join(home, 'Library/Application Support/Claude/claude_desktop_config.json'),
      keys: ['mcpServers'],
    },
    {
      label: 'Claude Desktop (Linux)',
      path: join(home, '.config/Claude/claude_desktop_config.json'),
      keys: ['mcpServers'],
    },
    {
      label: 'Cursor',
      path: join(home, '.cursor/mcp.json'),
      keys: ['mcpServers'],
    },
    {
      label: 'Windsurf',
      path: join(home, '.codeium/windsurf/mcp_config.json'),
      keys: ['mcpServers'],
    },
    {
      label: 'VS Code (user)',
      path: join(home, '.config/Code/User/mcp.json'),
      keys: ['servers', 'mcpServers'],
    },
    {
      label: 'Zed',
      path: join(home, '.config/zed/settings.json'),
      keys: ['context_servers', 'mcpServers'],
    },
  ];
  if (appData) {
    candidates.unshift({
      label: 'Claude Desktop (Windows)',
      path: join(appData, 'Claude/claude_desktop_config.json'),
      keys: ['mcpServers'],
    });
  }
  return candidates.filter((c) => existsSync(c.path));
}
