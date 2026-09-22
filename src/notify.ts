/** Alerts: a colored block on stderr (stdout belongs to MCP) + best-effort OS notification. */

import { spawn } from 'node:child_process';
import type { Severity } from './types.js';

const COLORS: Record<Severity, string> = {
  critical: '\x1b[41;97m', // red background
  high: '\x1b[45;97m', // magenta
  medium: '\x1b[43;30m', // yellow
  low: '\x1b[46;30m', // cyan
  info: '\x1b[40;97m', // gray
};
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

function stderrIsTty(): boolean {
  return process.stderr.isTTY === true && process.env['NO_COLOR'] === undefined;
}

export function alertBanner(severity: Severity, title: string, lines: string[] = []): void {
  const color = stderrIsTty() ? COLORS[severity] : '';
  const reset = stderrIsTty() ? RESET : '';
  const dim = stderrIsTty() ? DIM : '';
  const tag = severity.toUpperCase().padEnd(8);
  const out: string[] = [];
  out.push(`${color} mcp-snitch · ${tag} ${reset} ${title}`);
  for (const line of lines) out.push(`  ${dim}│${reset} ${line}`);
  process.stderr.write(out.join('\n') + '\n');
}

/** Fire a desktop notification if the platform supports it; never fail the proxy. */
export function desktopNotify(title: string, body: string): void {
  if (process.env['MCP_SNITCH_NOTIFY'] === 'off') return;
  try {
    let child;
    if (process.platform === 'darwin') {
      const script = `display notification ${JSON.stringify(body)} with title ${JSON.stringify(title)}`;
      child = spawn('osascript', ['-e', script], { stdio: 'ignore', detached: true });
    } else if (process.platform === 'linux') {
      child = spawn('notify-send', ['--app-name=mcp-snitch', title, body], {
        stdio: 'ignore',
        detached: true,
      });
    } else {
      return;
    }
    // The binary may not exist (ENOENT fires async as an 'error' event).
    child.on('error', () => undefined);
    child.unref();
  } catch {
    /* notifications are best-effort */
  }
}
