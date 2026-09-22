/** Append-only JSONL audit log, one file per day. */

import { appendFileSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditEvent } from './types.js';
import { auditDir } from './paths.js';
import { redactDeep } from './classify.js';

export class AuditLog {
  readonly dir: string;

  constructor(dir: string = auditDir()) {
    this.dir = dir;
  }

  write(event: Omit<AuditEvent, 'ts'>): void {
    const full = { ts: new Date().toISOString(), ...event } as AuditEvent;
    mkdirSync(this.dir, { recursive: true });
    const day = full.ts.slice(0, 10);
    appendFileSync(join(this.dir, `audit-${day}.jsonl`), JSON.stringify(redactDeep(full)) + '\n', 'utf8');
  }

  /** Return the last `n` events across all audit files. */
  tail(n = 20): AuditEvent[] {
    let files: string[];
    try {
      files = readdirSync(this.dir).filter((f) => f.endsWith('.jsonl')).sort();
    } catch {
      return [];
    }
    const events: AuditEvent[] = [];
    for (const file of files.slice(-5)) {
      try {
        const lines = readFileSync(join(this.dir, file), 'utf8').split('\n').filter(Boolean);
        for (const line of lines) {
          try {
            events.push(JSON.parse(line) as AuditEvent);
          } catch {
            /* skip malformed line */
          }
        }
      } catch {
        /* skip unreadable file */
      }
    }
    return events.slice(-n);
  }
}
