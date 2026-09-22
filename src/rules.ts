/** Rule store: JSON file of allow/deny rules with glob matching. */

import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Rule, RulesFile, ToolCall } from './types.js';
import { rulesPath } from './paths.js';

/** Translate a glob (`*` = any chars, `?` = one char) into an anchored RegExp. */
export function globToRegExp(glob: string): RegExp {
  let pattern = '';
  for (const ch of glob) {
    if (ch === '*') pattern += '.*';
    else if (ch === '?') pattern += '.';
    else if ('.+^${}()|[]\\/'.includes(ch)) pattern += '\\' + ch;
    else pattern += ch;
  }
  return new RegExp(`^${pattern}$`);
}

export function globMatch(glob: string, value: string): boolean {
  return globToRegExp(glob).test(value);
}

export function ruleMatches(rule: Rule, call: ToolCall): boolean {
  if (!globMatch(rule.server, call.server)) return false;
  if (!globMatch(rule.tool, call.tool)) return false;
  if (rule.args) {
    for (const [key, pattern] of Object.entries(rule.args)) {
      const actual = call.args[key];
      if (typeof actual !== 'string') return false;
      if (!globMatch(pattern, actual)) return false;
    }
  }
  return true;
}

export class RuleStore {
  readonly file: string;
  private data: RulesFile;

  constructor(file: string = rulesPath()) {
    this.file = file;
    this.data = RuleStore.load(file);
  }

  private static load(file: string): RulesFile {
    if (!existsSync(file)) return { version: 1, rules: [] };
    try {
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as RulesFile;
      if (!Array.isArray(parsed.rules)) return { version: 1, rules: [] };
      return { version: parsed.version ?? 1, rules: parsed.rules };
    } catch {
      return { version: 1, rules: [] };
    }
  }

  save(): void {
    mkdirSync(dirname(this.file), { recursive: true });
    writeFileSync(this.file, JSON.stringify(this.data, null, 2) + '\n', 'utf8');
  }

  list(): Rule[] {
    return [...this.data.rules];
  }

  add(partial: Omit<Rule, 'id' | 'created'>): Rule {
    const rule: Rule = {
      id: randomUUID().slice(0, 8),
      created: new Date().toISOString(),
      ...partial,
    };
    this.data.rules.push(rule);
    this.save();
    return rule;
  }

  remove(id: string): boolean {
    const before = this.data.rules.length;
    this.data.rules = this.data.rules.filter((r) => r.id !== id);
    const changed = this.data.rules.length !== before;
    if (changed) this.save();
    return changed;
  }

  clear(): number {
    const n = this.data.rules.length;
    this.data.rules = [];
    this.save();
    return n;
  }

  /** Deny takes precedence over allow; otherwise first match wins. */
  match(call: ToolCall): Rule | undefined {
    const matches = this.data.rules.filter((r) => ruleMatches(r, call));
    return matches.find((r) => r.action === 'deny') ?? matches.find((r) => r.action === 'allow');
  }
}
