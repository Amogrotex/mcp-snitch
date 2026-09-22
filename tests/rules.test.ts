import { describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { globMatch, RuleStore } from '../src/rules.js';
import type { Rule } from '../src/types.js';

function store(): RuleStore {
  const dir = mkdtempSync(join(tmpdir(), 'snitch-rules-'));
  return new RuleStore(join(dir, 'rules.json'));
}

const baseRule = (over: Partial<Rule>): Omit<Rule, 'id' | 'created'> => ({
  server: '*',
  tool: '*',
  action: 'allow',
  ...over,
});

describe('globMatch', () => {
  it('matches literals', () => {
    expect(globMatch('read_file', 'read_file')).toBe(true);
    expect(globMatch('read_file', 'write_file')).toBe(false);
  });

  it('supports * wildcards', () => {
    expect(globMatch('read_*', 'read_file')).toBe(true);
    expect(globMatch('read_*', 'write_file')).toBe(false);
    expect(globMatch('*', 'anything')).toBe(true);
  });

  it('supports ? single char', () => {
    expect(globMatch('get?', 'getX')).toBe(true);
    expect(globMatch('get?', 'getFile')).toBe(false);
    expect(globMatch('get?ile', 'getFile')).toBe(true);
  });

  it('escapes regex metacharacters', () => {
    expect(globMatch('a.b', 'a.b')).toBe(true);
    expect(globMatch('a.b', 'axb')).toBe(false);
    expect(globMatch('a+b', 'a+b')).toBe(true);
  });
});

describe('RuleStore', () => {
  it('persists and reloads rules', () => {
    const dir = mkdtempSync(join(tmpdir(), 'snitch-rules-'));
    const file = join(dir, 'rules.json');
    const a = new RuleStore(file);
    a.add(baseRule({ server: 'github', tool: 'delete_*', action: 'deny' }));
    const b = new RuleStore(file);
    expect(b.list()).toHaveLength(1);
    expect(b.list()[0]!.tool).toBe('delete_*');
  });

  it('deny takes precedence over allow', () => {
    const s = store();
    s.add(baseRule({ server: 'github', tool: '*', action: 'allow' }));
    s.add(baseRule({ server: 'github', tool: 'delete_repo', action: 'deny' }));
    const hit = s.match({ server: 'github', tool: 'delete_repo', args: {} });
    expect(hit?.action).toBe('deny');
    const other = s.match({ server: 'github', tool: 'list_repos', args: {} });
    expect(other?.action).toBe('allow');
  });

  it('matches argument patterns', () => {
    const s = store();
    s.add(
      baseRule({
        server: 'fs',
        tool: 'read_file',
        action: 'allow',
        args: { path: '~/projects/**' },
      }),
    );
    expect(
      s.match({ server: 'fs', tool: 'read_file', args: { path: '~/projects/a/b.ts' } })?.action,
    ).toBe('allow');
    expect(
      s.match({ server: 'fs', tool: 'read_file', args: { path: '~/.ssh/id_rsa' } }),
    ).toBeUndefined();
    expect(s.match({ server: 'fs', tool: 'read_file', args: {} })).toBeUndefined();
  });

  it('removes and clears', () => {
    const s = store();
    const r = s.add(baseRule({ action: 'deny', tool: 'danger' }));
    expect(s.remove(r.id)).toBe(true);
    expect(s.remove(r.id)).toBe(false);
    s.add(baseRule({ tool: 'x' }));
    expect(s.clear()).toBe(1);
    expect(s.list()).toHaveLength(0);
  });
});
