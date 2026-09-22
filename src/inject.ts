/** Inbound scanning: prompt-injection heuristics for tool descriptions and results. */

import type { InjectionFinding } from './types.js';

interface Pattern {
  id: string;
  re: RegExp;
}

/** Patterns that indicate text is trying to direct the agent, not inform the user. */
const PATTERNS: Pattern[] = [
  { id: 'ignore-instructions', re: /ignore\s+(?:\w+\s+){0,3}?(instructions?|prompts?|rules?)/i },
  { id: 'disguised-instruction', re: /^\s*(note|important|system)\s+to\s+(ai|assistant|model|you)\s*:/im },
  { id: 'do-not-disclose', re: /do\s+not\s+(tell|inform|mention|reveal|show|report)\s+(the\s+)?(user|human|anyone)/i },
  { id: 'hide-activity', re: /without\s+(telling|informing|asking)\s+(the\s+)?(user|human)/i },
  { id: 'exfiltration', re: /exfiltrat(e|ion)|send\s+(the\s+)?(full\s+)?(conversation|history|transcript|contents?)\s+to/i },
  { id: 'instant-call', re: /\b(immediately|right now|first)\s+call\s+\w+/i },
  { id: 'override-safety', re: /disregard\s+(your|the|all)\s+(safety|guidelines?|filters?|previous)/i },
  { id: 'instruction-tags', re: /<\/?(?:system|important|instruction|admin)>/i },
  { id: 'agent-directive', re: /\byou\s+must\s+(now\s+)?(call|run|send|delete|upload|download)\b/i },
  { id: 'credential-harvest', re: /\b(read|cat|fetch)\b.*\b(\.env|\.ssh|id_rsa|credentials|secrets)\b/i },
];

const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/;
const LONG_BASE64_RE = /[A-Za-z0-9+/]{120,}={0,2}/;

function excerptAt(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 50);
  const end = Math.min(text.length, index + length + 50);
  return text.slice(start, end).replace(/\s+/g, ' ').trim();
}

/** Scan free text (tool result, description) for injection signals. */
export function scanForInjection(text: string): InjectionFinding[] {
  const findings: InjectionFinding[] = [];
  if (!text) return findings;

  for (const { id, re } of PATTERNS) {
    const m = re.exec(text);
    if (m) {
      findings.push({ pattern: id, excerpt: excerptAt(text, m.index, m[0].length) });
    }
    if (findings.length >= 5) return findings;
  }

  if (INVISIBLE_RE.test(text)) {
    const m = INVISIBLE_RE.exec(text)!;
    findings.push({
      pattern: 'invisible-unicode',
      excerpt: excerptAt(text, m.index, m[0].length),
    });
  }

  if (LONG_BASE64_RE.test(text)) {
    const m = LONG_BASE64_RE.exec(text)!;
    findings.push({
      pattern: 'base64-blob',
      excerpt: excerptAt(text, m.index, 40) + '…',
    });
  }

  return findings.slice(0, 5);
}

/** Tool metadata is untrusted input — scan descriptions and parameter docs. */
export function scanToolMetadata(tool: {
  name: string;
  description?: string;
  inputSchema?: unknown;
}): InjectionFinding[] {
  const parts: string[] = [];
  if (tool.description) parts.push(tool.description);
  if (tool.inputSchema) parts.push(collectSchemaStrings(tool.inputSchema));
  return scanForInjection(parts.join('\n'));
}

function collectSchemaStrings(schema: unknown): string {
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(schema);
  return out.join('\n');
}

/** Flatten an MCP tool result's content blocks into one scannable string. */
export function resultText(result: unknown): string {
  if (!result || typeof result !== 'object') return '';
  const content = (result as { content?: unknown }).content;
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const block of content) {
    if (block && typeof block === 'object') {
      const b = block as { type?: string; text?: unknown; data?: unknown };
      if (b.type === 'text' && typeof b.text === 'string') parts.push(b.text);
      else if (typeof b.data === 'string') parts.push(b.data);
    }
  }
  return parts.join('\n');
}
