/** Shared types for mcp-snitch. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Decision = 'allow' | 'deny';
export type Mode = 'learn' | 'strict' | 'off';

export interface Rule {
  id: string;
  /** Glob over server name, `*` matches all. */
  server: string;
  /** Glob over tool name, e.g. `read_*`. */
  tool: string;
  action: Decision;
  /** Optional per-argument glob constraints: every entry must match. */
  args?: Record<string, string>;
  note?: string;
  created: string;
}

export interface RulesFile {
  version: number;
  rules: Rule[];
}

export interface ToolCall {
  server: string;
  tool: string;
  args: Record<string, unknown>;
}

export interface Evaluation {
  decision: Decision;
  reason: string;
  source: 'rule' | 'mode' | 'baseline' | 'policy' | 'tty';
  severity: Severity;
  summary: string;
  rule?: Rule;
}

export interface RiskAssessment {
  severity: Severity;
  summary: string;
  tags: string[];
  path?: string;
  domain?: string;
  command?: string;
}

export interface InjectionFinding {
  pattern: string;
  excerpt: string;
}

export interface ServerBaseline {
  /** Tool names seen at baseline time. */
  tools: string[];
  /** tool name -> sha256 of description + inputSchema (rug-pull detection). */
  descs: Record<string, string>;
  /** Normalized path prefixes this server has touched, e.g. `~/.ssh`. */
  pathRoots: string[];
  /** Hostnames this server's arguments have referenced. */
  domains: string[];
  /** True once a tools/list response has been recorded. */
  established: boolean;
  updatedAt: string;
}

export interface BaselineFile {
  version: number;
  servers: Record<string, ServerBaseline>;
}

export interface AuditEvent {
  ts: string;
  event:
    | 'session_start'
    | 'session_end'
    | 'call'
    | 'tool_list'
    | 'manifest_drift'
    | 'inbound_flag'
    | 'description_flag';
  server: string;
  [key: string]: unknown;
}
