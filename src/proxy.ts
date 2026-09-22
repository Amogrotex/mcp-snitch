/**
 * The proxy: client <-> mcp-snitch <-> upstream MCP server.
 *
 * - stdout/stdin of this process carry MCP JSON-RPC with the real client
 * - the upstream server runs as a child process on pipes
 * - outgoing tools/call requests are evaluated by the policy engine
 * - tools/list responses are scanned for injection and diffed for drift
 * - tool results coming back are scanned for indirect prompt injection
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { encode, errorResponse, extractMessages, type RpcMessage } from './rpc.js';
import type { Mode } from './types.js';
import type { RuleStore } from './rules.js';
import type { BaselineStore } from './baseline.js';
import { AuditLog } from './audit.js';
import { alertBanner, desktopNotify } from './notify.js';
import { evaluateCall, type PolicyContext } from './policy.js';
import { redactDeep } from './classify.js';
import { resultText, scanForInjection, scanToolMetadata } from './inject.js';

export interface ProxyOptions {
  /** Name used for baselines/rules/alerts; defaults to the upstream command. */
  serverName: string;
  command: string;
  args: string[];
  mode: Mode;
  rules: RuleStore;
  baseline: BaselineStore;
  audit: AuditLog;
}

type PendingKind = 'call' | 'list' | 'other';

interface PendingCall {
  tool: string;
  args: Record<string, unknown>;
}

export class McpProxy {
  private readonly opts: ProxyOptions;
  private readonly ctx: PolicyContext;
  private child: ChildProcess | undefined;
  private clientBuffer = '';
  private serverBuffer = '';
  private readonly pendingKind = new Map<number | string | null, PendingKind>();
  private readonly pendingCalls = new Map<number | string | null, PendingCall>();
  private readonly flaggedTools = new Set<string>();
  private prompting = false;
  private readonly queuedClient: RpcMessage[] = [];

  constructor(opts: ProxyOptions) {
    this.opts = opts;
    this.ctx = {
      mode: opts.mode,
      rules: opts.rules,
      baseline: opts.baseline,
      flaggedTools: this.flaggedTools,
    };
  }

  start(): void {
    const { command, args, serverName, mode } = this.opts;
    this.opts.audit.write({
      event: 'session_start',
      server: serverName,
      mode,
      command,
      args,
      pid: process.pid,
    });
    alertBanner('info', `session start — “${serverName}” [mode=${mode}]`, [
      `upstream: ${command} ${args.join(' ')}`,
    ]);

    this.child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });

    this.child.stderr?.on('data', (chunk: Buffer) => {
      process.stderr.write(chunk);
    });

    this.child.stdout?.on('data', (chunk: Buffer) => {
      this.onServerData(chunk.toString('utf8'));
    });

    this.child.on('error', (err) => {
      alertBanner('critical', `failed to start upstream: ${err.message}`);
      process.exit(1);
    });

    this.child.on('exit', (code, signal) => {
      this.opts.audit.write({
        event: 'session_end',
        server: serverName,
        code: code ?? null,
        signal: signal ?? null,
      });
      process.exit(code ?? 0);
    });

    process.stdin.on('data', (chunk: Buffer) => {
      this.onClientData(chunk.toString('utf8'));
    });
    process.stdin.on('end', () => {
      this.child?.stdin?.end();
      process.exit(0);
    });
    process.stdin.on('error', () => process.exit(0));
  }

  // ── client -> server ────────────────────────────────────────────────

  private onClientData(text: string): void {
    const { messages, rest } = extractMessages(this.clientBuffer + text);
    this.clientBuffer = rest;
    for (const msg of messages) this.handleClientMessage(msg);
  }

  private handleClientMessage(msg: RpcMessage): void {
    if (msg.method === 'tools/call' && msg.id !== undefined) {
      void this.handleToolCall(msg);
      return;
    }
    if (msg.method === 'tools/list' && msg.id !== undefined) {
      this.pendingKind.set(msg.id, 'list');
    } else if (msg.id !== undefined && msg.method) {
      this.pendingKind.set(msg.id, 'other');
    }
    this.toServer(msg);
  }

  private async handleToolCall(msg: RpcMessage): Promise<void> {
    const id = msg.id!;
    const params = (msg.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
    const tool = params.name ?? '<unknown>';
    const args = params.arguments ?? {};

    // Pause reading from the client while a TTY prompt is up so calls stay in order.
    this.prompting = true;
    process.stdin.pause();

    let evaluation;
    try {
      evaluation = await evaluateCall(this.ctx, { server: this.opts.serverName, tool, args });
    } finally {
      this.prompting = false;
      process.stdin.resume();
    }

    const base = {
      tool,
      args: redactDeep(args),
      decision: evaluation.decision,
      reason: evaluation.reason,
      severity: evaluation.severity,
      summary: evaluation.summary,
    };

    if (evaluation.decision === 'deny') {
      this.opts.audit.write({ event: 'call', server: this.opts.serverName, ...base });
      alertBanner(evaluation.severity, `DENIED ${this.opts.serverName}.${tool}`, [
        evaluation.summary,
        `reason: ${evaluation.reason}`,
        `to allow permanently: mcp-snitch rules add --server ${this.opts.serverName} --tool ${tool} --allow`,
      ]);
      this.toClient(
        errorResponse(id, -32001, `mcp-snitch denied: ${evaluation.summary} (${evaluation.reason})`),
      );
      return;
    }

    this.opts.audit.write({ event: 'call', server: this.opts.serverName, ...base });

    if (evaluation.severity === 'high' || evaluation.severity === 'critical') {
      alertBanner(evaluation.severity, `ALLOWED ${this.opts.serverName}.${tool}`, [
        evaluation.summary,
        `reason: ${evaluation.reason}`,
        `block permanently: mcp-snitch rules add --server ${this.opts.serverName} --tool ${tool} --deny`,
      ]);
      desktopNotify(`mcp-snitch: ${evaluation.severity} call allowed`, evaluation.summary);
    } else if (evaluation.severity === 'medium') {
      alertBanner('medium', `allowed ${this.opts.serverName}.${tool}`, [evaluation.summary]);
    }

    this.pendingKind.set(id, 'call');
    this.pendingCalls.set(id, { tool, args });
    this.toServer(msg);
  }

  // ── server -> client ────────────────────────────────────────────────

  private onServerData(text: string): void {
    const { messages, rest } = extractMessages(this.serverBuffer + text);
    this.serverBuffer = rest;
    for (const msg of messages) this.handleServerMessage(msg);
  }

  private handleServerMessage(msg: RpcMessage): void {
    if (msg.id !== undefined) {
      const kind = this.pendingKind.get(msg.id);

      if (kind === 'list') {
        this.inspectToolList(msg);
        this.pendingKind.delete(msg.id);
      } else if (kind === 'call') {
        this.inspectToolResult(msg);
        this.pendingKind.delete(msg.id);
        this.pendingCalls.delete(msg.id);
      } else {
        this.pendingKind.delete(msg.id);
      }
    }
    this.toClient(msg);
  }

  private inspectToolList(msg: RpcMessage): void {
    const result = msg.result as { tools?: { name: string; description?: string; inputSchema?: unknown }[] } | undefined;
    if (!result || !Array.isArray(result.tools)) return;
    const server = this.opts.serverName;
    const tools = result.tools;

    // 1. Metadata injection scan (tool poisoning lives in descriptions).
    for (const tool of tools) {
      const findings = scanToolMetadata(tool);
      if (findings.length > 0) {
        this.flaggedTools.add(tool.name);
        this.opts.audit.write({
          event: 'description_flag',
          server,
          tool: tool.name,
          findings,
        });
        alertBanner('high', `POISONED DESCRIPTION in ${server}.${tool.name}`, [
          ...findings.map((f) => `${f.pattern}: ${f.excerpt}`),
          'calls to this tool will be treated as high risk',
        ]);
        desktopNotify('mcp-snitch: tool description flagged', `${server}.${tool.name}`);
      }
    }

    // 2. Manifest drift (rug-pull detection).
    const { drift } = this.opts.baseline.recordToolList(server, tools);
    if (drift.length > 0) {
      this.opts.audit.write({ event: 'manifest_drift', server, drift });
      alertBanner('critical', `MANIFEST DRIFT on ${server} — possible rug-pull`, drift);
      desktopNotify('mcp-snitch: tool definitions changed', `${server}: ${drift.join('; ')}`);
    }

    this.opts.audit.write({
      event: 'tool_list',
      server,
      count: tools.length,
      flagged: tools.filter((t) => this.flaggedTools.has(t.name)).map((t) => t.name),
    });
  }

  private inspectToolResult(msg: RpcMessage): void {
    if (msg.error || msg.result === undefined) return;
    const pending = msg.id !== undefined ? this.pendingCalls.get(msg.id) : undefined;
    const text = resultText(msg.result);
    if (!text) return;

    const findings = scanForInjection(text);
    if (findings.length > 0) {
      const tool = pending?.tool ?? 'unknown';
      this.opts.audit.write({
        event: 'inbound_flag',
        server: this.opts.serverName,
        tool,
        findings,
      });
      alertBanner('high', `INBOUND INJECTION attempt from ${this.opts.serverName}.${tool}`, [
        ...findings.map((f) => `${f.pattern}: ${f.excerpt}`),
        'the text reached your model — review the session audit log',
      ]);
      desktopNotify('mcp-snitch: injection blocked from report', `${this.opts.serverName}.${tool}`);
    }
  }

  // ── transport helpers ───────────────────────────────────────────────

  private toServer(msg: RpcMessage): void {
    this.child?.stdin?.write(encode(msg));
  }

  private toClient(msg: RpcMessage): void {
    if (this.prompting) {
      this.queuedClient.push(msg);
      return;
    }
    process.stdout.write(encode(msg));
    // Flush anything queued behind a prompt.
    while (this.queuedClient.length > 0 && !this.prompting) {
      process.stdout.write(encode(this.queuedClient.shift()!));
    }
  }
}
