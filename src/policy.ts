/**
 * Policy engine: rules + risk classification + baseline anomalies + mode.
 *
 * Order of operations for an outgoing tools/call:
 *   1. mode 'off'            -> allow everything
 *   2. explicit deny rule    -> deny
 *   3. explicit allow rule   -> allow (still audited)
 *   4. severity from classify + anomalies + flagged descriptions:
 *        learn  -> critical/high prompt on TTY, otherwise allow + alert
 *        strict -> critical/high deny (or prompt on TTY), medium prompt/deny
 */

import type { Evaluation, Mode, ToolCall } from './types.js';
import type { RuleStore } from './rules.js';
import type { BaselineStore } from './baseline.js';
import { classifyCall } from './classify.js';
import { askOnTty } from './tty.js';

export interface PolicyContext {
  mode: Mode;
  rules: RuleStore;
  baseline: BaselineStore;
  /** Tool names whose descriptions were flagged at tools/list time. */
  flaggedTools: Set<string>;
}

export async function evaluateCall(ctx: PolicyContext, call: ToolCall): Promise<Evaluation> {
  const { mode, rules, baseline } = ctx;

  if (mode === 'off') {
    return allow('mode: off', 'info', 'mcp-snitch is in off mode');
  }

  const rule = rules.match(call);
  if (rule?.action === 'deny') {
    return {
      decision: 'deny',
      reason: `rule ${rule.id}${rule.note ? ` (${rule.note})` : ''}`,
      source: 'rule',
      severity: 'high',
      summary: `denied by your rule for ${rule.tool}`,
      rule,
    };
  }
  if (rule?.action === 'allow') {
    return {
      decision: 'allow',
      reason: `rule ${rule.id}${rule.note ? ` (${rule.note})` : ''}`,
      source: 'rule',
      severity: 'info',
      summary: `allowed by your rule for ${rule.tool}`,
      rule,
    };
  }

  const anomalies = baseline.anomalies(call.server, call.tool, call.args);
  const risk = classifyCall(call.server, call.tool, call.args, {
    flagged: ctx.flaggedTools.has(call.tool),
    anomalies,
  });

  const extra = [
    risk.summary,
    ...(anomalies.length ? [`anomaly: ${anomalies.join('; ')}`] : []),
    ...(risk.tags.length ? [`tags: ${risk.tags.join(', ')}`] : []),
  ];

  const needsPrompt =
    risk.severity === 'critical' ||
    risk.severity === 'high' ||
    (mode === 'strict' && risk.severity === 'medium');

  if (needsPrompt) {
    const answer = await askOnTty(
      `\n mcp-snitch · ${risk.severity.toUpperCase()} — allow this call? [y]es / [N]o  ` +
        `${call.server}.${call.tool}\n   ${risk.summary}\n   ▸ `,
    );
    if (answer === 'y') {
      return {
        decision: 'allow',
        reason: 'approved interactively on tty',
        source: 'tty',
        severity: risk.severity,
        summary: risk.summary,
      };
    }
    if (answer === 'n' || answer === 'timeout') {
      return {
        decision: 'deny',
        reason: answer === 'timeout' ? 'no answer within 20s (default deny)' : 'denied interactively',
        source: 'tty',
        severity: risk.severity,
        summary: risk.summary,
      };
    }
    // No TTY (headless / CI): fall back to mode defaults below.
    if (mode === 'strict') {
      return {
        decision: 'deny',
        reason: `strict mode: ${risk.severity} risk without an allow rule`,
        source: 'mode',
        severity: risk.severity,
        summary: risk.summary,
      };
    }
  }

  return {
    decision: 'allow',
    reason:
      risk.severity === 'low' || risk.severity === 'info'
        ? 'learn mode: routine call'
        : `learn mode: alerted on ${risk.severity} risk`,
    source: 'policy',
    severity: risk.severity,
    summary: `${risk.summary}${extra.length > 1 ? ` (${extra.slice(1).join(' | ')})` : ''}`,
  };
}

function allow(reason: string, severity: Evaluation['severity'], summary: string): Evaluation {
  return { decision: 'allow', reason, source: 'mode', severity, summary };
}
