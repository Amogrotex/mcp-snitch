/** Minimal JSON-RPC / MCP message helpers (newline-delimited over stdio). */

export interface RpcMessage {
  jsonrpc: '2.0';
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export function isRpcMessage(value: unknown): value is RpcMessage {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<string, unknown>)['jsonrpc'] === '2.0'
  );
}

/**
 * Extract complete newline-terminated JSON messages from a buffer.
 * Returns parsed messages plus the unconsumed remainder.
 */
export function extractMessages(buffer: string): { messages: RpcMessage[]; rest: string } {
  const messages: RpcMessage[] = [];
  let rest = buffer;
  for (;;) {
    const nl = rest.indexOf('\n');
    if (nl === -1) break;
    const line = rest.slice(0, nl).trim();
    rest = rest.slice(nl + 1);
    if (!line) continue;
    try {
      const parsed: unknown = JSON.parse(line);
      if (Array.isArray(parsed)) {
        for (const item of parsed) if (isRpcMessage(item)) messages.push(item);
      } else if (isRpcMessage(parsed)) {
        messages.push(parsed);
      }
    } catch {
      // Non-JSON line (stray stdout from a chatty server): drop it rather than
      // corrupt the client stream. It was never valid MCP traffic.
    }
  }
  return { messages, rest };
}

export function encode(message: RpcMessage): string {
  return JSON.stringify(message) + '\n';
}

export function errorResponse(id: number | string | null, code: number, message: string): RpcMessage {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/** JSON-RPC notifications carry no `id` field. */
export function isNotification(message: RpcMessage): boolean {
  return message.id === undefined;
}
