/**
 * Interactive allow/deny prompts.
 *
 * The proxy's stdin/stdout belong to the MCP protocol, so prompts go to the
 * controlling terminal (/dev/tty) when one is available. On headless setups
 * we return 'unavailable' and the policy mode decides the default action.
 */

import { closeSync, openSync } from 'node:fs';
import * as tty from 'node:tty';

export type TtyAnswer = 'y' | 'n' | 'timeout' | 'unavailable';

export async function askOnTty(question: string, timeoutMs = 20_000): Promise<TtyAnswer> {
  let fd: number | undefined;
  let stream: tty.ReadStream | undefined;
  try {
    fd = openSync('/dev/tty', 'r+');
    stream = new tty.ReadStream(fd);
  } catch {
    return 'unavailable';
  }

  return new Promise<TtyAnswer>((resolve) => {
    let settled = false;
    const finish = (answer: TtyAnswer) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stream!.removeListener('data', onData);
      stream!.pause();
      try {
        if (stream!.isTTY) stream!.setRawMode(false);
        stream!.destroy();
      } catch {
        /* ignore */
      }
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          /* ignore */
        }
      }
      resolve(answer);
    };

    const onData = (chunk: Buffer) => {
      const key = chunk.toString('utf8');
      if (key === 'y' || key === 'Y') finish('y');
      else if (key === 'n' || key === 'N' || key === '\u001b') finish('n');
      else if (key === '\r' || key === '\n') finish('n'); // default: deny
    };

    try {
      if (stream.isTTY) stream.setRawMode(true);
      stream.resume();
      stream.on('data', onData);
    } catch {
      finish('unavailable');
      return;
    }

    process.stderr.write(question);
    const timer = setTimeout(() => {
      process.stderr.write('\n');
      finish('timeout');
    }, timeoutMs);
  });
}
