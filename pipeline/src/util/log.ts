import type { Logger } from '../types';

type Level = 'info' | 'warn' | 'error';

export interface LoggerOptions {
  /** Line sink; defaults to stderr so stdout stays free for machine-readable output. */
  write?: (line: string) => void;
  clock?: () => Date;
}

// Line breaks (CI runners also split on a lone CR), other C0/C1 controls and Unicode line separators.
const CONTROL_RE = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F\u2028\u2029]/g;
const ESCAPES: Readonly<Record<string, string>> = { '\n': '\\n', '\r': '\\r' };

/**
 * Keep text on one line by writing control characters as visible escapes ("\r", "\u001b").
 * Messages can quote upstream bytes; a raw line break would let them start a line of their own,
 * which GitHub Actions reads as a workflow command (`::warning ::…`).
 */
export function escapeControls(text: string): string {
  return text.replace(CONTROL_RE, (ch) => ESCAPES[ch] ?? `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** Timestamped, levelled logger: `2026-10-26T19:30:00.000Z INFO  message`. One call, one line. */
export function createLogger(options: LoggerOptions = {}): Logger {
  const write = options.write ?? ((line: string) => void process.stderr.write(line));
  const clock = options.clock ?? (() => new Date());
  const emit = (level: Level, msg: string) => write(`${clock().toISOString()} ${level.toUpperCase().padEnd(5)} ${escapeControls(msg)}\n`);
  return {
    info: (msg) => emit('info', msg),
    warn: (msg) => emit('warn', msg),
    error: (msg) => emit('error', msg),
  };
}

/** Human-readable duration since `startMs` (a `performance.now()` reading), e.g. "1.25s". */
export function since(startMs: number): string {
  const ms = performance.now() - startMs;
  return ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(2)}s`;
}

/** Human-readable byte count, e.g. "1.8 MB". */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
