/**
 * Test helpers shared by the spawn tests and the CI smoke script: a localhost data server (gzip
 * when asked, like raw.githubusercontent.com) and an SDK client that starts a stdio server the way
 * MCP clients do, with the SDK's minimal environment plus the variables given.
 */
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { resolve, sep } from 'node:path';
import { gzipSync } from 'node:zlib';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

/** Serves `/v1/<path>` from `lookup`; 404 when it returns undefined. */
export async function serveData(lookup: (path: string) => Promise<Buffer | undefined>): Promise<{ base: string; requests: string[]; close: () => Promise<void> }> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    const path = decodeURIComponent((req.url ?? '').split('?')[0]).replace(/^\/v1\//, '');
    requests.push(path);
    void lookup(path).then(
      (body) => {
        if (!body) return void res.writeHead(404).end();
        const gzip = /\bgzip\b/.test(String(req.headers['accept-encoding'] ?? ''));
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', ...(gzip ? { 'content-encoding': 'gzip' } : {}) });
        res.end(gzip ? gzipSync(body) : body);
      },
      () => res.writeHead(500).end(),
    );
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return { base: `http://127.0.0.1:${port}/v1/`, requests, close: () => new Promise((r) => server.close(() => r())) };
}

/** A data tree held in memory (path under v1/ to JSON value). */
export const fromTree = (tree: Map<string, unknown>, fallback?: (path: string) => unknown) => async (path: string) => {
  const v = tree.get(path) ?? fallback?.(path);
  return v === undefined ? undefined : Buffer.from(JSON.stringify(v));
};

/** A data tree on disk (`<dir>/v1/...`), refusing paths outside it. */
export const fromDir = (dir: string) => async (path: string) => {
  const root = resolve(dir, 'v1');
  const file = resolve(root, path);
  if (!file.startsWith(root + sep)) return undefined;
  return readFile(file).catch(() => undefined);
};

/** Starts `command args` as a stdio MCP server and connects the SDK client to it. */
export async function connectStdio(command: string, args: string[], env: Record<string, string>, opts: { cwd?: string; mode?: 'auto' } = {}) {
  const transport = new StdioClientTransport({ command, args, env, cwd: opts.cwd, stderr: 'pipe' });
  let stderr = '';
  transport.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
  const client = new Client({ name: 'cverdict-test', version: '0' }, opts.mode ? { versionNegotiation: { mode: opts.mode } } : {});
  await client.connect(transport);
  return { client, stderr: () => stderr, close: () => client.close() };
}

export type CallResult = { isError?: boolean; content: { type: string; text: string }[]; structuredContent?: unknown };

/** Calls a tool and checks the result carries structuredContent and the same JSON as text. */
export async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<{ result: CallResult; value: Record<string, unknown> }> {
  const result = (await client.callTool({ name, arguments: args })) as CallResult;
  if (result.isError) throw new Error(`${name} answered isError: ${result.content[0]?.text}`);
  const value = JSON.parse(result.content[0].text) as Record<string, unknown>;
  if (JSON.stringify(value) !== JSON.stringify(result.structuredContent)) throw new Error(`${name}: structuredContent differs from the text block`);
  return { result, value };
}
