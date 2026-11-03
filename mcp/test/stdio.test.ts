/**
 * The built server as a client starts it: `npm run build:mcp` into a temp dir, then the bundle
 * spawned over stdio with the SDK's minimal environment, against a localhost data server. Also the
 * documented clone command, `npm run -s mcp`, which must print nothing but JSON-RPC to stdout.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MCP_SERVER } from '../../shared/mcp';
import { emptyShard, files } from './fixture';
import { call, connectStdio, fromTree, serveData } from './harness';

const ROOT = resolve(import.meta.dirname, '../..');
let out: string;
let bundle: string;
let data: Awaited<ReturnType<typeof serveData>>;

beforeAll(async () => {
  out = mkdtempSync(join(tmpdir(), 'cverdict-mcp-'));
  execFileSync(process.execPath, [join(ROOT, 'node_modules/vite/bin/vite.js'), 'build', '--config', 'mcp/vite.config.ts'], { cwd: ROOT, env: { ...process.env, MCP_OUT_DIR: out }, stdio: 'pipe' });
  bundle = join(out, 'cverdict-mcp.mjs');
  data = await serveData(fromTree(files(), (p) => (p.startsWith('cve/') ? emptyShard() : undefined)));
}, 60_000);

afterAll(async () => {
  await data?.close();
  rmSync(out, { recursive: true, force: true });
});

describe('the built bundle', () => {
  it('is one file with a node shebang and no imports beyond Node built-ins', () => {
    const src = readFileSync(bundle, 'utf8');
    expect(src.startsWith('#!/usr/bin/env node\n')).toBe(true);
    const imports = [...src.matchAll(/^import .* from "([^"]+)";?$/gm)].map((m) => m[1]);
    expect(imports.every((s) => s.startsWith('node:'))).toBe(true);
    expect(statSync(bundle).size).toBeLessThan(1_500_000);
  });

  for (const mode of [undefined, 'auto'] as const) {
    it(`answers a ${mode ?? 'legacy'} client over stdio`, async () => {
      const s = await connectStdio(process.execPath, [bundle], { CVERDICT_DATA_BASE: data.base });
      try {
        expect(s.client.getServerVersion()?.version).toBe(MCP_SERVER.version);
        expect((await s.client.listTools()).tools).toHaveLength(6);
        const { value } = await call(s.client, 'get_verdict', { ids: ['CVE-2026-10001', 'CVE-2019-0001'] });
        expect((value.items as { found: boolean; tier?: string }[]).map((i) => i.tier ?? i.found)).toEqual(['exploited', false]);
        const files = (value.data as { files: { url: string }[] }).files;
        expect(files.every((f) => f.url.startsWith(data.base))).toBe(true);
        const search = await call(s.client, 'search_cves', { query: 'fortinet' });
        expect(search.value.total).toBe(1);
        expect(s.stderr()).toContain(`${MCP_SERVER.npm} ${MCP_SERVER.version} on Node ${process.version}`);
      } finally {
        await s.close();
      }
    }, 30_000);
  }

  it('refuses a data base that is not https or localhost, with nothing on stdout', () => {
    const r = spawnSync(process.execPath, [bundle], { env: { PATH: process.env.PATH, CVERDICT_DATA_BASE: 'http://169.254.169.254/v1/' }, input: '', encoding: 'utf8' });
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('CVERDICT_DATA_BASE: use https (or http on localhost)');
  });
});

describe('npm run -s mcp, from a clone', () => {
  it('serves the same tools with nothing else on stdout', async () => {
    const s = await connectStdio('npm', ['--prefix', ROOT, 'run', '-s', 'mcp'], { CVERDICT_DATA_BASE: data.base });
    try {
      expect((await s.client.listTools()).tools.map((t) => t.name)).toContain('get_verdict');
      // Not kev_due: its default window follows the wall clock, the fixture does not.
      const { value } = await call(s.client, 'list_signal', {});
      expect(value.total).toBe(3);
    } finally {
      await s.close();
    }
  }, 60_000);
});
