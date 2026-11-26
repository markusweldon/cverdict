import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MCP_MSG } from '../../shared/mcp';
import { DataClient, type DataCall } from '../src/data';
import { DEPENDENCIES_BUDGET, InputError, checkDependencies, dependencyPaths } from '../src/tools';
import { npmLock, olderFile, packagesFile, tree } from '../../cli/test/fixture';
import { GEN, NOW, fakeFetch, files } from './fixture';

const BASE = 'https://data.test/v1/';
const LOCK = npmLock({ lodash: '4.17.20', minimist: '1.2.5', 'left-pad': '1.3.0', express: '4.18.2' });

function setup(o: { older?: boolean } = {}) {
  const t = files();
  t.set('packages.json', { ...packagesFile(), generated_at: GEN });
  if (o.older !== false) t.set('packages-older.json', olderFile(GEN));
  const f = fakeFetch(t, [BASE]);
  const dc = new DataClient({ bases: [BASE], fetch: f.fetch, now: () => NOW });
  return { log: f.log, run: <T>(fn: (c: DataCall) => Promise<T>) => dc.run(fn) };
}

describe('check_dependencies', () => {
  const root = tree({ 'package-lock.json': LOCK, 'api/requirements.txt': 'requests==2.28.0\nflask==3.0.0\n', 'node_modules/x/package-lock.json': LOCK, 'secret.txt': 'token=abc' });

  it('reads the project, ranks findings by tier, and says what each needs', async () => {
    const r = await setup().run((c) => checkDependencies(c, {}, NOW, root));
    expect(r.items.map((i) => [i.group, i.cve, i.package, i.version, i.fixed_in, i.file, i.tracked])).toEqual([
      ['exploited', 'CVE-2026-1001', 'lodash', '4.17.20', '4.17.21', 'package-lock.json', true],
      ['likely', 'CVE-2019-3001', 'flask', '3.0.0', '3.0.1', 'api/requirements.txt', false],
      ['likely', 'CVE-2026-1002', 'requests', '2.28.0', '2.31.0', 'api/requirements.txt', true],
      ['watch', 'CVE-2026-1003', 'minimist', '1.2.5', '1.2.6', 'package-lock.json', true],
    ]);
    expect(r.counts).toEqual({ exploited: 1, likely: 2, watch: 1, quiet: 1, possible: 0 });
    expect(r.items[1].url).toBe('https://www.cve.org/CVERecord?id=CVE-2019-3001');
    expect(r.items[0].url).toBe('https://cverdict.dev/cve/CVE-2026-1001');
    expect(r.files.map((f) => f.path)).toEqual(['package-lock.json', 'api/requirements.txt']);
    expect(r.coverage).toEqual({ tracked_cves: 4, older_cves: 1, advisories: 5, older_missing: null });
    expect(r.note).toBeNull();
    expect(r.data.files.map((f) => f.path)).toEqual(['v1/meta.json', 'v1/packages.json', 'v1/packages-older.json']);
    // Quiet findings are counted, and listed only when asked.
    const all = await setup().run((c) => checkDependencies(c, { paths: ['package-lock.json'], include_quiet: true, knob: 45 }, NOW, root));
    expect(all.items.map((i) => [i.group, i.cve])).toEqual([
      ['exploited', 'CVE-2026-1001'],
      ['likely', 'CVE-2026-1003'],
      ['quiet', 'CVE-2026-1004'],
    ]);
  });

  it('checks the tracked CVEs alone when the older file is not published, and says so', async () => {
    const r = await setup({ older: false }).run((c) => checkDependencies(c, { paths: ['api'] }, NOW, root));
    expect(r.items.map((i) => i.cve)).toEqual(['CVE-2026-1002']);
    expect(r.coverage.older_missing).toBe('packages-older.json is not published in this data');
    expect(r.note).toBe(MCP_MSG.olderMissing('packages-older.json is not published in this data'));
    expect(r.scope).toMatch(/^Tracked CVEs only/);
  });

  it('reads only lockfiles and SBOMs inside the working directory', async () => {
    const outside = tree({ 'package-lock.json': LOCK });
    symlinkSync(outside, join(root, 'link-out'));
    const t = setup();
    for (const [p, msg] of [
      ['secret.txt', MCP_MSG.notCheckable('secret.txt')],
      ['../', MCP_MSG.outsideRoot('../')],
      [outside, MCP_MSG.outsideRoot(outside)],
      ['link-out', MCP_MSG.outsideRoot('link-out')],
      ['link-out/package-lock.json', MCP_MSG.outsideRoot('link-out/package-lock.json')],
    ] as const) {
      await expect(t.run((c) => checkDependencies(c, { paths: [p] }, NOW, root))).rejects.toThrow(msg);
    }
    await expect(t.run((c) => checkDependencies(c, { paths: ['docs'] }, NOW, root))).rejects.toThrow(InputError);
    expect(dependencyPaths([join(root, 'api')], root)).toEqual(['api']);
  });

  it('never quotes a file in its errors', async () => {
    const dir = tree({ 'package-lock.json': '{"lockfileVersion": 3, "secret": "hunter2", oops}' });
    const r = await setup().run((c) => checkDependencies(c, {}, NOW, dir));
    expect(r.files).toEqual([{ path: 'package-lock.json', format: null, packages: 0, error: 'This looks like JSON, but it could not be read.' }]);
    expect(JSON.stringify(r)).not.toContain('hunter2');
  });

  it('cuts the least urgent findings to fit the size budget, and says so', async () => {
    const big = tree({});
    const names = Array.from({ length: 1200 }, (_, i) => `pkg-${i}`);
    mkdirSync(join(big, 'app'));
    writeFileSync(join(big, 'app', 'package-lock.json'), npmLock(Object.fromEntries(names.map((n) => [n, '1.0.0']))));
    const t = files();
    const p = packagesFile();
    p.packages.npm = Object.fromEntries(names.map((n) => [n, [['CVE-2026-1003', 'GHSA-mmmm-mmmm-mmmm', [['>=0', '<1.2.6']]]]]));
    t.set('packages.json', { ...p, generated_at: GEN });
    const dc = new DataClient({ bases: [BASE], fetch: fakeFetch(t, [BASE]).fetch, now: () => NOW });
    const r = await dc.run((c) => checkDependencies(c, {}, NOW, big));
    expect(r.total).toBe(1200);
    expect(r.omitted).toBeGreaterThan(0);
    expect(r.items.length + r.omitted).toBe(1200);
    expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThanOrEqual(DEPENDENCIES_BUDGET);
    expect(r.note).toContain(MCP_MSG.dependenciesCut(r.items.length, 1200));
  });
});
