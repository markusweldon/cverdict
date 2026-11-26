import { readFileSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SCHEMA_VERSION } from '../../shared/contract';
import { runAction, input, optionsFromInputs, outputLines } from '../src/action';
import { parseCli } from '../src/args';
import { checkFiles, countByGroup, failing, lineFinder, lowestFix } from '../src/check';
import { DataError, checkPackagesFile, loadPackages, urlFor } from '../src/data';
import { discover, isCheckable } from '../src/discover';
import { data, md, prop, toAnnotations, toJson, toMarkdown, toSarif, toText } from '../src/report';
import { DEFAULTS, run, type Options } from '../src/run';
import { VERSION } from '../src/version';
import { GEN, dataDir, dataDirWithOlder, npmLock, olderFile, packagesFile, tree } from './fixture';

const LOCK = npmLock({ lodash: '4.17.20', requests: '0', minimist: '1.2.5', 'left-pad': '1.3.0', express: '4.18.2' });
const REQS = 'requests==2.28.0\nflask==3.0.0\n';

const noFetch = (() => Promise.reject(new Error('no network in tests'))) as unknown as typeof fetch;
const io = () => {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (s: string) => void out.push(s), err: (s: string) => void err.push(s), fetch: noFetch } };
};
const opts = (cwd: string, o: Partial<Options> = {}): Options => ({ ...DEFAULTS, data: dataDir(), cwd, ...o });

describe('discover', () => {
  it('finds lockfiles and SBOMs, skips dependency and build folders, and go.sum next to go.mod', () => {
    const root = tree({
      'package-lock.json': LOCK,
      'node_modules/x/package-lock.json': LOCK,
      'svc/requirements-dev.txt': REQS,
      'svc/go.mod': 'module x\n',
      'svc/go.sum': '',
      'other/go.sum': '',
      'sbom/app.cdx.json': '{}',
      'target/bom.json': '{}',
      'README.md': '# hi',
      'package.json': '{}',
    });
    const d = discover(['.'], root);
    expect(d.files).toEqual(['package-lock.json', 'other/go.sum', 'sbom/app.cdx.json', 'svc/go.mod', 'svc/requirements-dev.txt']);
    expect(d.skipped).toEqual(['svc/go.sum']);
    expect(discover(['README.md', 'nope.lock'], root)).toMatchObject({ files: ['README.md'], missing: ['nope.lock'] });
    expect(discover([join(root, 'svc')], root).files).toEqual(['svc/go.mod', 'svc/requirements-dev.txt']);
  });

  it('never follows a symbolic link to a folder, and stops at the file cap', () => {
    const root = tree({ 'a/yarn.lock': '', 'b/yarn.lock': '', 'c/yarn.lock': '' });
    symlinkSync(join(root, 'a'), join(root, 'loop'));
    expect(discover(['.'], root).files).toEqual(['a/yarn.lock', 'b/yarn.lock', 'c/yarn.lock']);
    expect(discover(['.'], root, { depth: 12, files: 2 })).toMatchObject({ files: ['a/yarn.lock', 'b/yarn.lock'], truncated: true });
  });

  it('knows the SBOM names', () => {
    expect(['bom.json', 'bom.xml', 'sbom.json', 'sbom-app.json', 'x.cdx.xml', 'x.spdx', 'x.spdx.json', 'gradle.lockfile'].every(isCheckable)).toBe(true);
    expect(['package.json', 'bom.txt', 'notes.json'].some(isCheckable)).toBe(false);
  });
});

describe('data', () => {
  it('reads a data folder, a file, and a URL, and checks the schema', async () => {
    const dir = dataDir();
    expect((await loadPackages(dir)).from).toBe(join(dir, 'v1', 'packages.json'));
    expect((await loadPackages(join(dir, 'v1', 'packages.json'))).file.generated_at).toBe(GEN);
    const body = JSON.stringify(packagesFile());
    const seen: string[] = [];
    const ok = (async (url: string) => {
      seen.push(url);
      return new Response(body);
    }) as unknown as typeof fetch;
    expect((await loadPackages('https://mirror.example/v1', ok)).from).toBe('https://mirror.example/v1/packages.json');
    expect(seen).toEqual(['https://mirror.example/v1/packages.json', 'https://mirror.example/v1/packages-older.json']);
    expect(checkPackagesFile({ ...packagesFile(), schema_version: SCHEMA_VERSION + 1 })).toMatch(/schema_version/);
    expect(checkPackagesFile({ ...packagesFile(), cves: { cols: ['__proto__'], rows: [] } })).toMatch(/columns/);
    expect(urlFor('https://x/v1/')).toBe('https://x/v1/packages.json');
    expect(urlFor('https://x/v1/packages.json')).toBe('https://x/v1/packages.json');
  });

  it('tries each default base, and says why each failed', async () => {
    const urls: string[] = [];
    const flaky = (async (url: string) => {
      urls.push(url);
      return urls.length === 1 ? new Response('nope', { status: 503 }) : new Response(JSON.stringify(packagesFile()));
    }) as unknown as typeof fetch;
    const got = await loadPackages(null, flaky);
    // The first base fails; the second serves packages.json, then packages-older.json from the same base.
    expect(urls).toHaveLength(3);
    expect(got.from).toBe(urls[1]);
    expect(urls[2]).toBe(urls[1].replace('packages.json', 'packages-older.json'));
    const down = (async () => new Response('', { status: 500 })) as unknown as typeof fetch;
    await expect(loadPackages(null, down)).rejects.toThrow(/HTTP 500.*HTTP 500/);
    await expect(loadPackages('/no/such/dir')).rejects.toBeInstanceOf(DataError);
  });
});

describe('checkFiles', () => {
  const root = tree({ 'package-lock.json': LOCK, 'api/requirements.txt': REQS, 'bad.lock': 'junk', 'empty/yarn.lock': '' });
  const report = checkFiles(['package-lock.json', 'api/requirements.txt', 'empty/yarn.lock'], root, packagesFile());

  it('groups findings by tier at the evidence bar, most urgent first, with the line and the fix', () => {
    expect(report.findings.map((f) => [f.group, f.row.id, f.pkg.name, f.file, f.fixedIn])).toEqual([
      ['exploited', 'CVE-2026-1001', 'lodash', 'package-lock.json', '4.17.21'],
      ['likely', 'CVE-2026-1002', 'requests', 'api/requirements.txt', '2.31.0'],
      ['watch', 'CVE-2026-1003', 'minimist', 'package-lock.json', '1.2.6'],
      ['quiet', 'CVE-2026-1004', 'left-pad', 'package-lock.json', null],
    ]);
    const lodash = report.findings[0];
    expect(LOCK.split('\n')[lodash.line! - 1]).toContain('node_modules/lodash');
    expect(report.files.find((f) => f.path === 'empty/yarn.lock')?.error).toMatch(/No packages/);
    expect(countByGroup(report.findings)).toEqual({ exploited: 1, likely: 1, watch: 1, quiet: 1, possible: 0 });
  });

  it('moves a CVE between tiers with the evidence bar', () => {
    const at45 = checkFiles(['package-lock.json'], root, packagesFile(), 45);
    expect(at45.findings.find((f) => f.row.id === 'CVE-2026-1003')?.group).toBe('likely');
  });

  it('fails on confirmed findings at or above the tier only', () => {
    expect(failing(report, 'exploited').map((f) => f.row.id)).toEqual(['CVE-2026-1001']);
    expect(failing(report, 'likely')).toHaveLength(2);
    expect(failing(report, 'quiet')).toHaveLength(4);
    expect(failing(report, 'never')).toEqual([]);
  });

  it('reports ecosystems whose data is down and does not match them', () => {
    const r = checkFiles(['api/requirements.txt'], root, packagesFile({ down: true }));
    expect(r.ecosystemsDown).toEqual(['PyPI']);
    expect(r.findings).toEqual([]);
  });

  it('picks the fix for every advisory, by version order, and none when one has no fix', () => {
    const adv = (fixedIn: string | null) => ({ id: 'x', ranges: [], versions: [], listed: false, fixedIn });
    expect(lowestFix({ eco: 'npm', advisories: [adv('9.1.0'), adv('10.0.0')] })).toBe('10.0.0');
    expect(lowestFix({ eco: 'npm', advisories: [adv('9.1.0'), adv(null)] })).toBeNull();
    expect(lineFinder('a\n"lodash": {\n  "version": "4.17.20"\nlodash@4.17.20\n')('lodash', '4.17.20')).toBe(4);
    const find = lineFinder('"lodash.merge": "4.6.2",\n"resolved": "https://r/lodash/-/lodash-4.17.20.tgz"\n"node_modules/lodash": {\n');
    expect(find('lodash', '4.17.20')).toBe(3);
    expect(find('(a+)+$', null)).toBeNull();
  });
});

describe('reports', () => {
  const evil = 'x\n::set-env name=A::b <img src=x onerror=alert(1)> [link](javascript:alert(1)) | `';
  const root = tree({ 'purls.txt': `pkg:npm/lodash@4.17.20\npkg:npm/${encodeURIComponent(evil)}@1.0.0\n`, 'package-lock.json': LOCK });
  const report = checkFiles(['package-lock.json'], root, packagesFile());

  it('text and Markdown say what to fix, and the verdict', () => {
    const text = toText(report, 'exploited');
    expect(text).toContain('EXPLOITED (1)');
    expect(text).toContain('lodash 4.17.20  fixed in 4.17.21  package-lock.json:');
    expect(text).toMatch(/Result: fail\. 1 CVE at Exploited/);
    const m = toMarkdown(report, 'never');
    expect(m).toContain('#### Exploited (1)');
    expect(m).toContain('[CVE-2026-1001](https://cverdict.dev/cve/CVE-2026-1001)');
    expect(m).toContain('<details><summary>Quiet (1)</summary>');
    expect(m).toContain('reported only');
  });

  it('keeps untrusted names inert in Markdown and annotations', () => {
    expect(md(evil)).not.toMatch(/<img|\]\(|\n/);
    expect(data(evil)).not.toMatch(/\n/);
    expect(prop('a,b:c')).toBe('a%2Cb%3Ac');
    const withEvil = checkFiles(['purls.txt'], root, { ...packagesFile(), packages: { npm: { ...packagesFile().packages.npm, [evil]: [['CVE-2026-1001', 'GHSA-x', [['>=0']]]] } } });
    for (const line of toAnnotations(withEvil)) expect(line.split('\n')).toHaveLength(1);
    expect(toMarkdown(withEvil, 'never')).not.toMatch(/<img|::set-env name=A::b <|javascript:alert\(1\)\)/);
  });

  it('JSON lists every finding with whether it fails', () => {
    const j = JSON.parse(toJson(report, 'likely'));
    expect(j.failed).toBe(true);
    expect(j.findings.map((f: { cve: string; fails: boolean }) => [f.cve, f.fails])).toEqual([
      ['CVE-2026-1001', true],
      ['CVE-2026-1003', false],
      ['CVE-2026-1004', false],
    ]);
  });

  it('SARIF has a rule per CVE and a located result per finding, without Quiet', () => {
    const s = JSON.parse(toSarif(report, VERSION));
    expect(s.version).toBe('2.1.0');
    const r = s.runs[0];
    expect(r.tool.driver.rules.map((x: { id: string }) => x.id)).toEqual(['CVE-2026-1001', 'CVE-2026-1003']);
    expect(r.tool.driver.rules[0].properties['security-severity']).toBe('9.5');
    expect(r.results.map((x: { level: string }) => x.level)).toEqual(['error', 'note']);
    expect(r.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('package-lock.json');
    expect(r.results[0].partialFingerprints['cverdict/v1']).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe('run', () => {
  it('exits 1 on a confirmed CVE at --fail-on, 0 below it, and writes the extra reports', async () => {
    const root = tree({ 'package-lock.json': LOCK, 'summary.md': '# before\n' });
    const a = io();
    expect((await run(opts(root, { sarif: 'out/r.sarif', summary: 'summary.md', annotations: true }), a.io)).code).toBe(1);
    expect(a.out.join('')).toContain('::error file=package-lock.json,line=');
    expect(JSON.parse(readFileSync(join(root, 'out/r.sarif'), 'utf8')).runs[0].results).toHaveLength(2);
    expect(readFileSync(join(root, 'summary.md'), 'utf8')).toMatch(/^# before\n### CVErdict check/);
    expect((await run(opts(root, { failOn: 'never' }), io().io)).code).toBe(0);
    const clean = tree({ 'package-lock.json': npmLock({ express: '4.18.2' }) });
    expect((await run(opts(clean, { failOn: 'quiet' }), io().io)).code).toBe(0);
  });

  it('exits 2 when there is nothing to check or no index', async () => {
    const empty = tree({ 'README.md': '' });
    const a = io();
    expect((await run(opts(empty), a.io)).code).toBe(2);
    expect(a.err.join('')).toMatch(/No lockfile or SBOM found/);
    const root = tree({ 'package-lock.json': LOCK });
    expect((await run(opts(root, { data: null }), io().io)).code).toBe(2);
    const broken = tree({ 'yarn.lock': '' });
    expect((await run(opts(broken), io().io)).code).toBe(2);
  });
});

describe('args', () => {
  it('parses paths and options, with defaults', () => {
    expect(parseCli([])).toEqual({ kind: 'run', options: { ...DEFAULTS } });
    expect(parseCli(['a', 'b', '--fail-on', 'Likely', '--evidence-bar', '45', '--format', 'sarif', '-o', 'x.sarif', '--annotations'])).toMatchObject({
      kind: 'run',
      options: { paths: ['a', 'b'], failOn: 'likely', knob: 45, format: 'sarif', output: 'x.sarif', annotations: true },
    });
    expect(parseCli(['--help']).kind).toBe('help');
    expect(parseCli(['-v']).kind).toBe('version');
  });

  it('rejects bad values and unknown options', () => {
    expect(parseCli(['--fail-on', 'high'])).toMatchObject({ kind: 'error', message: expect.stringMatching(/--fail-on/) });
    expect(parseCli(['--evidence-bar', '50.5'])).toMatchObject({ kind: 'error' });
    expect(parseCli(['--format', 'xml'])).toMatchObject({ kind: 'error' });
    expect(parseCli(['--nope'])).toMatchObject({ kind: 'error' });
  });
});

describe('action', () => {
  it('reads inputs the way GitHub passes them', () => {
    const env = { 'INPUT_FAIL-ON': 'likely', INPUT_PATH: 'api\n\n web \n', 'INPUT_EVIDENCE-BAR': '40', 'INPUT_SARIF-FILE': 'r.sarif', INPUT_SUMMARY: 'false', GITHUB_WORKSPACE: '/w', GITHUB_STEP_SUMMARY: '/s' };
    expect(input(env, 'fail-on')).toBe('likely');
    expect(optionsFromInputs(env)).toMatchObject({ paths: ['api', 'web'], failOn: 'likely', knob: 40, sarif: 'r.sarif', summary: null, annotations: true, cwd: '/w' });
    expect(optionsFromInputs({ GITHUB_WORKSPACE: '/w', GITHUB_STEP_SUMMARY: '/s' })).toMatchObject({ paths: ['.'], failOn: 'exploited', summary: '/s' });
    expect(optionsFromInputs({ 'INPUT_FAIL-ON': 'critical' })).toMatch(/fail-on/);
    expect(outputLines({ a: 1, b: 'x\ny' })).toBe('a=1\nb=x y\n');
  });

  it('runs, writes the summary and the outputs, and reports errors as annotations', async () => {
    const root = tree({ 'package-lock.json': LOCK, out: '', sum: '' });
    const env = { GITHUB_WORKSPACE: root, GITHUB_OUTPUT: join(root, 'out'), GITHUB_STEP_SUMMARY: join(root, 'sum'), 'INPUT_DATA-URL': dataDir() };
    const a = io();
    expect(await runAction(env, a.io)).toBe(1);
    expect(readFileSync(join(root, 'out'), 'utf8')).toBe('exploited=1\nlikely=0\nwatch=1\nquiet=1\npossible=0\nfailed=true\nfailing-cves=1\nsarif-file=\n');
    expect(readFileSync(join(root, 'sum'), 'utf8')).toContain('### CVErdict check');
    const b = io();
    expect(await runAction({ ...env, INPUT_PATH: 'missing' }, b.io)).toBe(2);
    expect(b.out.join('')).toMatch(/^::error title=cverdict-check::missing: no such file or directory$/m);
  });
});

describe('version', () => {
  it('matches cli/package.json', () => {
    expect(VERSION).toBe(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
  });
});

describe('older CVEs (packages-older.json)', () => {
  const root = tree({ 'requirements.txt': REQS, 'package-lock.json': npmLock({ express: '4.18.2' }) });

  it('loads it beside packages.json, from a folder or a URL, and says why when it is missing', async () => {
    const both = await loadPackages(dataDirWithOlder());
    expect(both.olderError).toBeNull();
    expect([...both.olderIds]).toEqual(['CVE-2019-3001']);
    expect(both.file.cves.rows).toHaveLength(5);
    expect((await loadPackages(dataDir())).olderError).toMatch(/no packages-older\.json next to/);
    const seen: string[] = [];
    const serve = (older: boolean) =>
      (async (url: string) => {
        seen.push(url);
        if (url.endsWith('packages.json')) return new Response(JSON.stringify(packagesFile()));
        return older ? new Response(JSON.stringify(olderFile())) : new Response('', { status: 404 });
      }) as unknown as typeof fetch;
    expect((await loadPackages('https://m.example/v1/', serve(true))).olderIds.size).toBe(1);
    expect(seen).toEqual(['https://m.example/v1/packages.json', 'https://m.example/v1/packages-older.json']);
    expect((await loadPackages('https://m.example/v1/', serve(false))).olderError).toBe('packages-older.json: HTTP 404');
  });

  it('finds an older CVE, links it to cve.org, and words a clean result by what was covered', async () => {
    const a = io();
    expect((await run(opts(root, { data: dataDirWithOlder(), failOn: 'likely', format: 'json' }), a.io)).code).toBe(1);
    const j = JSON.parse(a.out.join(''));
    expect(j.findings.map((f: { cve: string; group: string; tracked: boolean; url: string }) => [f.cve, f.group, f.tracked, f.url])).toEqual([
      ['CVE-2019-3001', 'likely', false, 'https://www.cve.org/CVERecord?id=CVE-2019-3001'],
      ['CVE-2026-1002', 'likely', true, 'https://cverdict.dev/cve/CVE-2026-1002'],
    ]);
    expect(j).toMatchObject({ tracked_cves: 4, older_cves: 1, advisories: 5, older_error: null });
    const clean = tree({ 'package-lock.json': npmLock({ express: '4.18.2' }) });
    const b = io();
    await run(opts(clean, { data: dataDirWithOlder() }), b.io);
    expect(b.out.join('')).toContain('None of the CVEs OSV.dev advisories tie to package versions affects these packages.');
    expect(b.out.join('')).toContain('against the 5 CVEs OSV.dev advisories tie to package versions (data of');
    const c = io();
    await run(opts(clean), c.io);
    expect(c.out.join('')).toContain('No tracked CVE affects these packages. Older CVEs were not checked');
    expect(c.out.join('')).toMatch(/Run a scanner such as osv-scanner/);
  });
});
