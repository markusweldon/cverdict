import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { NUCLEI, SANITY, type SanityLimits } from '../../src/config';
import {
  cveFromTemplatePath,
  landingTimes,
  loadNucleiDates,
  isPullMerge,
  mainChain,
  mergeLandings,
  parseCommitGraph,
  readDatesFile,
  walkHistory,
  type NucleiAdded,
  type NucleiDatesFile,
} from '../../src/sources/nuclei-history';
import { captureLogger, tempDir } from './helpers';

const LIMITS: SanityLimits = { ...SANITY, nucleiDates: 1 };
const NOW = Date.parse('2026-11-13T12:00:00Z');

/** git with fixed author and committer dates, isolated from the user's configuration. */
function gitAt(cwd: string, date: string | null, ...args: string[]): string {
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_AUTHOR_NAME: 'Test',
    GIT_AUTHOR_EMAIL: 'test@example.invalid',
    GIT_COMMITTER_NAME: 'Test',
    GIT_COMMITTER_EMAIL: 'test@example.invalid',
    ...(date ? { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date } : {}),
  };
  return execFileSync('git', args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

/** A tiny upstream repository that tests commit to with explicit dates. */
function upstream() {
  const dir = path.join(tempDir('nuclei-history-'), 'origin');
  mkdirSync(dir, { recursive: true });
  gitAt(dir, null, 'init', '-q', '-b', 'main');
  const commit = (date: string, change: { add?: Record<string, string>; remove?: string[]; move?: [string, string][] }, message = 'update'): string => {
    for (const [file, body] of Object.entries(change.add ?? {})) {
      mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
      writeFileSync(path.join(dir, file), body);
    }
    for (const [from, to] of change.move ?? []) {
      mkdirSync(path.dirname(path.join(dir, to)), { recursive: true });
      gitAt(dir, null, 'mv', from, to);
    }
    for (const file of change.remove ?? []) gitAt(dir, null, 'rm', '-q', file);
    gitAt(dir, null, 'add', '-A');
    gitAt(dir, date, 'commit', '-q', '--no-gpg-sign', '--allow-empty', '-m', message);
    return gitAt(dir, null, 'rev-parse', 'HEAD');
  };
  return { dir, url: `file://${dir}`, commit, git: (date: string | null, ...args: string[]) => gitAt(dir, date, ...args) };
}

const walk = (dir: string, prev: NucleiDatesFile | null = null, head = gitAt(dir, null, 'rev-parse', 'HEAD')) =>
  walkHistory(dir, head, prev, { timeoutMs: 30_000, nowMs: NOW, unshallow: async () => false });

const asFile = (o: Awaited<ReturnType<typeof walk>>): NucleiDatesFile => ({
  version: 1,
  remote: NUCLEI.remote,
  branch: NUCLEI.branch,
  head: o.head,
  head_at: o.headAt,
  landed: o.landed,
  updated_at: new Date(NOW).toISOString(),
  dates: Object.fromEntries([...o.dates].map(([id, d]) => [id, [d.at, d.commit]])),
});

const iso = (s: string) => new Date(s).toISOString();

describe('cveFromTemplatePath', () => {
  it('reads one CVE ID from a template file name, in any case and folder', () => {
    expect(cveFromTemplatePath('http/cves/2021/CVE-2021-44228.yaml')).toBe('CVE-2021-44228');
    expect(cveFromTemplatePath('cves/2017/cve-2017-12637.yaml')).toBe('CVE-2017-12637');
    expect(cveFromTemplatePath('CVE-2020-2883.yml')).toBe('CVE-2020-2883');
    expect(cveFromTemplatePath('nuclei-templates/cves/CVE-2019-1234.yaml')).toBe('CVE-2019-1234');
    expect(cveFromTemplatePath('network/cves/2026/CVE-2026-119302.yaml')).toBe('CVE-2026-119302');
    expect(cveFromTemplatePath('dast/cves/2022/spring4shell-CVE-2022-22965.yaml')).toBe('CVE-2022-22965');
    expect(cveFromTemplatePath('cves/jira-cve-2017-9506.yaml')).toBe('CVE-2017-9506');
    expect(cveFromTemplatePath('http/cves/2019/CVE-2019-16759-1.yaml')).toBe('CVE-2019-16759');
    expect(cveFromTemplatePath('http/cves/2023/ CVE-2023-6389.yaml')).toBe('CVE-2023-6389');
    expect(cveFromTemplatePath('http/cves/2026/`CVE-2026-41042.yaml')).toBe('CVE-2026-41042');
    expect(cveFromTemplatePath('http/cves/2021/CVE-2021-45046-DAST.YAML')).toBe('CVE-2021-45046');
  });

  it('ignores files that are not templates for one CVE', () => {
    for (const p of [
      'http/cves/2021/CVE-2021-25065', // no extension
      'payloads/CVE-2020-5776.csv',
      'helpers/payloads/CVE-2020-6287.xml',
      'helpers/CVE-2021-1234.yaml',
      'workflows/CVE-2021-1234-workflow.yaml',
      '.github/CVE-2021-1234.yml',
      'http/cves/2021/CVE-2021-123.yaml', // too few digits
      'http/cves/2021/XCVE-2021-1234.yaml', // inside a longer token
      'http/cves/2021/CVE-2021-1234-CVE-2021-5678.yaml', // two CVEs: cannot tell which
      'http/cves/2021/CVE-2021-1234.yaml.bak',
      'http/misconfiguration/apache-status.yaml',
    ]) {
      expect(cveFromTemplatePath(p), p).toBeNull();
    }
    // The same ID twice in one name is still one CVE.
    expect(cveFromTemplatePath('http/cves/2021/CVE-2021-1234-cve-2021-1234.yaml')).toBe('CVE-2021-1234');
  });
});

describe('landingTimes and mergeLandings', () => {
  it('never lets a landing go back in time along the chain, nor past now', () => {
    const c = (sha: string, ct: string) => ({ sha: sha.repeat(40), ct: Date.parse(ct) / 1000, parent: null });
    const landed = landingTimes([c('a', '2026-01-02T00:00:00Z'), c('b', '2026-01-01T00:00:00Z'), c('c', '2026-01-03T00:00:00Z'), c('d', '2027-01-01T00:00:00Z')], null, NOW);
    expect([...landed.values()].map((t) => new Date(t).toISOString())).toEqual([
      '2026-01-02T00:00:00.000Z',
      '2026-01-02T00:00:00.000Z', // dated before its parent: it cannot have landed before it
      '2026-01-03T00:00:00.000Z',
      new Date(NOW).toISOString(), // dated in the future: we saw it now
    ]);
    // The floor from the previous walk applies to the first new commit.
    expect(landingTimes([c('e', '2025-12-31T00:00:00Z')], Date.parse('2026-01-05T00:00:00Z'), NOW).get('e'.repeat(40))).toBe(Date.parse('2026-01-05T00:00:00Z'));
  });

  it('keeps the earliest landing per CVE across paths, and the older commit on a tie', () => {
    const dates = new Map<string, NucleiAdded>([['CVE-2021-0001', { at: '2021-03-01T00:00:00.000Z', commit: 'x'.repeat(40) }]]);
    const a = 'a'.repeat(40);
    const b = 'b'.repeat(40);
    const added = new Map([
      [a, ['http/cves/2021/CVE-2021-0001.yaml', 'http/cves/2021/CVE-2021-0002.yaml', 'README.md']],
      [b, ['cves/2021/CVE-2021-0001.yaml', 'cves/2021/cve-2021-0002.yaml']],
    ]);
    const landed = new Map([
      [a, Date.parse('2021-02-01T00:00:00Z')],
      [b, Date.parse('2021-02-01T00:00:00Z')],
    ]);
    expect(mergeLandings(dates, added, landed)).toBe(2);
    expect(dates.get('CVE-2021-0001')).toEqual({ at: '2021-02-01T00:00:00.000Z', commit: a });
    expect(dates.get('CVE-2021-0002')).toEqual({ at: '2021-02-01T00:00:00.000Z', commit: a });
    // A batch time replaces every commit time.
    const batch = new Map<string, NucleiAdded>();
    mergeLandings(batch, added, landed, Date.parse('2021-06-01T00:00:00Z'));
    expect(batch.get('CVE-2021-0002')?.at).toBe('2021-06-01T00:00:00.000Z');
  });
});

describe('isPullMerge, parseCommitGraph and mainChain', () => {
  const [a, b, c, d, e] = ['a', 'b', 'c', 'd', 'e'].map((x) => x.repeat(40));
  it('recognises the merges that pulled upstream main into local work', () => {
    for (const subject of [
      "Merge branch 'main' of https://github.com/projectdiscovery/nuclei-templates",
      "Merge branch 'master' of https://github.com/projectdiscovery/nuclei-templates",
      "Merge branch 'main' of github.com:projectdiscovery/nuclei-templates.git",
      "Merge branch 'main' of https://github.com/projectdiscovery/nuclei-templates into main",
      "Merge remote-tracking branch 'origin/main'",
      "Merge remote-tracking branch 'upstream/master' into patch-1",
    ]) {
      expect(isPullMerge(subject), subject).toBe(true);
    }
    for (const subject of [
      'Merge pull request #123 from someone/main',
      "Merge branch 'main' of https://github.com/someone/nuclei-templates",
      "Merge branch 'patch-1' of https://github.com/projectdiscovery/nuclei-templates",
      "Merge branch 'main' into fix-typo",
      "Merge branch 'maintenance'",
      'update templates',
    ]) {
      expect(isPullMerge(subject), subject).toBe(false);
    }
  });

  it('follows first parents, and the second parent of a pull merge', () => {
    // e (pull merge: local d, upstream c) → c (PR merge: main b, branch a) → b
    const graph = parseCommitGraph(
      [
        `${e} 50 ${d} ${c}\tMerge branch 'main' of https://github.com/projectdiscovery/nuclei-templates`,
        `${d} 40 ${b}\tlocal work`,
        `${c} 30 ${b} ${a}\tMerge pull request #1 from someone/patch-1`,
        `${a} 20 ${b}\tbranch work`,
        `${b} 10\troot`,
        '',
      ].join('\n'),
    );
    expect(graph.get(e)).toEqual({ ct: 50, parents: [d, c], pull: true });
    expect(graph.get(c)?.pull).toBe(false);
    expect(mainChain(graph, e)).toEqual([
      { sha: e, ct: 50, parent: c },
      { sha: c, ct: 30, parent: b },
      { sha: b, ct: 10, parent: null },
    ]);
    // A range: the chain stops where the listed commits end.
    graph.delete(b);
    expect(mainChain(graph, e).at(-1)).toEqual({ sha: c, ct: 30, parent: b });
    expect(() => parseCommitGraph('nonsense 1\tx')).toThrow();
  });
});

describe('walkHistory on a local repository', () => {
  it('dates a CVE by its first landing across moves, deletions and re-adds', async () => {
    const up = upstream();
    const c1 = up.commit('2020-01-10T10:00:00Z', { add: { 'cves/2019/CVE-2019-0001.yaml': 'id: CVE-2019-0001', 'README.md': 'x' } });
    up.commit('2021-05-01T10:00:00Z', { move: [['cves/2019/CVE-2019-0001.yaml', 'http/cves/2019/CVE-2019-0001.yaml']] });
    up.commit('2022-01-01T10:00:00Z', { remove: ['http/cves/2019/CVE-2019-0001.yaml'] });
    up.commit('2022-06-01T10:00:00Z', { add: { 'http/cves/2019/CVE-2019-0001.yaml': 'id: CVE-2019-0001 again' } });
    // A template that was renamed to a different CVE ID dates the new ID from the rename.
    const c5 = up.commit('2023-01-01T10:00:00Z', { add: { 'http/cves/2023/CVE-2023-0002.yaml': 'id: CVE-2023-0002', 'helpers/CVE-2023-0003.yaml': 'x' } });
    const out = await walk(up.dir);
    expect(out.mode).toBe('full');
    expect(out.commits).toBe(5);
    expect(out.dates.get('CVE-2019-0001')).toEqual({ at: iso('2020-01-10T10:00:00Z'), commit: c1 });
    expect(out.dates.get('CVE-2023-0002')).toEqual({ at: iso('2023-01-01T10:00:00Z'), commit: c5 });
    expect(out.dates.has('CVE-2023-0003')).toBe(false);
    expect(out.landed).toBe(iso('2023-01-01T10:00:00Z'));
  });

  it('dates a template merged from a branch by the merge on main, not by the branch commit', async () => {
    const up = upstream();
    up.commit('2024-01-01T00:00:00Z', { add: { 'README.md': 'x' } });
    up.git(null, 'checkout', '-q', '-b', 'feature');
    const authored = up.commit('2024-01-05T00:00:00Z', { add: { 'http/cves/2024/CVE-2024-1111.yaml': 'id: CVE-2024-1111' } });
    up.git(null, 'checkout', '-q', 'main');
    up.commit('2024-01-10T00:00:00Z', { add: { 'http/cves/2024/CVE-2024-2222.yaml': 'id: CVE-2024-2222' } });
    up.git('2024-02-01T00:00:00Z', 'merge', '-q', '--no-ff', '--no-gpg-sign', '-m', 'Merge pull request #1', 'feature');
    const merge = up.git(null, 'rev-parse', 'HEAD');
    // A squash merge: one new commit on main with the branch's change.
    up.git(null, 'checkout', '-q', '-b', 'squashed');
    up.commit('2024-02-02T00:00:00Z', { add: { 'http/cves/2024/CVE-2024-3333.yaml': 'id: CVE-2024-3333' } });
    up.git(null, 'checkout', '-q', 'main');
    up.git(null, 'merge', '-q', '--squash', 'squashed');
    const squash = up.commit('2024-03-01T00:00:00Z', {}, 'Squashed PR #2');
    const out = await walk(up.dir);
    expect(out.dates.get('CVE-2024-1111')).toEqual({ at: iso('2024-02-01T00:00:00Z'), commit: merge });
    expect(out.dates.get('CVE-2024-1111')?.commit).not.toBe(authored);
    expect(out.dates.get('CVE-2024-2222')?.at).toBe(iso('2024-01-10T00:00:00Z'));
    expect(out.dates.get('CVE-2024-3333')).toEqual({ at: iso('2024-03-01T00:00:00Z'), commit: squash });
    // Only main's first parents are walked.
    expect(out.commits).toBe(4);
  });

  it('walks only the commits after the previous head, and starts over when history was rewritten', async () => {
    const up = upstream();
    const c1 = up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    const first = await walk(up.dir);
    const prev = asFile(first);
    expect((await walk(up.dir, prev)).mode).toBe('unchanged');

    up.commit('2025-02-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0002.yaml': 'b' } });
    // Moved: the earlier date stays.
    up.commit('2025-03-01T00:00:00Z', { move: [['http/cves/2025/CVE-2025-0001.yaml', 'http/cves/2025/old/CVE-2025-0001.yaml']] });
    const next = await walk(up.dir, prev);
    expect(next).toMatchObject({ mode: 'incremental', commits: 2, changed: 1 });
    expect(next.dates.get('CVE-2025-0001')).toEqual({ at: iso('2025-01-01T00:00:00Z'), commit: c1 });
    expect(next.dates.get('CVE-2025-0002')?.at).toBe(iso('2025-02-01T00:00:00Z'));

    // The previous head is gone from main (force-pushed): the whole history is walked again.
    up.git(null, 'checkout', '-q', '--orphan', 'rewritten');
    up.git(null, 'rm', '-rq', '--cached', '.');
    rmSync(path.join(up.dir, 'http'), { recursive: true, force: true });
    const r1 = up.commit('2025-04-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0009.yaml': 'c' } });
    const redo = await walk(up.dir, asFile(next), r1);
    expect(redo.mode).toBe('full');
    expect([...redo.dates.keys()]).toEqual(['CVE-2025-0009']);
  });

  it('dates a batch by its newest commit when main was fast-forwarded to a branch that merged main in', async () => {
    const up = upstream();
    const m0 = up.commit('2025-01-01T00:00:00Z', { add: { 'README.md': 'x' } });
    up.git(null, 'checkout', '-q', '-b', 'side');
    up.commit('2025-01-02T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0003.yaml': 'side' } });
    up.git(null, 'checkout', '-q', 'main');
    const m1 = up.commit('2025-01-05T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0004.yaml': 'main' } });
    const prev = asFile(await walk(up.dir, null, m1));
    up.git(null, 'checkout', '-q', 'side');
    up.git('2025-01-20T00:00:00Z', 'merge', '-q', '--no-ff', '--no-gpg-sign', '-m', 'merge main into side', 'main');
    const tip = up.git(null, 'rev-parse', 'HEAD');
    up.git(null, 'checkout', '-q', 'main');
    up.git(null, 'merge', '-q', '--ff-only', 'side');
    expect(up.git(null, 'rev-parse', `${tip}^1`)).not.toBe(m1);
    const out = await walk(up.dir, prev, tip);
    expect(out.mode).toBe('batch');
    // Committed on the side branch on Jan 2, but on main only from the push of Jan 20 at the earliest.
    expect(out.dates.get('CVE-2025-0003')).toMatchObject({ at: iso('2025-01-20T00:00:00Z') });
    expect(out.dates.get('CVE-2025-0004')?.at).toBe(iso('2025-01-05T00:00:00Z'));
    expect(m0).toMatch(/^[0-9a-f]{40}$/);
  });
});

describe('walkHistory with a maintainer who pulls main before pushing', () => {
  /** Upstream, plus a maintainer clone that commits a template locally and pulls main twice before pushing. */
  const scenario = () => {
    const up = upstream();
    up.commit('2025-08-01T00:00:00Z', { add: { 'README.md': 'x' } });
    const local = path.join(path.dirname(up.dir), 'maintainer');
    gitAt(path.dirname(up.dir), null, 'clone', '-q', up.url, local);
    const at = (date: string | null, ...args: string[]) => gitAt(local, date, ...args);
    mkdirSync(path.join(local, 'http/cves/2025'), { recursive: true });
    writeFileSync(path.join(local, 'http/cves/2025/CVE-2025-54309.yaml'), 'id: CVE-2025-54309');
    at(null, 'add', '-A');
    const authored = at('2025-08-28T16:17:00Z', 'commit', '-q', '--no-gpg-sign', '-m', 'add CVE-2025-54309');
    // Meanwhile main moves on, and the maintainer pulls it in twice without pushing.
    const u1 = up.commit('2025-08-29T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0101.yaml': 'u1' } });
    const pull = (date: string) => {
      at(null, 'fetch', '-q', 'origin');
      at(date, 'merge', '-q', '--no-ff', '--no-gpg-sign', '-m', "Merge branch 'main' of https://github.com/projectdiscovery/nuclei-templates", 'origin/main');
    };
    pull('2025-08-30T14:48:00Z');
    const u2 = up.commit('2025-08-31T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0102.yaml': 'u2' } });
    pull('2025-09-01T02:45:00Z');
    const pushed = at(null, 'rev-parse', 'HEAD');
    // The push: main is fast-forwarded to the maintainer's last pull merge.
    const push = () => {
      up.git(null, 'fetch', '-q', local, 'main');
      up.git(null, 'merge', '-q', '--ff-only', 'FETCH_HEAD');
    };
    return { up, authored, u1, u2, pushed, push };
  };

  it('dates the local commit by the last pull merge that main did not have it in, not by its commit time', async () => {
    const { up, authored, pushed, push } = scenario();
    push();
    expect(up.git(null, 'log', '-1', '--format=%s')).toMatch(/^Merge branch 'main' of /);
    const out = await walk(up.dir);
    expect(out.mode).toBe('full');
    // Committed on Aug 28, pulled over twice, on main only from the push of the second pull merge.
    expect(out.dates.get('CVE-2025-54309')).toEqual({ at: iso('2025-09-01T02:45:00Z'), commit: pushed });
    expect(out.dates.get('CVE-2025-54309')?.commit).not.toBe(authored);
    // Chain: the pushed merge, then main as it was (u2, u1, the first commit): the first pull merge was never on main.
    expect(out.commits).toBe(4);
    // Main's own commits keep their times.
    expect(out.dates.get('CVE-2025-0101')?.at).toBe(iso('2025-08-29T00:00:00Z'));
    expect(out.dates.get('CVE-2025-0102')?.at).toBe(iso('2025-08-31T00:00:00Z'));
  });

  it('gives the same dates whether the history is walked at once or hour by hour', async () => {
    const { up, push, u1, u2 } = scenario();
    const atU1 = asFile(await walk(up.dir, null, u1));
    const atU2 = asFile(await walk(up.dir, atU1, u2));
    push();
    const hourly = await walk(up.dir, atU2);
    const full = await walk(up.dir);
    // The pushed merge sits right on the last head seen: an ordinary hourly step.
    expect(hourly).toMatchObject({ mode: 'incremental', commits: 1 });
    expect(full.mode).toBe('full');
    expect(Object.fromEntries([...hourly.dates].map(([k, v]) => [k, v.at]))).toEqual(Object.fromEntries([...full.dates].map(([k, v]) => [k, v.at])));
  });
});

describe('loadNucleiDates (cache clone, dates file, fallbacks)', () => {
  const setup = () => {
    const up = upstream();
    const cacheDir = tempDir('nuclei-cache-');
    const log = captureLogger();
    const load = (o: { offline?: boolean; remote?: string; limits?: SanityLimits; repoDir?: string; depth?: number } = {}) =>
      loadNucleiDates({ cacheDir, offline: o.offline ?? false, log, limits: o.limits ?? LIMITS, remote: o.remote ?? up.url, repoDir: o.repoDir, shallowDepth: o.depth, now: () => NOW });
    const file = path.join(cacheDir, 'sources', NUCLEI.datesFile);
    const clone = path.join(cacheDir, 'git', NUCLEI.historyDir);
    return { up, cacheDir, log, load, file, clone };
  };

  it('clones, writes the dates file, then updates it from the last commit walked', async () => {
    const { up, log, load, file, clone } = setup();
    const c1 = up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    const first = await load();
    expect(first).toMatchObject({ head: c1, stale: false, error: null });
    expect(first.dates?.get('CVE-2025-0001')).toEqual({ at: iso('2025-01-01T00:00:00Z'), commit: c1 });
    const saved = await readDatesFile(file);
    expect(saved).toMatchObject({ head: c1, head_at: iso('2025-01-01T00:00:00Z'), dates: { 'CVE-2025-0001': [iso('2025-01-01T00:00:00Z'), c1] } });
    // Blobless: no file contents were downloaded.
    expect(gitAt(clone, null, 'config', 'remote.origin.partialclonefilter')).toBe('blob:none');

    const c2 = up.commit('2025-02-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0002.yaml': 'b' } });
    const second = await load();
    expect(second).toMatchObject({ head: c2, stale: false });
    expect(log.lines.at(-1)).toMatch(/incremental, 1 commits walked, 1 new or earlier/);
    expect((await readDatesFile(file))?.dates['CVE-2025-0002']).toEqual([iso('2025-02-01T00:00:00Z'), c2]);
  });

  it('without the clone, makes a shallow clone and walks only the commits since the last one walked', async () => {
    const { up, log, load, clone } = setup();
    up.commit('2020-01-01T00:00:00Z', { add: { 'http/cves/2020/CVE-2020-0001.yaml': 'a' } });
    up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'b' } });
    await load();
    rmSync(clone, { recursive: true, force: true });
    const c3 = up.commit('2025-01-10T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0003.yaml': 'c' } });
    const out = await load({ depth: 2 });
    expect(out).toMatchObject({ head: c3, stale: false });
    expect(gitAt(clone, null, 'rev-parse', '--is-shallow-repository')).toBe('true');
    expect(Number(gitAt(clone, null, 'rev-list', '--count', 'HEAD'))).toBe(2);
    expect(log.lines.at(-1)).toMatch(/incremental, 1 commits walked/);
    // The dates from before the shallow clone are kept.
    expect(out.dates?.get('CVE-2020-0001')?.at).toBe(iso('2020-01-01T00:00:00Z'));
    expect(out.dates?.get('CVE-2025-0003')?.at).toBe(iso('2025-01-10T00:00:00Z'));
  });

  it('deepens a shallow clone that misses the last commit walked', async () => {
    const { up, log, load, clone } = setup();
    up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    await load();
    rmSync(clone, { recursive: true, force: true });
    up.commit('2025-07-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0002.yaml': 'b' } });
    // One commit deep: the last walked commit is not in the clone, so the rest is fetched.
    const out = await load({ depth: 1 });
    expect(out).toMatchObject({ stale: false, error: null });
    expect(gitAt(clone, null, 'rev-parse', '--is-shallow-repository')).toBe('false');
    expect(log.lines.at(-1)).toMatch(/incremental, 1 commits walked/);
    expect(out.dates?.get('CVE-2025-0001')?.at).toBe(iso('2025-01-01T00:00:00Z'));
  });

  it('keeps the previous dates and says they are stale when the fetch fails, offline, or the walk is implausible', async () => {
    const { up, load, file, clone } = setup();
    const c1 = up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    await load();
    const missing = `file://${path.join(tempDir(), 'gone')}`;

    // Fetch fails: the local clone is still walked, marked stale with the error.
    const failed = await load({ remote: missing });
    expect(failed).toMatchObject({ head: c1, stale: true });
    expect(failed.error).toMatch(/git fetch/);
    expect(failed.dates?.get('CVE-2025-0001')?.commit).toBe(c1);

    // No clone and no network: the cached dates, stale.
    rmSync(clone, { recursive: true, force: true });
    expect(await load({ offline: true })).toMatchObject({ head: c1, stale: true, error: null });
    const unreachable = await load({ remote: missing });
    expect(unreachable).toMatchObject({ head: c1, stale: true, error: expect.stringMatching(/git clone/) });
    expect(unreachable.dates?.size).toBe(1);

    // Fewer dates than the sanity minimum: the previous file is kept, not overwritten.
    up.commit('2025-02-01T00:00:00Z', { add: { 'README.md': 'x' } });
    const implausible = await load({ limits: { ...LIMITS, nucleiDates: 5 } });
    expect(implausible).toMatchObject({ head: c1, stale: true, error: expect.stringMatching(/only 1 CVEs with a template date/) });
    expect((await readDatesFile(file))?.head).toBe(c1);
  });

  it('starts from nothing without a usable dates file, and never throws', async () => {
    const { up, load, file } = setup();
    expect(await load({ offline: true })).toEqual({ dates: null, head: null, stale: true, as_of: null, error: 'no cached template dates' });
    expect(await load({ remote: `file://${path.join(tempDir(), 'gone')}` })).toMatchObject({ dates: null, stale: true, error: expect.stringMatching(/git clone/) });
    up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, '{"version":1,"broken":');
    const out = await load();
    expect(out.dates?.size).toBe(1);
    expect(JSON.parse(readFileSync(file, 'utf8')).version).toBe(1);
  });

  it('reads an existing clone as is (never fetched)', async () => {
    const { up, load, clone } = setup();
    const c1 = up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    const out = await load({ repoDir: up.dir, remote: 'file:///nowhere' });
    expect(out).toMatchObject({ head: c1, stale: false, error: null });
    expect(existsSync(clone)).toBe(false);
  });

  it('never writes the cached dates from a clone given with --nuclei-dir', async () => {
    const { up, load, file } = setup();
    const c1 = up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    up.commit('2025-02-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0002.yaml': 'b' } });
    await load();
    const saved = readFileSync(file, 'utf8');
    // An older checkout of the same history, and a fork with its own commit: read, not saved.
    const older = path.join(tempDir(), 'older');
    gitAt(path.dirname(older), null, 'clone', '-q', up.url, older);
    gitAt(older, null, 'reset', '-q', '--hard', c1);
    const fork = await load({ repoDir: older });
    expect(fork).toMatchObject({ head: c1, stale: false });
    expect(fork.dates?.has('CVE-2025-0002')).toBe(false);
    writeFileSync(path.join(older, 'http/cves/2025/CVE-2025-0009.yaml'), 'fork');
    gitAt(older, null, 'add', '-A');
    gitAt(older, '2025-03-01T00:00:00Z', 'commit', '-q', '--no-gpg-sign', '-m', 'fork');
    expect((await load({ repoDir: older })).dates?.has('CVE-2025-0009')).toBe(true);
    expect(readFileSync(file, 'utf8')).toBe(saved);
  });

  it('says when stale dates were last current, so their age can be checked', async () => {
    const { up, load, file } = setup();
    up.commit('2025-01-01T00:00:00Z', { add: { 'http/cves/2025/CVE-2025-0001.yaml': 'a' } });
    let now = NOW;
    const at = (o: Parameters<typeof load>[0] = {}) =>
      loadNucleiDates({ cacheDir: path.dirname(path.dirname(file)), offline: o.offline ?? false, log: captureLogger(), limits: o.limits ?? LIMITS, remote: o.remote ?? up.url, now: () => now });
    expect((await at()).as_of).toBe(new Date(NOW).toISOString());
    // Fresh again an hour later with nothing new upstream: still current, and the file says so.
    now = NOW + 3_600_000;
    expect(await at()).toMatchObject({ stale: false, as_of: new Date(now).toISOString() });
    expect((await readDatesFile(file))?.checked_at).toBe(new Date(now).toISOString());
    const lastGood = new Date(now).toISOString();
    // Then three days of failed fetches: the dates stay as of the last good check.
    now = NOW + 72 * 3_600_000;
    const gone = `file://${path.join(tempDir(), 'gone')}`;
    expect(await at({ remote: gone })).toMatchObject({ stale: true, as_of: lastGood });
    expect(await at({ offline: true })).toMatchObject({ stale: true, as_of: lastGood });
    expect(await at({ limits: { ...LIMITS, nucleiDates: 5 } })).toMatchObject({ stale: true, as_of: lastGood });
    expect((await readDatesFile(file))?.checked_at).toBe(lastGood);
    void load;
  });
});
