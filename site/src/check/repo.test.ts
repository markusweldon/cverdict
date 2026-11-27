import { describe, expect, it } from 'vitest';
import { addWorkflowUrl, workflowYaml, WORKFLOW_PATH } from './ci';
import { API, MAX_REPO_FILES, RAW, ROOT_NAMES, RepoError, fetchRepoFiles, parseRepo, pickFiles, rawUrl } from './repo';
import { createSession } from './session';
import { testIndex } from './fixtures/index';

describe('parseRepo', () => {
  it('reads owner/repo, github.com addresses and /tree/<branch>', () => {
    expect(parseRepo('vercel/next.js')).toEqual({ owner: 'vercel', repo: 'next.js', ref: null });
    expect(parseRepo(' https://github.com/vercel/next.js.git ')).toEqual({ owner: 'vercel', repo: 'next.js', ref: null });
    expect(parseRepo('github.com/a-b/c_d/')).toEqual({ owner: 'a-b', repo: 'c_d', ref: null });
    expect(parseRepo('https://github.com/o/r/tree/release/1.2')).toEqual({ owner: 'o', repo: 'r', ref: 'release/1.2' });
    expect(parseRepo('git@github.com:o/r.git')).toEqual({ owner: 'o', repo: 'r', ref: null });
    expect(parseRepo('https://github.com/o/r?tab=readme')).toEqual({ owner: 'o', repo: 'r', ref: null });
  });

  it('refuses anything that is not a repository', () => {
    for (const bad of ['', 'just-a-name', 'o/..', '-o/r', 'o/r/blob/main/x', 'o/r/tree/../../etc', 'o/r/tree/a b', 'https://gitlab.com/o/r/x', `${'a'.repeat(40)}/r`]) expect(parseRepo(bad), bad).toBeNull();
  });
});

describe('pickFiles', () => {
  const blob = (path: string) => ({ path, type: 'blob' });
  it('keeps lockfiles and SBOMs outside dependency and build folders, shallowest first, without a go.sum next to a go.mod', () => {
    const got = pickFiles([
      blob('README.md'),
      blob('web/package-lock.json'),
      blob('package-lock.json'),
      blob('node_modules/x/package-lock.json'),
      blob('svc/go.mod'),
      blob('svc/go.sum'),
      blob('tools/go.sum'),
      blob('sbom/app.cdx.json'),
      blob('vendor/y/composer.lock'),
      { path: 'api', type: 'tree' },
    ]);
    expect(got).toEqual({ paths: ['package-lock.json', 'sbom/app.cdx.json', 'svc/go.mod', 'tools/go.sum', 'web/package-lock.json'], skipped: 0 });
  });

  it('caps the files and counts the rest', () => {
    const many = Array.from({ length: MAX_REPO_FILES + 7 }, (_, i) => blob(`pkg${String(i).padStart(3, '0')}/yarn.lock`));
    expect(pickFiles(many)).toMatchObject({ skipped: 7 });
    expect(pickFiles(many).paths).toHaveLength(MAX_REPO_FILES);
  });
});

type Route = (url: string) => Response | undefined;
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
const LOCK = JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/left-pad': { version: '1.3.0' } } });

function github(routes: Record<string, () => Response>, fallback?: Route) {
  const calls: string[] = [];
  const impl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    return routes[url]?.() ?? fallback?.(url) ?? new Response('not found', { status: 404 });
  }) as typeof fetch;
  return { calls, impl };
}

describe('fetchRepoFiles', () => {
  const ref = { owner: 'acme', repo: 'shop', ref: null };

  it('asks for the default branch and the tree, then downloads the picked files from raw', async () => {
    const g = github({
      [`${API}/repos/acme/shop`]: () => json({ default_branch: 'trunk' }),
      [`${API}/repos/acme/shop/git/trees/trunk?recursive=1`]: () => json({ tree: [{ path: 'package-lock.json', type: 'blob' }, { path: 'docs/a.md', type: 'blob' }], truncated: false }),
      [`${RAW}/acme/shop/trunk/package-lock.json`]: () => new Response(LOCK),
    });
    const got = await fetchRepoFiles(ref, g.impl);
    expect(got).toMatchObject({ ref: 'trunk', skipped: 0, truncated: false, rootOnly: null });
    expect(got.files.map((f) => f.path)).toEqual(['package-lock.json']);
    expect(g.calls.every((u) => u.startsWith(`${API}/`) || u.startsWith(`${RAW}/`))).toBe(true);
  });

  it('tries the root by name when GitHub’s API limit is reached, and says so', async () => {
    const g = github({ [`${API}/repos/acme/shop`]: () => json({ message: 'rate limit' }, 403), [`${RAW}/acme/shop/HEAD/yarn.lock`]: () => new Response('# yarn lockfile v1\n') });
    const got = await fetchRepoFiles(ref, g.impl);
    expect(got.rootOnly).toMatch(/API limit/);
    expect(got.files.map((f) => f.path)).toEqual(['yarn.lock']);
    expect(g.calls.filter((u) => u.startsWith(RAW))).toHaveLength(ROOT_NAMES.length);
  });

  it('says a missing or private repository is not found, and an empty one has no lockfile', async () => {
    await expect(fetchRepoFiles(ref, github({}).impl)).rejects.toMatchObject({ kind: 'not-found' });
    const empty = github({
      [`${API}/repos/acme/shop`]: () => json({ default_branch: 'main' }),
      [`${API}/repos/acme/shop/git/trees/main?recursive=1`]: () => json({ tree: [{ path: 'README.md', type: 'blob' }] }),
    });
    await expect(fetchRepoFiles(ref, empty.impl)).rejects.toBeInstanceOf(RepoError);
    await expect(fetchRepoFiles(ref, empty.impl)).rejects.toMatchObject({ kind: 'no-files' });
  });

  it('encodes every path segment of the raw URL', () => {
    expect(rawUrl({ owner: 'o', repo: 'r', ref: null }, 'feat/x', 'a b/#c.lock')).toBe(`${RAW}/o/r/feat/x/a%20b/%23c.lock`);
  });
});

describe('session.runRepo', () => {
  const index = () => new Response(JSON.stringify(testIndex()), { status: 200 });
  const client = () => {
    const calls: string[] = [];
    const load = (path: string) => async () => {
      calls.push(path);
      if (path === 'packages-older.json') throw new Error('none');
      return JSON.parse(await index().text());
    };
    return { calls, client: { packages: { key: 'packages.json', load: load('packages.json'), peek: () => undefined }, packagesOlder: { key: 'packages-older.json', load: load('packages-older.json'), peek: () => undefined } } };
  };

  it('reads every lockfile of the repository into one result, and names what it read', async () => {
    const g = github({
      [`${API}/repos/acme/shop`]: () => json({ default_branch: 'main' }),
      [`${API}/repos/acme/shop/git/trees/main?recursive=1`]: () => json({ tree: [{ path: 'package-lock.json', type: 'blob' }, { path: 'api/requirements.txt', type: 'blob' }, { path: 'web/yarn.lock', type: 'blob' }] }),
      [`${RAW}/acme/shop/main/package-lock.json`]: () => new Response(LOCK),
      [`${RAW}/acme/shop/main/api/requirements.txt`]: () => new Response('django==3.2.0\n'),
      [`${RAW}/acme/shop/main/web/yarn.lock`]: () => new Response('{ broken'),
    });
    const c = client();
    const s = createSession(c.client);
    const stages: string[] = [];
    const out = await s.runRepo('https://github.com/acme/shop', { fetch: g.impl, onStage: (st) => stages.push(st.stage) });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.held.file).toBe('acme/shop@main');
    expect(out.held.repo?.files.map((f) => [f.path, f.format])).toEqual([
      ['api/requirements.txt', 'requirements'],
      ['package-lock.json', 'npm-lock'],
    ]);
    expect(out.held.repo?.unread.map((f) => f.path)).toEqual(['web/yarn.lock']);
    expect(out.held.result.total).toBe(2);
    expect(stages[0]).toBe('fetching');
    // The index files and GitHub, nothing else.
    expect(c.calls.sort()).toEqual(['packages-older.json', 'packages.json']);
    expect(g.calls.every((u) => u.startsWith(`${API}/`) || u.startsWith(`${RAW}/`))).toBe(true);
  });

  it('reports a bad name or a GitHub error as a repo failure, without asking GitHub for a bad name', async () => {
    const g = github({});
    const s = createSession(client().client);
    const bad = await s.runRepo('not a repo', { fetch: g.impl });
    expect(bad.ok === false && bad.failure.kind === 'repo' && bad.failure.error.kind).toBe('invalid');
    expect(g.calls).toEqual([]);
    const missing = await s.runRepo('acme/gone', { fetch: g.impl });
    expect(missing.ok === false && missing.failure.kind === 'repo' && missing.failure.error.kind).toBe('not-found');
  });
});

describe('the In CI workflow', () => {
  it('runs the pinned Action on pull requests, pushes and a daily schedule', () => {
    const y = workflowYaml();
    expect(y).toMatch(/uses: markusweldon\/cverdict\/action@check-v\d+\.\d+\.\d+/);
    expect(y).toContain('pull_request:');
    expect(y).toContain("cron: '17 6 * * *'");
    expect(y).toContain('fail-on: exploited');
  });

  it('opens GitHub’s new-file page with the workflow filled in for the branch', () => {
    const u = new URL(addWorkflowUrl({ owner: 'acme', repo: 'shop' }, 'trunk'));
    expect(u.origin + u.pathname).toBe('https://github.com/acme/shop/new/trunk');
    expect(u.searchParams.get('filename')).toBe(WORKFLOW_PATH);
    expect(u.searchParams.get('value')).toContain('branches: [trunk]');
  });
});
