/**
 * The privacy promises of the Check page, tested on the session logic (vitest runs in node, with
 * no DOM): no request before the first touch, exactly two after it (packages.json and
 * packages-older.json, fixed URLs), none from a check, and no write to storage, history or cookies.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { testIndex } from './fixtures/index';

// Browser globals as spies, installed before the site modules load (data.ts reads sessionStorage
// once at startup, as on every page).
function storageSpy() {
  return { getItem: vi.fn(() => null), setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn(), key: vi.fn(() => null), length: 0 };
}
const local = storageSpy();
const sess = storageSpy();
const hist = { state: null, length: 1, pushState: vi.fn(), replaceState: vi.fn(), back: vi.fn(), forward: vi.fn(), go: vi.fn() };
const setCookie = vi.fn();
const doc = {};
Object.defineProperty(doc, 'cookie', { get: () => '', set: setCookie });
const globalFetch = vi.fn(() => Promise.reject(new Error('no network in tests')));
vi.stubGlobal('localStorage', local);
vi.stubGlobal('sessionStorage', sess);
vi.stubGlobal('history', hist);
vi.stubGlobal('document', doc);
vi.stubGlobal('fetch', globalFetch);
vi.stubGlobal('window', { localStorage: local, sessionStorage: sess, history: hist, document: doc, location: new URL('https://cverdict.test/check'), fetch: globalFetch, addEventListener: vi.fn() });

const { createSession, fileTooLarge, FILE_MAX, fmtSize, indexGlyphs, PASTE_MAX, pasteTooLarge, session } = await import('./session');
const { createDataClient } = await import('../data');
const fetchesAtImport = globalFetch.mock.calls.length;

const base = '/data/v1/';
type Reply = () => Response | Promise<Response>;
const ok: Reply = () => new Response(JSON.stringify(testIndex()), { status: 200, headers: { 'content-type': 'application/json' } });

const notFound: Reply = () => new Response('not found', { status: 404 });
const BOTH = [`${base}packages.json`, `${base}packages-older.json`];

/** `replies` answer the packages.json requests in turn; packages-older.json gets `older` (default: a 404, as from older data). */
function spyClient(...replies: Reply[]) {
  return spyClientWith(notFound, ...replies);
}

function spyClientWith(older: Reply, ...replies: Reply[]) {
  const calls: string[] = [];
  let tracked = 0;
  const impl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith('packages-older.json')) return older();
    tracked++;
    return (replies[tracked - 1] ?? replies[replies.length - 1] ?? ok)();
  }) as typeof fetch;
  return { calls, client: createDataClient(base, impl) };
}

const fixtures = readdirSync(new URL('./fixtures/', import.meta.url)).filter((f) => !f.endsWith('.ts'));
const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

function expectNoWrites() {
  for (const s of [local, sess]) {
    expect(s.setItem).not.toHaveBeenCalled();
    expect(s.removeItem).not.toHaveBeenCalled();
    expect(s.clear).not.toHaveBeenCalled();
  }
  expect(hist.pushState).not.toHaveBeenCalled();
  expect(hist.replaceState).not.toHaveBeenCalled();
  expect(setCookie).not.toHaveBeenCalled();
  expect(globalFetch).not.toHaveBeenCalled();
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('check session', () => {
  it('makes no request when the page module loads or a session is created', () => {
    expect(fetchesAtImport).toBe(0);
    expect(session.started()).toBe(false);
    const { calls } = spyClient();
    createSession({ packages: createDataClient(base, (() => Promise.reject(new Error('unused'))) as typeof fetch).packages });
    expect(calls).toEqual([]);
  });

  it('makes exactly two requests on the first touch, for the two package files, and reuses them', async () => {
    const { calls, client } = spyClient();
    const s = createSession(client);
    expect(calls).toEqual([]);
    const a = s.touch();
    s.touch();
    s.touch();
    expect(calls).toEqual(BOTH);
    expect(await a).toBe(await s.touch());
    expect(calls).toHaveLength(2);
    expectNoWrites();
  });

  it('makes no request and writes nothing while checking any fixture, including non-Latin names', async () => {
    const { calls, client } = spyClient();
    const s = createSession(client);
    await s.touch();
    expect(fixture('shop.cdx.json')).toMatch(/Łódź-utils.*\n.*жук.*\n.*thạch/);
    for (const f of fixtures) {
      const out = await s.run(fixture(f), f);
      expect(out.ok, f).toBe(true);
    }
    const pasted = await s.run('pkg:npm/%C5%81%C3%B3d%C5%BA@1.0.0\npkg:pypi/%D0%B6%D1%83%D0%BA@0.1\n', null);
    expect(pasted.ok && pasted.held.result.clean.map((c) => c.name)).toEqual(['Łódź', 'жук']);
    expect(calls).toEqual(BOTH);
    expectNoWrites();
  });

  it('keeps the last result in memory until clear()', async () => {
    const { client } = spyClient();
    const s = createSession(client);
    s.touch();
    expect(s.held()).toBeNull();
    const out = await s.run(fixture('app.spdx.json'), 'app.spdx.json');
    expect(out.ok).toBe(true);
    expect(s.held()?.file).toBe('app.spdx.json');
    expect(s.held()?.result.cves.map((c) => c.row.id).sort()).toEqual(['CVE-2021-44228', 'CVE-2021-45046']);
    s.clear();
    expect(s.held()).toBeNull();
    expectNoWrites();
  });

  it('refuses a paste over 5 MB whole, instead of cutting it', async () => {
    const { calls, client } = spyClient();
    const s = createSession(client);
    await s.touch();
    await s.run('pkg:npm/a@1.0.0', null);
    const big = `${'pkg:npm/a@1.0.0\n'.repeat(Math.ceil((6 * 1024 * 1024) / 16))}`;
    const out = await s.run(big, null);
    expect(out).toEqual({ ok: false, failure: { kind: 'paste-too-large', size: big.length } });
    // The earlier result stays; nothing was read from the refused text.
    expect(s.held()?.result.total).toBe(1);
    expect(pasteTooLarge(PASTE_MAX)).toBeNull();
    expect(pasteTooLarge(PASTE_MAX + 1)?.kind).toBe('paste-too-large');
    // A file of the same size is fine: files may be up to 50 MB.
    expect((await s.run(big, 'purls.txt')).ok).toBe(true);
    expect(fileTooLarge(FILE_MAX)).toBeNull();
    expect(fileTooLarge(80 * 1024 * 1024)).toEqual({ kind: 'file-too-large', size: 80 * 1024 * 1024 });
    expect(calls).toHaveLength(2);
  });

  it('reports a failed index load, and only Retry asks again', async () => {
    const { calls, client } = spyClient(() => new Response('upstream error', { status: 502 }), ok);
    const s = createSession(client);
    await expect(s.touch()).rejects.toThrow('HTTP 502');
    const out = await s.run(fixture('purls.txt'), 'purls.txt');
    expect(out.ok === false && out.failure.kind === 'index' && !out.failure.notPublished).toBe(true);
    s.touch();
    expect(calls).toHaveLength(2);
    await s.retry();
    expect(calls).toEqual([...BOTH, ...BOTH]);
    expect((await s.run(fixture('purls.txt'), 'purls.txt')).ok).toBe(true);
    expect(calls).toHaveLength(4);
  });

  it('lists the index characters that need web font subsets, from the index alone', () => {
    const index = testIndex();
    expect(indexGlyphs(index)).toBe('');
    // Rows render titles and vendors in the web fonts: a title with Ł or ő needs the latin-ext
    // subset. The page loads it when the index arrives, so a match can never be what fetches it.
    index.cves.rows[0][index.cves.cols.indexOf('t')] = 'Łódź Gőzös – überflow';
    const glyphs = indexGlyphs(index);
    expect([...glyphs].sort()).toEqual(['Ł', 'ó', 'ź', 'ő', 'ö', '–', 'ü'].sort());
    expect(glyphs).toBe(indexGlyphs(index));
  });

  it('formats sizes for the messages', () => {
    expect([fmtSize(300), fmtSize(218_372), fmtSize(5_452_595), fmtSize(6.1 * 1024 * 1024), fmtSize(80 * 1024 * 1024)]).toEqual(['1 KB', '213 KB', '5.2 MB', '6.1 MB', '80 MB']);
    // Just over a limit never reads as the limit.
    expect([fmtSize(PASTE_MAX + 1), fmtSize(FILE_MAX + 1), fmtSize(PASTE_MAX), fmtSize(FILE_MAX)]).toEqual(['5.1 MB', '51 MB', '5 MB', '50 MB']);
  });

  it('drops a request that hangs when the user presses Retry', async () => {
    const { calls, client } = spyClient(() => new Promise<Response>(() => undefined), ok);
    const s = createSession(client);
    s.touch();
    s.touch();
    expect(calls).toHaveLength(2);
    await s.retry();
    expect(calls).toHaveLength(4);
    expect(s.index()?.cves.rows.length).toBe(testIndex().cves.rows.length);
  });

  it('says "not published yet" when the data predates packages.json', async () => {
    const { client } = spyClient(() => new Response('not found', { status: 404 }));
    const s = createSession(client);
    const out = await s.run('pkg:npm/a@1.0.0', null);
    expect(out.ok === false && out.failure.kind === 'index' && out.failure.notPublished).toBe(true);
  });

  it('parses while the index loads and says it is waiting', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { client } = spyClient(async () => {
      await gate;
      return ok();
    });
    const s = createSession(client);
    s.touch();
    const stages: string[] = [];
    const run = s.run(fixture('requirements.txt'), 'requirements.txt', { onStage: (st) => stages.push(`${st.stage} ${'packages' in st ? st.packages : st.repo}`) });
    await new Promise((r) => setTimeout(r, 5));
    expect(stages).toEqual(['waiting 5']);
    release();
    expect((await run).ok).toBe(true);
  });

  it('returns parse failures without touching the network again', async () => {
    const { calls, client } = spyClient();
    const s = createSession(client);
    await s.touch();
    const out = await s.run('just some words\nthat are not a lockfile', null);
    expect(out.ok === false && out.failure.kind === 'parse' && out.failure.error.kind).toBe('unknown');
    expect(calls).toHaveLength(2);
  });

  it('merges packages-older.json into the index, and checks the tracked CVEs alone without it', async () => {
    const tracked = testIndex();
    const extra = testIndex();
    const id = 'CVE-2019-9001';
    const cols = extra.cves.cols;
    const r = [...extra.cves.rows[0]];
    r[cols.indexOf('id')] = id;
    extra.cves.rows = [r];
    extra.packages = { npm: { 'left-pad': [[id, 'GHSA-9999-9999-9999', [['>=0', '<9.0.0']]]] } };
    const { client } = spyClientWith(() => new Response(JSON.stringify(extra), { status: 200 }));
    const s = createSession(client);
    await s.touch();
    expect(s.index()?.cves.rows).toHaveLength(tracked.cves.rows.length + 1);
    expect(s.older()).toEqual({ loaded: true, ids: new Set([id]) });
    const out = await s.run('pkg:npm/left-pad@1.0.0', null);
    expect(out.ok && out.held.result.cves.map((c) => c.row.id)).toContain(id);
    const without = createSession(spyClient().client);
    await without.touch();
    expect(without.older()).toEqual({ loaded: false, ids: new Set() });
    expect(without.index()?.cves.rows).toHaveLength(tracked.cves.rows.length);
  });
});
