/**
 * The privacy promises of the Check page, tested on the session logic (vitest runs in node, with
 * no DOM): no request before the first touch, exactly one after it (for packages.json), none from
 * a check, and no write to storage, history or cookies.
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

const { createSession, fileTooLarge, FILE_MAX, fmtSize, PASTE_MAX, pasteTooLarge, session } = await import('./session');
const { createDataClient } = await import('../data');
const fetchesAtImport = globalFetch.mock.calls.length;

const base = '/data/v1/';
type Reply = () => Response | Promise<Response>;
const ok: Reply = () => new Response(JSON.stringify(testIndex()), { status: 200, headers: { 'content-type': 'application/json' } });

function spyClient(...replies: Reply[]) {
  const calls: string[] = [];
  const impl = (async (input: RequestInfo | URL) => {
    calls.push(String(input));
    return (replies[calls.length - 1] ?? replies[replies.length - 1] ?? ok)();
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

  it('makes exactly one request on the first touch, for packages.json, and reuses it', async () => {
    const { calls, client } = spyClient();
    const s = createSession(client);
    expect(calls).toEqual([]);
    const a = s.touch();
    s.touch();
    s.touch();
    expect(calls).toEqual([`${base}packages.json`]);
    expect(await a).toBe(await s.touch());
    expect(calls).toHaveLength(1);
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
    expect(calls).toEqual([`${base}packages.json`]);
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
    expect(calls).toHaveLength(1);
  });

  it('reports a failed index load, and only Retry asks again', async () => {
    const { calls, client } = spyClient(() => new Response('upstream error', { status: 502 }), ok);
    const s = createSession(client);
    await expect(s.touch()).rejects.toThrow('HTTP 502');
    const out = await s.run(fixture('purls.txt'), 'purls.txt');
    expect(out.ok === false && out.failure.kind === 'index' && !out.failure.notPublished).toBe(true);
    s.touch();
    expect(calls).toHaveLength(1);
    await s.retry();
    expect(calls).toHaveLength(2);
    expect((await s.run(fixture('purls.txt'), 'purls.txt')).ok).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it('formats sizes for the messages', () => {
    expect([fmtSize(300), fmtSize(218_372), fmtSize(5_452_595), fmtSize(6.1 * 1024 * 1024), fmtSize(80 * 1024 * 1024)]).toEqual(['1 KB', '213 KB', '5.2 MB', '6.1 MB', '80 MB']);
  });

  it('drops a request that hangs when the user presses Retry', async () => {
    const { calls, client } = spyClient(() => new Promise<Response>(() => undefined), ok);
    const s = createSession(client);
    s.touch();
    s.touch();
    expect(calls).toHaveLength(1);
    await s.retry();
    expect(calls).toHaveLength(2);
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
    const run = s.run(fixture('requirements.txt'), 'requirements.txt', { onStage: (st) => stages.push(`${st.stage} ${st.packages}`) });
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
    expect(calls).toHaveLength(1);
  });
});
