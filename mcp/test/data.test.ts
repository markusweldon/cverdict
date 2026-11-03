import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ROW_COLS } from '../../shared/contract';
import { MCP_DATA_BASES } from '../../shared/mcp';
import { shardOf } from '../../shared/shard';
import { DataClient, basesFromEnv, parse, type DataClientOptions } from '../src/data';
import { getVerdict, listSignal, wokeUp } from '../src/tools';
import { GEN, NOW, emptyShard, fakeFetch, files, meta, stall, type Script } from './fixture';

const A = 'https://a.test/v1/';
const B = 'https://b.test/v1/';

function setup(script?: Script, opts: Partial<DataClientOptions> = {}, tree = files()) {
  let clock = NOW;
  const f = fakeFetch(tree, [A, B], script);
  const dc = new DataClient({ bases: [A, B], fetch: f.fetch, now: () => clock, ...opts });
  return {
    dc,
    tree,
    log: f.log,
    tick: (ms: number) => (clock += ms),
    signal: () => dc.run((c) => listSignal(c, {}, clock)),
  };
}

const paths = (log: { path: string; base: string }[]) => log.map((l) => `${l.base === A ? 'A' : 'B'}:${l.path}`);

afterEach(() => {
  vi.useRealTimers();
});

describe('cache', () => {
  it('refetches meta after the TTL and other files only when the run changes', async () => {
    const t = setup();
    await t.signal();
    expect(paths(t.log)).toEqual(['A:meta.json', 'A:signal.json']);
    await t.signal();
    expect(t.log).toHaveLength(2);
    t.tick(301_000);
    await t.signal();
    expect(paths(t.log).slice(2)).toEqual(['A:meta.json']);
  });

  it('refetches a file from an older run at most once per TTL (a CDN can lag behind meta.json)', async () => {
    const t = setup();
    await t.signal();
    const G2 = '2026-11-03T07:50:00.000Z';
    t.tree.set('meta.json', meta({ generated_at: G2 }));
    t.tick(301_000);
    const r = await t.signal();
    expect(paths(t.log).slice(2)).toEqual(['A:meta.json', 'A:signal.json']);
    // The answer shows both runs rather than hiding the lag.
    expect(r.data.files.map((f) => [f.path, f.generated_at])).toEqual([
      ['v1/meta.json', G2],
      ['v1/signal.json', GEN],
    ]);
    await t.signal();
    expect(t.log).toHaveLength(4);
    t.tick(301_000);
    await t.signal();
    expect(paths(t.log).slice(4)).toEqual(['A:meta.json', 'A:signal.json']);
  });

  it('shares in-flight fetches between concurrent calls', async () => {
    const t = setup();
    await Promise.all([t.signal(), t.signal(), t.dc.run((c) => listSignal(c, { tiers: ['exploited'] }, NOW))]);
    expect(paths(t.log)).toEqual(['A:meta.json', 'A:signal.json']);
  });

  it('keeps at most 64 shards, dropping the least recently loaded', async () => {
    const t = setup();
    const names = Array.from({ length: 70 }, (_, i) => i.toString(16).padStart(2, '0'));
    for (const n of names) await t.dc.run((c) => c.shards([n]));
    const before = t.log.length;
    await t.dc.run((c) => c.shards([names[69]]));
    expect(t.log.length).toBe(before);
    await t.dc.run((c) => c.shards([names[0]]));
    expect(t.log.slice(before).map((l) => l.path)).toEqual(['cve/00.json']);
  });
});

describe('bases and failures', () => {
  it('treats 404 as final: the next base is not asked', async () => {
    const t = setup((path) => (path === 'woke.json' ? new Response('', { status: 404 }) : undefined));
    await expect(t.dc.run((c) => wokeUp(c, {}, NOW))).rejects.toThrow('woke.json is not on the data branch yet, so this tool has nothing to read. The other tools still work.');
    expect(paths(t.log)).toEqual(['A:meta.json', 'A:woke.json']);
  });

  it('falls through to the next base on 5xx and network errors', async () => {
    const t = setup((path, base) => {
      if (base !== A) return undefined;
      if (path === 'meta.json') return new Response('', { status: 503 });
      throw new TypeError('fetch failed', { cause: Object.assign(new Error('getaddrinfo ENOTFOUND a.test'), { code: 'ENOTFOUND' }) });
    });
    const r = await t.signal();
    expect(paths(t.log)).toEqual(['A:meta.json', 'B:meta.json', 'A:signal.json', 'B:signal.json']);
    expect(r.data.files.map((f) => f.url)).toEqual([`${B}meta.json`, `${B}signal.json`]);
  });

  it('refuses redirects and treats one as a failure of that base', async () => {
    const t = setup((_path, base, init) => {
      expect(init.redirect).toBe('error');
      if (base === A) throw new TypeError('fetch failed', { cause: new Error('unexpected redirect') });
      return undefined;
    });
    const r = await t.signal();
    expect(r.data.files.every((f) => f.url.startsWith(B))).toBe(true);
  });

  it('moves a base that answers 429 or 403 to the back for 10 minutes', async () => {
    let throttled = true;
    const t = setup((_path, base) => (base === A && throttled ? new Response('', { status: 429 }) : undefined));
    await t.signal();
    expect(paths(t.log)).toEqual(['A:meta.json', 'B:meta.json', 'B:signal.json']);
    throttled = false;
    t.tick(301_000);
    await t.signal();
    expect(paths(t.log).slice(3)).toEqual(['B:meta.json']);
    t.tick(300_000);
    await t.signal();
    expect(paths(t.log).slice(4)).toEqual(['A:meta.json']);
  });

  it('falls through after 4 s without response headers', async () => {
    vi.useFakeTimers();
    const t = setup((_path, base, init) => (base === A ? stall(init) : undefined));
    const p = t.signal();
    await vi.advanceTimersByTimeAsync(4_100);
    await vi.advanceTimersByTimeAsync(4_100);
    const r = await p;
    expect(r.data.files.map((f) => f.url)).toEqual([`${B}meta.json`, `${B}signal.json`]);
  });

  it('answers with the 3.4 message when every base fails and nothing is cached', async () => {
    const t = setup((_path, base) => new Response('', { status: base === A ? 503 : 502 }));
    await expect(t.signal()).rejects.toThrow(
      'CVErdict could not load its data right now (a.test: HTTP 503 for meta.json; b.test: HTTP 502 for meta.json). Try again in a few minutes, or read the files directly: https://github.com/markusweldon/cverdict/tree/data/v1',
    );
  });

  it('rejects another schema_version with an update message, even with a copy cached', async () => {
    const t = setup();
    await t.signal();
    t.tree.set('meta.json', { ...meta(), schema_version: 2 });
    t.tick(301_000);
    await expect(t.signal()).rejects.toThrow('The published data uses schema version 2; this server reads version 1. Update the server: https://github.com/markusweldon/cverdict/blob/main/mcp/README.md');
  });

  it('answers from the last good copy when a refresh fails, says so, and retries only after the TTL', async () => {
    let down = false;
    const t = setup((_path, base) => (down ? new Response('', { status: base === A ? 503 : 429 }) : undefined));
    await t.signal();
    down = true;
    t.tick(301_000);
    const r = await t.signal();
    expect(r.data.warning).toBe('Could not refresh the data (a.test: HTTP 503 for meta.json; b.test: HTTP 429 for meta.json). This answer uses the copy loaded at 2026-11-03 08:20 UTC.');
    expect(r.total).toBeGreaterThan(0);
    const n = t.log.length;
    await t.signal();
    expect(t.log.length).toBe(n);
    down = false;
    t.tick(301_000);
    expect((await t.signal()).data.warning).toBeNull();
  });
});

describe('untrusted downloads', () => {
  const zeros = new Uint8Array(1024 * 1024);

  it('aborts a body past the cap while reading it', async () => {
    let pulled = 0;
    const t = setup(
      (path) =>
        path === 'meta.json'
          ? new Response(
              new ReadableStream({
                pull(c) {
                  pulled += zeros.byteLength;
                  c.enqueue(zeros);
                },
              }),
              { headers: { 'content-encoding': 'gzip' } },
            )
          : undefined,
      { bases: [A], maxBytes: 4 * 1024 * 1024 },
    );
    await expect(t.signal()).rejects.toThrow(`a.test: body over ${4 * 1024 * 1024} bytes for meta.json`);
    expect(pulled).toBeLessThanOrEqual(7 * 1024 * 1024);
  });

  it('refuses a Content-Length over the cap before reading', async () => {
    let pulled = 0;
    const t = setup(
      () =>
        new Response(
          new ReadableStream({
            pull(c) {
              pulled++;
              c.enqueue(zeros);
            },
          }),
          { headers: { 'content-length': String(30 * 1024 * 1024) } },
        ),
      { bases: [A] },
    );
    await expect(t.signal()).rejects.toThrow('body over');
    expect(pulled).toBeLessThanOrEqual(1);
  });

  it('rejects row tables whose columns differ from ROW_COLS, and never gives a row another prototype', async () => {
    const tree = files();
    const signal = tree.get('signal.json') as { cols: string[] };
    tree.set('signal.json', { ...signal, cols: ['__proto__', ...ROW_COLS.slice(1)] });
    const t = setup(undefined, { bases: [A] }, tree);
    await expect(t.signal()).rejects.toThrow('a.test: not valid data: columns differ from ROW_COLS for signal.json');
    // A spoof that joins to the same string is caught too.
    expect(() => parse.rows({ cols: ['id,pub', ...ROW_COLS.slice(2)], rows: [] })).toThrow('columns differ');
    const ok = parse.rows(files().get('index.json') as Record<string, unknown>);
    expect(ok.rows.every((r) => Object.getPrototypeOf(r) === Object.prototype)).toBe(true);
  });

  it('rejects a row of the wrong length', () => {
    expect(() => parse.rows({ cols: [...ROW_COLS], rows: [['CVE-2026-1']] })).toThrow('a row has the wrong length');
  });
});

describe('deadline and timers', () => {
  it('answers "not loaded in time" within the 10 s call deadline, fetching at most 6 shards at once', async () => {
    vi.useFakeTimers();
    // 15 IDs (the most get_verdict takes) in 15 shards: three waves of 3.9 s at 6 at a time.
    const ids: string[] = [];
    for (let n = 1; ids.length < 15; n++) {
      const id = `CVE-2026-${String(20000 + n)}`;
      if (!ids.some((x) => shardOf(x) === shardOf(id))) ids.push(id);
    }
    let open = 0;
    let peak = 0;
    const t = setup((path, _base, init) => {
      if (!path.startsWith('cve/')) return undefined;
      open++;
      peak = Math.max(peak, open);
      return stall(init, 3_900, () => Response.json(emptyShard())).finally(() => open--);
    });
    let settled = -1;
    const start = Date.now();
    const p = t.dc.run((c) => getVerdict(c, { ids }, NOW)).catch((e: Error) => {
      settled = Date.now() - start;
      return e;
    });
    for (let i = 0; i < 12 && settled < 0; i++) await vi.advanceTimersByTimeAsync(1_000);
    const err = await p;
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/^CVErdict could not load its data in time \(.*no answer within 10 s for cve\/..\.json\)\. Try again in a minute/);
    expect(settled).toBeGreaterThanOrEqual(10_000);
    expect(settled).toBeLessThanOrEqual(10_500);
    expect(new Set(ids.map(shardOf)).size).toBe(15);
    expect(peak).toBe(6);
  });

  it('stops a call at the first failed shard: fetches in flight are aborted, queued ones never sent', async () => {
    const ids = Array.from({ length: 15 }, (_, i) => `CVE-2026-${30000 + i}`);
    let first = true;
    let aborted = 0;
    const t = setup((path, _base, init) => {
      if (!path.startsWith('cve/')) return undefined;
      if (first) {
        first = false;
        return new Response('', { status: 404 });
      }
      return stall(init).catch((e) => {
        aborted++;
        throw e;
      });
    });
    await expect(t.dc.run((c) => getVerdict(c, { ids }, NOW))).rejects.toThrow('is not on the data branch yet');
    await new Promise((r) => setTimeout(r, 10));
    const shardRequests = t.log.filter((l) => l.path.startsWith('cve/')).length;
    expect(new Set(ids.map(shardOf)).size).toBeGreaterThan(6);
    expect(shardRequests).toBeLessThanOrEqual(6);
    expect(aborted).toBe(shardRequests - 1);
  });

  it('leaves no timer running after a call, and fetches nothing while idle', async () => {
    vi.useFakeTimers();
    const t = setup();
    await t.signal();
    await t.dc.run((c) => getVerdict(c, { ids: ['CVE-2026-10001', 'CVE-2026-10002'] }, NOW));
    expect(vi.getTimerCount()).toBe(0);
    const n = t.log.length;
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(t.log.length).toBe(n);
  });
});

describe('CVERDICT_DATA_BASE', () => {
  it('defaults to the data branch, then the site', () => {
    expect(basesFromEnv(undefined)).toEqual([...MCP_DATA_BASES]);
    expect(basesFromEnv(' ')).toEqual(MCP_DATA_BASES);
    expect(MCP_DATA_BASES).toEqual(['https://raw.githubusercontent.com/markusweldon/cverdict/data/v1/', 'https://cverdict-psi.vercel.app/data/v1/']);
  });

  it('takes https bases and http on localhost only', () => {
    expect(basesFromEnv('https://mirror.example/v1, http://localhost:5173/data/v1')).toEqual(['https://mirror.example/v1/', 'http://localhost:5173/data/v1/']);
    expect(basesFromEnv('http://127.0.0.1:8080/v1/')).toEqual(['http://127.0.0.1:8080/v1/']);
    expect(() => basesFromEnv('http://169.254.169.254/v1/')).toThrow('use https');
    expect(() => basesFromEnv('file:///etc/v1/')).toThrow('use https');
    expect(() => basesFromEnv('https://user:pw@mirror.example/v1/')).toThrow('no credentials');
    expect(() => basesFromEnv('not a url')).toThrow('not a URL');
  });
});

describe('with a real HTTP server and the real fetch', () => {
  let server: Server | undefined;
  afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

  async function serve(handler: Parameters<typeof createServer>[1]): Promise<string> {
    server = createServer(handler);
    await new Promise<void>((r) => server!.listen(0, '127.0.0.1', r));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it('stops a gzip bomb at the decoded cap and does not follow redirects', async () => {
    const bomb = gzipSync(Buffer.alloc(40 * 1024 * 1024, 0x20));
    const tree = files();
    const origin = await serve((req, res) => {
      const path = req.url!.replace(/^\/(a|b)\/v1\//, '');
      if (req.url!.startsWith('/a/') && path === 'signal.json') {
        res.writeHead(200, { 'content-encoding': 'gzip', 'content-type': 'application/json' });
        res.end(bomb);
      } else if (req.url!.startsWith('/a/') && path === 'meta.json') {
        res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data' });
        res.end();
      } else {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(tree.get(path) ?? emptyShard()));
      }
    });
    const dc = new DataClient({ bases: [`${origin}/a/v1/`], now: () => NOW });
    await expect(dc.run((c) => listSignal(c, {}, NOW))).rejects.toThrow(/127\.0\.0\.1:\d+: unexpected redirect for meta\.json/);
    const two = new DataClient({ bases: [`${origin}/b/v1/`], now: () => NOW });
    const t0 = Date.now();
    const meta = await two.run((c) => c.meta());
    expect(meta.generated_at).toBe(GEN);
    const bombed = new DataClient({ bases: [`${origin}/a/v1/`], fetch: (u, i) => fetch(String(u).replace('/a/v1/meta.json', '/b/v1/meta.json'), i), now: () => NOW });
    await expect(bombed.run((c) => listSignal(c, {}, NOW))).rejects.toThrow(`body over ${24 * 1024 * 1024} bytes for signal.json`);
    expect(Date.now() - t0).toBeLessThan(10_000);
  });
});
