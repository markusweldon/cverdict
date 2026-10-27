import { describe, expect, it } from 'vitest';
import { ROW_COLS, SCHEMA_VERSION, type CveDetail } from '../../shared/contract';
import { shardOf } from '../../shared/shard';
import { createDataClient, DataError, normalizeCveId } from './data';

type Routes = Record<string, unknown | (() => Response)>;

function fakeFetch(routes: Routes) {
  const calls: string[] = [];
  const impl = (async (input: RequestInfo | URL) => {
    const url = String(input);
    calls.push(url);
    const hit = routes[url];
    if (hit === undefined) return new Response('not found', { status: 404 });
    if (typeof hit === 'function') return (hit as () => Response)();
    return new Response(JSON.stringify(hit), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { impl, calls };
}

const base = '/data/v1/';
const head = { schema_version: SCHEMA_VERSION, generated_at: '2026-10-26T19:30:00.000Z' };
const row = ['CVE-2026-1001', '2026-10-26T10:00:00Z', 'fortinet', 'Fortinet', 'FortiOS', 'Auth bypass', 92, 'exploited', 1, 0, 1, 0, ['kev.listed'], 9.8, 0.4, '2026-10-29', null];

describe('createDataClient', () => {
  it('decodes row tables and fetches each file once', async () => {
    const { impl, calls } = fakeFetch({ [`${base}signal.json`]: { ...head, scope: 's', cols: ROW_COLS, rows: [row] } });
    const client = createDataClient(base, impl);
    expect(client.signal.peek()).toBeUndefined();
    const [a, b] = await Promise.all([client.signal.load(), client.signal.load()]);
    expect(a).toBe(b);
    expect(a[0]).toMatchObject({ id: 'CVE-2026-1001', s: 92, tier: 'exploited', x: 1, c: ['kev.listed'], kd: '2026-10-29' });
    expect(client.signal.peek()).toBe(a);
    await client.signal.load();
    expect(calls).toEqual([`${base}signal.json`]);
  });

  it('evicts failures so a retry refetches', async () => {
    let n = 0;
    const { impl, calls } = fakeFetch({
      [`${base}meta.json`]: () => (++n === 1 ? new Response('boom', { status: 503 }) : new Response(JSON.stringify({ ...head, knob_default: 50 }))),
    });
    const client = createDataClient(base, impl);
    await expect(client.meta.load()).rejects.toMatchObject({ name: 'DataError', status: 503 });
    await expect(client.meta.load()).resolves.toMatchObject({ knob_default: 50 });
    expect(calls).toHaveLength(2);
  });

  it('rejects files from another schema version and invalid JSON', async () => {
    const { impl } = fakeFetch({
      [`${base}stats.json`]: { schema_version: 2, generated_at: 'x' },
      [`${base}kev.json`]: () => new Response('{nope', { status: 200 }),
    });
    const client = createDataClient(base, impl);
    await expect(client.stats.load()).rejects.toThrow(/schema version 2/);
    await expect(client.kev.load()).rejects.toBeInstanceOf(DataError);
  });

  it('reports network errors as DataError', async () => {
    const client = createDataClient(base, (() => Promise.reject(new TypeError('offline'))) as typeof fetch);
    await expect(client.batches.load()).rejects.toThrow(/Network error/);
  });

  it('reads details from the shard named by shardOf, sharing one fetch per shard', async () => {
    const id = 'CVE-2026-1001';
    const detail = { id, score: { value: 92 } } as unknown as CveDetail;
    const { impl, calls } = fakeFetch({ [`${base}cve/${shardOf(id)}.json`]: { ...head, items: { [id]: detail } } });
    const client = createDataClient(base, impl);
    const loader = client.detail(' cve-2026-1001 ');
    expect(loader.key).toBe(`cve:${id}`);
    expect(loader.peek()).toBeUndefined();
    expect(await loader.load()).toEqual(detail);
    expect(client.detail(id).peek()).toEqual(detail);
    expect(calls).toEqual([`${base}cve/${shardOf(id)}.json`]);
  });

  it('returns null for IDs outside the data and for invalid IDs, without fetching the latter', async () => {
    const { impl, calls } = fakeFetch({ [`${base}cve/${shardOf('CVE-2019-0708')}.json`]: { ...head, items: {} } });
    const client = createDataClient(base, impl);
    expect(await client.detail('CVE-2019-0708').load()).toBeNull();
    expect(await client.detail('__proto__').load()).toBeNull();
    expect(client.detail('not-a-cve').peek()).toBeNull();
    expect(calls).toHaveLength(1);
  });

  it('checks for a newer run without the cache and swallows failures', async () => {
    const { impl } = fakeFetch({ [`${base}meta.json`]: { ...head, generated_at: '2026-10-26T20:30:00.000Z' } });
    expect(await createDataClient(base, impl).latestGeneratedAt()).toBe('2026-10-26T20:30:00.000Z');
    expect(await createDataClient(base, fakeFetch({}).impl).latestGeneratedAt()).toBeNull();
  });
});

describe('normalizeCveId', () => {
  it('upper-cases, trims and validates', () => {
    expect(normalizeCveId(' cve-2026-12345 ')).toBe('CVE-2026-12345');
    expect(normalizeCveId('CVE-2026-123')).toBeNull();
    expect(normalizeCveId('<script>')).toBeNull();
  });
});
