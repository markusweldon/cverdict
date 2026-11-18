import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { CIRCL_KEV, EU_KEV, SANITY, SIBERKAPAN, type SanityLimits } from '../../src/config';
import { euKevListings, loadCirclKev, loadEuKev, loadSiberKapan, mergeCatalogs, parseCirclKev, parseEuKevBody, parseEuKevDump } from '../../src/sources/catalogs';
import { SanityError } from '../../src/sources/source';
import { HttpClient, type FetchLike } from '../../src/util/http';
import { makeKev, makeKevCatalog } from '../fixtures/model/builders';
import { captureLogger, FIXTURES, tempDir } from './helpers';

const read = (name: string) => readFileSync(path.join(FIXTURES, name));
const LOOSE: SanityLimits = { ...SANITY, euKevEntries: 1, euvdDumpRows: 1, circlKevEntries: 1, siberkapanEntries: 1 };
const CIRCL = { id: 'circl-kev' as const, origin: CIRCL_KEV.origin, entryUrl: CIRCL_KEV.entryUrl };

function client(fetch: FetchLike, cacheDir = tempDir(), clock = () => Date.parse('2026-11-18T12:00:00Z')) {
  return new HttpClient({ cacheDir, offline: false, log: captureLogger(), fetch, sleep: async () => {}, clock });
}
const ok = (body: Buffer | string) => async () => new Response(typeof body === 'string' ? body : new Uint8Array(body), { status: 200 });

describe('ENISA EU KEV (EUVD dump)', () => {
  it('keeps only EU KEV rows, by CVE ID, and remembers whether CISA KEV also lists them', () => {
    const { entries, rows, newest } = parseEuKevDump(JSON.parse(read('euvd-kev-sample.json').toString()));
    expect(rows).toBe(4);
    expect(newest).toBe('2026-10-24');
    expect([...entries.keys()]).toEqual(['CVE-2026-110447', 'CVE-2026-0257', 'CVE-2026-100878']);
    expect(entries.get('CVE-2026-100878')).toEqual({ euvdId: 'EUVD-2026-58113', dateAdded: '2026-10-24', euOnly: true });
    expect(entries.get('CVE-2026-110447')?.euOnly).toBe(false);
  });

  it('drops a malformed EUVD id from the link and tolerates odd rows', () => {
    const { entries } = parseEuKevDump([
      { cveId: 'cve-2026-1001', euvdId: '<script>', dateAdded: '2026-02-30', sources: ['eukev_kev'] },
      { cveId: 'CVE-2026-1001', euvdId: 'EUVD-2026-9', dateAdded: '2026-03-01', sources: ['eukev_kev'] },
      null,
      { cveId: 'CVE-2026-1002', sources: 'eukev_kev' },
    ]);
    expect(entries.get('CVE-2026-1001')).toEqual({ euvdId: null, dateAdded: null, euOnly: true });
    expect(entries.has('CVE-2026-1002')).toBe(false);
    expect(euKevListings(entries, null).get('CVE-2026-1001')).toEqual({ catalog: 'eu-kev', added: null, status: 'confirmed', url: EU_KEV.info.home });
  });

  it('dates a listing only when the dump date cannot be the CISA one', () => {
    const raw = new Map([
      ['CVE-2026-1', { euvdId: 'EUVD-2026-1', dateAdded: '2026-09-25', euOnly: false }],
      ['CVE-2026-2', { euvdId: 'EUVD-2026-2', dateAdded: '2026-09-25', euOnly: false }],
      ['CVE-2026-3', { euvdId: 'EUVD-2026-3', dateAdded: '2026-09-25', euOnly: false }],
      ['CVE-2026-4', { euvdId: 'EUVD-2026-4', dateAdded: '2026-09-25', euOnly: true }],
    ]);
    const kev = makeKevCatalog([makeKev('CVE-2026-1', { dateAdded: '2026-10-13' }), makeKev('CVE-2026-2', { dateAdded: '2026-09-25' })]);
    const added = (k: typeof kev | null) => Object.fromEntries([...euKevListings(raw, k)].map(([id, l]) => [id, l.added]));
    // Before the CISA day: EU KEV's own. The CISA day: CISA's, EU listed it then or later. Not in the
    // CISA feed (removed there): unknown. EU only: EU KEV's own.
    expect(added(kev)).toEqual({ 'CVE-2026-1': '2026-09-25', 'CVE-2026-2': null, 'CVE-2026-3': null, 'CVE-2026-4': '2026-09-25' });
    // Without the CISA catalog nothing shared can be dated.
    expect(added(null)).toEqual({ 'CVE-2026-1': null, 'CVE-2026-2': null, 'CVE-2026-3': null, 'CVE-2026-4': '2026-09-25' });
    expect(euKevListings(raw, kev).get('CVE-2026-1')?.url).toBe('https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-1');
  });

  it('rejects a dump that is not an array or is implausibly small', () => {
    expect(() => parseEuKevDump({ items: [] })).toThrow(/expected an array/);
    const body = read('euvd-kev-sample.json');
    expect(() => parseEuKevBody(body, SANITY)).toThrow(SanityError);
    expect(() => parseEuKevBody(body, { ...LOOSE, euKevEntries: 4 })).toThrow(/only 3 EU KEV entries/);
    expect(parseEuKevBody(body, LOOSE)).toMatchObject({ records: 3, version: '2026-10-24' });
  });
});

describe('CIRCL Vulnerability-Lookup catalogs', () => {
  it('keeps exploited CVE entries of the requested catalog; confirmed beats suspected', () => {
    const { entries, newest } = parseCirclKev(JSON.parse(read('circl-kev-sample.json').toString()), CIRCL);
    expect(newest).toBe('2026-10-25');
    // The GCVE id, the CISA catalog's entry and the withdrawn one are skipped.
    expect([...entries.keys()]).toEqual(['CVE-2026-109733', 'CVE-2026-94220']);
    expect(entries.get('CVE-2026-109733')).toEqual({
      catalog: 'circl-kev',
      added: '2026-10-25',
      status: 'confirmed',
      url: 'https://vulnerability.circl.lu/vuln/cve-2026-109733',
      seen: '2026-10-20',
    });
    expect(entries.get('CVE-2026-94220')?.status).toBe('suspected');
  });

  it('dates a listing by asserted_at only: first_seen_at may be estimated after the fact', () => {
    const { entries } = parseCirclKev(JSON.parse(read('siberkapan-sample.json').toString()), { id: 'siberkapan', origin: SIBERKAPAN.origin, entryUrl: SIBERKAPAN.entryUrl });
    expect(entries.get('CVE-2026-110447')).toMatchObject({ added: null, seen: '2026-10-05' });
  });

  it('of two entries with the same status, keeps the earliest dated one', () => {
    const entry = (asserted: string | null) => ({
      vulnerability: { vulnId: 'CVE-2026-5005' },
      gcve: { origin_uuid: CIRCL_KEV.origin },
      status: { exploited: true, status_reason: 'confirmed' },
      timestamps: asserted ? { asserted_at: asserted } : {},
    });
    const { entries } = parseCirclKev({ data: [entry(null), entry('2026-10-09T00:00:00Z'), entry('2026-10-01T00:00:00Z'), entry('2026-10-05T00:00:00Z')] }, CIRCL);
    expect(entries.get('CVE-2026-5005')?.added).toBe('2026-10-01');
  });

  it('rejects a truncated page and a body without data', () => {
    expect(() => parseCirclKev({ metadata: { count: 1001 }, data: [] }, CIRCL)).toThrow(/page holds 0 of 1001 entries/);
    expect(() => parseCirclKev({ error: 'rate limited' }, CIRCL)).toThrow(/missing "data"/);
  });
});

describe('loading the catalogs', () => {
  it('serves the cached copy, marked stale, when the live fetch fails, and nothing without one', async () => {
    const cacheDir = tempDir();
    const first = await loadEuKev(client(ok(read('euvd-kev-sample.json')), cacheDir), LOOSE);
    expect(first.status).toMatchObject({ id: 'eu-kev', ok: true, stale: false, records: 3, license: EU_KEV.info.license });
    // A day later (past the 6-hour reuse window) the host fails: the cached copy is used.
    const failing: FetchLike = async () => new Response('Bad Gateway', { status: 502 });
    const later = await loadEuKev(client(failing, cacheDir, () => Date.parse('2026-11-19T12:00:00Z')), LOOSE);
    expect(later.status).toMatchObject({ ok: true, stale: true, records: 3 });
    expect(later.status.error).toMatch(/HTTP 502/);
    expect(later.data?.size).toBe(3);
    const none = await loadCirclKev(client(failing), LOOSE);
    expect(none.data).toBeNull();
    expect(none.status).toMatchObject({ id: 'circl-kev', ok: false, stale: true });
  });

  it('rejects a body that fails its checks and keeps the last good copy', async () => {
    const cacheDir = tempDir();
    await loadSiberKapan(client(ok(read('siberkapan-sample.json')), cacheDir), LOOSE);
    const empty = await loadSiberKapan(
      client(ok(JSON.stringify({ metadata: { count: 0 }, data: [] })), cacheDir, () => Date.parse('2026-11-19T12:00:00Z')),
      LOOSE,
    );
    expect(empty.status).toMatchObject({ ok: true, stale: true });
    expect(empty.status.error).toMatch(/only 0 SiberKapan honeypot catalog CVE entries/);
    expect([...(empty.data?.keys() ?? [])]).toEqual(['CVE-2026-110447']);
  });

  it('asks CIRCL at most every 12 hours and identifies itself', async () => {
    const cacheDir = tempDir();
    const seen: { url: string; ua: string | null }[] = [];
    const fetch: FetchLike = async (url, init) => {
      seen.push({ url, ua: new Headers(init.headers).get('user-agent') });
      return new Response(read('circl-kev-sample.json'), { status: 200 });
    };
    await loadCirclKev(client(fetch, cacheDir, () => Date.parse('2026-11-18T00:00:00Z')), LOOSE);
    const reused = await loadCirclKev(client(fetch, cacheDir, () => Date.parse('2026-11-18T11:00:00Z')), LOOSE);
    expect(reused.status).toMatchObject({ ok: true, stale: false });
    await loadCirclKev(client(fetch, cacheDir, () => Date.parse('2026-11-18T13:00:00Z')), LOOSE);
    expect(seen.map((s) => s.url)).toEqual([CIRCL_KEV.urls[0], CIRCL_KEV.urls[0]]);
    expect(seen[0].ua).toMatch(/^cverdict-pipeline \(\+https:\/\/github\.com\//);
  });

  it('merges the catalogs per ingested CVE in a fixed order', () => {
    const l = (catalog: 'eu-kev' | 'circl-kev' | 'siberkapan', added: string | null) => ({ catalog, added, status: 'confirmed' as const, url: 'u' });
    const merged = mergeCatalogs(
      new Set(['CVE-1', 'CVE-2']),
      new Map([['CVE-1', l('eu-kev', '2026-01-01')], ['CVE-9', l('eu-kev', null)]]),
      null,
      new Map([['CVE-1', l('siberkapan', null)], ['CVE-2', l('siberkapan', null)]]),
    );
    expect([...merged]).toEqual([
      ['CVE-1', [l('eu-kev', '2026-01-01'), l('siberkapan', null)]],
      ['CVE-2', [l('siberkapan', null)]],
    ]);
  });
});
