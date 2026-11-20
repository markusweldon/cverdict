import { describe, expect, it } from 'vitest';
import { NEW_EXPLOITED_LIST_MAX, SCHEMA_VERSION } from '../../../shared/contract';
import { buildStats, dayRange, firstExploitedSignal, freshListings, isNewlyExploited, monthRange, newlyExploitedSignal, shortTitle } from '../../src/stats';
import type { History } from '../../src/types';
import { NOW, daysAgo, listing, makeCve, makeKev, makeKevCatalog, msf, score, ssvc } from '../fixtures/model/builders';
import type { CatalogListing } from '../../src/types';

const DAY_MS = 86_400_000;

function history(): History {
  return {
    published: new Map([
      ['1999-09', 1500],
      ['2026-10', 16000],
    ]),
    reserved: new Map([['2026-10', 20000]]),
    rejected: new Map([['2026-10', 300]]),
    ai: new Map([['2026-10', 120]]),
    totalRecords: 414000,
  };
}

describe('ranges', () => {
  it('monthRange is inclusive and crosses years', () => {
    expect(monthRange('2025-11', '2026-02')).toEqual(['2025-11', '2025-12', '2026-01', '2026-02']);
  });

  it('dayRange covers both partial end days', () => {
    const days = dayRange(new Date('2026-09-26T19:30:00Z'), NOW);
    expect(days[0]).toBe('2026-09-26');
    expect(days.at(-1)).toBe('2026-10-26');
    expect(days).toHaveLength(31);
  });
});

describe('buildStats', () => {
  const windowStart = new Date(NOW.getTime() - 30 * DAY_MS);
  const window = [
    score(makeCve({ id: 'CVE-2026-1', published: '2026-10-26T18:10:00Z', cna: 'microsoft', aiCredit: 'Claude' })),
    score(makeCve({ id: 'CVE-2026-2', published: '2026-10-26T18:50:00Z', cna: 'microsoft', aiCredit: 'claude', cnaCvssMissing: true })),
    score(makeCve({ id: 'CVE-2026-3', published: '2026-10-13T17:00:00Z', cna: 'oracle', aiCredit: 'Big Sleep' }), {
      kev: [makeKev('CVE-2026-3')],
    }),
    score(makeCve({ id: 'CVE-2026-4', published: daysAgo(29.99), cna: 'microsoft' }), { metasploit: { 'CVE-2026-4': [msf('exploit/x')] } }),
  ];
  const kev = makeKevCatalog([makeKev('CVE-2021-1', { dateAdded: '2021-11-03' }), makeKev('CVE-2026-3', { dateAdded: '2026-10-21' })]);
  const stats = buildStats({ history: history(), kev, window, windowStart, now: NOW });

  it('has the header fields', () => {
    expect(stats.schema_version).toBe(SCHEMA_VERSION);
    expect(stats.generated_at).toBe(NOW.toISOString());
  });

  it('monthly: every month since 1999 with KEV additions per month', () => {
    expect(stats.monthly[0]).toEqual({ month: '1999-01', published: 0, reserved: 0, rejected: 0, ai: 0, kev_added: 0 });
    expect(stats.monthly.at(-1)).toEqual({ month: '2026-10', published: 16000, reserved: 20000, rejected: 300, ai: 120, kev_added: 1 });
    expect(stats.monthly.find((m) => m.month === '2021-11')!.kev_added).toBe(1);
    expect(stats.monthly.find((m) => m.month === '1999-09')!.published).toBe(1500);
    expect(stats.monthly).toHaveLength((2026 - 1999) * 12 + 10);
  });

  it('daily: full window days (the partial first day left out), then today so far', () => {
    expect(stats.daily).toHaveLength(30);
    expect(stats.daily[0]).toEqual({ date: '2026-09-27', published: 0, passed: 0, exploited: 0 });
    expect(stats.daily.at(-1)).toEqual({ date: '2026-10-26', published: 2, passed: 0, exploited: 0 });
    expect(stats.daily.find((d) => d.date === '2026-10-13')).toEqual({ date: '2026-10-13', published: 1, passed: 1, exploited: 1 });
    // CVE-2026-4 was published at 19:44 on Sep 26, inside the window but on its partial first day.
    expect(stats.daily.some((d) => d.date === '2026-09-26')).toBe(false);
  });

  it('daily: a window starting at midnight keeps its first day', () => {
    const start = new Date('2026-09-26T00:00:00Z');
    const s = buildStats({ history: history(), kev, window, windowStart: start, now: NOW });
    expect(s.daily[0].date).toBe('2026-09-26');
    expect(s.daily).toHaveLength(31);
  });

  it('hourly: tier counts per hour bucket across the window', () => {
    expect(stats.hourly.start).toBe('2026-09-26T19:00:00.000Z');
    expect(stats.hourly.hours).toBe(30 * 24 + 1);
    expect(stats.hourly.counts).toHaveLength(stats.hourly.hours);
    const last = stats.hourly.counts.at(-2)!; // 18:00–19:00 on Oct 26
    expect(last).toEqual([0, 0, 0, 2]);
    expect(stats.hourly.counts.reduce((a, c) => a + c.reduce((x, y) => x + y, 0), 0)).toBe(4);
    expect(stats.hourly.counts[0]).toEqual([0, 1, 0, 0]);
  });

  it('cnas: counts, passed, CNA-missing CVSS and missing SSVC', () => {
    expect(stats.cnas[0]).toEqual({ cna: 'microsoft', count: 3, passed: 1, no_cvss: 1, ssvc_missing: 3 });
    expect(stats.cnas[1]).toMatchObject({ cna: 'oracle', count: 1, passed: 1 });
  });

  it('ai_credits: grouped case-insensitively, most frequent first', () => {
    expect(stats.ai_credits).toEqual([
      { text: 'Claude', count: 2 },
      { text: 'Big Sleep', count: 1 },
    ]);
  });
});

describe('newly exploited (hourly.new_exploited)', () => {
  const ID = 'CVE-2026-500';
  const cve = (o = {}) => makeCve({ id: ID, published: '2026-10-20T10:20:00Z', ...o });
  const kevOn = (dateAdded: string) => score(cve(), { kev: [makeKev(ID, { dateAdded })] });
  const listed = (...ls: CatalogListing[]) => score(cve(), { catalogs: { [ID]: ls } });
  // NOW is 2026-10-26T19:30Z, so the cutoff is 2026-10-23T19:30Z.

  it('counts a listing day from its 00:00 UTC start: inside 72h when that start is at or after now - 72h', () => {
    expect(isNewlyExploited(kevOn('2026-10-24'), undefined, NOW)).toBe(true);
    expect(isNewlyExploited(kevOn('2026-10-26'), undefined, NOW)).toBe(true);
    // Oct 23 00:00 is 91.5 hours before NOW: it may be older than 72h, so it is not new.
    expect(isNewlyExploited(kevOn('2026-10-23'), undefined, NOW)).toBe(false);
  });

  it('the 72h boundary is inclusive', () => {
    const midnight = new Date('2026-10-26T00:00:00Z');
    expect(isNewlyExploited(kevOn('2026-10-23'), undefined, midnight)).toBe(true);
    expect(isNewlyExploited(kevOn('2026-10-22'), undefined, midnight)).toBe(false);
    expect(isNewlyExploited(kevOn('2026-10-23'), undefined, new Date(midnight.getTime() + 1))).toBe(false);
  });

  it('uses the frozen now, not the clock: a listing after now does not exist yet', () => {
    const frozen = new Date('2026-10-25T12:00:00Z');
    expect(isNewlyExploited(kevOn('2026-10-26'), undefined, frozen)).toBe(false);
    expect(isNewlyExploited(kevOn('2026-10-25'), undefined, frozen)).toBe(true);
  });

  it('EU KEV and confirmed CIRCL listings count; CIRCL suspected or attempts-only and SiberKapan do not', () => {
    expect(isNewlyExploited(listed(listing('eu-kev', '2026-10-25')), [listing('eu-kev', '2026-10-25')], NOW)).toBe(true);
    expect(isNewlyExploited(listed(listing('circl-kev', '2026-10-25')), [listing('circl-kev', '2026-10-25')], NOW)).toBe(true);
    // Exploited through the vendor two days ago, so new; an older entry that does not set the tier does not block it.
    const itw = score(cve({ published: '2026-10-24T10:00:00Z', vendorInTheWild: true }));
    expect(itw.tier).toBe('exploited');
    expect(isNewlyExploited(itw, undefined, NOW)).toBe(true);
    for (const l of [listing('circl-kev', '2026-10-01', { status: 'suspected' }), listing('circl-kev', '2026-10-01', { attemptsOnly: true }), listing('siberkapan', '2026-10-01')]) {
      expect(isNewlyExploited(itw, [l], NOW)).toBe(true);
    }
  });

  it('SSVC exploitation active counts from its timestamp; an earlier one does not hide a new KEV listing', () => {
    const active = (at: string | null) => score(cve({ ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: at } }));
    expect(active('2026-10-25T08:00:00Z').tier).toBe('exploited');
    expect(isNewlyExploited(active('2026-10-25T08:00:00Z'), undefined, NOW)).toBe(true);
    expect(isNewlyExploited(active('2026-10-23T19:00:00Z'), undefined, NOW)).toBe(false);
    // Undated, it could be older.
    expect(isNewlyExploited(active(null), undefined, NOW)).toBe(false);
    // Exploited through SSVC since Oct 20, then listed by CISA KEV on Oct 25: the new listing is news.
    const both = score(cve({ ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: '2026-10-20T12:00:00Z' } }), { kev: [makeKev(ID, { dateAdded: '2026-10-25' })] });
    expect(newlyExploitedSignal(both, undefined, NOW)).toMatchObject({ via: 'CISA KEV', at: '2026-10-25' });
    // Its first signal alone is old.
    expect(firstExploitedSignal(both, undefined, NOW)).toBeNull();
    // SSVC alone from Oct 20: not new.
    expect(isNewlyExploited(active('2026-10-20T12:00:00Z'), undefined, NOW)).toBe(false);
    // An SSVC timestamp after the frozen now does not exist yet.
    expect(isNewlyExploited(active('2026-10-27T00:00:00Z'), undefined, NOW)).toBe(false);
  });

  it('a CNA exploited flag counts from publication', () => {
    expect(isNewlyExploited(score(cve({ published: '2026-10-25T00:00:00Z', cnaExploitMaturity: ['A'] })), undefined, NOW)).toBe(true);
    expect(isNewlyExploited(score(cve({ cnaExploitMaturity: ['A'] })), undefined, NOW)).toBe(false);
    // Flagged at publication on Oct 20, then listed by KEV on Oct 25: the KEV listing is new.
    const flagged = score(cve({ vendorInTheWild: true }), { kev: [makeKev(ID, { dateAdded: '2026-10-25' })] });
    expect(newlyExploitedSignal(flagged, undefined, NOW)).toMatchObject({ via: 'CISA KEV', at: '2026-10-25' });
    expect(isNewlyExploited(score(cve({ vendorInTheWild: true })), undefined, NOW)).toBe(false);
  });

  it('a new listing counts even after an older one, and the newest is named', () => {
    // CISA KEV on Oct 1, EU KEV on Oct 25: EU KEV is news.
    expect(newlyExploitedSignal(kevOn('2026-10-01'), [listing('eu-kev', '2026-10-25')], NOW)).toMatchObject({ via: 'EU KEV', at: '2026-10-25' });
    // EU KEV on Oct 2, CISA KEV on Oct 25.
    expect(newlyExploitedSignal(kevOn('2026-10-25'), [listing('eu-kev', '2026-10-02')], NOW)).toMatchObject({ via: 'CISA KEV', at: '2026-10-25' });
    // Both new: the newer is named; the same day names CISA KEV.
    expect(newlyExploitedSignal(kevOn('2026-10-24'), [listing('circl-kev', '2026-10-26')], NOW)).toMatchObject({ via: 'CIRCL', at: '2026-10-26' });
    expect(newlyExploitedSignal(kevOn('2026-10-25'), [listing('eu-kev', '2026-10-25')], NOW)).toMatchObject({ via: 'CISA KEV' });
    // Nothing in the last 72 hours.
    expect(isNewlyExploited(kevOn('2026-10-01'), [listing('eu-kev', '2026-10-02')], NOW)).toBe(false);
  });

  it('a new signal after the first one counts when it is a catalog listing, not SSVC', () => {
    // Vendor flag at publication (Oct 25), SSVC on Oct 26: the first signal (Vendor) is new and named, SSVC is not a listing.
    const s = score(cve({ published: '2026-10-25T00:00:00Z', vendorInTheWild: true, ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: '2026-10-26T08:00:00Z' } }));
    expect(newlyExploitedSignal(s, undefined, NOW)).toMatchObject({ via: 'Vendor' });
    // Old vendor flag, new SSVC: not new.
    const old = score(cve({ vendorInTheWild: true, ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: '2026-10-26T08:00:00Z' } }));
    expect(isNewlyExploited(old, undefined, NOW)).toBe(false);
  });

  it('freshListings: dated CISA KEV (or its ADP copy), EU KEV and confirmed CIRCL listings in the last 72 hours', () => {
    const vias = (s: ReturnType<typeof score>, ls?: CatalogListing[]) => freshListings(s, ls, NOW).map((x) => `${x.via} ${x.at}`);
    expect(vias(kevOn('2026-10-25'), [listing('eu-kev', '2026-10-24'), listing('circl-kev', '2026-10-26'), listing('siberkapan', '2026-10-26')])).toEqual([
      'CISA KEV 2026-10-25',
      'EU KEV 2026-10-24',
      'CIRCL 2026-10-26',
    ]);
    expect(vias(kevOn('2026-10-25'), [listing('circl-kev', '2026-10-26', { status: 'suspected' }), listing('circl-kev', '2026-10-26', { attemptsOnly: true }), listing('eu-kev', null)])).toEqual(['CISA KEV 2026-10-25']);
    expect(vias(score(cve({ adpKev: { dateAdded: '2026-10-26', reference: null } })))).toEqual(['CISA KEV 2026-10-26']);
    // Old, or after now.
    expect(vias(kevOn('2026-10-23'), [listing('eu-kev', '2026-10-27')])).toEqual([]);
  });

  it('an undated signal rules out the first-signal path, but a dated new listing still counts', () => {
    const s = kevOn('2026-10-25');
    expect(firstExploitedSignal(s, [listing('circl-kev', null)], NOW)).toBeNull();
    expect(isNewlyExploited(s, [listing('circl-kev', null)], NOW)).toBe(true);
    // Undated SSVC and a vendor flag from Oct 20, no new listing: not new.
    const undated = score(cve({ vendorInTheWild: true, ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: null } }));
    expect(isNewlyExploited(undated, [listing('circl-kev', null)], NOW)).toBe(false);
    expect(isNewlyExploited(s, [listing('eu-kev', null, { notBefore: '2026-10-25' })], NOW)).toBe(true);
    const adpOnly = score(cve({ adpKev: { dateAdded: null, reference: null } }));
    expect(isNewlyExploited(adpOnly, undefined, NOW)).toBe(false);
    const adpDated = score(cve({ adpKev: { dateAdded: '2026-10-25', reference: null } }));
    expect(isNewlyExploited(adpDated, undefined, NOW)).toBe(true);
  });

  it('only Exploited CVEs qualify', () => {
    expect(isNewlyExploited(score(cve()), [listing('siberkapan', '2026-10-25')], NOW)).toBe(false);
  });

  it('buildStats lists [hour, count] for hours by publication, oldest first, and [] when none', () => {
    const windowStart = new Date(NOW.getTime() - 30 * DAY_MS);
    const kev = makeKevCatalog();
    const a = score(makeCve({ id: 'CVE-2026-501', published: '2026-10-20T10:20:00Z' }), { kev: [makeKev('CVE-2026-501', { dateAdded: '2026-10-25' })] });
    const b = score(makeCve({ id: 'CVE-2026-502', published: '2026-10-20T10:50:00Z' }), { kev: [makeKev('CVE-2026-502', { dateAdded: '2026-10-26' })] });
    const c = score(makeCve({ id: 'CVE-2026-503', published: '2026-10-02T03:00:00Z' }), { catalogs: { 'CVE-2026-503': [listing('eu-kev', '2026-10-24')] } });
    const old = score(makeCve({ id: 'CVE-2026-504', published: '2026-10-02T03:00:00Z' }), { kev: [makeKev('CVE-2026-504', { dateAdded: '2026-10-03' })] });
    const catalogs = new Map([['CVE-2026-503', [listing('eu-kev', '2026-10-24')]]]);
    const s = buildStats({ history: history(), kev, window: [a, b, c, old], windowStart, now: NOW, catalogs });
    const start = Date.parse(s.hourly.start);
    const hourOf = (iso: string) => Math.floor((Date.parse(iso) - start) / 3_600_000);
    expect(s.hourly.new_exploited).toEqual([
      [hourOf('2026-10-02T03:00:00Z'), 1],
      [hourOf('2026-10-20T10:20:00Z'), 2],
    ]);
    for (const [h, n] of s.hourly.new_exploited!) expect(n).toBeLessThanOrEqual(s.hourly.counts[h][0]);
    expect(buildStats({ history: history(), kev, window: [old], windowStart, now: NOW }).hourly.new_exploited).toEqual([]);
  });

  it('names the first signal and when it came: a day for listings, a time for SSVC and the CNA flag', () => {
    const pick = (s: ReturnType<typeof score>, ls?: CatalogListing[]) => {
      const f = firstExploitedSignal(s, ls, NOW);
      return f && { at: f.at, via: f.via };
    };
    expect(pick(kevOn('2026-10-25'))).toEqual({ at: '2026-10-25', via: 'CISA KEV' });
    expect(pick(listed(listing('eu-kev', '2026-10-24')), [listing('eu-kev', '2026-10-24')])).toEqual({ at: '2026-10-24', via: 'EU KEV' });
    expect(pick(listed(listing('circl-kev', '2026-10-25')), [listing('circl-kev', '2026-10-25')])).toEqual({ at: '2026-10-25', via: 'CIRCL' });
    const active = score(cve({ ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: '2026-10-25T08:00:00Z' } }));
    expect(pick(active)).toEqual({ at: '2026-10-25T08:00:00.000Z', via: 'CISA SSVC' });
    expect(pick(score(cve({ published: '2026-10-25T09:15:00Z', vendorInTheWild: true })))).toEqual({ at: '2026-10-25T09:15:00.000Z', via: 'Vendor' });
    // EU KEV on Oct 24, CISA KEV on Oct 25: EU KEV came first.
    expect(pick(kevOn('2026-10-25'), [listing('eu-kev', '2026-10-24')])).toEqual({ at: '2026-10-24', via: 'EU KEV' });
    // The same day in both: CISA KEV is named.
    expect(pick(kevOn('2026-10-25'), [listing('eu-kev', '2026-10-25')])).toEqual({ at: '2026-10-25', via: 'CISA KEV' });
    expect(pick(kevOn('2026-10-01'))).toBeNull();
  });

  it('buildStats names the CVEs newest first, with short titles, and counts them from the same list', () => {
    const windowStart = new Date(NOW.getTime() - 30 * DAY_MS);
    const kev = makeKevCatalog();
    const a = score(makeCve({ id: 'CVE-2026-601', published: '2026-10-20T10:20:00Z', affected: [{ vendor: 'Fortinet', product: 'FortiOS', purl: null }] }), {
      kev: [makeKev('CVE-2026-601', { dateAdded: '2026-10-24' })],
    });
    const b = score(makeCve({ id: 'CVE-2026-602', published: '2026-10-26T09:00:00Z', vendorInTheWild: true, affected: [{ vendor: 'Microsoft', product: 'Microsoft Exchange', purl: null }] }));
    const c = score(makeCve({ id: 'CVE-2026-603', published: '2026-10-20T10:40:00Z', cna: 'GitHub_M', affected: [] }), { kev: [makeKev('CVE-2026-603', { dateAdded: '2026-10-25' })] });
    const s = buildStats({ history: history(), kev, window: [a, b, c], windowStart, now: NOW });
    const start = Date.parse(s.hourly.start);
    const hourOf = (iso: string) => Math.floor((Date.parse(iso) - start) / 3_600_000);
    expect(s.hourly.new_exploited_cves).toEqual([
      { id: 'CVE-2026-602', title: 'Microsoft Exchange', via: 'Vendor', at: '2026-10-26T09:00:00.000Z', hour: hourOf('2026-10-26T09:00:00Z') },
      { id: 'CVE-2026-603', title: 'GitHub', via: 'CISA KEV', at: '2026-10-25', hour: hourOf('2026-10-20T10:40:00Z') },
      { id: 'CVE-2026-601', title: 'Fortinet · FortiOS', via: 'CISA KEV', at: '2026-10-24', hour: hourOf('2026-10-20T10:20:00Z') },
    ]);
    expect(s.hourly.new_exploited).toEqual([
      [hourOf('2026-10-20T10:20:00Z'), 2],
      [hourOf('2026-10-26T09:00:00Z'), 1],
    ]);
  });

  it('keeps the newest NEW_EXPLOITED_LIST_MAX in the list and still counts every one', () => {
    const windowStart = new Date(NOW.getTime() - 30 * DAY_MS);
    const n = NEW_EXPLOITED_LIST_MAX + 7;
    const window = Array.from({ length: n }, (_, i) => {
      const id = `CVE-2026-${7000 + i}`;
      // One a minute back from NOW, each flagged by its CNA at publication.
      return score(makeCve({ id, published: new Date(NOW.getTime() - (i + 1) * 60_000).toISOString(), vendorInTheWild: true, affected: [{ vendor: 'Acme', product: 'x'.repeat(120), purl: null }] }));
    });
    const s = buildStats({ history: history(), kev: makeKevCatalog(), window, windowStart, now: NOW });
    const list = s.hourly.new_exploited_cves!;
    expect(list).toHaveLength(NEW_EXPLOITED_LIST_MAX);
    expect(list[0].id).toBe('CVE-2026-7000');
    expect(list.at(-1)!.id).toBe(`CVE-2026-${7000 + NEW_EXPLOITED_LIST_MAX - 1}`);
    expect(s.hourly.new_exploited!.reduce((t, [, k]) => t + k, 0)).toBe(n);
    // Long names are cut to 80 characters.
    expect(list[0].title).toHaveLength(80);
    expect(list[0].title.endsWith('…')).toBe(true);
  });
});

describe('newly exploited CVEs published before the window', () => {
  const windowStart = new Date(NOW.getTime() - 30 * DAY_MS);
  const old = (id: string, published: string, o: Parameters<typeof score>[1] = {}, c = {}) => score(makeCve({ id, published, inWindow: false, ...c }), o);

  it('lists a fresh catalog listing of an older CVE without an hour, with its publication day, and counts it in the total only', () => {
    const inWin = score(makeCve({ id: 'CVE-2026-801', published: '2026-10-20T10:20:00Z' }), { kev: [makeKev('CVE-2026-801', { dateAdded: '2026-10-24' })] });
    // Published in March 2024, listed by CISA KEV on Oct 25 (two days ago).
    const php = old('CVE-2024-4577', '2024-03-12T08:00:00Z', { kev: [makeKev('CVE-2024-4577', { dateAdded: '2026-10-25' })] }, { affected: [{ vendor: 'PHP Group', product: 'PHP', purl: null }] });
    // Listed by EU KEV on Oct 26, CISA KEV years ago: the EU KEV listing is news.
    const euNew = old('CVE-2021-44228', '2021-12-10T00:00:00Z', { kev: [makeKev('CVE-2021-44228', { dateAdded: '2021-12-10' })], catalogs: { 'CVE-2021-44228': [listing('eu-kev', '2026-10-26')] } });
    // Listed long ago only: not new.
    const stale = old('CVE-2023-1000', '2023-01-01T00:00:00Z', { kev: [makeKev('CVE-2023-1000', { dateAdded: '2023-02-01' })] });
    // A fresh SSVC or vendor flag on an older CVE is not enough (only catalog listings count outside the window).
    const ssvcOnly = old('CVE-2023-2000', '2023-01-01T00:00:00Z', {}, { ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: '2026-10-26T08:00:00Z' } });
    const catalogs = new Map([['CVE-2021-44228', [listing('eu-kev', '2026-10-26')]]]);
    const s = buildStats({ history: history(), kev: makeKevCatalog(), window: [inWin], windowStart, now: NOW, catalogs, outside: [php, euNew, stale, ssvcOnly] });
    const start = Date.parse(s.hourly.start);
    expect(s.hourly.new_exploited_cves).toEqual([
      { id: 'CVE-2021-44228', title: expect.any(String), via: 'EU KEV', at: '2026-10-26', published: '2021-12-10' },
      { id: 'CVE-2024-4577', title: 'PHP Group · PHP', via: 'CISA KEV', at: '2026-10-25', published: '2024-03-12' },
      { id: 'CVE-2026-801', title: expect.any(String), via: 'CISA KEV', at: '2026-10-24', hour: Math.floor((Date.parse('2026-10-20T10:20:00Z') - start) / 3_600_000) },
    ]);
    // Only the window's CVE is on the chart; the total counts all three.
    expect(s.hourly.new_exploited!.reduce((t, [, n]) => t + n, 0)).toBe(1);
    expect(s.hourly.new_exploited_total).toBe(3);
  });

  it('the total counts every one before the cap, older CVEs included', () => {
    const n = NEW_EXPLOITED_LIST_MAX + 3;
    const outside = Array.from({ length: n }, (_, i) => old(`CVE-2020-${10000 + i}`, '2020-05-01T00:00:00Z', { kev: [makeKev(`CVE-2020-${10000 + i}`, { dateAdded: '2026-10-26' })] }));
    const s = buildStats({ history: history(), kev: makeKevCatalog(), window: [], windowStart, now: NOW, outside });
    expect(s.hourly.new_exploited_cves).toHaveLength(NEW_EXPLOITED_LIST_MAX);
    expect(s.hourly.new_exploited_total).toBe(n);
    expect(s.hourly.new_exploited).toEqual([]);
  });

  it('a CVE given both in the window and outside is listed once, by its window row', () => {
    const a = score(makeCve({ id: 'CVE-2026-901', published: '2026-10-20T10:20:00Z' }), { kev: [makeKev('CVE-2026-901', { dateAdded: '2026-10-24' })] });
    const s = buildStats({ history: history(), kev: makeKevCatalog(), window: [a], windowStart, now: NOW, outside: [a] });
    expect(s.hourly.new_exploited_cves).toHaveLength(1);
    expect(s.hourly.new_exploited_cves![0].hour).toBeTypeOf('number');
    expect(s.hourly.new_exploited_total).toBe(1);
  });
});

describe('shortTitle', () => {
  it('uses vendor and product, else the CNA name, else the CVE ID', () => {
    expect(shortTitle(score(makeCve({ id: 'CVE-2026-1', affected: [{ vendor: 'Fortinet', product: 'FortiOS', purl: null }] })))).toBe('Fortinet · FortiOS');
    expect(shortTitle(score(makeCve({ id: 'CVE-2026-2', cna: 'GitHub_M', affected: [] })))).toBe('GitHub');
    expect(shortTitle(score(makeCve({ id: 'CVE-2026-3', cna: '', affected: [] })))).toBe('CVE-2026-3');
    expect(shortTitle(score(makeCve({ id: 'CVE-2026-4', cna: '  ', affected: [{ vendor: 'n/a', product: '', purl: null }] })))).toBe('CVE-2026-4');
  });
});
