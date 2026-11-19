import { describe, expect, it } from 'vitest';
import { SCHEMA_VERSION } from '../../../shared/contract';
import { buildStats, dayRange, isNewlyExploited, monthRange } from '../../src/stats';
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

  it('SSVC exploitation active counts from its timestamp, and an earlier one blocks a new KEV listing', () => {
    const active = (at: string | null) => score(cve({ ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: at } }));
    expect(active('2026-10-25T08:00:00Z').tier).toBe('exploited');
    expect(isNewlyExploited(active('2026-10-25T08:00:00Z'), undefined, NOW)).toBe(true);
    expect(isNewlyExploited(active('2026-10-23T19:00:00Z'), undefined, NOW)).toBe(false);
    // Undated, it could be older.
    expect(isNewlyExploited(active(null), undefined, NOW)).toBe(false);
    // Shown as Exploited through SSVC since Oct 20: a KEV listing on Oct 25 is not new exploitation.
    const both = score(cve({ ssvc: { ...ssvc('active', 'no', 'partial')!, timestamp: '2026-10-20T12:00:00Z' } }), { kev: [makeKev(ID, { dateAdded: '2026-10-25' })] });
    expect(isNewlyExploited(both, undefined, NOW)).toBe(false);
    // An SSVC timestamp after the frozen now does not exist yet.
    expect(isNewlyExploited(active('2026-10-27T00:00:00Z'), undefined, NOW)).toBe(false);
  });

  it('a CNA exploited flag counts from publication', () => {
    expect(isNewlyExploited(score(cve({ published: '2026-10-25T00:00:00Z', cnaExploitMaturity: ['A'] })), undefined, NOW)).toBe(true);
    expect(isNewlyExploited(score(cve({ cnaExploitMaturity: ['A'] })), undefined, NOW)).toBe(false);
    // Flagged at publication on Oct 20, then listed by KEV on Oct 25: Exploited since Oct 20.
    const flagged = score(cve({ vendorInTheWild: true }), { kev: [makeKev(ID, { dateAdded: '2026-10-25' })] });
    expect(isNewlyExploited(flagged, undefined, NOW)).toBe(false);
  });

  it('takes the first exploited listing: an old one rules out a new one', () => {
    const s = kevOn('2026-10-01');
    expect(isNewlyExploited(s, [listing('eu-kev', '2026-10-25')], NOW)).toBe(false);
    expect(isNewlyExploited(kevOn('2026-10-25'), [listing('eu-kev', '2026-10-02')], NOW)).toBe(false);
  });

  it('an undated listing could be older and rules the CVE out, unless it is bounded by another listing', () => {
    const s = kevOn('2026-10-25');
    expect(isNewlyExploited(s, [listing('circl-kev', null)], NOW)).toBe(false);
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
});
