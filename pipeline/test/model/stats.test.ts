import { describe, expect, it } from 'vitest';
import { SCHEMA_VERSION } from '../../../shared/contract';
import { buildStats, dayRange, monthRange } from '../../src/stats';
import type { History } from '../../src/types';
import { NOW, daysAgo, makeCve, makeKev, makeKevCatalog, msf, score } from '../fixtures/model/builders';

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
