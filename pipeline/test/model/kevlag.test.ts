import { describe, expect, it } from 'vitest';
import { KEV_LAG_BUCKETS, kevLagBucket } from '../../../shared/contract';
import { buildStats, kevLag, median } from '../../src/stats';
import { checkKevLag } from '../../src/validate';
import type { JsonObject } from '../../src/util/json';
import { NOW, makeCve, makeKev, makeKevCatalog, score } from '../fixtures/model/builders';

const rec = (id: string, published: string) => score(makeCve({ id, published }));

describe('kevLagBucket', () => {
  it('splits days into before, same day, a week, a month, a year and later', () => {
    expect([-3, -1, 0, 1, 7, 8, 30, 31, 365, 366, 4000].map(kevLagBucket)).toEqual([0, 0, 1, 2, 2, 3, 3, 4, 4, 5, 5]);
    expect(KEV_LAG_BUCKETS).toHaveLength(6);
  });
});

describe('median', () => {
  it('takes the middle value, or the mean of the two middle ones', () => {
    expect(median([])).toBeNull();
    expect(median([5])).toBe(5);
    expect(median([9, 1, 5])).toBe(5);
    expect(median([1, 2, 3, 10])).toBe(2.5);
    expect(median([-2, 4])).toBe(1);
  });
});

describe('kevLag', () => {
  // NOW is 2026-10-26T19:30:00Z.
  const records = [
    rec('CVE-2023-1', '2023-03-01T23:59:00Z'), // added 2023-03-02: 1 day (by UTC day, not 1 minute)
    rec('CVE-2023-2', '2023-01-10T08:00:00Z'), // added 2023-01-10: same day
    rec('CVE-2026-1', '2026-10-20T10:00:00Z'), // added 2026-10-18: before publication
    rec('CVE-2026-2', '2026-09-01T00:00:00Z'), // added 2026-10-01: 30 days
    rec('CVE-2014-1', '2014-06-01T00:00:00Z'), // added 2026-02-01: years later
    rec('CVE-2026-3', '2026-10-25T00:00:00Z'), // added after NOW: not counted
  ];
  const kev = makeKevCatalog([
    makeKev('CVE-2023-1', { dateAdded: '2023-03-02' }),
    makeKev('CVE-2023-2', { dateAdded: '2023-01-10' }),
    makeKev('CVE-2026-1', { dateAdded: '2026-10-18' }),
    makeKev('CVE-2026-2', { dateAdded: '2026-10-01' }),
    makeKev('CVE-2014-1', { dateAdded: '2026-02-01' }),
    makeKev('CVE-2026-3', { dateAdded: '2026-10-30' }),
    makeKev('CVE-2026-9', { dateAdded: '2026-05-01' }), // no published record: left out
    makeKev('CVE-2026-8', { dateAdded: 'not a date' }),
  ]);
  const rows = kevLag(kev, [...records, rec('CVE-2026-8', '2026-01-01T00:00:00Z')], NOW);

  it('groups by the year CISA added the CVE, every year to now, empty ones included', () => {
    expect(rows.map((r) => r.year)).toEqual([2023, 2024, 2025, 2026]);
    expect(rows.map((r) => r.partial)).toEqual([false, false, false, true]);
    expect(rows[1]).toEqual({ year: 2024, count: 0, buckets: [0, 0, 0, 0, 0, 0], median_days: null, partial: false });
  });

  it('counts whole days from the UTC publication day to dateAdded, into buckets that sum to the count', () => {
    expect(rows[0]).toMatchObject({ count: 2, buckets: [0, 1, 1, 0, 0, 0], median_days: 0.5 });
    const y26 = rows[3];
    expect(y26.count).toBe(3);
    expect(y26.buckets).toEqual([1, 0, 0, 1, 0, 1]);
    expect(y26.median_days).toBe(30);
  });

  it('is empty without KEV entries that match a record', () => {
    expect(kevLag(makeKevCatalog(), records, NOW)).toEqual([]);
    expect(kevLag(kev, [], NOW)).toEqual([]);
  });

  it('is in stats.json, from the window and the records outside it', () => {
    const history = { published: new Map(), reserved: new Map(), rejected: new Map(), ai: new Map(), totalRecords: 0 };
    const s = buildStats({ history, kev, window: records.slice(2), windowStart: NOW, now: NOW, outside: records.slice(0, 2) });
    expect(s.kev_lag).toEqual(rows.slice(0, 4).map((r, i) => (i === 3 ? { ...r, count: 3 } : r)));
  });
});

describe('checkKevLag', () => {
  const ok = (): JsonObject => ({
    generated_at: '2026-10-26T19:30:00.000Z',
    monthly: [
      { month: '2025-05', kev_added: 4 },
      { month: '2026-01', kev_added: 3 },
    ],
    kev_lag: [
      { year: 2025, count: 2, buckets: [0, 1, 1, 0, 0, 0], median_days: 0.5, partial: false },
      { year: 2026, count: 3, buckets: [1, 0, 0, 1, 0, 1], median_days: 30, partial: true },
    ],
  });
  const run = (doc: JsonObject) => {
    const errors: string[] = [];
    checkKevLag(doc, errors);
    return errors;
  };

  it('accepts a good file, an empty list and none at all', () => {
    expect(run(ok())).toEqual([]);
    expect(run({ ...ok(), kev_lag: [] })).toEqual([]);
    expect(run({ generated_at: '2026-10-26T19:30:00.000Z' })).toEqual([]);
  });

  it('rejects buckets that do not sum, gaps, a wrong partial flag, a stray median and too many additions', () => {
    const mutate = (f: (rows: JsonObject[]) => void) => {
      const doc = ok();
      f(doc.kev_lag as JsonObject[]);
      return run(doc);
    };
    expect(mutate((r) => (r[1].count = 4))[0]).toMatch(/buckets sum to 3, count is 4/);
    expect(mutate((r) => r.splice(1, 0, { ...r[0] }))[0]).toMatch(/skips or repeats a year at 2025/);
    expect(mutate((r) => (r[1].partial = false))[0]).toMatch(/bad row/);
    expect(mutate((r) => (r[0].median_days = 0.25))[0]).toMatch(/bad row/);
    expect(mutate((r) => Object.assign(r[0], { count: 0, buckets: [0, 0, 0, 0, 0, 0] }))[0]).toMatch(/bad row/);
    expect(mutate((r) => r.pop())[0]).toMatch(/ends at 2025/);
    expect(mutate((r) => Object.assign(r[0], { count: 5, buckets: [0, 5, 0, 0, 0, 0] }))[0]).toMatch(/more than the 4 KEV additions/);
    expect(run({ ...ok(), kev_lag: 'x' })[0]).toMatch(/not an array/);
  });
});
