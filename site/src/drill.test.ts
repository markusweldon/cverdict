import { describe, expect, it } from 'vitest';
import { binDay, binRange, binsOf, dayOf, dayStart, dayTotal, exploreDayHref, hoursPerBin, onDay, parseDay } from './drill';
import { DAY_MS, HOUR_MS } from './format';

const at = (iso: string) => Date.parse(iso);

describe('parseDay', () => {
  it('accepts real calendar dates as UTC midnight', () => {
    expect(parseDay('2026-10-13')).toBe(at('2026-10-13T00:00:00Z'));
    expect(parseDay(' 2026-10-13 ')).toBe(at('2026-10-13T00:00:00Z'));
    expect(parseDay('2028-02-29')).toBe(at('2028-02-29T00:00:00Z'));
  });

  it('ignores anything else', () => {
    for (const raw of [null, undefined, '', 'yesterday', '2026-10-1', '2026-1-13', '20261013', '2026-13-01', '2026-02-30', '2026-02-29', '2026-10-13T00:00:00Z', '2026-10-13x', '-2026-10-13']) {
      expect(parseDay(raw)).toBeNull();
    }
  });
});

describe('days', () => {
  it('maps a timestamp to its UTC day', () => {
    expect(dayOf(at('2026-10-13T23:59:59Z'))).toBe('2026-10-13');
    expect(dayOf(at('2026-10-14T00:00:00Z'))).toBe('2026-10-14');
    expect(dayStart(at('2026-10-13T17:04:00Z'))).toBe(at('2026-10-13T00:00:00Z'));
  });

  it('includes midnight and excludes the next one', () => {
    const d = at('2026-10-13T00:00:00Z');
    expect(onDay(d, d)).toBe(true);
    expect(onDay(d + DAY_MS - 1, d)).toBe(true);
    expect(onDay(d + DAY_MS, d)).toBe(false);
    expect(onDay(d - 1, d)).toBe(false);
  });
});

describe('waterfall columns', () => {
  const start = at('2026-10-04T01:00:00Z');
  const hourly = Array.from({ length: 721 }, (_, i) => [i % 2, 1, 0, 2]);

  it('widens columns until each is at least `pitch` px', () => {
    expect(hoursPerBin(721, 2200, 3)).toBe(1);
    expect(hoursPerBin(721, 1200, 3)).toBe(2);
    expect(hoursPerBin(721, 358, 3)).toBe(7);
    expect(hoursPerBin(721, 0, 3)).toBe(1);
  });

  it('groups hours and sums their counts; the last column may be short', () => {
    const bins = binsOf(hourly, start, 7);
    expect(bins).toHaveLength(103);
    expect(bins[0]).toEqual({ from: start, hours: 7, c: [3, 7, 0, 14] });
    expect(bins[1].from).toBe(start + 7 * HOUR_MS);
    expect(bins[102].hours).toBe(721 - 102 * 7);
  });

  it('opens the day a column starts on, even when it crosses midnight', () => {
    const bins = binsOf(hourly, start, 7);
    // Column 3 runs Oct 4 22:00 to Oct 5 05:00.
    expect(new Date(bins[3].from).toISOString()).toBe('2026-10-04T22:00:00.000Z');
    expect(binDay(bins[3].from)).toBe('2026-10-04');
    expect(binDay(bins[4].from)).toBe('2026-10-05');
  });

  it('counts every CVE on a day, clipped to the hours the window has', () => {
    const day = at('2026-10-05T00:00:00Z');
    expect(dayTotal(hourly, start, day)).toBe(24 * 3 + 12);
    // The window starts at 01:00 on Oct 4: 23 hours of that day, alternating 3 and 4 from 01:00.
    expect(dayTotal(hourly, start, at('2026-10-04T00:00:00Z'))).toBe(23 * 3 + 11);
    expect(dayTotal(hourly, start, at('2026-09-01T00:00:00Z'))).toBe(0);
    expect(dayTotal(hourly, start, at('2026-12-01T00:00:00Z'))).toBe(0);
  });
});

describe('binRange', () => {
  it('labels a column inside one day', () => {
    expect(binRange(at('2026-10-13T14:00:00Z'), 2, 2026)).toBe('Oct 13 · 14:00–16:00 UTC');
  });

  it('names the second day when a column crosses midnight', () => {
    expect(binRange(at('2026-10-03T18:00:00Z'), 7, 2026)).toBe('Oct 3 · 18:00 – Oct 4 · 01:00 UTC');
    expect(binRange(at('2026-10-31T23:00:00Z'), 2, 2026)).toBe('Oct 31 · 23:00 – Nov 1 · 01:00 UTC');
  });

  it('keeps a column that ends at midnight on its own day', () => {
    expect(binRange(at('2026-10-03T22:00:00Z'), 2, 2026)).toBe('Oct 3 · 22:00–24:00 UTC');
    expect(binRange(at('2026-10-03T00:00:00Z'), 24, 2026)).toBe('Oct 3 · 00:00–24:00 UTC');
  });

  it('adds the year when it is not the reference year', () => {
    expect(binRange(at('2026-12-31T20:00:00Z'), 6, 2026)).toBe('Dec 31 · 20:00 – Jan 1, 2027 · 02:00 UTC');
  });
});

describe('exploreDayHref', () => {
  it('opens Explore on the day, by score, carrying a non-default knob', () => {
    expect(exploreDayHref('2026-10-13')).toBe('/explore?day=2026-10-13&sort=score');
    expect(exploreDayHref('2026-10-13', 50)).toBe('/explore?day=2026-10-13&sort=score');
    expect(exploreDayHref('2026-10-13', 60)).toBe('/explore?day=2026-10-13&sort=score&knob=60');
  });
});
