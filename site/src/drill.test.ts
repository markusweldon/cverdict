import { describe, expect, it } from 'vitest';
import { binDay, binRange, binsOf, dayInWindow, dayOf, dayStart, dayTotal, exploreDayHref, hoursPerBin, onDay, parseDay, placeLabels } from './drill';
import { DAY_MS, fmtDate, HOUR_MS } from './format';

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

describe('drill-down edge cases', () => {
  it('parses only real days, with leap years and padding', () => {
    expect(parseDay('2000-02-29')).toBe(at('2000-02-29T00:00:00Z'));
    expect(parseDay('\t2026-10-13\n')).toBe(at('2026-10-13T00:00:00Z'));
    for (const raw of ['2100-02-29', '2026-00-10', '2026-10-00', '2026-10-32', '0000-01-01', '0099-12-31', '２０２６-10-13', '2026-10-13 2026-10-14']) {
      expect(parseDay(raw)).toBeNull();
    }
  });

  it('knows which days the window touches, partial ends included', () => {
    const window = { from: '2026-10-04T01:57:14.909Z', to: '2026-11-03T01:57:14.909Z' };
    expect(dayInWindow(at('2026-10-03T00:00:00Z'), window)).toBe(false);
    expect(dayInWindow(at('2026-10-04T00:00:00Z'), window)).toBe(true);
    expect(dayInWindow(at('2026-11-03T00:00:00Z'), window)).toBe(true);
    expect(dayInWindow(at('2026-11-04T00:00:00Z'), window)).toBe(false);
  });

  it('splits every hour into exactly one day', () => {
    const start = at('2026-10-04T01:00:00Z');
    const counts = Array.from({ length: 721 }, (_, i) => [i % 3, i % 5, 1, i % 7]);
    const all = counts.reduce((a, c) => a + c[0] + c[1] + c[2] + c[3], 0);
    let sum = 0;
    for (let d = dayStart(start); d < start + 721 * HOUR_MS; d += DAY_MS) sum += dayTotal(counts, start, d);
    expect(sum).toBe(all);
  });

  it('names the start day and, past midnight, the end day of every column at every width', () => {
    const start = at('2026-10-04T01:00:00Z');
    const counts = Array.from({ length: 721 }, () => [0, 0, 0, 1]);
    for (let per = 1; per <= 9; per++) {
      for (const b of binsOf(counts, start, per)) {
        const end = b.from + b.hours * HOUR_MS;
        const label = binRange(b.from, b.hours, 2026);
        expect(binDay(b.from)).toBe(new Date(b.from).toISOString().slice(0, 10));
        expect(label.startsWith(`${fmtDate(dayOf(b.from), 2026)} · `)).toBe(true);
        const crosses = dayOf(end - 1) !== dayOf(b.from);
        expect(label.includes(' – ')).toBe(crosses);
        if (crosses) expect(label).toContain(`– ${fmtDate(dayOf(end), 2026)} · `);
      }
    }
  });

  it('keeps hours per column sane for odd widths', () => {
    expect(hoursPerBin(721, -5, 3)).toBe(1);
    expect(hoursPerBin(0, 400, 3)).toBe(1);
    expect(hoursPerBin(721, 1, 3)).toBe(2163);
  });
});

describe('waterfall spike labels', () => {
  it('places the biggest first, drops collisions, and returns the rest left to right for Tab', () => {
    // As on Today at 1440 px: callers pass the biggest spike first.
    const labels = [
      { item: 'Microsoft 1,407', x: 463, w: 90 },
      { item: 'Oracle 1,076 + Chrome 353', x: 772, w: 160 },
      { item: 'near Oracle', x: 700, w: 60 },
      { item: 'Chrome 247', x: 174, w: 70 },
      { item: 'Apple 324', x: 1100, w: 60 },
    ];
    const placed = placeLabels(labels, 1120);
    expect(placed.map((p) => p.item)).toEqual(['Chrome 247', 'Microsoft 1,407', 'Oracle 1,076 + Chrome 353', 'Apple 324']);
    // Kept inside the chart, pinned to the right edge when it touches it.
    expect(placed[3]).toEqual({ item: 'Apple 324', left: 1060, right: true });
    expect(placed[0]).toEqual({ item: 'Chrome 247', left: 139, right: false });
  });
});
