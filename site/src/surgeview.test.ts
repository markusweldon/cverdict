import { describe, expect, it } from 'vitest';
import type { StatsFile, SurgeFile } from '../../shared/contract';
import { shiftMonth } from './surge';
import {
  DEFAULT_VIEW,
  buildSeries,
  busiestPoint,
  csvColumns,
  exportName,
  filterIndex,
  filterWords,
  pointChange,
  readView,
  toCsv,
  usableSurge,
  viewQuery,
  viewSearch,
  viewRange,
  visibleOverlays,
  withPreset,
  xTicks,
  zoomTo,
  type View,
} from './surgeview';

type Month = StatsFile['monthly'][number];

/** Monthly rows from 1999-01 to 2026-11 with 100 published each, 10 more per year after 2020. */
const monthly: Month[] = [];
for (let m = '1999-01'; m <= '2026-11'; m = shiftMonth(m, 1)) {
  const y = Number(m.slice(0, 4));
  monthly.push({ month: m, published: 100 + Math.max(0, y - 2020) * 10, reserved: 120, rejected: 2, ai: y >= 2025 ? 3 : 0, kev_added: 1 });
}
const N = monthly.length;
const AT = '2026-11-15T12:00:00Z'; // half of November

/** Every month: 10 critical, 20 high, 30 medium, 10 low, rest none; Wordfence takes 20 medium, Linux 10 high. */
function surgeFile(): SurgeFile {
  const severity = monthly.map((m) => [10, 20, 30, 10, m.published - 70]);
  const from = N - 24;
  return {
    schema_version: 1,
    generated_at: AT,
    start: '1999-01',
    severity,
    cnas: [
      { cna: 'Wordfence', from, severity: Array.from({ length: 24 }, () => [0, 0, 20, 0, 0]) },
      { cna: 'Linux', from, severity: Array.from({ length: 24 }, () => [0, 10, 0, 0, 0]) },
      { cna: 'mitre', from: 0, severity: monthly.map(() => [0, 0, 0, 0, 1]) },
    ],
    kev: [
      [N - 1, 1, 1, 2],
      [N - 1, -1, 0, 1],
      [N - 13, 1, 1, 1],
    ],
  };
}
const surge = surgeFile();
const q = (s: string) => readView(new URLSearchParams(s));

describe('view <-> URL', () => {
  it('the default view has a clean URL', () => {
    expect(viewSearch(DEFAULT_VIEW)).toBe('');
    expect(Object.values(viewQuery(DEFAULT_VIEW)).every((v) => v === null)).toBe(true);
    expect(q('')).toEqual(DEFAULT_VIEW);
  });

  it('round-trips every control', () => {
    const s = '?from=2024-01&to=2026-11&group=quarter&count=reserved&sev=critical,high&view=severity&cna=-wordfence,-patchstack&kev=1&scale=log&compare=1&lines=kevpub';
    const v = q(s.slice(1));
    expect(v).toMatchObject({ from: '2024-01', to: '2026-11', group: 'quarter', count: 'reserved', sev: ['critical', 'high'], stack: true, cnaOnly: null, cnaOut: ['wordfence', 'patchstack'], kev: true, log: true, compare: true, lines: ['kevpub'] });
    expect(viewSearch(v)).toBe(s);
    expect(viewSearch(q('range=24m'))).toBe('?range=24m');
    expect(viewSearch(q('lines=none'))).toBe('?lines=none');
  });

  it('ignores junk and normalises what it can', () => {
    const v = q('from=2026-13&to=1990-01&group=week&sev=critical,bogus&cna=<script>,-x y&range=7d&scale=lin&kev=yes');
    expect(v).toEqual({ ...DEFAULT_VIEW, sev: ['critical'] });
    expect(q('from=2026-05&to=2024-02')).toMatchObject({ from: '2024-02', to: '2026-05' });
    expect(q('sev=none,low,medium,high,critical').sev).toEqual([]);
    expect(q('sev=HIGH,critical').sev).toEqual(['critical', 'high']);
    // One CNA to include wins over any exclusions.
    expect(q('cna=-wordfence,linux,apple')).toMatchObject({ cnaOnly: 'linux', cnaOut: [] });
  });

  it('a preset clears a custom range; a drag sets one over whole buckets', () => {
    const v = withPreset({ ...DEFAULT_VIEW, from: '2020-01', to: '2021-01' }, '12m');
    expect(v).toMatchObject({ preset: '12m', from: null, to: null });
    const s = buildSeries(monthly, surge, { ...DEFAULT_VIEW, group: 'quarter', preset: '24m' }, AT);
    expect(zoomTo(DEFAULT_VIEW, s.points, 5, 2)).toMatchObject({ from: s.points[2].first, to: s.points[5].last });
  });
});

describe('range and grouping', () => {
  it('presets count back from the latest month, the partial one included', () => {
    expect(viewRange(monthly, { ...DEFAULT_VIEW, preset: '12m' })).toEqual({ a: N - 12, b: N - 1, custom: false });
    expect(viewRange(monthly, DEFAULT_VIEW)).toEqual({ a: 0, b: N - 1, custom: false });
  });

  it('a custom range is clamped and widened to whole quarters or years', () => {
    expect(viewRange(monthly, { ...DEFAULT_VIEW, from: '1990-01', to: '2030-01' })).toMatchObject({ a: 0, b: N - 1, custom: true });
    const r = viewRange(monthly, { ...DEFAULT_VIEW, from: '2024-02', to: '2025-05', group: 'quarter' });
    expect([monthly[r.a].month, monthly[r.b].month]).toEqual(['2024-01', '2025-06']);
    const y = viewRange(monthly, { ...DEFAULT_VIEW, from: '2024-02', to: '2026-03', group: 'year' });
    expect([monthly[y.a].month, monthly[y.b].month]).toEqual(['2024-01', '2026-11']);
  });

  it('a range end wholly outside the data is junk: dropped, and with both gone the preset shows', () => {
    // to=1990-05 is dropped on read, from=2030-01 is past the data: the default view, not one month.
    expect(viewRange(monthly, q('from=2030-01&to=1990-05'))).toEqual({ a: 0, b: N - 1, custom: false });
    expect(viewRange(monthly, q('range=12m&from=2030-01'))).toEqual({ a: N - 12, b: N - 1, custom: false });
    expect(viewRange(monthly, { ...DEFAULT_VIEW, from: '2027-01', to: '2030-01' })).toMatchObject({ custom: false });
    expect(viewRange(monthly, { ...DEFAULT_VIEW, to: '1998-05' })).toMatchObject({ custom: false });
    // An end past the data with a real start is clamped, as before.
    expect(viewRange(monthly, q('from=2025-06&to=2030-01'))).toMatchObject({ a: N - 18, b: N - 1, custom: true });
    // The latest month itself is still a fine start.
    expect(viewRange(monthly, { ...DEFAULT_VIEW, from: '2026-11' })).toEqual({ a: N - 1, b: N - 1, custom: true });
  });

  it('the busiest period counts the one still filling once it is already the highest', () => {
    // A year 2026 so far already above the full 2025, as on the real Nov 2026 data.
    const y = [
      { key: '2024', value: 40000, partial: false },
      { key: '2025', value: 48151, partial: false },
      { key: '2026', value: 90436, partial: true },
    ];
    expect(busiestPoint(y)).toMatchObject({ key: '2026', partial: true });
    // A tie goes to the earlier, complete period.
    expect(busiestPoint([{ key: 'a', value: 5 }, { key: 'b', value: 5 }])).toMatchObject({ key: 'a' });
    const m = buildSeries(monthly, surge, { ...DEFAULT_VIEW, preset: '12m' }, AT).points;
    expect(busiestPoint(m)).toMatchObject({ key: '2026-01', partial: false });
    expect(busiestPoint(m.slice(-1))).toBeNull();
    expect(busiestPoint([{ value: 0 }, { value: 0 }])).toBeNull();
  });

  it('sums months into quarters and years and marks the partial period', () => {
    const s = buildSeries(monthly, surge, { ...DEFAULT_VIEW, preset: '24m', group: 'quarter' }, AT);
    expect(s.points.map((p) => p.key).slice(-2)).toEqual(['2026-Q3', '2026-Q4']);
    const q3 = s.points[s.points.length - 2];
    expect(q3).toMatchObject({ label: 'Q3 2026', first: '2026-07', last: '2026-09', partial: false, value: 3 * 160, kevadd: 3, ai: 9 });
    expect(s.points[s.points.length - 1]).toMatchObject({ first: '2026-10', last: '2026-11', partial: true, value: 320 });
    const y = buildSeries(monthly, surge, { ...DEFAULT_VIEW, group: 'year' }, AT);
    expect(y.points).toHaveLength(28);
    expect(y.points[0]).toMatchObject({ key: '1999', label: '1999', value: 1200, prev: null });
    expect(y.points[27]).toMatchObject({ key: '2026', partial: true, value: 11 * 160 });
  });

  it('compares with the same period a year earlier, the partial month at the same point', () => {
    const s = buildSeries(monthly, surge, { ...DEFAULT_VIEW, preset: '12m' }, AT);
    const last = s.points[s.points.length - 1];
    expect(last.prev).toBeCloseTo(150 * ((14.5 * 24) / 24 / 30), 5);
    expect(s.points[0].prev).toBe(140);
    expect(pointChange(s.points[0])).toBeCloseTo(150 / 140 - 1, 6);
    const yr = buildSeries(monthly, surge, { ...DEFAULT_VIEW, group: 'year' }, AT).points[27];
    expect(yr.prev).toBeCloseTo(10 * 150 + 150 * (14.5 / 30), 5);
    // Reserved counts keep growing for weeks: no comparison for its partial month.
    expect(buildSeries(monthly, surge, { ...DEFAULT_VIEW, preset: '12m', count: 'reserved' }, AT).points[11].prev).toBeNull();
  });
});

describe('filters', () => {
  const at = (v: Partial<View>) => buildSeries(monthly, surge, { ...DEFAULT_VIEW, preset: '12m', ...v }, AT);

  it('unfiltered, the count is stats.json published; bands come from surge.json', () => {
    const s = at({ stack: true });
    expect(s.narrowed).toBe(false);
    expect(s.points[0]).toMatchObject({ value: 150, bands: [10, 20, 30, 10, 80] });
  });

  it('severity keeps only the chosen bands', () => {
    const p = at({ sev: ['critical', 'high'] }).points[0];
    expect(p).toMatchObject({ value: 30, bands: [10, 20, 0, 0, 0] });
  });

  it('excluding CNAs subtracts their rows; one CNA only uses its row', () => {
    expect(at({ cnaOut: ['wordfence', 'linux'] }).points[0]).toMatchObject({ value: 120, bands: [10, 10, 10, 10, 80] });
    expect(at({ cnaOnly: 'linux' }).points[0]).toMatchObject({ value: 10, bands: [0, 10, 0, 0, 0] });
    // Before a CNA's first month it has none.
    expect(buildSeries(monthly, surge, { ...DEFAULT_VIEW, from: '2020-01', to: '2020-01', cnaOnly: 'linux' }, AT).points[0].value).toBe(0);
    // A CNA surge.json does not list is ignored.
    expect(at({ cnaOut: ['apple'] }).narrowed).toBe(false);
  });

  it('KEV only counts KEV cells by publication month, with the other filters', () => {
    const s = at({ kev: true });
    expect(s.points[11]).toMatchObject({ value: 3, kevpub: 3 });
    expect(s.points[0].value).toBe(0);
    expect(at({ kev: true, cnaOut: ['linux'] }).points[11].value).toBe(1);
    expect(at({ kev: true, sev: ['high'] }).points[11].value).toBe(2);
    expect(at({}).points[11].kevpub).toBe(3);
    expect(at({ cnaOnly: 'linux' }).points[11].kevpub).toBe(2);
  });

  it('a filtered comparison is filtered the same way', () => {
    const s = buildSeries(monthly, surge, { ...DEFAULT_VIEW, from: '2026-01', to: '2026-01', cnaOnly: 'linux' }, AT);
    expect(s.points[0]).toMatchObject({ value: 10, prev: 10 });
    const k = at({ kev: true });
    expect(k.points[11].prev).toBeCloseTo(1 * (14.5 / 30), 5);
  });

  it('without a usable surge.json the filters are off and the count stays whole', () => {
    for (const file of [null, { ...surge, severity: surge.severity.slice(0, -1) }, { ...surge, start: '2000-01' }]) {
      const s = buildSeries(monthly, file, { ...DEFAULT_VIEW, preset: '12m', sev: ['critical'], kev: true }, AT);
      expect(s).toMatchObject({ filtersReady: false, narrowed: false });
      expect(s.points[0]).toMatchObject({ value: 150, bands: null, kevpub: null });
    }
    expect(usableSurge(monthly, surge)).toBe(surge);
  });

  it('filters do not apply to Reserved', () => {
    const s = at({ count: 'reserved', sev: ['critical'] });
    expect(s.narrowed).toBe(false);
    expect(s.points[0].value).toBe(120);
  });

  it('lines that count every CVE hide while a filter narrows the count', () => {
    expect(visibleOverlays({ ...DEFAULT_VIEW, lines: ['kevpub', 'kevadd', 'ai'] }, at({}))).toEqual(['kevpub', 'kevadd', 'ai']);
    expect(visibleOverlays({ ...DEFAULT_VIEW, lines: ['kevpub', 'kevadd', 'ai'] }, at({ sev: ['low'] }))).toEqual(['kevpub']);
    expect(visibleOverlays({ ...DEFAULT_VIEW, kev: true, lines: ['kevpub', 'kevadd'] }, at({ kev: true }))).toEqual([]);
  });

  it('says what the filters do', () => {
    const idx = filterIndex(surge);
    expect(filterWords({ ...DEFAULT_VIEW, sev: ['critical', 'high'], cnaOut: ['wordfence', 'linux'], kev: true }, idx)).toBe('Critical and High; excluding the Linux kernel and Wordfence; in CISA KEV only');
    expect(filterWords({ ...DEFAULT_VIEW, cnaOnly: 'linux' }, idx)).toBe('from Linux kernel only');
    expect(filterWords(DEFAULT_VIEW, idx)).toBe('');
    expect(filterWords({ ...DEFAULT_VIEW, sev: ['low'] }, null)).toBe('');
  });
});

describe('CSV', () => {
  it('has exactly the columns and rows on screen', () => {
    const v: View = { ...DEFAULT_VIEW, preset: '12m', group: 'quarter', stack: true, sev: ['critical', 'high'], compare: true, lines: ['kevpub', 'ai'] };
    const s = buildSeries(monthly, surge, v, AT);
    const csv = toCsv(s.points, csvColumns(v, s));
    const rows = csv.trim().split('\r\n');
    expect(rows[0]).toBe('period,first_month,last_month,partial,critical,high,published,published_year_earlier,in_kev_by_publication');
    expect(rows).toHaveLength(s.points.length + 1);
    expect(rows[rows.length - 1]).toBe(`2026-Q4,2026-10,2026-11,yes,20,40,60,${Math.round(s.points[s.points.length - 1].prev!)},3`);
    expect(csv.endsWith('\r\n')).toBe(true);
  });

  it('unfiltered, lists the count and the default lines', () => {
    const s = buildSeries(monthly, surge, { ...DEFAULT_VIEW, preset: '12m' }, AT);
    const rows = toCsv(s.points, csvColumns(DEFAULT_VIEW, s)).split('\r\n');
    expect(rows[0]).toBe('period,first_month,last_month,partial,published,added_to_kev,ai_credited');
    expect(rows[1]).toBe('2025-12,2025-12,2025-12,no,150,1,3');
    expect(exportName(s.points, DEFAULT_VIEW, 'csv')).toBe('cverdict-cves-2025-12-to-2026-11.csv');
    expect(exportName(s.points, { ...DEFAULT_VIEW, group: 'year' }, 'png')).toBe('cverdict-cves-2025-12-to-2026-11-year.png');
  });
});

describe('xTicks', () => {
  const pts = (group: 'month' | 'quarter' | 'year', v: Partial<View> = {}) => buildSeries(monthly, surge, { ...DEFAULT_VIEW, group, ...v }, AT).points;

  it('labels years on long ranges and months on short ones, never touching', () => {
    const all = xTicks(pts('month'), 'month', 1000);
    expect(all.every((t) => /^\d{4}$/.test(t.label))).toBe(true);
    const short = xTicks(pts('month', { preset: '12m' }), 'month', 1000);
    expect(short.map((t) => t.label)).toEqual(['Dec 2025', 'Jan 2026', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov']);
    // At 18 points over 1100 px, "Jun" would touch a left-anchored "May 2024".
    const z = xTicks(pts('month', { from: '2024-05', to: '2025-11' }), 'month', 1100);
    expect(z.slice(0, 2).map((t) => t.label)).toEqual(['May 2024', 'Jul']);
    for (const [group, px] of [['month', 320], ['month', 1100], ['quarter', 320], ['year', 300]] as const) {
      const p = pts(group, { preset: '24m' });
      const t = xTicks(p, group, px);
      const per = px / Math.max(1, p.length - 1);
      for (let i = 1; i < t.length; i++) {
        const prev = t[i - 1].i === 0 ? t[i - 1].label.length * 6.5 : (t[i - 1].label.length * 6.5) / 2;
        expect((t[i].i - t[i - 1].i) * per).toBeGreaterThanOrEqual(prev + (t[i].label.length * 6.5) / 2 + 10);
      }
      expect(t.length).toBeGreaterThan(0);
    }
    expect(xTicks(pts('quarter', { preset: '12m' }), 'quarter', 800)[0].label).toBe('Q4 2025');
    expect(xTicks([], 'month', 100)).toEqual([]);
  });
});
