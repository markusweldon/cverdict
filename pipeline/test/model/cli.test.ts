import { describe, expect, it, vi } from 'vitest';
import { BRAND } from '../../../shared/brand';
import { USAGE, UsageError, formatSummary, parseCli } from '../../src/cli';
import type { RunSummary } from '../../src/run';

vi.mock('../../src/ingest', () => ({ ingest: vi.fn() }));

describe('parseCli', () => {
  it('applies the documented defaults', () => {
    expect(parseCli([])).toEqual({
      out: 'site/public/data',
      previous: null,
      cache: '.cache',
      cvelistDir: undefined,
      pocDir: undefined,
      now: undefined,
      windowDays: 30,
      offline: false,
      knob: undefined,
      refreshBacktest: false,
    });
  });

  it('parses every flag, in both --flag value and --flag=value forms', () => {
    const opts = parseCli([
      '--out', 'out', '--previous=published', '--cache', '.c', '--cvelist-dir', '/a', '--poc-dir=/b',
      '--now', '2026-10-26T19:30:00Z', '--window-days', '14', '--knob=60', '--offline', '--refresh-backtest',
    ]);
    expect(opts).toEqual({
      out: 'out',
      previous: 'published',
      cache: '.c',
      cvelistDir: '/a',
      pocDir: '/b',
      now: new Date('2026-10-26T19:30:00Z'),
      windowDays: 14,
      offline: true,
      knob: 60,
      refreshBacktest: true,
    });
  });

  it('reads --now without an offset as UTC, whatever the host time zone', () => {
    const tz = process.env.TZ;
    process.env.TZ = 'America/New_York';
    try {
      expect(parseCli(['--now', '2026-10-26T19:30:00'])!.now!.toISOString()).toBe('2026-10-26T19:30:00.000Z');
      expect(parseCli(['--now', '2026-10-26'])!.now!.toISOString()).toBe('2026-10-26T00:00:00.000Z');
      expect(parseCli(['--now', '2026-10-26T15:30:00-04:00'])!.now!.toISOString()).toBe('2026-10-26T19:30:00.000Z');
    } finally {
      if (tz === undefined) delete process.env.TZ;
      else process.env.TZ = tz;
    }
  });

  it('returns null for --help / -h', () => {
    expect(parseCli(['--help'])).toBeNull();
    expect(parseCli(['-h'])).toBeNull();
    expect(USAGE).toContain('--cvelist-dir');
    expect(USAGE).toContain(BRAND.name);
  });

  it.each([
    [['--bogus'], /bogus/],
    [['stray'], /positional|stray/i],
    [['--now', 'yesterday'], /--now/],
    [['--now', 'Oct 26 2026 19:30'], /--now/],
    [['--now', '2026-02-30T00:00:00Z'], /--now/],
    [['--window-days', '0'], /--window-days/],
    [['--window-days', '3.5'], /whole number/],
    [['--knob', '20'], /--knob/],
    [['--knob', '-5'], /./],
  ])('rejects %j', (argv, message) => {
    expect(() => parseCli(argv)).toThrow(UsageError);
    expect(() => parseCli(argv)).toThrow(message);
  });
});

describe('formatSummary', () => {
  const makeSummary = (sources: unknown[]) =>
    ({
      out: '/x/site/public/data',
      durationMs: 81234,
      batches: [],
      validation: { ok: true, warnings: ['w'], errors: [], sizes: [], files: 266 },
      top: [{ id: 'CVE-2026-1001', s: 100, tier: 'exploited', v: 'Microsoft', p: 'Windows' }],
      meta: {
        score_model: 'v0.1.0',
        knob_default: 50,
        window: { from: '2026-09-26T19:30:00.000Z', to: '2026-10-26T19:30:00.000Z', days: 30 },
        counts: {
          window_published: 16000,
          window_passed: 320,
          window_by_tier: { exploited: 20, likely: 300, watch: 2680, quiet: 13000 },
          published_24h: 500,
          passed_24h: 9,
          published_7d: 3500,
          passed_7d: 70,
          rejected_window: 120,
          ai_credited_window: 40,
          kev_total: 1756,
          kev_adds_30d: 26,
          batches_window: 12,
        },
        sources,
      },
      woke: { days: 30, items: [{}, {}], counts: { kev: 2, exploitdb: 0, metasploit: 1, nuclei: 0, poc: 0, epss: 0 }, skipped: [{ kind: 'epss', reason: 'x' }] },
      receipts: {
        forward: { since: '2026-10-01T00:17:00.000Z', runs: 600, listed: 12, eligible: 5, methods: [{ method: 'cverdict', before: 3 }] },
        backtest: { computed_at: '2026-10-25T00:17:00.000Z', sets: [{ key: 'recent', n: 80, strict: [{ method: 'cverdict', before: 40 }] }] },
      },
      packages: {
        cves: { rows: [['CVE-2021-44228'], ['CVE-2026-1001'], ['CVE-2026-1002']] },
        packages: {
          npm: { lodash: [['CVE-2026-1001', 'GHSA-a'], ['CVE-2026-1002', 'GHSA-b']] },
          Maven: { 'org.apache.logging.log4j:log4j-core': [['CVE-2021-44228', 'GHSA-c']], 'x:y': [['CVE-2021-44228', 'GHSA-c']] },
        },
        sources: [
          { ecosystem: 'npm', ok: true, stale: false, fetched_at: '2026-10-26T19:20:00.000Z' },
          { ecosystem: 'Maven', ok: true, stale: true, fetched_at: '2026-10-25T19:20:00.000Z' },
          { ecosystem: 'PyPI', ok: false, stale: true, fetched_at: null },
        ],
      },
    }) as unknown as RunSummary;

  it('prints counts by tier, the pass rate and the top ids', () => {
    const text = formatSummary(makeSummary([{ id: 'epss', ok: true, stale: true, records: 300000, error: 'HTTP 403' }]));
    expect(text).toContain('Published in window: 16,000');
    expect(text).toContain('Woke up (old CVEs, new evidence in 30 days): 2 · kev 2, exploitdb 0, metasploit 1, nuclei 0, poc 0, epss 0 · skipped: epss');
    expect(text).toContain('Receipts: log since 2026-10-01T00:17:00.000Z (600 runs) · 5 of 12 KEV additions counted, CVErdict first on 3 · backtest 2026-10-25: CVErdict 40 of 80 (strict)');
    expect(text).toMatch(/exploited\s+20\s+0\.1%/);
    expect(text).toContain('Pass rate (exploited + likely): 2.0% — 1 in 50');
    expect(text).toMatch(/CVE-2026-1001\s+100\s+exploited\s+Microsoft Windows/);
    expect(text).toMatch(/epss\s+stale\s+300,000\s+\(HTTP 403\)/);
    expect(text).toContain('266 files · 1 warnings · 81.2 s');
    expect(text).toContain('Packages: 3 packages, 3 CVEs (npm 2, Maven 1), OSV copy from 2026-10-25T19:20:00.000Z · stale: Maven · not checked: PyPI');
  });

  it('keeps upstream text in source errors on one line', () => {
    const error = 'EPSS: unexpected header "x\r::warning title=Forged::y"';
    const lines = formatSummary(makeSummary([{ id: 'epss', ok: false, stale: true, records: null, error }])).split(/\r\n|\r|\n/);
    expect(lines.some((l) => l.trimStart().startsWith('::'))).toBe(false);
    expect(lines.find((l) => l.includes('Forged'))).toMatch(/epss\s+DOWN.*x\\r::warning/);
  });
});
