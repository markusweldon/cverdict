/**
 * OSV.dev feeds packages.json only. Whether its download worked must not change a single score,
 * chip, unknown, receipt or backtest figure: only packages.json and the osv entry of
 * meta.sources may differ (NON_SCORING_SOURCES in emit/build.ts).
 */
import { describe, expect, it } from 'vitest';
import type { Meta, SourceStatus } from '../../../shared/contract';
import type { BacktestInputs } from '../../src/backtest';
import { buildOutput, NON_SCORING_SOURCES } from '../../src/emit/build';
import { PATHS } from '../../src/emit/json';
import { emptyOsvData, type OsvData } from '../../src/sources/osv';
import { NOW, cohort, cvss, makeCve, makeIngest, makeKev } from '../fixtures/model/builders';

const ID = 'CVE-2026-100001';
const cves = [...cohort(20), makeCve({ id: ID, published: '2026-10-01T00:00:00Z', ...cvss(9.8) }), makeCve({ id: 'CVE-2021-44228', published: '2021-12-10T00:00:00.000Z', inWindow: false })];
const kev = [makeKev(ID, { dateAdded: '2026-10-20' }), makeKev('CVE-2021-44228', { dateAdded: '2021-12-10', dueDate: '2021-12-24' })];
const refresh: BacktestInputs = { epss: new Map(), reuse: new Map(), metasploitModified: new Map(), exploitdbAdded: new Map(), volumeFrom: '2026-05-07T03:17:00.000Z' };

function osvWith(up: boolean): { data: OsvData; status: SourceStatus } {
  const data = emptyOsvData(up ? 'no copy' : 'fetch failed');
  if (up) {
    data.mirror.ecosystems.Maven = {
      full_sync_at: NOW.toISOString(),
      zip_etag: null,
      cursor: NOW.toISOString(),
      fetched_at: NOW.toISOString(),
      records: [['GHSA-jfh8-c2jp-5v3q', '2026-10-01T00:00:00Z', ['CVE-2021-44228'], [['org.apache.logging.log4j:log4j-core', [['>=2.13.0', '<2.15.0']]]]]],
    };
    data.statuses.Maven = { ok: true, stale: false, fetched_at: NOW.toISOString(), modified: NOW.toISOString(), advisories: 1, error: null };
  }
  const status: SourceStatus = {
    id: 'osv', name: 'OSV.dev advisories', url: 'https://storage.googleapis.com/osv-vulnerabilities', ok: up, stale: true,
    fetched_at: up ? NOW.toISOString() : null, upstream_version: null, records: up ? 1 : 0, error: up ? 'PyPI: no copy' : 'npm: fetch failed', license: 'test',
  };
  return { data, status };
}

function build(up: boolean) {
  const base = makeIngest(cves, { kev });
  const osv = osvWith(up);
  return buildOutput({ ingest: { ...base, sources: [...base.sources, osv.status], osv: osv.data, backtest: refresh }, now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://x.test' });
}

describe('OSV never feeds a score', () => {
  it('is the one non-scoring source', () => {
    expect([...NON_SCORING_SOURCES]).toEqual(['osv']);
  });

  it('leaves every file but packages.json and meta.json byte-identical when OSV is down', () => {
    const up = build(true);
    const down = build(false);
    expect([...up.files.keys()].sort()).toEqual([...down.files.keys()].sort());
    const differ = [...up.files.keys()].filter((p) => up.files.get(p) !== down.files.get(p)).sort();
    expect(differ).toEqual([PATHS.meta, PATHS.packages]);
    // The shards, receipts (with the refreshed backtest) and state really were compared.
    expect(up.files.has(PATHS.shard('00'))).toBe(true);
    expect(up.receipts.backtest?.sources_down).toEqual([]);
    expect(down.receipts.backtest?.sources_down).toEqual([]);
    expect(down.scored.every((s) => !s.unknowns.some((u) => /OSV/.test(u)))).toBe(true);

    const meta = (b: typeof up) => JSON.parse(b.files.get(PATHS.meta)!) as Meta;
    const strip = (m: Meta) => ({ ...m, sources: m.sources.filter((s) => s.id !== 'osv') });
    expect(strip(meta(up))).toEqual(strip(meta(down)));
    expect(meta(down).sources.find((s) => s.id === 'osv')).toMatchObject({ ok: false });
    expect(up.packages.cves.rows.map((r) => r[0])).toEqual(['CVE-2021-44228']);
    expect(down.packages.packages).toEqual({});
  });

  it('still reports a scoring source that is down as unknown evidence (the filter is not too wide)', () => {
    const base = makeIngest(cves, { kev, down: ['exploitdb'] });
    const built = buildOutput({ ingest: { ...base, backtest: refresh }, now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://x.test' });
    expect(built.receipts.backtest?.sources_down).toEqual(['exploitdb']);
  });
});
