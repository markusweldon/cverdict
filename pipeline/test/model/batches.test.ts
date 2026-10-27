import { describe, expect, it } from 'vitest';
import { BATCH_MIN } from '../../../shared/model';
import { assignBatches, slugify } from '../../src/batches';
import { toRow } from '../../src/rows';
import { scoreCve } from '../../src/score';
import { NOW, cohort, makeCve, makeEnrichment, msf } from '../fixtures/model/builders';

const enr = makeEnrichment({ metasploit: { 'CVE-2026-200007': [msf('exploit/windows/local/x')] } });
const scoreAll = (cves: ReturnType<typeof cohort>) => cves.map((c) => scoreCve(c, enr, { now: NOW }));

describe('slugify', () => {
  it('makes URL-safe ids', () => {
    expect(slugify('Microsoft')).toBe('microsoft');
    expect(slugify('Red Hat, Inc.')).toBe('red-hat-inc');
    expect(slugify('Ünïcode CNA')).toBe('unicode-cna');
    expect(slugify('***')).toBe('unknown');
  });
});

describe('assignBatches', () => {
  it(`groups ≥ ${BATCH_MIN} window records per (CNA, UTC day)`, () => {
    const scored = scoreAll(cohort(60));
    const [batch, ...rest] = assignBatches(scored);
    expect(rest).toHaveLength(0);
    expect(batch).toMatchObject({ id: 'microsoft-2026-10-13', cna: 'microsoft', date: '2026-10-13', count: 60 });
    expect(Object.values(batch.by_tier).reduce((a, b) => a + b, 0)).toBe(60);
    expect(batch.by_tier.likely).toBe(1);
  });

  it('tags every member with the batch chip and id', () => {
    const scored = scoreAll(cohort(BATCH_MIN));
    assignBatches(scored);
    for (const s of scored) {
      expect(s.batch).toBe('microsoft-2026-10-13');
      const chip = s.reasons.find((r) => r.id === 'batch')!;
      expect(chip).toMatchObject({ label: 'Part of Microsoft patch day · Oct 13 (50)', points: 0, polarity: 'info', at: '2026-10-13' });
      // INFO chips come after scoring families and before unknowns
      const i = s.reasons.indexOf(chip);
      expect(s.reasons.slice(i + 1).every((r) => r.family === 'INFO' || r.polarity === 'unknown')).toBe(true);
      expect(toRow(s).b).toBe('microsoft-2026-10-13');
    }
  });

  it('formats large counts', () => {
    const scored = scoreAll(cohort(1407));
    assignBatches(scored);
    expect(scored[0].reasons.find((r) => r.id === 'batch')!.label).toBe('Part of Microsoft patch day · Oct 13 (1,407)');
  });

  it('names the CNA for people and calls aggregator CNAs’ days bulk releases', () => {
    const label = (cna: string) => {
      const scored = scoreAll(cohort(BATCH_MIN, { cna, published: '2026-10-26T10:00:00Z' }));
      assignBatches(scored);
      return scored[0].reasons.find((r) => r.id === 'batch')!.label;
    };
    expect(label('VulnCheck')).toBe('Part of VulnCheck bulk release · Oct 26 (50)');
    expect(label('GitHub_M')).toBe('Part of GitHub bulk release · Oct 26 (50)');
    expect(label('Chrome')).toBe('Part of Google Chrome patch day · Oct 26 (50)');
    expect(label('Linux')).toBe('Part of Linux kernel patch day · Oct 26 (50)');
    expect(label('juniper')).toBe('Part of Juniper patch day · Oct 26 (50)');
  });

  it('is idempotent (no duplicate batch chips)', () => {
    const scored = scoreAll(cohort(BATCH_MIN));
    assignBatches(scored);
    assignBatches(scored);
    expect(scored[0].reasons.filter((r) => r.id === 'batch')).toHaveLength(1);
  });

  it(`ignores groups below ${BATCH_MIN}, other days, and records outside the window`, () => {
    const small = scoreAll(cohort(BATCH_MIN - 1));
    expect(assignBatches(small)).toEqual([]);
    expect(small.every((s) => s.batch === null && !s.reasons.some((r) => r.id === 'batch'))).toBe(true);

    const outside = scoreAll(cohort(BATCH_MIN, { inWindow: false }));
    expect(assignBatches(outside)).toEqual([]);

    const split = scoreAll([...cohort(30), ...cohort(30, { startId: 300000, published: '2026-10-14T01:00:00Z' })]);
    expect(assignBatches(split)).toEqual([]);
  });

  it('groups by the UTC day of the publish timestamp', () => {
    const scored = scoreAll([...cohort(25), ...cohort(25, { startId: 300000, published: '2026-10-13T23:59:59+00:00' })]);
    expect(assignBatches(scored)).toHaveLength(1);
  });

  it('lists families (first affected product) and the top rows', () => {
    const scored = scoreAll(cohort(60));
    const [batch] = assignBatches(scored);
    // count desc, then passed desc, then name
    expect(batch.families).toEqual([
      { name: 'Windows Server 2025', count: 20, passed: 1 },
      { name: 'Office', count: 20, passed: 0 },
      { name: 'Windows 11', count: 20, passed: 0 },
    ]);
    expect(batch.top).toHaveLength(5);
    expect(batch.top[0].id).toBe('CVE-2026-200007');
    const scores = batch.top.map((r) => r.s);
    expect([...scores].sort((a, b) => b - a)).toEqual(scores);
    expect(batch.top.every((r) => r.b === batch.id)).toBe(true);
  });

  it('returns batches newest first', () => {
    const scored = scoreAll([
      ...cohort(50),
      ...cohort(50, { startId: 300000, cna: 'oracle', published: '2026-10-20T20:00:00Z' }),
      ...cohort(50, { startId: 400000, cna: 'adobe', published: '2026-10-13T17:00:00Z' }),
    ]);
    expect(assignBatches(scored).map((b) => b.id)).toEqual(['oracle-2026-10-20', 'adobe-2026-10-13', 'microsoft-2026-10-13']);
  });

  it('caps families at 8', () => {
    const cves = cohort(90).map((c, i) => makeCve({ ...c, affected: [{ vendor: 'Microsoft', product: `Product ${i % 10}`, purl: null }] }));
    const [batch] = assignBatches(scoreAll(cves));
    expect(batch.families).toHaveLength(8);
  });
});
