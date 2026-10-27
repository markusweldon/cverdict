import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SCHEMA_VERSION, type Change, type Row } from '../../../shared/contract';
import { buildChanges } from '../../src/changes';
import { rowTable } from '../../src/emit/json';

const NOW = new Date('2026-10-26T19:30:00Z');
const PREV_RUN = '2026-10-26T18:30:00.000Z';

function row(id: string, o: Partial<Row> = {}): Row {
  return {
    id,
    pub: '2026-10-20T10:00:00.000Z',
    cna: 'acme',
    v: 'Acme',
    p: 'Widget',
    t: 'title',
    s: 30,
    tier: 'watch',
    x: 0,
    w: 0,
    k: 0,
    ai: 0,
    c: ['sev.high', 'x.none'],
    cv: 7.5,
    e: null,
    kd: null,
    b: null,
    ...o,
  };
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'changes-'));
  mkdirSync(join(dir, 'v1'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function writePrevious(rows: Row[], items?: Change[], kevIds?: string[]): void {
  writeFileSync(join(dir, 'v1', 'index.json'), JSON.stringify(rowTable(rows, 'test', PREV_RUN)));
  if (items) writeFileSync(join(dir, 'v1', 'changes.json'), JSON.stringify({ schema_version: SCHEMA_VERSION, generated_at: PREV_RUN, items }));
  if (kevIds) {
    const entries = kevIds.map((id) => ({ id }));
    writeFileSync(join(dir, 'v1', 'kev.json'), JSON.stringify({ schema_version: SCHEMA_VERSION, generated_at: PREV_RUN, catalog_version: null, entries }));
  }
}

describe('buildChanges', () => {
  it('returns an empty file without a previous run', () => {
    const f = buildChanges([row('CVE-2026-1', { tier: 'likely' })], null, NOW);
    expect(f).toEqual({ schema_version: SCHEMA_VERSION, generated_at: NOW.toISOString(), items: [] });
    expect(buildChanges([row('CVE-2026-1', { tier: 'likely' })], join(dir, 'missing'), NOW).items).toEqual([]);
  });

  it('records a tier rise with the chips that appeared', () => {
    writePrevious([row('CVE-2026-1')]);
    const f = buildChanges([row('CVE-2026-1', { tier: 'likely', s: 55, c: ['sev.crit_net', 'ssvc.total'] })], dir, NOW);
    expect(f.items).toEqual([{ id: 'CVE-2026-1', at: NOW.toISOString(), from: 'watch', to: 'likely', added: ['sev.crit_net', 'ssvc.total'] }]);
  });

  it('records a new E/X chip even without a tier change', () => {
    writePrevious([row('CVE-2026-1', { tier: 'likely', c: ['x.nuclei'] })]);
    const f = buildChanges([row('CVE-2026-1', { tier: 'likely', c: ['x.metasploit'] })], dir, NOW);
    expect(f.items.map((i) => [i.id, i.from, i.to, i.added])).toEqual([['CVE-2026-1', 'likely', 'likely', ['x.metasploit']]]);
  });

  it('records a new KEV listing', () => {
    writePrevious([row('CVE-2026-1', { tier: 'likely', c: ['x.metasploit'] })]);
    const f = buildChanges([row('CVE-2026-1', { tier: 'exploited', k: 1, x: 1, c: ['kev.listed', 'x.metasploit'] })], dir, NOW);
    expect(f.items[0]).toMatchObject({ from: 'likely', to: 'exploited', added: ['kev.listed'] });
  });

  it('ignores unchanged rows, tier drops, and new non-E/X chips', () => {
    writePrevious([row('CVE-2026-1'), row('CVE-2026-2', { tier: 'likely', s: 55 }), row('CVE-2026-3')]);
    const f = buildChanges(
      [row('CVE-2026-1'), row('CVE-2026-2', { tier: 'watch', s: 40 }), row('CVE-2026-3', { c: ['sev.high', 'x.none', 'ai.credit'] })],
      dir,
      NOW,
    );
    expect(f.items).toEqual([]);
  });

  it('new arrivals count only when they reach exploited/likely', () => {
    writePrevious([row('CVE-2026-1')]);
    const f = buildChanges(
      [row('CVE-2026-1'), row('CVE-2026-8', { pub: '2026-10-26T19:00:00Z', tier: 'likely', c: ['x.nuclei'] }), row('CVE-2026-9', { pub: '2026-10-26T19:00:00Z' })],
      dir,
      NOW,
    );
    expect(f.items).toEqual([{ id: 'CVE-2026-8', at: NOW.toISOString(), from: null, to: 'likely', added: ['x.nuclei'] }]);
  });

  it('does not treat rows older than the previous window as new, unless newly KEV-listed', () => {
    const old = row('CVE-2025-5', { pub: '2025-01-01T00:00:00Z', tier: 'likely' });
    const kev = row('CVE-2024-7', { pub: '2024-03-01T00:00:00Z', tier: 'exploited', k: 1, x: 1, c: ['kev.listed'] });
    const knownKev = row('CVE-2024-8', { pub: '2024-03-01T00:00:00Z', tier: 'exploited', k: 1, x: 1, c: ['kev.listed'] });
    writePrevious([row('CVE-2026-1')], undefined, ['CVE-2024-8']);
    const f = buildChanges([row('CVE-2026-1'), old, kev, knownKev], dir, NOW);
    expect(f.items).toEqual([{ id: 'CVE-2024-7', at: NOW.toISOString(), from: null, to: 'exploited', added: ['kev.listed'] }]);
  });

  it('records no KEV arrivals outside the window when the previous kev.json is missing', () => {
    writePrevious([row('CVE-2026-1')]);
    const kev = row('CVE-2024-7', { pub: '2024-03-01T00:00:00Z', tier: 'exploited', k: 1, x: 1, c: ['kev.listed'] });
    expect(buildChanges([row('CVE-2026-1'), kev], dir, NOW).items).toEqual([]);
  });

  it('merges with previous items: one per CVE, keeps the original `from`, drops > 7 days, newest first', () => {
    const items: Change[] = [
      { id: 'CVE-2026-1', at: '2026-10-25T10:00:00.000Z', from: 'quiet', to: 'watch', added: ['x.poc'] },
      { id: 'CVE-2026-2', at: '2026-10-24T10:00:00.000Z', from: null, to: 'likely', added: ['x.nuclei'] },
      { id: 'CVE-2026-3', at: '2026-10-10T10:00:00.000Z', from: 'watch', to: 'likely', added: ['x.poc'] },
    ];
    writePrevious([row('CVE-2026-1')], items);
    const f = buildChanges([row('CVE-2026-1', { tier: 'likely', c: ['x.poc', 'sev.crit_net'] })], dir, NOW);
    expect(f.items).toEqual([
      { id: 'CVE-2026-1', at: NOW.toISOString(), from: 'quiet', to: 'likely', added: ['sev.crit_net', 'x.poc'] },
      items[1],
    ]);
  });

  it('does not repeat an item already reported for the same state', () => {
    const kev = row('CVE-2024-7', { pub: '2024-03-01T00:00:00Z', tier: 'exploited', k: 1, x: 1, c: ['kev.listed'] });
    const first: Change = { id: 'CVE-2024-7', at: '2026-10-26T18:30:00.000Z', from: null, to: 'exploited', added: ['kev.listed'] };
    writePrevious([row('CVE-2026-1')], [first], []);
    expect(buildChanges([row('CVE-2026-1'), kev], dir, NOW).items).toEqual([first]);
  });

  it('caps at 500 items', () => {
    const prev = Array.from({ length: 600 }, (_, i) => row(`CVE-2026-${10000 + i}`));
    writePrevious(prev);
    const cur = prev.map((r) => ({ ...r, tier: 'likely' as const, s: 60 }));
    const f = buildChanges(cur, dir, NOW);
    expect(f.items).toHaveLength(500);
  });

  it('ignores malformed previous files', () => {
    writeFileSync(join(dir, 'v1', 'index.json'), '{not json');
    writeFileSync(join(dir, 'v1', 'changes.json'), JSON.stringify({ schema_version: 99, items: [{ id: 'x' }] }));
    expect(buildChanges([row('CVE-2026-1', { tier: 'likely' })], dir, NOW).items).toEqual([]);

    writePrevious([row('CVE-2026-1')], [{ id: 'CVE-2026-5', at: 'not a date', from: null, to: 'likely', added: [] }]);
    expect(buildChanges([row('CVE-2026-1')], dir, NOW).items).toEqual([]);
  });
});
