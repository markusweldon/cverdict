import { describe, expect, it } from 'vitest';
import { WAKE_KINDS } from '../../../shared/contract';
import { buildOutput } from '../../src/emit/build';
import { PATHS } from '../../src/emit/json';
import { parseState } from '../../src/state';
import type { EpssTable, ExploitDbData, PocRepo } from '../../src/types';
import {
  buildWoke,
  detectWakes,
  epssPastDates,
  failedWakeDetection,
  MAX_STATE_GAP_HOURS,
  WOKE_SECTION,
  type WakeInput,
  type WokeState,
} from '../../src/woke';
import { NOW, dateAgo, daysAgo, makeCve, makeIngest, makeKev, makeKevCatalog, msf, nucleiTemplate, repo, score } from '../fixtures/model/builders';

const HOUR = 3_600_000;
const later = (hours: number) => new Date(NOW.getTime() + hours * HOUR);

function epssTable(scoreDate: string, scores: Record<string, number>): EpssTable {
  return { model: 'v2026.06.15', scoreDate, scores: new Map(Object.entries(scores).map(([id, epss]) => [id, { epss, percentile: 0.9 }])) };
}

function edbData(first: Record<string, string>): ExploitDbData {
  return {
    byCve: new Map(),
    firstAdded: new Map(Object.entries(first).map(([cve, date], i) => [cve, { date, id: String(50000 + i), url: `https://www.exploit-db.com/exploits/${50000 + i}` }])),
  };
}

/** Every source loaded, nothing in it, no previous state. */
function input(o: Partial<WakeInput> = {}): WakeInput {
  return {
    now: NOW,
    kev: makeKevCatalog(),
    exploitdb: edbData({}),
    metasploit: new Map(),
    nuclei: new Map(),
    poc: new Map(),
    epss: epssTable(dateAgo(0), {}),
    epssPast: epssTable(dateAgo(30), {}),
    epssPastError: null,
    previous: null,
    previousAt: null,
    ...o,
  };
}

const kinds = (d: ReturnType<typeof detectWakes>, id: string) => (d.signals.get(id) ?? []).map((s) => s.kind);

describe('detectWakes: dated signals work from the first run', () => {
  it('KEV dateAdded within 30 days', () => {
    const d = detectWakes(input({ kev: makeKevCatalog([makeKev('CVE-2019-0001', { dateAdded: dateAgo(3) }), makeKev('CVE-2019-0002', { dateAdded: dateAgo(31) })]) }));
    expect(d.signals.get('CVE-2019-0001')).toEqual([
      { kind: 'kev', at: dateAgo(3), first_seen: false, label: 'added to CISA KEV', source: 'kev', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2019-0001' },
    ]);
    expect(d.signals.has('CVE-2019-0002')).toBe(false);
  });

  it("the CVE's first Exploit-DB entry, by date added", () => {
    const d = detectWakes(input({ exploitdb: edbData({ 'CVE-2019-0001': dateAgo(10), 'CVE-2019-0002': dateAgo(45) }) }));
    expect(d.signals.get('CVE-2019-0001')?.[0]).toMatchObject({ kind: 'exploitdb', at: dateAgo(10), first_seen: false, label: 'first Exploit-DB entry (EDB-50000)', url: 'https://www.exploit-db.com/exploits/50000' });
    expect(d.signals.has('CVE-2019-0002')).toBe(false);
  });

  it("the CVE's first vetted PoC repo, with the scoring vetting rule", () => {
    const poc = new Map<string, PocRepo[]>([
      ['CVE-2019-0001', [repo(daysAgo(12)), repo(daysAgo(2), 0, false, 'b')]],
      ['CVE-2019-0002', [repo(daysAgo(400)), repo(daysAgo(5), 0, false, 'b')]], // had one long ago
      ['CVE-2019-0003', [repo(daysAgo(1))]], // unstarred and 1 day old: not vetted yet
      ['CVE-2019-0004', [repo(daysAgo(1), 5)]], // 5 stars: vetted at once
      ['CVE-2019-0005', [repo(daysAgo(10), 9, true)]], // forks never count
    ]);
    const d = detectWakes(input({ poc }));
    expect(d.signals.get('CVE-2019-0001')?.[0]).toMatchObject({ kind: 'poc', at: daysAgo(12), url: 'https://github.com/nomi-sec/PoC-in-GitHub/blob/master/2019/CVE-2019-0001.json' });
    expect(kinds(d, 'CVE-2019-0002')).toEqual([]);
    expect(kinds(d, 'CVE-2019-0003')).toEqual([]);
    expect(kinds(d, 'CVE-2019-0004')).toEqual(['poc']);
    expect(kinds(d, 'CVE-2019-0005')).toEqual([]);
  });

  it('orders several signals for one CVE oldest first', () => {
    const d = detectWakes(
      input({
        kev: makeKevCatalog([makeKev('CVE-2019-0001', { dateAdded: dateAgo(2) })]),
        poc: new Map([['CVE-2019-0001', [repo(daysAgo(9))]]]),
        exploitdb: edbData({ 'CVE-2019-0001': dateAgo(5) }),
      }),
    );
    expect(kinds(d, 'CVE-2019-0001')).toEqual(['poc', 'exploitdb', 'kev']);
  });
});

describe('detectWakes: undated artifacts need carried-forward state', () => {
  const first = () =>
    detectWakes(
      input({
        metasploit: new Map([['CVE-2019-0001', [msf('exploit/linux/http/a')]]]),
        nuclei: new Map([['CVE-2019-0002', [nucleiTemplate('CVE-2019-0002')]]]),
      }),
    );

  it('the first run takes a baseline: nothing already there counts as new', () => {
    const d = first();
    expect(d.signals.size).toBe(0);
    expect(d.tracking).toEqual({ metasploit: NOW.toISOString(), nuclei: NOW.toISOString(), epss: NOW.toISOString() });
    expect(d.state.metasploit).toEqual({ since: NOW.toISOString(), known: ['CVE-2019-0001'], fresh: {} });
    expect(d.notes.some((n) => /metasploit: baseline of 1 CVEs/.test(n))).toBe(true);
  });

  it('a later run reports a first module with the time it first saw it, and keeps the date', () => {
    const base = first();
    const next = later(1);
    const mods = new Map([
      ['CVE-2019-0001', [msf('exploit/linux/http/a')]],
      ['CVE-2019-0009', [msf('exploit/linux/http/new')]],
    ]);
    const d = detectWakes(input({ now: next, metasploit: mods, nuclei: new Map(), previous: base.state, previousAt: NOW.toISOString() }));
    expect(d.signals.get('CVE-2019-0009')).toEqual([
      { kind: 'metasploit', at: next.toISOString(), first_seen: true, label: 'first Metasploit module', source: 'metasploit', url: msf('exploit/linux/http/new').url },
    ]);
    expect(d.state.metasploit?.since).toBe(NOW.toISOString());
    // A second module for a CVE that already had one is not a wake-up.
    expect(d.signals.has('CVE-2019-0001')).toBe(false);
    // The template that vanished upstream stays known, so it cannot come back as "new".
    expect(d.state.nuclei?.known).toEqual(['CVE-2019-0002']);

    const after = later(5);
    const d2 = detectWakes(input({ now: after, metasploit: mods, previous: d.state, previousAt: next.toISOString() }));
    expect(d2.signals.get('CVE-2019-0009')?.[0].at).toBe(next.toISOString());

    // After WAKE_DAYS it drops out of the feed but stays known.
    const month = new Date(next.getTime() + 31 * 86_400_000);
    let state = d2.state;
    let at = after;
    for (let t = at.getTime() + 24 * HOUR; t <= month.getTime(); t += 24 * HOUR) {
      const run = detectWakes(input({ now: new Date(t), metasploit: mods, previous: state, previousAt: at.toISOString() }));
      state = run.state;
      at = new Date(t);
    }
    expect(state.metasploit?.fresh).toEqual({});
    expect(state.metasploit?.known).toContain('CVE-2019-0009');
  });

  it('a source that is down keeps its state and reports the kind as skipped', () => {
    const base = first();
    const d = detectWakes(input({ now: later(1), metasploit: null, previous: base.state, previousAt: NOW.toISOString() }));
    expect(d.state.metasploit).toEqual(base.state.metasploit);
    expect(d.skipped).toEqual([{ kind: 'metasploit', reason: 'Metasploit could not be loaded this run' }]);
  });

  it(`restarts the baseline after a gap of more than ${MAX_STATE_GAP_HOURS} h instead of dating old modules today, keeping what it had dated`, () => {
    const base = first();
    const mods = new Map([['CVE-2019-0009', [msf('exploit/x')]]]);
    const seen = detectWakes(input({ now: later(1), metasploit: mods, previous: base.state, previousAt: NOW.toISOString() }));
    const gapAt = later(1 + MAX_STATE_GAP_HOURS + 1);
    const d = detectWakes(
      input({ now: gapAt, metasploit: new Map([...mods, ['CVE-2019-0010', [msf('exploit/y')]]]), previous: seen.state, previousAt: later(1).toISOString() }),
    );
    expect([...d.signals.keys()]).toEqual(['CVE-2019-0009']);
    expect(d.signals.get('CVE-2019-0009')?.[0].at).toBe(later(1).toISOString());
    expect(d.state.metasploit?.since).toBe(gapAt.toISOString());
    expect(d.state.metasploit?.known).toEqual(['CVE-2019-0001', 'CVE-2019-0009', 'CVE-2019-0010']);
    expect(d.notes.some((n) => /first-seen tracking restarts/.test(n))).toBe(true);
  });
});

describe('detectWakes: EPSS jumps', () => {
  const jumpy = {
    'CVE-2019-0001': [0.02, 0.3], // 15×: jump
    'CVE-2019-0002': [0.05, 0.12], // 2.4×: no
    'CVE-2019-0003': [0.01, 0.08], // below 10%: no
    'CVE-2019-0004': [null, 0.5], // no score 30 days ago: unknown, not a jump
    'CVE-2019-0005': [0.0333, 0.1], // exactly 3× and exactly 10%: jump
  } as const;
  const tables = (pairs: typeof jumpy, now = NOW) => {
    const past: Record<string, number> = {};
    const cur: Record<string, number> = {};
    for (const [id, [a, b]] of Object.entries(pairs)) {
      if (a !== null) past[id] = a;
      cur[id] = b;
    }
    return { epss: epssTable(dateAgo(0, now), cur), epssPast: epssTable(dateAgo(30, now), past) };
  };

  it('the first run baselines current jumps (their day is unknown), later runs report new ones', () => {
    const base = detectWakes(input(tables(jumpy)));
    expect(base.signals.size).toBe(0);
    expect(Object.keys(base.state.epss!.jumps).sort()).toEqual(['CVE-2019-0001', 'CVE-2019-0005']);
    expect(Object.values(base.state.epss!.jumps).every((j) => j.baseline)).toBe(true);

    const next = new Date(NOW.getTime() + 24 * HOUR);
    const moved = { ...jumpy, 'CVE-2019-0002': [0.03, 0.4] } as unknown as typeof jumpy;
    const d = detectWakes(input({ ...tables(moved, next), now: next, previous: base.state, previousAt: NOW.toISOString() }));
    expect([...d.signals.keys()]).toEqual(['CVE-2019-0002']);
    expect(d.signals.get('CVE-2019-0002')?.[0]).toMatchObject({
      kind: 'epss',
      at: dateAgo(0, next),
      first_seen: true,
      label: 'EPSS rose from 3.0% to 40.0% in 30 days',
      url: 'https://api.first.org/data/v1/epss?cve=CVE-2019-0002&scope=time-series',
    });
  });

  it('skips the check when the old file is missing, and says so: missing data is not "no jump"', () => {
    const { epss } = tables(jumpy);
    const d = detectWakes(input({ epss, epssPast: null, epssPastError: 'HTTP 404' }));
    expect(d.skipped).toEqual([{ kind: 'epss', reason: 'The EPSS scores from 30 days earlier could not be loaded, so no jumps were checked' }]);
    expect(d.notes).toContain('epss: no scores from 30 days earlier (HTTP 404)');
    expect(d.state.epss).toBeNull();
    expect(d.tracking.epss).toBeNull();
  });

  it('keeps known jumps when the old file is missing on a later run', () => {
    const base = detectWakes(input(tables(jumpy)));
    const next = later(1);
    const d = detectWakes(input({ now: next, epss: tables(jumpy).epss, epssPast: null, epssPastError: 'timed out', previous: base.state, previousAt: NOW.toISOString() }));
    expect(d.state.epss).toEqual(base.state.epss);
    expect(d.skipped.map((s) => s.kind)).toEqual(['epss']);
  });

  it('asks for the day 30 days before the score date, then the day before', () => {
    expect(epssPastDates('2026-11-02')).toEqual(['2026-10-03', '2026-10-02']);
  });
});

describe('detectWakes: unavailable dated sources', () => {
  it('reports each as skipped instead of finding nothing', () => {
    const d = detectWakes(input({ kev: null, exploitdb: null, poc: null, epss: null }));
    expect(d.skipped.map((s) => s.kind)).toEqual(['kev', 'exploitdb', 'poc', 'epss']);
  });

  it('a failed detection keeps the previous state and skips every kind', () => {
    const prev: WokeState = { metasploit: { since: daysAgo(3), known: ['CVE-2019-0001'], fresh: {} }, nuclei: null, epss: null };
    const f = failedWakeDetection(prev, 'boom');
    expect(f.state).toBe(prev);
    expect(f.tracking).toEqual({ metasploit: daysAgo(3), nuclei: null, epss: null });
    expect(f.skipped.map((s) => s.kind)).toEqual([...WAKE_KINDS]);
  });
});

describe('WOKE_SECTION.parse', () => {
  it('round-trips detectWakes state and drops malformed entries', () => {
    const d = detectWakes(input({ metasploit: new Map([['CVE-2019-0001', [msf('exploit/a')]]]) }));
    const json = JSON.parse(JSON.stringify(d.state));
    expect(WOKE_SECTION.parse(json)).toEqual(d.state);
    const messy = {
      metasploit: { since: 'not a date', known: [] },
      nuclei: { since: daysAgo(1), known: ['CVE-2019-0002', 'nonsense', 7], fresh: { 'CVE-2019-0002': { at: daysAgo(1), url: 'javascript:alert(1)' }, bad: { at: 'x' } } },
      epss: { since: daysAgo(1), jumps: { 'CVE-2019-0003': { at: dateAgo(1), from: 0.01, to: 0.5 }, 'CVE-2019-0004': { at: dateAgo(1), from: -1, to: 2 } } },
    };
    expect(WOKE_SECTION.parse(messy)).toEqual({
      metasploit: null,
      nuclei: { since: daysAgo(1), known: ['CVE-2019-0002'], fresh: { 'CVE-2019-0002': { at: daysAgo(1), url: null } } },
      epss: { since: daysAgo(1), checked: null, jumps: { 'CVE-2019-0003': { at: dateAgo(1), from: 0.01, to: 0.5, baseline: false } } },
    });
    expect(WOKE_SECTION.parse('garbage')).toBeNull();
  });
});

describe('buildWoke', () => {
  const old = (id: string, published = '2019-05-01T00:00:00.000Z') => makeCve({ id, published, inWindow: false });

  it('keeps only CVEs published before the window, newest wake first, and sets their detail field', () => {
    const wake = detectWakes(
      input({
        kev: makeKevCatalog([makeKev('CVE-2019-0001', { dateAdded: dateAgo(2) })]),
        poc: new Map([
          ['CVE-2019-0002', [repo(daysAgo(10))]],
          ['CVE-2026-100001', [repo(daysAgo(10))]],
        ]),
      }),
    );
    const scored = [
      score(old('CVE-2019-0001'), { kev: [makeKev('CVE-2019-0001', { dateAdded: dateAgo(2) })] }),
      score(old('CVE-2019-0002'), { poc: { 'CVE-2019-0002': [repo(daysAgo(10))] } }),
      score(makeCve({ id: 'CVE-2026-100001' })), // in the window: the normal views already show it
    ];
    const out = buildWoke(scored, wake, NOW, new Date(NOW.getTime() - 30 * 86_400_000));
    expect(out.file.items.map((i) => i.id)).toEqual(['CVE-2019-0001', 'CVE-2019-0002']);
    expect(out.file.counts).toEqual({ kev: 1, exploitdb: 0, metasploit: 0, nuclei: 0, poc: 1, epss: 0 });
    expect(out.file.items[0].row).toMatchObject({ id: 'CVE-2019-0001', tier: 'exploited', k: 1 });
    expect(out.file.items[0].at).toBe(dateAgo(2));
    expect(scored[0].woke).toEqual({ at: dateAgo(2), signals: out.file.items[0].signals });
    expect(scored[2].woke).toBeNull();
    expect(out.file.published_before).toBe(daysAgo(30));
  });

  it('only counts evidence that arrived after the CVE left the window, so ageing out is not waking up', () => {
    const early = [makeKev('CVE-2026-90001', { dateAdded: dateAgo(8) })]; // listed at 27 days old
    const late = [makeKev('CVE-2026-90002', { dateAdded: dateAgo(3) })]; // listed at 32 days old
    const wake = detectWakes(input({ kev: makeKevCatalog([...early, ...late]) }));
    const scored = [
      score(old('CVE-2026-90001', daysAgo(35)), { kev: early }),
      score(old('CVE-2026-90002', daysAgo(35)), { kev: late }),
    ];
    expect(buildWoke(scored, wake, NOW, new Date(NOW.getTime() - 30 * 86_400_000)).file.items.map((i) => i.id)).toEqual(['CVE-2026-90002']);
  });

  it('leaves out CVEs that were in KEV before the period: they never fell asleep', () => {
    const kev = [makeKev('CVE-2019-0001', { dateAdded: dateAgo(200) })];
    const wake = detectWakes(input({ kev: makeKevCatalog(kev), poc: new Map([['CVE-2019-0001', [repo(daysAgo(10))]]]) }));
    const s = score(old('CVE-2019-0001'), { kev, poc: { 'CVE-2019-0001': [repo(daysAgo(10))] } });
    expect(buildWoke([s], wake, NOW, new Date(NOW.getTime() - 30 * 86_400_000)).file.items).toEqual([]);
  });
});

describe('buildOutput with woke CVEs', () => {
  it('emits woke.json, the feed, state.json, and shards only woke candidates that qualified', () => {
    const cves = [makeCve(), makeCve({ id: 'CVE-2019-0001', published: '2019-05-01T00:00:00.000Z', inWindow: false }), makeCve({ id: 'CVE-2019-0002', published: '2019-05-01T00:00:00.000Z', inWindow: false })];
    const wake = detectWakes(input({ poc: new Map([['CVE-2019-0001', [repo(daysAgo(6))]]]) }));
    // CVE-2019-0002 was ingested as a candidate (say, an unvetted PoC) but has no signal.
    const built = buildOutput({ ingest: makeIngest(cves, { poc: { 'CVE-2019-0001': [repo(daysAgo(6))] }, wake }), now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://example.test' });
    const woke = JSON.parse(built.files.get(PATHS.woke)!);
    expect(woke.items.map((i: { id: string }) => i.id)).toEqual(['CVE-2019-0001']);
    expect(built.scored.map((s) => s.cve.id).sort()).toEqual(['CVE-2019-0001', 'CVE-2026-100001']);
    expect(built.files.get(PATHS.wokeFeed)).toContain('CVE-2019-0001 · Acme Widget · woke up: first PoC repo on GitHub (unverified)');
    const state = parseState(built.files.get(PATHS.state)!);
    expect(state.status).toBe('ok');
    expect(WOKE_SECTION.parse(state.sections.get('woke')?.data)).toEqual(wake.state);
  });
});
