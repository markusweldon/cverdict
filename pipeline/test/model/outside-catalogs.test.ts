/**
 * Old CVEs (published before the window) that only ENISA EU KEV or the CIRCL catalog list as
 * exploited: kept like CISA KEV's, with a CVE page, Woke Up and "what changed" treatment, and never
 * a CISA due date. SiberKapan, CIRCL suspected and CIRCL attempts-only listings keep nothing.
 */
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ChangesFile, CveShard, KevFile, StatsFile, WokeFile } from '../../../shared/contract';
import { shardOf } from '../../../shared/shard';
import { buildOutput, exploitedElsewhere } from '../../src/emit/build';
import { PATHS, writeFiles } from '../../src/emit/json';
import { exploitedCatalogIds, firstExploitedListing, isExploitedListing } from '../../src/sources/catalogs';
import type { CatalogListing } from '../../src/types';
import { validateOutput } from '../../src/validate';
import { buildWoke, detectWakes, type WakeInput } from '../../src/woke';
import { NOW, cohort, dateAgo, daysAgo, listing, makeCve, makeIngest, makeKev, makeKevCatalog, repo, score } from '../fixtures/model/builders';

const EU = 'CVE-2018-0001';
const CIRCL = 'CVE-2017-0002';
const ATTEMPTS = 'CVE-2016-0003';
const SUSPECTED = 'CVE-2016-0004';
const SIBER = 'CVE-2016-0005';

const eu = listing('eu-kev', dateAgo(3));
const circl = listing('circl-kev', dateAgo(200));
const attempts = listing('circl-kev', dateAgo(2), { attemptsOnly: true });
const suspected = listing('circl-kev', dateAgo(2), { status: 'suspected' });
const siber = listing('siberkapan', dateAgo(2));

describe('isExploitedListing and friends', () => {
  it('counts every EU KEV listing and CIRCL confirmed with more than attempts, nothing else', () => {
    expect(isExploitedListing(eu)).toBe(true);
    expect(isExploitedListing(listing('eu-kev', null, { notBefore: dateAgo(9) }))).toBe(true);
    expect(isExploitedListing(circl)).toBe(true);
    expect(isExploitedListing(attempts)).toBe(false);
    expect(isExploitedListing(suspected)).toBe(false);
    expect(isExploitedListing(siber)).toBe(false);
    const catalogs = [
      new Map([[EU, eu]]),
      new Map([
        [CIRCL, circl],
        [ATTEMPTS, attempts],
        [SUSPECTED, suspected],
      ]),
      null,
      new Map([[SIBER, siber]]),
    ];
    expect([...exploitedCatalogIds(catalogs)].sort()).toEqual([CIRCL, EU]);
    // A frozen --now before the EU listing: it does not exist yet (scoring ignores it too).
    expect([...exploitedCatalogIds(catalogs, dateAgo(5))]).toEqual([CIRCL]);
    expect(isExploitedListing(listing('eu-kev', null), dateAgo(5))).toBe(true);
  });

  it('dates a CVE by its earliest dated exploited listing, ignoring undated and information-only ones', () => {
    expect(firstExploitedListing([listing('eu-kev', null), attempts, siber, suspected])).toBeNull();
    expect(firstExploitedListing([eu, circl, listing('circl-kev', dateAgo(900), { attemptsOnly: true })])).toEqual(circl);
    expect(firstExploitedListing(undefined)).toBeNull();
    expect(firstExploitedListing([eu], dateAgo(4))).toBeNull();
  });
});

const baseWake = (o: Partial<WakeInput> = {}): WakeInput => ({
  now: NOW,
  kev: makeKevCatalog(),
  exploitdb: { byCve: new Map(), firstAdded: new Map(), added: new Map() },
  metasploit: new Map(),
  nuclei: new Map(),
  poc: new Map(),
  epss: null,
  epssPast: null,
  epssPastError: null,
  previous: null,
  previousAt: null,
  ...o,
});

describe('detectWakes: the catalog kind', () => {
  const catalogs = (euMap: [string, CatalogListing][] | null, circlMap: [string, CatalogListing][] | null): WakeInput['catalogs'] => ({
    'eu-kev': euMap && new Map(euMap),
    'circl-kev': circlMap && new Map(circlMap),
  });

  it('signals a first exploited listing dated in the period, from either catalog', () => {
    const d = detectWakes(baseWake({ catalogs: catalogs([[EU, eu]], [[CIRCL, circl], [ATTEMPTS, attempts], [SUSPECTED, suspected]]) }));
    expect(d.signals.get(EU)).toEqual([{ kind: 'catalog', at: dateAgo(3), first_seen: false, label: 'listed in ENISA EU KEV', source: 'eu-kev', url: eu.url }]);
    // Listed 200 days ago: not in the period. Attempts and suspected entries are no signal at all.
    expect(d.signals.has(CIRCL)).toBe(false);
    expect(d.signals.has(ATTEMPTS)).toBe(false);
    expect(d.signals.has(SUSPECTED)).toBe(false);
    expect(d.skipped.filter((s) => s.kind === 'catalog')).toEqual([]);
    const c = detectWakes(baseWake({ catalogs: catalogs([], [[CIRCL, listing('circl-kev', dateAgo(1))]]) }));
    expect(c.signals.get(CIRCL)?.[0]).toMatchObject({ kind: 'catalog', label: 'listed by CIRCL as exploited', source: 'circl-kev' });
  });

  it('is first of its kind: an older listing in the other catalog, or an undated one, wakes nothing', () => {
    const d = detectWakes(baseWake({ catalogs: catalogs([[EU, eu]], [[EU, listing('circl-kev', dateAgo(400))]]) }));
    expect(d.signals.has(EU)).toBe(false);
    const undated = detectWakes(baseWake({ catalogs: catalogs([[EU, listing('eu-kev', null)]], []) }));
    expect(undated.signals.size).toBe(0);
  });

  it('reports a catalog that could not be loaded, and still reads the other', () => {
    const one = detectWakes(baseWake({ catalogs: catalogs(null, [[CIRCL, listing('circl-kev', dateAgo(1))]]) }));
    expect(one.skipped.filter((s) => s.kind === 'catalog')).toEqual([{ kind: 'catalog', reason: 'ENISA EU KEV could not be loaded this run' }]);
    expect(one.signals.has(CIRCL)).toBe(true);
    const both = detectWakes(baseWake({ catalogs: catalogs(null, null) }));
    expect(both.skipped.filter((s) => s.kind === 'catalog')).toEqual([{ kind: 'catalog', reason: 'ENISA EU KEV and the CIRCL catalog could not be loaded this run' }]);
  });

  it('counts an exploited listing before the period as older evidence for exploit artifacts', () => {
    const poc = new Map([[CIRCL, [repo(daysAgo(4))]], [ATTEMPTS, [repo(daysAgo(4))]]]);
    const d = detectWakes(baseWake({ poc, catalogs: catalogs([], [[CIRCL, circl], [ATTEMPTS, listing('circl-kev', dateAgo(300), { attemptsOnly: true })]]) }));
    // CIRCL confirmed it 200 days ago: a new PoC is not news. Attempts only are not exploitation.
    expect(d.signals.has(CIRCL)).toBe(false);
    expect(d.signals.get(ATTEMPTS)?.map((s) => s.kind)).toEqual(['poc']);
  });
});

describe('buildWoke: exploited listings', () => {
  const windowStart = new Date(NOW.getTime() - 30 * 86_400_000);
  const old = (id: string) => makeCve({ id, published: '2018-03-01T00:00:00.000Z', inWindow: false });

  it('keeps a CVE that a catalog listed in the period, and leaves out one listed before it', () => {
    const kevNow = makeKev(CIRCL, { dateAdded: dateAgo(2) });
    const scored = [score(old(EU), { catalogs: { [EU]: [eu] } }), score(old(CIRCL), { kev: [kevNow], catalogs: { [CIRCL]: [circl] } })];
    const signals = new Map([
      [EU, [{ kind: 'catalog' as const, at: dateAgo(3), first_seen: false, label: 'listed in ENISA EU KEV', source: 'eu-kev' as const, url: eu.url }]],
      [CIRCL, [{ kind: 'kev' as const, at: dateAgo(2), first_seen: false, label: 'added to CISA KEV', source: 'kev' as const, url: null }]],
    ]);
    const wake = { signals, state: { metasploit: null, nuclei: null, epss: null }, tracking: { metasploit: null, nuclei: null, epss: null }, skipped: [], notes: [] };
    const out = buildWoke(scored, wake, NOW, windowStart, new Map([[EU, [eu]], [CIRCL, [circl]]]));
    // CIRCL listed it as exploited 200 days ago: the CISA listing now does not wake it.
    expect(out.file.items.map((i) => i.id)).toEqual([EU]);
    expect(out.file.counts.catalog).toBe(1);
    expect(out.file.items[0].row.k).toBe(0);
  });

  it('keeps an EU KEV or confirmed CIRCL listing from the last days in the window, once the CVE has left it', () => {
    // Published 35 days ago (left the window 5 days ago), listed 8 days ago while still in it.
    const ids = ['CVE-2026-70001', 'CVE-2026-70002', 'CVE-2026-70003'];
    const listings: Record<string, CatalogListing> = {
      [ids[0]]: listing('eu-kev', dateAgo(8)),
      [ids[1]]: listing('circl-kev', dateAgo(8)),
      [ids[2]]: listing('circl-kev', dateAgo(8), { status: 'suspected' }),
    };
    const wake = detectWakes(baseWake({ catalogs: { 'eu-kev': new Map([[ids[0], listings[ids[0]]]]), 'circl-kev': new Map([[ids[1], listings[ids[1]]], [ids[2], listings[ids[2]]]]) } }));
    const scored = ids.map((id) => score(makeCve({ id, published: daysAgo(35), inWindow: false }), { catalogs: { [id]: [listings[id]] } }));
    const out = buildWoke(scored, wake, NOW, windowStart, new Map(ids.map((id) => [id, [listings[id]]])));
    // A suspected CIRCL entry is information only and wakes nothing.
    expect(out.file.items.map((i) => [i.id, i.signals.map((x) => x.kind)]).sort()).toEqual([
      [ids[0], ['catalog']],
      [ids[1], ['catalog']],
    ]);
  });
});

describe('buildOutput: CVEs only EU KEV or CIRCL list', () => {
  const cves = [
    ...cohort(3),
    ...[EU, CIRCL, ATTEMPTS, SUSPECTED, SIBER].map((id) => makeCve({ id, published: '2016-06-01T00:00:00.000Z', inWindow: false })),
  ];
  const catalogs = { [EU]: [eu], [CIRCL]: [circl], [ATTEMPTS]: [attempts], [SUSPECTED]: [suspected], [SIBER]: [siber] };
  const wake = detectWakes(
    baseWake({
      catalogs: {
        'eu-kev': new Map([[EU, eu]]),
        'circl-kev': new Map([
          [CIRCL, circl],
          [ATTEMPTS, attempts],
          [SUSPECTED, suspected],
        ]),
      },
    }),
  );
  const run = (previous: string | null) => buildOutput({ ingest: makeIngest(cves, { catalogs, wake }), now: NOW, windowDays: 30, knob: 50, previous, siteUrl: 'https://example.test' });

  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'outside-catalogs-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const read = <T>(root: string, p: string): T => JSON.parse(readFileSync(join(root, p), 'utf8')) as T;

  it('gives each a CVE page in the Exploited tier with no due date, and keeps nothing for information-only listings', async () => {
    const built = run(null);
    await writeFiles(dir, built.files);
    expect(validateOutput(dir).errors).toEqual([]);
    expect([...exploitedElsewhere(new Map(Object.entries(catalogs)), NOW)].sort()).toEqual([CIRCL, EU]);
    expect([...exploitedElsewhere(new Map(Object.entries(catalogs)), new Date(NOW.getTime() - 5 * 86_400_000))]).toEqual([CIRCL]);
    for (const id of [EU, CIRCL]) {
      const d = read<CveShard>(dir, PATHS.shard(shardOf(id))).items[id];
      expect(d.score.tier).toBe('exploited');
      expect(d.kev).toBeNull();
      expect(d.reasons.some((r) => r.id === 'kev.due' || r.id === 'kev.listed')).toBe(false);
    }
    for (const id of [ATTEMPTS, SUSPECTED, SIBER]) expect(read<CveShard>(dir, PATHS.shard(shardOf(id))).items[id]).toBeUndefined();
    // Not CISA KEV: no KEV Clock entry, no due-date calendar event, no KEV feed entry.
    expect(read<KevFile>(dir, PATHS.kev).entries.map((e) => e.id)).not.toContain(EU);
    for (const p of [PATHS.kevDueIcs, PATHS.kevFeed]) expect(built.files.get(p)).not.toContain(EU);
    // Woke Up: the EU listing 3 days ago; CIRCL's is 200 days old.
    const woke = read<WokeFile>(dir, PATHS.woke);
    expect(woke.items.map((i) => i.id)).toEqual([EU]);
    expect(built.files.get(PATHS.wokeFeed)).toContain(EU);
  });

  it('names an older CVE that CISA KEV listed in the last 72 hours in stats.json, without an hour, and validates', async () => {
    const OLD = 'CVE-2019-11510';
    const kev = [makeKev(OLD, { dateAdded: dateAgo(1) })];
    const built = buildOutput({ ingest: makeIngest([...cohort(3), makeCve({ id: OLD, published: '2019-04-26T00:00:00.000Z', inWindow: false })], { kev }), now: NOW, windowDays: 30, knob: 50, previous: null, siteUrl: 'https://example.test' });
    await writeFiles(dir, built.files);
    expect(validateOutput(dir).errors).toEqual([]);
    const stats = read<StatsFile>(dir, PATHS.stats);
    expect(stats.hourly.new_exploited_cves).toEqual([{ id: OLD, title: expect.any(String), via: 'CISA KEV', at: dateAgo(1), published: '2019-04-26' }]);
    expect(stats.hourly.new_exploited).toEqual([]);
    expect(stats.hourly.new_exploited_total).toBe(1);
  });

  it('reports a recent listing once in changes.json, and an old one never', async () => {
    await writeFiles(dir, run(null).files);
    const second = run(dir);
    const items = JSON.parse(second.files.get(PATHS.changes)!) as ChangesFile;
    expect(items.items.filter((i) => [EU, CIRCL].includes(i.id))).toEqual([{ id: EU, at: NOW.toISOString(), from: null, to: 'exploited', added: expect.arrayContaining(['eukev.listed']) }]);
    const next = mkdtempSync(join(tmpdir(), 'outside-catalogs-'));
    try {
      await writeFiles(next, second.files);
      const third = JSON.parse(run(next).files.get(PATHS.changes)!) as ChangesFile;
      expect(third.items.filter((i) => i.id === EU)).toHaveLength(1);
    } finally {
      rmSync(next, { recursive: true, force: true });
    }
  });
});
