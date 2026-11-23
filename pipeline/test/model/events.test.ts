import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { compareEvents, selectFeedEvents } from '../../../shared/atom';
import type { EventItem, EventsFile, Row } from '../../../shared/contract';
import { buildOutput } from '../../src/emit/build';
import { writeFiles, PATHS } from '../../src/emit/json';
import { EVENTS_MAX_ITEMS, buildEvents, catalogSnapshot, eventKey, idsHash, parseItem, type EventsInput } from '../../src/events';
import { loadState, readSection } from '../../src/state';
import { EVENTS_SECTION } from '../../src/events';
import { validateOutput } from '../../src/validate';
import { dateAgo, daysAgo, listing, makeCve, makeIngest, makeKev, msf, NOW, score, type EnrichmentSpec } from '../fixtures/model/builders';
import { toRow } from '../../src/rows';
import type { NormalizedCve } from '../../src/types';

const HOUR = 3_600_000;
const T1 = NOW;
const T2 = new Date(NOW.getTime() + HOUR);
const T3 = new Date(NOW.getTime() + 2 * HOUR);

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'events-'));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const A = 'CVE-2026-100001';
const B = 'CVE-2019-0001';
const C = 'CVE-2026-100003';
const D = 'CVE-2018-0002';
const E = 'CVE-2026-100005';

const cves = (): NormalizedCve[] => [
  makeCve({ id: A }),
  makeCve({ id: B, published: '2019-03-01T00:00:00.000Z', inWindow: false, affected: [{ vendor: 'Fortinet', product: 'FortiOS', purl: null }] }),
  makeCve({ id: C }),
  makeCve({ id: D, published: '2018-05-01T00:00:00.000Z', inWindow: false, affected: [{ vendor: 'Ivanti', product: 'Connect Secure', purl: null }] }),
  makeCve({ id: E }),
];

/** Run buildOutput at `now` against `previous`, write it under root/<name>, validate it, and return the events file. */
async function runAt(name: string, now: Date, spec: EnrichmentSpec, previous: string | null) {
  const built = buildOutput({ ingest: makeIngest(cves(), spec), now, windowDays: 30, knob: 50, previous, previousState: loadState(previous), siteUrl: 'https://example.test' });
  const out = join(root, name);
  await writeFiles(out, built.files);
  const v = validateOutput(out);
  expect(v.errors).toEqual([]);
  const file = JSON.parse(readFileSync(join(out, PATHS.events), 'utf8')) as EventsFile;
  return { out, file, built, xml: readFileSync(join(out, PATHS.eventsFeed), 'utf8') };
}

describe('events.json across runs', () => {
  it('backfills a first run, diffs the next one, folds tier moves and never repeats an event', async () => {
    // Run 1: no previous tree. B was added to KEV two days ago, C twelve days ago (outside 7 days).
    const spec1: EnrichmentSpec = { kev: [makeKev(B, { dateAdded: dateAgo(2), vendorProject: 'Fortinet', product: 'FortiOS' }), makeKev(C, { dateAdded: dateAgo(12) })] };
    const r1 = await runAt('r1', T1, spec1, null);
    expect(r1.file.previous_at).toBeNull();
    expect(r1.file.items.map((i) => [i.id, i.at, i.backfill])).toEqual([[`kev_added:${B}`, `${dateAgo(2)}T00:00:00Z`, true]]);
    expect(r1.file.items[0]).toMatchObject({ vendor: 'Fortinet', product: 'FortiOS', tier_after: 'exploited', via: 'kev', tier_before: null });
    expect(r1.file.catalogs.kev).toMatchObject({ version: '2026.10.23', count: 2, ids_sha256: idsHash([B, C]) });

    // Run 2: A gained a Metasploit module (Likely), E an EU KEV listing (Exploited), D a fresh KEV listing.
    const spec2: EnrichmentSpec = {
      kev: [...spec1.kev!, makeKev(D, { dateAdded: dateAgo(0, T2), vendorProject: 'Ivanti', product: 'Connect Secure' })],
      metasploit: { [A]: [msf('exploit/multi/http/acme_widget')] },
      catalogs: { [E]: [listing('eu-kev', dateAgo(1, T2))] },
    };
    const r2 = await runAt('r2', T2, spec2, r1.out);
    const at2 = T2.toISOString();
    expect(r2.file.previous_at).toBe(T1.toISOString());
    const byId = new Map(r2.file.items.map((i) => [i.id, i]));
    expect([...byId.keys()].sort()).toEqual([`catalog_listed:eu-kev:${E}`, `kev_added:${B}`, `kev_added:${D}`, `metasploit_module:${A}`].sort());
    expect(byId.get(`metasploit_module:${A}`)).toMatchObject({ at: at2, tier_before: 'quiet', tier_after: 'likely', via: 'metasploit', backfill: false });
    expect(byId.get(`catalog_listed:eu-kev:${E}`)).toMatchObject({ at: at2, tier_before: 'quiet', tier_after: 'exploited', via: 'eu-kev' });
    expect(byId.get(`kev_added:${D}`)).toMatchObject({ at: at2, vendor: 'Ivanti', tier_after: 'exploited' });
    // The tier moves rode on those events: none of their own, but remembered.
    expect(r2.file.items.some((i) => i.type === 'tier_up')).toBe(false);
    const keys2 = readSection(loadState(r2.out), EVENTS_SECTION)!.keys;
    expect(Object.keys(keys2)).toEqual(expect.arrayContaining([`tier_up:${A}:likely`, `tier_up:${E}:exploited`]));
    // The carried item keeps its first `at`.
    expect(byId.get(`kev_added:${B}`)!.at).toBe(`${dateAgo(2)}T00:00:00Z`);
    expect(r2.file.items).toEqual([...r2.file.items].sort(compareEvents));
    expect(r2.xml).toContain(`<id>tag:cverdict-psi.vercel.app,2026:cverdict/event/metasploit_module:${A}</id>`);
    expect(r2.xml).toContain('Tier: Quiet → Likely next · score');

    // Run 3: same inputs. Nothing new, the same items, the same keys.
    const r3 = await runAt('r3', T3, spec2, r2.out);
    expect(r3.file.items).toEqual(r2.file.items);
    expect(readSection(loadState(r3.out), EVENTS_SECTION)!.keys).toEqual(keys2);
  });

  it('runs the diff and backfills on the first deploy (a previous tree without events.json)', async () => {
    const r1 = await runAt('r1', T1, {}, null);
    rmSync(join(r1.out, PATHS.events));
    rmSync(join(r1.out, 'v1/state.json'));
    const spec: EnrichmentSpec = { kev: [makeKev(B, { dateAdded: dateAgo(3, T2) })], metasploit: { [A]: [msf('exploit/x')] } };
    const r2 = await runAt('r2', T2, spec, r1.out);
    expect(r2.file.items.map((i) => [i.id, i.backfill])).toEqual([
      // Not in the previous kev.json, so it is new to this run (and first in priority).
      [`kev_added:${B}`, false],
      [`metasploit_module:${A}`, false],
    ]);
  });

  it('reports a tier move with no other event as tier_up, and a genuinely new CVE once', async () => {
    const r1 = await runAt('r1', T1, {}, null);
    // A new CVE published after the previous run with a vendor in-the-wild statement.
    const F = 'CVE-2026-100099';
    const extra = makeCve({ id: F, published: new Date(T2.getTime() - 10 * 60_000).toISOString(), vendorInTheWild: true });
    const built = buildOutput({ ingest: makeIngest([...cves(), extra], { epss: { [C]: [0.5, 0.99] } }), now: T2, windowDays: 30, knob: 50, previous: r1.out, siteUrl: 'https://example.test' });
    const ev = JSON.parse(built.files.get(PATHS.events)!) as EventsFile;
    const f = ev.items.find((i) => i.cve === F)!;
    expect(f).toMatchObject({ id: `vendor_exploited:${F}`, tier_before: null, tier_after: 'exploited', via: 'cvelist' });
    expect(f.detail).toMatch(/^New CVE, published /);
    expect(ev.items.filter((i) => i.cve === F)).toHaveLength(1);
  });

  it('emits nothing for the diff types on a first run', async () => {
    const r1 = await runAt('r1', T1, { metasploit: { [A]: [msf('exploit/x')] } }, null);
    expect(r1.file.items).toEqual([]);
  });
});

function item(o: Partial<EventItem> & Pick<EventItem, 'type' | 'cve'>): EventItem {
  const base = { at: T1.toISOString().replace('.000Z', 'Z'), vendor: 'Acme', product: 'Widget', tier_before: null, tier_after: 'likely' as const, score: 60, title: 't', via: 'computed' as const, url: null, detail: 'd', backfill: false, ...o };
  return { ...base, id: eventKey(base.type, base.cve, { via: base.via, tierAfter: base.tier_after }) };
}

function input(o: Partial<EventsInput>): EventsInput {
  return {
    now: T1,
    byId: new Map(),
    rows: new Map<string, Row>(),
    diff: null,
    previous: [],
    previousState: null,
    kev: { version: null, dateReleased: null, entries: new Map() },
    woke: { schema_version: 1, generated_at: T1.toISOString(), since: daysAgo(30), days: 30, published_before: daysAgo(30), tracking: { metasploit: null, nuclei: null, epss: null }, skipped: [], counts: { kev: 0, catalog: 0, exploitdb: 0, metasploit: 0, nuclei: 0, poc: 0, epss: 0 }, items: [] },
    snapshots: { kev: null, eu_kev: null },
    ...o,
  };
}

describe('buildEvents', () => {
  it('caps the log by dropping the lowest-priority oldest items, and keeps it newest first', () => {
    const prev: EventItem[] = [];
    for (let i = 0; i < EVENTS_MAX_ITEMS + 50; i++) {
      const at = new Date(T1.getTime() - i * 60_000).toISOString().replace('.000Z', 'Z');
      prev.push(item({ type: i % 10 === 0 ? 'kev_added' : 'tier_up', cve: `CVE-2026-${200000 + i}`, at, via: i % 10 === 0 ? 'kev' : 'computed' }));
    }
    const out = buildEvents(input({ previous: prev.sort(compareEvents) }));
    expect(out.file.items).toHaveLength(EVENTS_MAX_ITEMS);
    expect(out.file.items.filter((i) => i.type === 'kev_added')).toHaveLength(prev.filter((i) => i.type === 'kev_added').length);
    expect(out.file.items).toEqual([...out.file.items].sort(compareEvents));
    // The dropped ones stay remembered, so they never come back.
    expect(Object.keys(out.state.keys)).toHaveLength(EVENTS_MAX_ITEMS);
  });

  it('drops items older than 7 days and items dated after now, and forgets keys after 14 days', () => {
    const prev = [item({ type: 'tier_up', cve: 'CVE-2026-1001', at: daysAgo(8) }), item({ type: 'tier_up', cve: 'CVE-2026-1002', at: daysAgo(-1) }), item({ type: 'tier_up', cve: 'CVE-2026-1003', at: daysAgo(1) })];
    const out = buildEvents(input({ previous: prev, previousState: { keys: { 'tier_up:CVE-2026-9:likely': daysAgo(15), 'tier_up:CVE-2026-8:likely': daysAgo(13) } } }));
    expect(out.file.items.map((i) => i.cve)).toEqual(['CVE-2026-1003']);
    expect(Object.keys(out.state.keys).sort()).toEqual(['tier_up:CVE-2026-1003:likely', 'tier_up:CVE-2026-8:likely']);
  });

  it('rejects carried items whose id does not match their fields, or that are malformed', () => {
    const good = item({ type: 'kev_added', cve: 'CVE-2026-1001', via: 'kev' });
    expect(parseItem(good)).toEqual(good);
    expect(parseItem({ ...good, id: 'kev_added:CVE-2026-1002' })).toBeNull();
    expect(parseItem({ ...good, type: 'nope' })).toBeNull();
    expect(parseItem({ ...good, cve: '<script>' })).toBeNull();
    expect(parseItem({ ...good, tier_after: 'urgent' })).toBeNull();
    expect(parseItem({ ...good, at: 'yesterday' })).toBeNull();
    expect(parseItem({ ...item({ type: 'catalog_listed', cve: 'CVE-2026-1', via: 'kev' }) })).toBeNull();
  });

  it('hashes catalog ids the way the fast check does', () => {
    // printf 'CVE-2024-0001\nCVE-2025-0002\n' | sha256sum
    expect(idsHash(['cve-2025-0002 ', 'CVE-2024-0001', 'CVE-2024-0001', 'not-a-cve'])).toBe('da8cc54d3b48971b4ea3dfdda933e2a2b5e6d8c5cc643df8c14fa1ec7ed17f1a');
    expect(catalogSnapshot([], null, null)).toBeNull();
    expect(catalogSnapshot(null, null, null)).toBeNull();
    expect(catalogSnapshot(['CVE-2024-0001'], 'v', 'f')).toMatchObject({ count: 1, version: 'v', fetched_at: 'f' });
  });

  it('turns an old CVE that woke up with its first exploit artifact into one event, dated now or backfilled', () => {
    const s = score(makeCve({ id: B, published: '2019-03-01T00:00:00.000Z', inWindow: false }), { metasploit: { [B]: [msf('exploit/b')] } });
    const row = toRow(s);
    const sig = { kind: 'metasploit' as const, at: daysAgo(2), first_seen: true, label: 'first Metasploit module', source: 'metasploit' as const, url: 'https://example.test/m' };
    const old = { ...sig, kind: 'exploitdb' as const, at: dateAgo(9), source: 'exploitdb' as const, label: 'first Exploit-DB entry (EDB-1)' };
    const base = input({ byId: new Map([[B, s]]), rows: new Map([[B, row]]) });
    const woke = { ...base.woke, items: [{ id: B, at: sig.at, signals: [old, sig], row }] };
    const normal = buildEvents({ ...base, woke, previous: [] });
    expect(normal.file.items.map((i) => [i.id, i.at, i.backfill, i.via, i.url])).toEqual([[`metasploit_module:${B}`, T1.toISOString(), false, 'metasploit', 'https://example.test/m']]);
    expect(normal.file.items[0].detail).toBe('Published Mar 1, 2019. First Metasploit module.');
    const first = buildEvents({ ...base, woke, previous: null });
    expect(first.file.items.map((i) => [i.id, i.at, i.backfill])).toEqual([[`metasploit_module:${B}`, daysAgo(2).replace(/\.\d+Z$/, 'Z'), true]]);
    // Seen before (in state): never again.
    expect(buildEvents({ ...base, woke, previous: [], previousState: normal.state }).file.items).toEqual([]);
  });

  it('keeps every urgent event in a full feed, newest first', () => {
    const items = [
      ...Array.from({ length: 30 }, (_, i) => item({ type: 'tier_up', cve: `CVE-2026-${3000 + i}`, at: new Date(T1.getTime() - i * 1000).toISOString() })),
      item({ type: 'kev_added', cve: 'CVE-2026-9999', via: 'kev', at: daysAgo(2) }),
    ].sort(compareEvents);
    const picked = selectFeedEvents(items, 10);
    expect(picked).toHaveLength(10);
    expect(picked[picked.length - 1].cve).toBe('CVE-2026-9999');
    expect(picked).toEqual([...picked].sort(compareEvents));
  });
});
