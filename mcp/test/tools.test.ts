import { describe, expect, it } from 'vitest';
import type { McpNotFound, McpVerdict } from '../../shared/contract';
import { MCP_MSG, VERDICT } from '../../shared/mcp';
import { BASE_POINTS } from '../../shared/model';
import { shardOf } from '../../shared/shard';
import { DataClient, type DataCall } from '../src/data';
import { InputError, getVerdict, kevDue, listSignal, parseUtc, receipts, searchCves, wokeUp } from '../src/tools';
import { CVE, GEN, NOW, fakeFetch, files } from './fixture';

const BASE = 'https://data.test/v1/';

function setup(tree = files()) {
  const f = fakeFetch(tree, [BASE]);
  const dc = new DataClient({ bases: [BASE], fetch: f.fetch, now: () => NOW });
  return { log: f.log, run: <T>(fn: (c: DataCall) => Promise<T>) => dc.run(fn) };
}

const found = (i: McpVerdict | McpNotFound) => {
  if (!i.found) throw new Error(`${i.id} not found`);
  return i;
};

describe('get_verdict', () => {
  it('answers each tier with its verdict, chips, score math and links', async () => {
    const t = setup();
    const r = await t.run((c) => getVerdict(c, { ids: [CVE.exploited.id, CVE.likely.id, CVE.watch.id, CVE.quiet.id] }, NOW));
    const [e, l, w, q] = r.items.map(found);
    expect([e.tier, l.tier, w.tier, q.tier]).toEqual(['exploited', 'likely', 'watch', 'quiet']);
    expect(e.verdict).toBe(VERDICT.exploited);
    expect(q.verdict).toBe('Quiet. No evidence yet. Quiet is not safe.');
    expect(e.kev).toEqual({ date_added: CVE.exploited.kev!.date_added, due_date: CVE.exploited.kev!.due_date, ransomware: 'Known' });
    expect(e.reasons[0]).toEqual({ id: 'chip.0', label: 'chip.0', points: 75, polarity: 'up', url: 'https://example.test/evidence', at: expect.any(String) });
    expect(e.reasons.at(-1)).toEqual({ id: 'epss.cold', label: 'epss.cold', points: 0, polarity: 'unknown' });
    // base + the sum of points is the score for an exploited CVE, and raw for any other.
    const sum = (v: McpVerdict) => v.score_math.base + v.reasons.reduce((s, x) => s + x.points, 0);
    expect(e.score_math.base).toBe(BASE_POINTS);
    expect(sum(e)).toBe(e.score);
    expect(sum(l)).toBe(l.score_math.raw);
    expect(sum(q)).toBe(q.score_math.raw);
    expect(q.score).toBe(0);
    expect(e.links).toEqual({ page: `https://cverdict.dev/cve/${e.id}`, json: `${BASE}cve/${shardOf(e.id)}.json`, cve_org: `https://www.cve.org/CVERecord?id=${e.id}` });
    expect(e.detail).toBeUndefined();
  });

  it('re-tiers at the knob like the site', async () => {
    const t = setup();
    const ids = [CVE.exploited.id, CVE.likely.id, CVE.watch.id, CVE.weaponized.id];
    const at = async (knob: number) => (await t.run((c) => getVerdict(c, { ids, knob }, NOW))).items.map((i) => found(i).tier);
    expect(await at(30)).toEqual(['exploited', 'likely', 'likely', 'likely']);
    expect(await at(50)).toEqual(['exploited', 'likely', 'watch', 'likely']);
    expect(await at(80)).toEqual(['exploited', 'watch', 'watch', 'likely']);
  });

  it('answers unknown and invalid IDs in place, dedupes and normalizes', async () => {
    const t = setup();
    const r = await t.run((c) => getVerdict(c, { ids: [' cve-2026-10001 ', 'CVE-2026-10001', 'CVE-2019-0001', 'not-a-cve', '__proto__'] }, NOW));
    expect(r.items.map((i) => [i.id, i.found])).toEqual([
      ['CVE-2026-10001', true],
      ['CVE-2019-0001', false],
      ['NOT-A-CVE', false],
      ['__PROTO__', false],
    ]);
    expect(r.items[1]).toEqual({ id: 'CVE-2019-0001', found: false, note: MCP_MSG.notFound, links: { cve_org: 'https://www.cve.org/CVERecord?id=CVE-2019-0001' } });
    expect(r.items[2]).toEqual({ id: 'NOT-A-CVE', found: false, note: 'Not a CVE ID. Expected CVE-YYYY-NNNN.', links: null });
    // Only the two valid IDs' shards were fetched.
    expect(t.log.map((l) => l.path).sort()).toEqual(['meta.json', `cve/${shardOf('CVE-2019-0001')}.json`, `cve/${shardOf('CVE-2026-10001')}.json`].sort());
  });

  it('adds the detail only when asked, for at most 5 IDs', async () => {
    const t = setup();
    const one = await t.run((c) => getVerdict(c, { ids: [CVE.quiet.id], detail: true }, NOW));
    const q = found(one.items[0]);
    expect(q.detail?.description).toBe(CVE.quiet.description);
    expect(Object.keys(q.detail!)).toEqual(['description', 'affected', 'cwe', 'ssvc', 'kev', 'epss', 'exploits', 'tags', 'timeline', 'references']);
    // The title falls back to the description, on one line.
    expect(q.title).toBe('Line one. Line two <script>alert(1)</script>');
    const five = Array.from({ length: 5 }, (_, i) => `CVE-2026-${30000 + i}`);
    await expect(t.run((c) => getVerdict(c, { ids: five, detail: true }, NOW))).resolves.toBeTruthy();
    await expect(t.run((c) => getVerdict(c, { ids: [...five, 'CVE-2026-39999'], detail: true }, NOW))).rejects.toThrow('detail: true takes at most 5 IDs; ask again in groups of 5.');
  });

  it('names every file and the age of the data', async () => {
    const t = setup();
    const r = await t.run((c) => getVerdict(c, { ids: [CVE.exploited.id, CVE.old.id] }, NOW));
    expect(r.data.generated_at).toBe(GEN);
    expect(r.data.age_hours).toBe(1);
    expect(r.data.sources_down).toEqual(['epss']);
    expect(r.data.sources_stale).toEqual(['exploitdb']);
    expect(r.data.warning).toBeNull();
    expect(r.data.files.map((f) => f.path).sort()).toEqual(['v1/meta.json', `v1/cve/${shardOf(CVE.exploited.id)}.json`, `v1/cve/${shardOf(CVE.old.id)}.json`].sort());
    expect(r.data.files.every((f) => f.url === `${BASE}${f.path.slice(3)}` && f.generated_at === GEN)).toBe(true);
  });
});

describe('list_signal', () => {
  it('reads signal.json for Exploited and Likely next at a knob of 35 or more, else index.json', async () => {
    const t = setup();
    const file = async (a: Parameters<typeof listSignal>[1]) => {
      const r = await t.run((c) => listSignal(c, a, NOW));
      expect(r.data.files.map((f) => f.path)).toContain(`v1/${r.file}`);
      return r.file;
    };
    expect(await file({})).toBe('signal.json');
    expect(await file({ knob: 35, tiers: ['exploited'] })).toBe('signal.json');
    expect(await file({ knob: 34 })).toBe('index.json');
    expect(await file({ tiers: ['watch'] })).toBe('index.json');
    expect(await file({ tiers: ['quiet', 'likely'] })).toBe('index.json');
  });

  it('filters by tier, vendor, publish date and KEV, highest score first, with paging', async () => {
    const t = setup();
    const ids = async (a: Parameters<typeof listSignal>[1]) => (await t.run((c) => listSignal(c, a, NOW))).items.map((i) => i.id);
    expect(await ids({})).toEqual([CVE.exploited.id, CVE.likely.id, CVE.weaponized.id]);
    expect(await ids({ tiers: ['watch', 'quiet'] })).toEqual([CVE.watch.id, 'CVE-2026-10006', CVE.quiet.id]);
    expect(await ids({ vendor: 'ACME widget' })).toEqual([CVE.exploited.id, CVE.likely.id, CVE.weaponized.id]);
    expect(await ids({ vendor: 'fortinet', tiers: ['quiet'] })).toEqual(['CVE-2026-10006']);
    expect(await ids({ kev_only: true })).toEqual([CVE.exploited.id]);
    expect(await ids({ published_since: CVE.likely.published.slice(0, 10) })).toEqual([CVE.likely.id]);
    const p1 = await t.run((c) => listSignal(c, { limit: 2 }, NOW));
    expect([p1.total, p1.offset, p1.next_offset, p1.items.length]).toEqual([3, 0, 2, 2]);
    const p2 = await t.run((c) => listSignal(c, { limit: 2, offset: 2 }, NOW));
    expect([p2.total, p2.offset, p2.next_offset, p2.items.map((i) => i.id)]).toEqual([3, 2, null, [CVE.weaponized.id]]);
  });

  it('re-tiers rows at the knob', async () => {
    const t = setup();
    const r = await t.run((c) => listSignal(c, { knob: 30 }, NOW));
    expect(r.items.map((i) => [i.id, i.tier])).toEqual([
      [CVE.exploited.id, 'exploited'],
      [CVE.likely.id, 'likely'],
      [CVE.watch.id, 'likely'],
      [CVE.weaponized.id, 'likely'],
    ]);
  });

  it('rejects dates it cannot apply instead of ignoring them', async () => {
    const t = setup();
    for (const bad of ['2026-13-40', '2026-02-30', '2026-10-01T00:00:00+02:00', 'yesterday', '2026-10-01T00:00:00.000Z1234567']) {
      await expect(t.run((c) => listSignal(c, { published_since: bad }, NOW))).rejects.toThrow(InputError);
    }
  });
});

describe('dates', () => {
  it('accepts UTC dates and date-times only', () => {
    expect(parseUtc('2026-10-01')).toBe(Date.parse('2026-10-01T00:00:00Z'));
    expect(parseUtc('2026-10-01T00:00Z')).toBe(Date.parse('2026-10-01T00:00:00Z'));
    expect(parseUtc('2026-10-01T00:00:00.000Z')).toBe(Date.parse('2026-10-01T00:00:00Z'));
    for (const bad of ['2026-13-40', '2026-02-30', '2026-10-01T24:00Z', '2026-10-01T00:00:00+02:00', 'yesterday', '2026-10-01T00:00:00.000000Z', 'x'.repeat(31)]) expect(parseUtc(bad)).toBeNaN();
  });
});

describe('kev_due', () => {
  it('counts UTC calendar days, edges inclusive', async () => {
    const t = setup();
    const r = await t.run((c) => kevDue(c, {}, NOW));
    expect(r.today_utc).toBe('2026-11-03');
    expect([r.from, r.to]).toEqual(['2026-10-27', '2026-11-10']);
    expect(r.items.map((i) => [i.id, i.days_left])).toEqual([
      ['CVE-2026-0014', -7],
      ['CVE-2026-0011', -1],
      ['CVE-2026-0010', 0],
      ['CVE-2026-0012', 7],
    ]);
    expect(r.items[0].name).toBe('Acme Widget flaw');
    expect(r.items[0].required_action).toBe('Apply mitigations.');
    const wide = await t.run((c) => kevDue(c, { within_days: 60, overdue_days: 14 }, NOW));
    expect(wide.items.map((i) => i.days_left)).toEqual([-8, -7, -1, 0, 7, 8, 60]);
    const none = await t.run((c) => kevDue(c, { within_days: 0, overdue_days: 0 }, NOW));
    expect(none.items.map((i) => i.id)).toEqual(['CVE-2026-0010']);
  });

  it('pages at 50, so a large CISA batch stays within the answer budget', async () => {
    const tree = files();
    const kev = tree.get('kev.json') as { entries: { id: string; due_date: string }[] };
    const one = kev.entries[0];
    tree.set('kev.json', { ...kev, entries: Array.from({ length: 120 }, (_, i) => ({ ...one, id: `CVE-2026-${20000 + i}`, due_date: '2026-11-05' })) });
    const t = setup(tree);
    const first = await t.run((c) => kevDue(c, {}, NOW));
    expect([first.total, first.offset, first.next_offset, first.items.length]).toEqual([120, 0, 50, 50]);
    const last = await t.run((c) => kevDue(c, { offset: 100, limit: 50 }, NOW));
    expect([last.total, last.next_offset, last.items.length, last.items[0].id]).toEqual([120, null, 20, 'CVE-2026-20100']);
  });

  it('moves with the UTC day at midnight, not with the hour', async () => {
    const t = setup();
    const late = await t.run((c) => kevDue(c, { within_days: 0, overdue_days: 0 }, Date.parse('2026-11-03T23:59:59Z')));
    const next = await t.run((c) => kevDue(c, { within_days: 0, overdue_days: 1 }, Date.parse('2026-11-04T00:00:00Z')));
    expect(late.items.map((i) => [i.id, i.days_left])).toEqual([['CVE-2026-0010', 0]]);
    expect(next.items.map((i) => [i.id, i.days_left])).toEqual([['CVE-2026-0010', -1]]);
  });
});

describe('woke_up', () => {
  it('defaults to 7 days before the data was generated, comparing date-only signals by day', async () => {
    const t = setup();
    const r = await t.run((c) => wokeUp(c, {}, NOW));
    expect(r.since).toBe('2026-10-27T06:50:00.000Z');
    expect(r.items.map((i) => i.id)).toEqual(['CVE-2021-44228', 'CVE-2020-0002', 'CVE-2020-0004']);
    expect(r.items[0]).toMatchObject({ id: 'CVE-2021-44228', tier: 'exploited', woke_at: '2026-11-01', signals: [{ kind: 'kev', label: 'added to CISA KEV' }] });
    expect(r.tracking.nuclei).toBeNull();
    expect(r.skipped).toEqual([{ kind: 'nuclei', reason: 'not tracked yet' }]);
  });

  it('takes a since date and kinds, and pages', async () => {
    const t = setup();
    const ids = async (a: Parameters<typeof wokeUp>[1]) => (await t.run((c) => wokeUp(c, a, NOW))).items.map((i) => i.id);
    expect(await ids({ since: '2026-10-01' })).toEqual(['CVE-2021-44228', 'CVE-2020-0002', 'CVE-2020-0003', 'CVE-2020-0004', 'CVE-2020-0005']);
    expect(await ids({ since: '2026-10-27T06:49Z' })).toEqual(['CVE-2021-44228', 'CVE-2020-0002', 'CVE-2020-0003', 'CVE-2020-0004']);
    expect(await ids({ since: '2026-10-01', kinds: ['kev'] })).toEqual(['CVE-2021-44228', 'CVE-2020-0005']);
    const p = await t.run((c) => wokeUp(c, { since: '2026-10-01', limit: 2, offset: 2 }, NOW));
    expect([p.total, p.next_offset, p.items.length]).toEqual([5, 4, 2]);
    await expect(t.run((c) => wokeUp(c, { since: 'last week' }, NOW))).rejects.toThrow('since must be a UTC date');
  });

  it('says so when woke.json is not published', async () => {
    const tree = files();
    tree.delete('woke.json');
    const t = setup(tree);
    await expect(t.run((c) => wokeUp(c, {}, NOW))).rejects.toThrow(MCP_MSG.notPublished('woke.json'));
  });
});

describe('receipts', () => {
  it('summarises without the per-CVE lists', async () => {
    const t = setup();
    const r = await t.run((c) => receipts(c, {}, NOW));
    expect(r.page).toBe('https://cverdict.dev/receipts');
    expect(Object.keys(r.forward).sort()).toEqual(['eligible', 'gap_total', 'last', 'listed', 'methods', 'runs', 'since', 'volume', 'watch_days']);
    expect(r.backtest).toMatchObject({ hindsight: true, listed: 2, excluded: [{ code: 'not_public', n: 2 }], epss_missing: 1, sources_down: [] });
    expect(JSON.stringify(r)).not.toContain('"items"');
    expect(r.cve).toBeUndefined();
  });

  it('finds one CVE in the forward items, the uncounted listings and the backtest', async () => {
    const t = setup();
    const fwd = await t.run((c) => receipts(c, { id: 'cve-2026-10001' }, NOW));
    expect(fwd.cve).toMatchObject({ id: 'CVE-2026-10001', forward: { kev_added: '2026-10-31', flags: { cverdict: { outcome: 'earlier' } }, row: { id: 'CVE-2026-10001', tier: 'exploited', vendor: 'Acme' } }, backtest: null });
    const unc = await t.run((c) => receipts(c, { id: 'CVE-2020-0005' }, NOW));
    expect(unc.cve?.forward).toEqual({ id: 'CVE-2020-0005', kev_added: '2026-10-14', reason: 'older' });
    const bt = await t.run((c) => receipts(c, { id: 'CVE-2021-44228' }, NOW));
    expect(bt.cve).toMatchObject({ forward: null, backtest: { strict: { cverdict: true }, row: { tier: 'exploited' } } });
    await expect(t.run((c) => receipts(c, { id: 'log4shell' }, NOW))).rejects.toThrow(MCP_MSG.notCveId);
  });
});

describe('search_cves', () => {
  it('needs every word, ignores case, ranks by score and pages', async () => {
    const t = setup();
    const ids = async (a: Parameters<typeof searchCves>[1]) => (await t.run((c) => searchCves(c, a, NOW))).items.map((i) => i.id);
    expect(await ids({ query: 'acme widget' })).toEqual([CVE.exploited.id, CVE.likely.id, CVE.watch.id, CVE.weaponized.id, CVE.quiet.id]);
    expect(await ids({ query: 'FORTINET heap' })).toEqual(['CVE-2026-10006']);
    expect(await ids({ query: 'fortinet widget' })).toEqual([]);
    expect(await ids({ query: 'cve-2026-10002' })).toEqual([CVE.likely.id]);
    expect(await ids({ query: 'acme', tiers: ['watch'] })).toEqual([CVE.watch.id]);
    expect(await ids({ query: 'acme', tiers: ['likely'], knob: 30 })).toEqual([CVE.likely.id, CVE.watch.id, CVE.weaponized.id]);
    const r = await t.run((c) => searchCves(c, { query: 'acme', limit: 2, offset: 4 }, NOW));
    expect([r.total, r.offset, r.next_offset, r.items.length]).toEqual([5, 4, null, 1]);
    expect(r.scope).toBe('CVEs published in the 30-day window (index.json), matched on ID, CNA, vendor, product and title. For older CVEs, use get_verdict.');
  });

  it('matches regular expression characters literally and puts titles on one line', async () => {
    const t = setup();
    const r = await t.run((c) => searchCves(c, { query: '(a.b+c)' }, NOW));
    expect(r.items.map((i) => [i.id, i.title])).toEqual([['CVE-2026-10006', 'Fortinet FortiGate heap overflow (a.b+c)']]);
    expect((await t.run((c) => searchCves(c, { query: '.*' }, NOW))).total).toBe(0);
  });

  it('cuts a row title to 160 characters, as the pipeline does, when a mirror sends a longer one', async () => {
    const tree = files();
    const index = tree.get('index.json') as { cols: string[]; rows: unknown[][] };
    const t = index.cols.indexOf('t');
    tree.set('index.json', { ...index, rows: index.rows.map((r) => r.map((v, i) => (i === t ? `${String(v)} ${'x'.repeat(100_000)}` : v))) });
    const r = await setup(tree).run((c) => searchCves(c, { query: 'acme', limit: 50 }, NOW));
    expect(r.items.length).toBe(5);
    expect(r.items.every((i) => i.title.length === 160 && i.title.endsWith('…'))).toBe(true);
  });

  it('takes at most 8 words', async () => {
    const t = setup();
    await expect(t.run((c) => searchCves(c, { query: 'a b c d e f g h' }, NOW))).resolves.toBeTruthy();
    await expect(t.run((c) => searchCves(c, { query: 'a b c d e f g h i' }, NOW))).rejects.toThrow('query takes at most 8 words.');
  });
});
