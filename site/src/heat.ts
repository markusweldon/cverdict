/**
 * Heating up (Today): the few CVEs with the most new exploitation evidence in the last 7 days, from events.json.
 * Ranked by evidence only, never by how much a CVE is talked about, and no nicknames.
 */
import type { EventItem, EventsFile, EventType, Tier } from '../../shared/contract';

/**
 * Points per event: exploitation reports weigh most, then working exploit code, then the tier moving up. The fast
 * lane is a stand-in for an exploit sign on very new CVEs, not evidence of attacks, so it adds nothing here.
 */
export const HEAT_POINTS: Readonly<Record<EventType, number>> = {
  kev_added: 5,
  catalog_listed: 4,
  vendor_exploited: 4,
  metasploit_module: 3,
  exploitdb_entry: 2,
  nuclei_template: 2,
  tier_up: 1,
  fast_lane: 0,
};

/** Evidence loses half its weight every this many days, so this week's news outranks last week's. */
export const HEAT_HALF_LIFE_DAYS = 3;
export const HEAT_DAYS = 7;
export const HEAT_MAX = 4;

/** What happened, as the cards say it, most important first. */
export const HEAT_LABEL: Readonly<Record<EventType, string>> = {
  kev_added: 'CISA KEV',
  catalog_listed: 'Listed exploited',
  vendor_exploited: 'Vendor: exploited',
  metasploit_module: 'Metasploit',
  exploitdb_entry: 'Exploit-DB',
  nuclei_template: 'Nuclei',
  tier_up: 'Tier up',
  fast_lane: 'Fast lane',
};

export interface HeatCard {
  cve: string;
  vendor: string;
  product: string;
  /** Tier and score after the newest event. */
  tier: Tier;
  score: number;
  heat: number;
  /** Distinct event types, highest points first. */
  what: EventType[];
  /** Newest event time (ISO). */
  latest: string;
  /** Other heated CVEs of the same vendor, hottest first (shown as "+N more"). */
  more: string[];
  /**
   * The evidence behind the heat, for the card's 7-day strip: each event with points, by day
   * (0 is HEAT_DAYS - 1 days ago, HEAT_DAYS - 1 is the last 24 hours), the card's other CVEs included.
   */
  timeline: { day: number; type: EventType }[];
}

/** One card per vendor: three Danfoss controllers listed on the same day are one story. Case and spacing do not matter. */
const vendorKey = (c: Pick<HeatCard, 'vendor' | 'product' | 'cve'>) => (c.vendor || c.product || c.cve).toLowerCase().replace(/\s+/g, ' ').trim();

const DAY_MS = 86_400_000;
const ORDER = (Object.keys(HEAT_POINTS) as EventType[]).sort((a, b) => HEAT_POINTS[b] - HEAT_POINTS[a]);

/**
 * The top HEAT_MAX CVEs by decayed evidence points over the HEAT_DAYS before the file's generated_at, among those
 * Exploited or Likely next now. Ties go to the newest evidence, then the CVE ID. Events from the future (clock skew)
 * count as new; a CVE with nothing but zero-point events is left out.
 */
export function heatingUp(file: Pick<EventsFile, 'generated_at' | 'items'> | null | undefined, max = HEAT_MAX): HeatCard[] {
  if (!file) return [];
  const now = Date.parse(file.generated_at);
  if (!Number.isFinite(now)) return [];
  const by = new Map<string, { items: EventItem[]; heat: number }>();
  for (const it of file.items) {
    const at = Date.parse(it.at);
    if (!Number.isFinite(at) || at < now - HEAT_DAYS * DAY_MS) continue;
    const age = Math.max(0, now - at) / DAY_MS;
    const g = by.get(it.cve) ?? { items: [], heat: 0 };
    g.items.push(it);
    g.heat += (HEAT_POINTS[it.type] ?? 0) * 0.5 ** (age / HEAT_HALF_LIFE_DAYS);
    by.set(it.cve, g);
  }
  const cards: HeatCard[] = [];
  for (const [cve, { items, heat }] of by) {
    const newest = items.reduce((a, b) => (Date.parse(b.at) > Date.parse(a.at) ? b : a));
    if (heat <= 0 || (newest.tier_after !== 'exploited' && newest.tier_after !== 'likely')) continue;
    const types = new Set(items.map((i) => i.type));
    const timeline = items
      .filter((i) => (HEAT_POINTS[i.type] ?? 0) > 0)
      .map((i) => ({ day: Math.max(0, HEAT_DAYS - 1 - Math.floor(Math.max(0, now - Date.parse(i.at)) / DAY_MS)), type: i.type }));
    cards.push({
      cve,
      vendor: newest.vendor,
      product: newest.product,
      tier: newest.tier_after,
      score: newest.score,
      heat,
      what: ORDER.filter((t) => types.has(t) && HEAT_POINTS[t] > 0),
      latest: newest.at,
      more: [],
      timeline,
    });
  }
  cards.sort((a, b) => b.heat - a.heat || Date.parse(b.latest) - Date.parse(a.latest) || a.cve.localeCompare(b.cve));
  const lead = new Map<string, HeatCard>();
  const out: HeatCard[] = [];
  for (const c of cards) {
    const key = vendorKey(c);
    const first = lead.get(key);
    if (first) {
      first.more.push(c.cve);
      first.timeline.push(...c.timeline);
    } else {
      lead.set(key, c);
      out.push(c);
    }
  }
  const byWeight = (a: { day: number; type: EventType }, b: { day: number; type: EventType }) => a.day - b.day || HEAT_POINTS[b.type] - HEAT_POINTS[a.type];
  return out.slice(0, max).map((c) => ({ ...c, timeline: c.timeline.sort(byWeight) }));
}
