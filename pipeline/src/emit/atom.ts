/**
 * Atom 1.0 feeds (RFC 4287). Rendering lives in shared/atom.ts (also used by api/feed.ts); CVE
 * text is attacker-controlled, so everything goes through escapeXml() and only `type="text"`
 * constructs are used.
 */
import { BRAND } from '../../../shared/brand';
import { cveUrl, eventsFeed as renderEventsFeed, latestUpdated as latest, oneLine, renderFeed, selectFeedEvents, tagUri, TIER_LABEL, type AtomEntry } from '../../../shared/atom';
import type { CveDetail, EventsFile, KevEntry, Reason, WokeFile } from '../../../shared/contract';
import { topChipIds } from '../rows';
import { dayLabel } from '../score';
import { KEV_RECENT_DAYS, PATHS, daysAgo } from './json';
import { parseIsoDate } from '../util/dates';

export { cveUrl, escapeXml } from '../../../shared/atom';

const SIGNAL_FEED_MAX = 100;
const WOKE_FEED_MAX = 100;
/** feeds/events.xml carries at most this many events. */
export const EVENTS_FEED_MAX = 200;

export interface FeedOptions {
  /** Public site origin (+ base path), no trailing slash. */
  siteUrl: string;
  /** Origin for the feed and entry IDs (BRAND.feedIdBase), so they survive a move of siteUrl. Default: siteUrl. */
  idBase?: string;
  now: Date;
}

/** Epoch ms of YYYY-MM-DD (UTC midnight) or an ISO date-time; NaN when unparseable. */
function toTime(date: string): number {
  return parseIsoDate(date)?.getTime() ?? NaN;
}

/** RFC 3339 timestamp of `date`, or of `fallback` when `date` is unparseable. */
function rfc3339(date: string, fallback: Date): string {
  const t = toTime(date);
  return new Date(Number.isNaN(t) ? fallback.getTime() : t).toISOString();
}

/**
 * Chips whose `at` dates a change of state: counting exploitation or exploit evidence (KEV
 * dateAdded, SSVC "active"/"poc", first vetted PoC, Exploit-DB). EPSS chips are dated by the
 * latest daily score, which moves every day, and the SSVC family by CISA's latest re-assessment.
 */
const isTransition = (r: Reason) => r.points > 0 && (r.family === 'E' || r.family === 'X') && r.source !== 'epss';

/** When a CVE reached its current state: the newest transition date, or publication. */
function signalUpdated(d: CveDetail, now: Date): string {
  let t = toTime(d.published);
  if (Number.isNaN(t)) t = now.getTime();
  for (const r of d.reasons) {
    const at = isTransition(r) && r.at ? toTime(r.at) : NaN;
    if (at > t && at <= now.getTime()) t = at;
  }
  return new Date(t).toISOString();
}

/** Newest 100 exploited/likely CVEs from the window. `details` should be window records only. */
export function signalFeed(details: readonly CveDetail[], opts: FeedOptions): string {
  const { siteUrl, now } = opts;
  const idBase = opts.idBase ?? siteUrl;
  const entries = details
    .filter((d) => d.score.tier === 'exploited' || d.score.tier === 'likely')
    .map((d) => ({ d, updated: signalUpdated(d, now) }))
    .sort((a, b) => b.updated.localeCompare(a.updated) || b.d.score.value - a.d.score.value || a.d.id.localeCompare(b.d.id))
    .slice(0, SIGNAL_FEED_MAX)
    .map(({ d, updated }): AtomEntry => {
      const first = d.affected[0];
      const product = first ? oneLine(`${first.vendor} ${first.product}`) : '';
      const tier = TIER_LABEL[d.score.tier];
      const labels = topChipIds(d.reasons).map((id) => d.reasons.find((r) => r.id === id)!.label);
      return {
        id: tagUri(idBase, `signal/${d.id}/${d.score.tier}`),
        title: [d.id, product, tier].filter(Boolean).join(' · '),
        link: cveUrl(siteUrl, d.id),
        updated,
        published: rfc3339(d.published, now),
        summary: `${tier} · score ${d.score.value}/100. ${labels.join('; ')}`,
        content: d.title ? `${d.title}\n\n${d.description}` : d.description,
        categories: [d.score.tier, d.cna].filter(Boolean),
      };
    });
  return renderFeed({
    id: `${idBase}/${PATHS.signalFeed}`,
    title: `${BRAND.name} · exploited and likely-next CVEs`,
    subtitle: BRAND.tagline,
    self: `${siteUrl}/${PATHS.signalFeed}`,
    alternate: `${siteUrl}/`,
    updated: latest(entries, now.toISOString()),
    entries,
  });
}

/** CISA KEV additions from the last 30 days, newest first. */
export function kevFeed(kev: readonly KevEntry[], opts: FeedOptions): string {
  const { siteUrl, now } = opts;
  const idBase = opts.idBase ?? siteUrl;
  const since = daysAgo(now, KEV_RECENT_DAYS);
  const entries = kev
    .filter((k) => k.date_added >= since)
    .sort((a, b) => b.date_added.localeCompare(a.date_added) || a.id.localeCompare(b.id))
    .map((k): AtomEntry => {
      const facts = [
        `Added ${dayLabel(k.date_added, now)}, due ${dayLabel(k.due_date, now)}.`,
        `Known ransomware use: ${k.ransomware}.`,
        ...(k.forensic_triage ? ['Forensic triage requested (BOD 26-04).'] : []),
        ...(k.score !== null ? [`${BRAND.name} score ${k.score}/100.`] : []),
      ];
      return {
        id: tagUri(idBase, `kev/${k.id}`),
        title: `${k.id} · ${k.vendor} ${k.product} · due ${dayLabel(k.due_date, now)}`,
        link: cveUrl(siteUrl, k.id),
        related: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(k.id)}`,
        updated: rfc3339(k.date_added, now),
        published: rfc3339(k.date_added, now),
        summary: `${k.name}. ${facts.join(' ')}`,
        content: `${k.description}\n\nRequired action: ${k.required_action}`,
        categories: ['kev', ...(k.ransomware.toLowerCase() === 'known' ? ['ransomware'] : [])],
      };
    });
  return renderFeed({
    id: `${idBase}/${PATHS.kevFeed}`,
    title: `${BRAND.name} · CISA KEV additions`,
    subtitle: `CISA Known Exploited Vulnerabilities added in the last ${KEV_RECENT_DAYS} days.`,
    self: `${siteUrl}/${PATHS.kevFeed}`,
    alternate: `${siteUrl}/kev`,
    updated: latest(entries, now.toISOString()),
    entries,
  });
}

type WokeItem = WokeFile['items'][number];
/** KEV and catalog listings and Exploit-DB entries always make the feed, and come first when it is full. */
const isPriorityWake = (it: WokeItem) => it.signals.some((s) => s.kind === 'kev' || s.kind === 'catalog' || s.kind === 'exploitdb');
/**
 * A wake that only comes from a PoC repo (unverified code, mostly unstarred) is in the feed only
 * when CVErdict rates the CVE Likely next or Exploited: otherwise it is noise for a subscriber.
 */
export function inWokeFeed(it: WokeItem): boolean {
  if (it.signals.some((s) => s.kind !== 'poc')) return true;
  return it.row.tier === 'exploited' || it.row.tier === 'likely';
}

/**
 * Up to 100 old CVEs that woke up, newest wake first (from woke.json): every KEV, catalog and
 * Exploit-DB wake first, then the newest of the rest. PoC-only wakes need Likely next or Exploited.
 */
export function wokeFeedItems(woke: WokeFile): WokeItem[] {
  const shown = woke.items.filter(inWokeFeed);
  const keep = new Set([...shown.filter(isPriorityWake), ...shown.filter((it) => !isPriorityWake(it))].slice(0, WOKE_FEED_MAX));
  return shown.filter((it) => keep.has(it));
}

export function wokeFeed(woke: WokeFile, opts: FeedOptions): string {
  const { siteUrl, now } = opts;
  const idBase = opts.idBase ?? siteUrl;
  const entries = wokeFeedItems(woke).map((it): AtomEntry => {
    const r = it.row;
    const product = oneLine(`${r.v} ${r.p}`);
    const newest = it.signals[it.signals.length - 1];
    const tier = TIER_LABEL[r.tier];
    const lines = it.signals.map((sig) => `${dayLabel(sig.at, now)}: ${sig.label}${sig.first_seen ? ' (the day we first saw it)' : ''}.`);
    return {
      // One entry per CVE: a later signal updates it instead of adding a duplicate.
      id: tagUri(idBase, `woke/${it.id}`),
      title: [it.id, product, `woke up: ${newest.label}`].filter(Boolean).join(' · '),
      link: cveUrl(siteUrl, it.id),
      ...(newest.url ? { related: newest.url } : {}),
      updated: rfc3339(it.at, now),
      published: rfc3339(it.signals[0].at, now),
      summary: `Published ${dayLabel(r.pub, now)}. ${lines.join(' ')} ${tier} · score ${r.s}/100.`,
      content: r.t,
      categories: ['woke', ...new Set(it.signals.map((sig) => sig.kind)), r.tier],
    };
  });
  return renderFeed({
    id: `${idBase}/${PATHS.wokeFeed}`,
    title: `${BRAND.name} · old CVEs that woke up`,
    subtitle: `CVEs published before the last ${woke.days} days that gained exploitation evidence in that time. Up to ${WOKE_FEED_MAX}: every CISA KEV, EU KEV and CIRCL listing and Exploit-DB entry, and a PoC repo alone only when rated Likely next or Exploited.`,
    self: `${siteUrl}/${PATHS.wokeFeed}`,
    alternate: `${siteUrl}/woke`,
    updated: latest(entries, now.toISOString()),
    entries,
  });
}

/**
 * feeds/events.xml: up to EVENTS_FEED_MAX verdict events from events.json, newest first. When
 * there are more, every KEV and catalog listing, vendor report, move into Exploited and Metasploit
 * module is kept first (shared/atom.ts selectFeedEvents).
 */
export function eventsFeed(events: EventsFile, opts: FeedOptions): string {
  const { siteUrl, now } = opts;
  const items = selectFeedEvents(events.items, EVENTS_FEED_MAX);
  return renderEventsFeed({
    siteUrl,
    idBase: opts.idBase ?? siteUrl,
    path: PATHS.eventsFeed,
    title: `${BRAND.name} · verdict events`,
    subtitle: `Why verdicts moved in the last ${events.days} days: CISA KEV and catalog listings, vendor reports, moves into Likely next or Exploited, the fast lane, and new exploit modules and templates. Up to ${EVENTS_FEED_MAX}, newest first.`,
    alternate: '',
    fallbackUpdated: now.toISOString(),
    items,
  });
}
