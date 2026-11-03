/**
 * Atom 1.0 feeds (RFC 4287). CVE text is attacker-controlled: everything goes through
 * escapeXml(), and only `type="text"` constructs are used, so no markup ever comes from data.
 */
import { BRAND, REPO_URL } from '../../../shared/brand';
import type { CveDetail, KevEntry, Reason, Tier, WokeFile } from '../../../shared/contract';
import { topChipIds } from '../rows';
import { dayLabel } from '../score';
import { KEV_RECENT_DAYS, PATHS, daysAgo } from './json';
import { parseIsoDate } from '../util/dates';

const SIGNAL_FEED_MAX = 100;
const WOKE_FEED_MAX = 100;
/** Fixed date for tag: URIs (RFC 4151), so entry ids never change. */
const TAG_DATE = '2026';
const TIER_LABEL: Record<Tier, string> = { exploited: 'Exploited', likely: 'Likely next', watch: 'Watch', quiet: 'Quiet' };

export interface FeedOptions {
  /** Public site origin (+ base path), no trailing slash. */
  siteUrl: string;
  now: Date;
}

/** Characters not allowed in XML 1.0 documents (incl. lone surrogates). */
const XML_INVALID = /[^\t\n\r -퟿-�\u{10000}-\u{10FFFF}]/gu;
const XML_ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' };

/** Escape text for XML element content and attribute values; drops characters XML cannot carry. */
export function escapeXml(text: string): string {
  return text
    .replace(/\r\n?/g, '\n')
    .replace(XML_INVALID, '')
    .replace(/[&<>"']/g, (ch) => XML_ESCAPES[ch]);
}

/** Single-line text (titles): whitespace runs, including newlines, become one space. */
function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
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

export const cveUrl = (siteUrl: string, id: string) => `${siteUrl}/cve/${encodeURIComponent(id)}`;

function tagUri(siteUrl: string, specific: string): string {
  return `tag:${new URL(siteUrl).host},${TAG_DATE}:${BRAND.slug}/${specific}`;
}

interface AtomEntry {
  id: string;
  title: string;
  link: string;
  related?: string;
  updated: string;
  published: string;
  summary: string;
  content?: string;
  categories: string[];
}

interface AtomFeed {
  id: string;
  title: string;
  subtitle: string;
  self: string;
  alternate: string;
  updated: string;
  entries: AtomEntry[];
}

function renderEntry(e: AtomEntry): string {
  const lines = [
    '<entry>',
    `<id>${escapeXml(e.id)}</id>`,
    `<title type="text">${escapeXml(oneLine(e.title))}</title>`,
    `<link rel="alternate" type="text/html" href="${escapeXml(e.link)}"/>`,
    ...(e.related ? [`<link rel="related" href="${escapeXml(e.related)}"/>`] : []),
    `<updated>${e.updated}</updated>`,
    `<published>${e.published}</published>`,
    ...e.categories.map((c) => `<category term="${escapeXml(oneLine(c))}"/>`),
    `<summary type="text">${escapeXml(e.summary)}</summary>`,
    ...(e.content ? [`<content type="text">${escapeXml(e.content)}</content>`] : []),
    '</entry>',
  ];
  return lines.join('\n');
}

function renderFeed(f: AtomFeed): string {
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<feed xmlns="http://www.w3.org/2005/Atom">',
    `<id>${escapeXml(f.id)}</id>`,
    `<title type="text">${escapeXml(f.title)}</title>`,
    `<subtitle type="text">${escapeXml(f.subtitle)}</subtitle>`,
    `<link rel="self" type="application/atom+xml" href="${escapeXml(f.self)}"/>`,
    `<link rel="alternate" type="text/html" href="${escapeXml(f.alternate)}"/>`,
    `<updated>${f.updated}</updated>`,
    `<author><name>${escapeXml(BRAND.name)}</name><uri>${escapeXml(REPO_URL)}</uri></author>`,
    `<generator uri="${escapeXml(REPO_URL)}">${escapeXml(`${BRAND.slug}-pipeline`)}</generator>`,
    ...f.entries.map(renderEntry),
    '</feed>',
    '',
  ].join('\n');
}

/** Latest entry time, so the feed's <updated> only moves when its content does. */
function latest(entries: AtomEntry[], fallback: string): string {
  return entries.reduce((max, e) => (e.updated > max ? e.updated : max), entries.length ? '' : fallback);
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
        id: tagUri(siteUrl, `signal/${d.id}/${d.score.tier}`),
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
    id: `${siteUrl}/${PATHS.signalFeed}`,
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
        id: tagUri(siteUrl, `kev/${k.id}`),
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
    id: `${siteUrl}/${PATHS.kevFeed}`,
    title: `${BRAND.name} · CISA KEV additions`,
    subtitle: `CISA Known Exploited Vulnerabilities added in the last ${KEV_RECENT_DAYS} days.`,
    self: `${siteUrl}/${PATHS.kevFeed}`,
    alternate: `${siteUrl}/kev`,
    updated: latest(entries, now.toISOString()),
    entries,
  });
}

/** The newest 100 old CVEs that woke up, newest wake first (from woke.json). */
export function wokeFeed(woke: WokeFile, opts: FeedOptions): string {
  const { siteUrl, now } = opts;
  const entries = woke.items.slice(0, WOKE_FEED_MAX).map((it): AtomEntry => {
    const r = it.row;
    const product = oneLine(`${r.v} ${r.p}`);
    const newest = it.signals[it.signals.length - 1];
    const tier = TIER_LABEL[r.tier];
    const lines = it.signals.map((sig) => `${dayLabel(sig.at, now)}: ${sig.label}${sig.first_seen ? ' (the day we first saw it)' : ''}.`);
    return {
      // One entry per CVE: a later signal updates it instead of adding a duplicate.
      id: tagUri(siteUrl, `woke/${it.id}`),
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
    id: `${siteUrl}/${PATHS.wokeFeed}`,
    title: `${BRAND.name} · old CVEs that woke up`,
    subtitle: `CVEs published before the last ${woke.days} days that gained exploitation evidence in that time.`,
    self: `${siteUrl}/${PATHS.wokeFeed}`,
    alternate: `${siteUrl}/woke`,
    updated: latest(entries, now.toISOString()),
    entries,
  });
}
