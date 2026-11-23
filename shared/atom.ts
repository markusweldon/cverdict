/**
 * Atom 1.0 rendering (RFC 4287) shared by the pipeline's feeds and the per-vendor feed function
 * (api/feed.ts), so both produce byte-identical entries. CVE text is attacker-controlled:
 * everything goes through escapeXml(), and only `type="text"` constructs are used, so no markup
 * ever comes from data.
 *
 * Pure, no DOM or Node APIs. Imports carry `.js` extensions because api/feed.ts runs this as plain
 * Node ESM.
 */
import { BRAND, REPO_URL } from './brand.js';
import type { EventItem, EventType, Tier } from './contract.js';

/** Fixed date for tag: URIs (RFC 4151), so entry ids never change. */
const TAG_DATE = '2026';
export const TIER_LABEL: Record<Tier, string> = { exploited: 'Exploited', likely: 'Likely next', watch: 'Watch', quiet: 'Quiet' };

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
export function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

export const cveUrl = (siteUrl: string, id: string) => `${siteUrl}/cve/${encodeURIComponent(id)}`;

export function tagUri(base: string, specific: string): string {
  return `tag:${new URL(base).host},${TAG_DATE}:${BRAND.slug}/${specific}`;
}

export interface AtomEntry {
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

export interface AtomFeed {
  id: string;
  title: string;
  subtitle: string;
  self: string;
  alternate: string;
  updated: string;
  entries: AtomEntry[];
}

export function renderEntry(e: AtomEntry): string {
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

export function renderFeed(f: AtomFeed): string {
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
export function latestUpdated(entries: readonly AtomEntry[], fallback: string): string {
  return entries.reduce((max, e) => (e.updated > max ? e.updated : max), entries.length ? '' : fallback);
}

// ── Verdict events (v1/events.json, feeds/events.xml, /feeds/v/<slug>.xml) ──────────────────

/** Event classes, most urgent first. A tier move into Exploited outranks one into Likely next. */
export const EVENT_PRIORITY: readonly string[] = [
  'kev_added',
  'catalog_listed',
  'vendor_exploited',
  'tier_up:exploited',
  'metasploit_module',
  'fast_lane',
  'nuclei_template',
  'exploitdb_entry',
  'tier_up:likely',
];
/** The first this many classes always make a full feed (kept before the newest of the rest). */
export const EVENT_PRIORITY_KEEP = 5;

/** Rank of an event in EVENT_PRIORITY (lower is more urgent). */
export function eventRank(item: Pick<EventItem, 'type' | 'tier_after'>): number {
  const i = EVENT_PRIORITY.indexOf(item.type === 'tier_up' ? `tier_up:${item.tier_after}` : item.type);
  return i === -1 ? EVENT_PRIORITY.length : i;
}

/** events.json order: newest `at` first, then priority, then CVE, then id. */
export function compareEvents(a: EventItem, b: EventItem): number {
  return b.at.localeCompare(a.at) || eventRank(a) - eventRank(b) || a.cve.localeCompare(b.cve) || a.id.localeCompare(b.id);
}

/**
 * At most `max` items of a newest-first list for a feed: every item of the first
 * EVENT_PRIORITY_KEEP classes first, then the newest of the rest. The result stays newest first.
 */
export function selectFeedEvents(items: readonly EventItem[], max: number): EventItem[] {
  const urgent = (it: EventItem) => eventRank(it) < EVENT_PRIORITY_KEEP;
  const keep = new Set([...items.filter(urgent), ...items.filter((it) => !urgent(it))].slice(0, max));
  return items.filter((it) => keep.has(it));
}

export const EVENT_LABEL: Record<EventType, string> = {
  kev_added: 'Added to CISA KEV',
  catalog_listed: 'Listed as exploited',
  vendor_exploited: 'Vendor reports exploitation',
  tier_up: 'Tier moved up',
  fast_lane: 'Fast lane',
  metasploit_module: 'Metasploit module',
  nuclei_template: 'Nuclei template',
  exploitdb_entry: 'Exploit-DB entry',
};

/** "Tier: Likely next → Exploited · score 92/100." */
export function tierLine(item: Pick<EventItem, 'tier_before' | 'tier_after' | 'score'>): string {
  const after = TIER_LABEL[item.tier_after];
  const move = item.tier_before && item.tier_before !== item.tier_after ? `${TIER_LABEL[item.tier_before]} → ${after}` : after;
  return `Tier: ${move} · score ${item.score}/100.`;
}

export interface EventFeedOptions {
  /** Public site origin (+ base path) for links, no trailing slash. */
  siteUrl: string;
  /** Origin for feed and entry ids (BRAND.feedIdBase), so they survive a move of siteUrl. */
  idBase: string;
}

export function eventEntry(item: EventItem, opts: EventFeedOptions): AtomEntry {
  return {
    id: tagUri(opts.idBase, `event/${item.id}`),
    title: item.title,
    link: cveUrl(opts.siteUrl, item.cve),
    ...(item.url ? { related: item.url } : {}),
    updated: item.at,
    published: item.at,
    summary: `${item.detail} ${tierLine(item)}`,
    categories: [item.type, item.tier_after],
  };
}

export interface EventsFeedInput extends EventFeedOptions {
  /** Feed id path under idBase, and self path under siteUrl, e.g. "feeds/events.xml". */
  path: string;
  title: string;
  subtitle: string;
  /** Path of the alternate (HTML) page under siteUrl, "" for the home page. */
  alternate: string;
  /** <updated> when there are no entries (the data's generated_at). */
  fallbackUpdated: string;
  items: readonly EventItem[];
}

export function eventsFeed(f: EventsFeedInput): string {
  const entries = f.items.map((it) => eventEntry(it, f));
  return renderFeed({
    id: `${f.idBase}/${f.path}`,
    title: f.title,
    subtitle: f.subtitle,
    self: `${f.siteUrl}/${f.path}`,
    alternate: `${f.siteUrl}/${f.alternate}`,
    updated: latestUpdated(entries, f.fallbackUpdated),
    entries,
  });
}
