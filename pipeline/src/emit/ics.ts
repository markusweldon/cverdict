/**
 * iCalendar (RFC 5545) feed of CISA KEV due dates: one all-day VEVENT per KEV entry whose due
 * date falls in [today − 7 days, today + 60 days]. CRLF line endings, TEXT escaping, and
 * folding at 75 octets without splitting UTF-8 sequences.
 */
import { BRAND } from '../../../shared/brand';
import { CVE_ID_RE } from '../../../shared/shard';
import type { KevEntry } from '../../../shared/contract';
import { cveUrl, type FeedOptions } from './atom';
import { daysAgo } from './json';
import { addDays, normalizeYmd, parseIsoDate, ymd } from '../util/dates';

const CRLF = '\r\n';
const MAX_OCTETS = 75;
const DUE_PAST_DAYS = 7;
const DUE_AHEAD_DAYS = 60;

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Escape a TEXT value (RFC 5545 §3.3.11). Line breaks become "\n"; other controls are dropped
 * and lone surrogates (not encodable as UTF-8) become U+FFFD.
 */
export function escapeIcsText(text: string): string {
  return text
    .replace(LONE_SURROGATE, '\uFFFD')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, '')
    .replace(/[\\;,\n]/g, (ch) => (ch === '\n' ? '\\n' : `\\${ch}`));
}

/** Fold a content line (RFC 5545 §3.1): at most 75 octets per physical line, continuation lines start with a space. */
export function foldLine(line: string): string {
  const parts: string[] = [];
  let current = '';
  let octets = 0;
  for (const ch of line) {
    const size = Buffer.byteLength(ch, 'utf8');
    // Continuation lines carry a leading space, which counts towards the limit.
    const limit = parts.length === 0 ? MAX_OCTETS : MAX_OCTETS - 1;
    if (octets + size > limit) {
      parts.push(current);
      current = '';
      octets = 0;
    }
    current += ch;
    octets += size;
  }
  parts.push(current);
  return parts.join(`${CRLF} `);
}

/** 20261026T193000Z */
function icsUtc(d: Date): string {
  return d.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

/** 2026-10-29 → 20261029 */
const icsDate = (date: string) => date.replace(/-/g, '');

function nextDay(date: string): string {
  return ymd(addDays(parseIsoDate(date)!, 1));
}

function vevent(k: KevEntry, opts: FeedOptions, stamp: string): string[] {
  const url = cveUrl(opts.siteUrl, k.id);
  const description = [
    k.name,
    `Added to CISA KEV ${k.date_added}. Known ransomware use: ${k.ransomware}.`,
    ...(k.forensic_triage ? ['CISA asks for forensic triage (BOD 26-04).'] : []),
    `Required action: ${k.required_action}`,
    url,
  ].join('\n');
  return [
    'BEGIN:VEVENT',
    `UID:${k.id}-kev-due@${BRAND.slug}`,
    `DTSTAMP:${stamp}`,
    `DTSTART;VALUE=DATE:${icsDate(k.due_date)}`,
    `DTEND;VALUE=DATE:${icsDate(nextDay(k.due_date))}`,
    `SUMMARY:${escapeIcsText(`KEV due: ${k.id} · ${k.vendor} ${k.product}`)}`,
    `DESCRIPTION:${escapeIcsText(description)}`,
    `URL:${url}`,
    `CATEGORIES:${escapeIcsText('CISA KEV')}`,
    'TRANSP:TRANSPARENT',
    'END:VEVENT',
  ];
}

export function kevDueCalendar(kev: readonly KevEntry[], opts: FeedOptions): string {
  const from = daysAgo(opts.now, DUE_PAST_DAYS);
  const to = daysAgo(opts.now, -DUE_AHEAD_DAYS);
  const stamp = icsUtc(opts.now);
  const due = kev
    .filter((k) => CVE_ID_RE.test(k.id) && normalizeYmd(k.due_date) === k.due_date && k.due_date >= from && k.due_date <= to)
    .sort((a, b) => a.due_date.localeCompare(b.due_date) || a.id.localeCompare(b.id));
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    `PRODID:-//${escapeIcsText(BRAND.name)}//KEV due dates//EN`,
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    `NAME:${escapeIcsText(`${BRAND.name} · CISA KEV due dates`)}`,
    `X-WR-CALNAME:${escapeIcsText(`${BRAND.name} · CISA KEV due dates`)}`,
    `X-WR-CALDESC:${escapeIcsText('Remediation due dates for CISA Known Exploited Vulnerabilities.')}`,
    'REFRESH-INTERVAL;VALUE=DURATION:PT1H',
    'X-PUBLISHED-TTL:PT1H',
    ...due.flatMap((k) => vevent(k, opts, stamp)),
    'END:VCALENDAR',
  ];
  return lines.map(foldLine).join(CRLF) + CRLF;
}
