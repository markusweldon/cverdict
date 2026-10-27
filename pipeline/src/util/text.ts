/**
 * Sanitisation for attacker-controllable upstream text (CVE records contain `<script>` and
 * `onerror` payloads, bidi tricks and stray control bytes). Output is plain text; HTML is kept
 * verbatim as characters and must only ever be rendered as text.
 */
import { CVE_ID_RE } from '../../../shared/shard';

// Whitespace-like controls become a space before stripping, so words are not glued together.
const SPACE_CONTROLS_RE = /[\t\v\f]/g;
const NEWLINES_RE = /\r\n?|[\u0085\u2028\u2029]/g;
// Remaining C0/C1 controls and DEL, plus invisible formatting characters that can disguise text:
// zero-width characters, bidi marks/embeddings/overrides/isolates, word joiners and the BOM.
const STRIP_RE = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
const HSPACE_RE = /[ \u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]+/g;

function clean(value: string): string {
  return value
    .replace(LONE_SURROGATE_RE, '\uFFFD')
    .replace(SPACE_CONTROLS_RE, ' ')
    .replace(NEWLINES_RE, '\n')
    .replace(STRIP_RE, '')
    .replace(HSPACE_RE, ' ');
}

/**
 * Multi-line plain text: strips control and invisible characters (keeping `\n`), collapses runs
 * of spaces and blank lines, trims, and truncates to `maxLength` characters.
 */
export function sanitizeText(value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value === '') return '';
  const text = clean(value)
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return truncate(text, maxLength);
}

/** Single-line plain text (titles, vendor and product names): like sanitizeText, newlines become spaces. */
export function sanitizeLine(value: unknown, maxLength: number): string {
  if (typeof value !== 'string' || value === '') return '';
  return truncate(clean(value).replace(/\n/g, ' ').replace(/ {2,}/g, ' ').trim(), maxLength);
}

/** Cut to at most `maxLength` UTF-16 units without splitting a surrogate pair. */
export function clip(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  const code = text.charCodeAt(maxLength - 1);
  return text.slice(0, code >= 0xd800 && code <= 0xdbff ? maxLength - 1 : maxLength);
}

/** Truncate to at most `maxLength` characters including a trailing "…", preferring a word break. */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  let head = clip(text, maxLength - 1);
  const space = head.lastIndexOf(' ');
  if (space >= maxLength * 0.8) head = head.slice(0, space);
  return `${head.trimEnd()}…`;
}

/**
 * At most `maxLength` characters of `text` around `text.slice(index, index + length)`, marked
 * with "…" where cut (at a nearby word break when there is one), so that span is always visible.
 */
export function excerpt(text: string, index: number, length: number, maxLength: number): string {
  if (text.length <= maxLength) return text;
  const room = maxLength - 2; // both ellipses
  const snap = Math.floor(maxLength / 5);
  let start = Math.max(0, Math.min(index - Math.floor((room - length) / 2), text.length - room));
  let end = Math.min(text.length, start + room);
  const space = text.indexOf(' ', start);
  if (start > 0 && text[start - 1] !== ' ' && space !== -1 && space < index && space - start < snap) start = space + 1;
  const back = text.lastIndexOf(' ', end);
  if (end < text.length && text[end] !== ' ' && back >= index + length && end - back < snap) end = back;
  // Never split a surrogate pair.
  if (isLowSurrogate(text.charCodeAt(start))) start++;
  if (end < text.length && isLowSurrogate(text.charCodeAt(end))) end--;
  return `${start > 0 ? '…' : ''}${text.slice(start, end).trim()}${end < text.length ? '…' : ''}`;
}

const isLowSurrogate = (code: number) => code >= 0xdc00 && code <= 0xdfff;

/** An absolute http(s) URL in canonical form, or null. Rejects credentials and other schemes. */
export function sanitizeUrl(value: unknown, maxLength = 2048): string | null {
  if (typeof value !== 'string') return null;
  const raw = value.trim();
  if (raw.length === 0 || raw.length > maxLength || !/^https?:\/\//i.test(raw)) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || !url.hostname) return null;
  return url.href.length <= maxLength ? url.href : null;
}

/** Upper-cased CVE ID if `value` is one (4+ digit sequence numbers), else null. */
export function normalizeCveId(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const id = value.trim().toUpperCase();
  return CVE_ID_RE.test(id) ? id : null;
}
