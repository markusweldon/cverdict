import { describe, expect, it } from 'vitest';
import { addDays, daysBetween, monthKey, normalizeIso, normalizeYmd, parseIsoDate, ymd } from '../../src/util/dates';
import { createLogger, escapeControls } from '../../src/util/log';
import { clip, excerpt, normalizeCveId, sanitizeLine, sanitizeText, sanitizeUrl, truncate } from '../../src/util/text';

const ch = (code: number) => String.fromCharCode(code);
const RLO = ch(0x202e); // right-to-left override
const ZWSP = ch(0x200b);
const NBSP = ch(0xa0);
const LINE_SEP = ch(0x2028);
const EMOJI = String.fromCodePoint(0x1f600); // a surrogate pair

describe('sanitizeText', () => {
  it('strips C0/C1 controls except newline, mapping whitespace-like controls to spaces', () => {
    expect(sanitizeText(`a${ch(0)}b${ch(7)}c${ch(0x9b)}d\te${ch(0x0b)}f`, 100)).toBe('abcd e f');
    expect(sanitizeText('one\r\ntwo\rthree', 100)).toBe('one\ntwo\nthree');
    expect(sanitizeText(`x${LINE_SEP}y${ch(0x85)}z`, 100)).toBe('x\ny\nz');
  });

  it('removes bidi overrides and zero-width characters that could disguise text', () => {
    expect(sanitizeText(`admin${RLO}txt.exe${ZWSP}`, 100)).toBe('admintxt.exe');
  });

  it('collapses horizontal whitespace and blank lines, and trims', () => {
    expect(sanitizeText(`  a ${NBSP}  b \n\n\n\n  c  `, 100)).toBe('a b\n\nc');
  });

  it('replaces lone surrogates and keeps valid pairs', () => {
    expect(sanitizeText(`a${ch(0xd800)}b${EMOJI}`, 100)).toBe(`a${ch(0xfffd)}b${EMOJI}`);
  });

  it('keeps HTML as literal text (rendering is text-only)', () => {
    const payload = 'e.g., <img src=x onerror=alert(1)> or <script>alert(1)</script>';
    expect(sanitizeText(payload, 1000)).toBe(payload);
  });

  it('returns an empty string for non-strings', () => {
    expect(sanitizeText(undefined, 10)).toBe('');
    expect(sanitizeText(42, 10)).toBe('');
    expect(sanitizeText({ value: 'x' }, 10)).toBe('');
  });
});

describe('truncate / clip / sanitizeLine', () => {
  it('truncates to the limit including the ellipsis, preferring a word break', () => {
    const out = truncate('The quick brown fox jumps over the lazy dog', 20);
    expect(out.length).toBeLessThanOrEqual(20);
    expect(out).toBe('The quick brown fox…');
    expect(truncate('short', 20)).toBe('short');
    expect(truncate('abcdefghijklmnopqrstuvwxyz', 10)).toBe('abcdefghi…');
  });

  it('never splits a surrogate pair', () => {
    const text = `abc${EMOJI}def`;
    expect(clip(text, 4)).toBe('abc');
    expect(clip(text, 5)).toBe(`abc${EMOJI}`);
  });

  it('sanitizeLine turns newlines into single spaces', () => {
    expect(sanitizeLine('Windows\n  Server\r\n2025', 100)).toBe('Windows Server 2025');
  });
});

describe('sanitizeUrl', () => {
  it('accepts absolute http(s) URLs in canonical form', () => {
    expect(sanitizeUrl(' https://example.com/a b ')).toBe('https://example.com/a%20b');
    expect(sanitizeUrl('HTTP://Example.COM/x')).toBe('http://example.com/x');
  });

  it('rejects other schemes, credentials, relative and over-long URLs', () => {
    for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'ftp://example.com', '//example.com', '/x', 'https://user:pw@example.com/', '', 7]) {
      expect(sanitizeUrl(bad)).toBeNull();
    }
    expect(sanitizeUrl(`https://example.com/${'a'.repeat(3000)}`)).toBeNull();
  });
});

describe('normalizeCveId', () => {
  it('accepts 4 to 7+ digit sequence numbers, upper-casing', () => {
    expect(normalizeCveId('CVE-2026-0257')).toBe('CVE-2026-0257');
    expect(normalizeCveId(' cve-2026-104596 ')).toBe('CVE-2026-104596');
    expect(normalizeCveId('CVE-2015-1000000')).toBe('CVE-2015-1000000');
    expect(normalizeCveId('CVE-2026-12345678')).toBe('CVE-2026-12345678');
  });

  it('rejects malformed IDs', () => {
    for (const bad of ['CVE-2026-123', 'CVE-26-1234', 'GHSA-xxxx', 'CVE-2026-1234 extra', null]) expect(normalizeCveId(bad)).toBeNull();
  });
});

describe('dates', () => {
  it('parses ISO 8601 variants as UTC', () => {
    expect(normalizeIso('2026-10-13T19:01:34.060Z')).toBe('2026-10-13T19:01:34.060Z');
    expect(normalizeIso('2026-10-09T00:00:00+00:00')).toBe('2026-10-09T00:00:00.000Z');
    expect(normalizeIso('2026-10-09T02:00:00+0200')).toBe('2026-10-09T00:00:00.000Z');
    expect(normalizeIso('2024-01-01T00:00:00')).toBe('2024-01-01T00:00:00.000Z');
    expect(normalizeIso('2025-05-21 08:32:40 +0000')).toBe('2025-05-21T08:32:40.000Z');
    expect(normalizeIso('2026-10-23')).toBe('2026-10-23T00:00:00.000Z');
    expect(normalizeIso('2026-09-28T13:01:58.831171Z')).toBe('2026-09-28T13:01:58.831Z');
  });

  it('rejects impossible dates and garbage', () => {
    for (const bad of ['2026-02-30', '2026-13-01T00:00:00Z', 'yesterday', '', null, 20261026]) expect(parseIsoDate(bad)).toBeNull();
  });

  it('formats and does arithmetic in UTC', () => {
    const d = new Date('2026-10-26T19:30:00Z');
    expect(ymd(d)).toBe('2026-10-26');
    expect(monthKey(d)).toBe('2026-10');
    expect(ymd(addDays(d, -30))).toBe('2026-09-26');
    expect(daysBetween(new Date('2026-10-13T19:30:00Z'), d)).toBe(13);
    expect(normalizeYmd('2026-10-23')).toBe('2026-10-23');
  });
});

describe('createLogger', () => {
  it('writes timestamped, levelled lines', () => {
    const lines: string[] = [];
    const log = createLogger({ write: (l) => lines.push(l), clock: () => new Date('2026-10-26T19:30:00Z') });
    log.info('hello');
    log.warn('careful');
    log.error('broken');
    expect(lines).toEqual([
      '2026-10-26T19:30:00.000Z INFO  hello\n',
      '2026-10-26T19:30:00.000Z WARN  careful\n',
      '2026-10-26T19:30:00.000Z ERROR broken\n',
    ]);
  });

  it('keeps every message on one line, so upstream bytes cannot start a workflow command', () => {
    const lines: string[] = [];
    const log = createLogger({ write: (l) => lines.push(l), clock: () => new Date('2026-10-26T19:30:00Z') });
    log.warn('EPSS: unexpected header "cve\r::warning title=Forged::x"');
    log.error(`KEV: invalid JSON ([\n::error::x]${LINE_SEP}::add-mask::y${ch(0x1b)}[31m)`);
    expect(lines).toEqual([
      '2026-10-26T19:30:00.000Z WARN  EPSS: unexpected header "cve\\r::warning title=Forged::x"\n',
      '2026-10-26T19:30:00.000Z ERROR KEV: invalid JSON ([\\n::error::x]\\u2028::add-mask::y\\u001b[31m)\n',
    ]);
    // What a runner sees after splitting on CR, LF and CRLF: no line starts with "::".
    for (const line of lines.join('').split(/\r\n|\r|\n/)) expect(line.trimStart().startsWith('::')).toBe(false);
  });

  it('escapeControls leaves tabs and ordinary text alone', () => {
    expect(escapeControls('a\tb ünï 😀')).toBe('a\tb ünï 😀');
    expect(escapeControls('x\r\ny\u0000')).toBe('x\\r\\ny\\u0000');
  });
});

describe('excerpt', () => {
  const long = 'Paul Bottinelli of Trail of Bits in collaboration with OpenAI, reported through the coordinated disclosure programme';

  it('keeps the matched span visible, with ellipses where cut', () => {
    const at = long.indexOf('OpenAI');
    const out = excerpt(long, at, 6, 80);
    expect(out).toContain('OpenAI');
    expect(out.length).toBeLessThanOrEqual(80);
    expect(out.startsWith('…')).toBe(true);
    expect(out.endsWith('…')).toBe(true);
    expect(excerpt(long, 0, 4, 80).startsWith('Paul Bottinelli')).toBe(true);
    const end = excerpt(long, long.length - 9, 9, 80);
    expect(end.endsWith('programme')).toBe(true);
    expect(end.length).toBeLessThanOrEqual(80);
  });

  it('returns short text unchanged and never splits a surrogate pair', () => {
    expect(excerpt('Claude', 0, 6, 80)).toBe('Claude');
    const emoji = `${EMOJI.repeat(60)} Claude ${EMOJI.repeat(60)}`;
    const out = excerpt(emoji, emoji.indexOf('Claude'), 6, 40);
    expect(out).toContain('Claude');
    expect(out.length).toBeLessThanOrEqual(40);
    expect(out).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/);
  });
});
