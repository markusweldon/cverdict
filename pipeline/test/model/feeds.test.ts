import { describe, expect, it } from 'vitest';
import { BRAND } from '../../../shared/brand';
import type { KevEntry } from '../../../shared/contract';
import { escapeXml, kevFeed, signalFeed, wokeFeed } from '../../src/emit/atom';
import { buildWoke, detectWakes } from '../../src/woke';
import { escapeIcsText, foldLine, kevDueCalendar } from '../../src/emit/ics';
import { toDetail } from '../../src/rows';
import { NOW, cvss, dateAgo, daysAgo, makeCve, makeKev, makeKevCatalog, msf, repo, score, ssvc } from '../fixtures/model/builders';

const SITE = 'https://example.test';
const opts = { siteUrl: SITE, now: NOW };

const HOSTILE_TITLE = '<script>alert(1)</script> & "quoted" \'apos\' ]]> <img src=x onerror=alert(2)>';
const HOSTILE_TEXT = `Bad\u0000bytes\u0007 and a lone \uD800 surrogate.\r\nATTENDEE:mailto:evil@example.com\r\nBEGIN:VEVENT ${'A'.repeat(2000)} ünïcödé 😀`;

const ATOM_TAGS = new Set(['?xml', 'feed', 'id', 'title', 'subtitle', 'link', 'updated', 'author', 'name', 'uri', 'generator', 'entry', 'published', 'category', 'summary', 'content']);

function expectSafeXml(xml: string): void {
  expect(xml).not.toMatch(/<script|<img/i);
  // every ampersand starts an entity
  expect(xml).not.toMatch(/&(?!(amp|lt|gt|quot|apos);)/);
  // no characters XML 1.0 cannot carry
  expect(xml).not.toMatch(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/);
  expect(xml).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/);
  // only our own elements exist
  for (const [, name] of xml.matchAll(/<\/?([^\s/>]+)/g)) expect(ATOM_TAGS.has(name)).toBe(true);
}

function kevEntry(o: Partial<KevEntry> = {}): KevEntry {
  return {
    id: 'CVE-2026-100001',
    vendor: 'Acme',
    product: 'Widget',
    name: 'Acme Widget SQL Injection Vulnerability',
    date_added: dateAgo(3),
    due_date: dateAgo(-3),
    ransomware: 'Unknown',
    forensic_triage: false,
    description: 'Acme Widget contains a SQL injection vulnerability.',
    required_action: 'Apply mitigations per vendor instructions.',
    in_window: true,
    score: 92,
    ...o,
  };
}

describe('escapeXml', () => {
  it('escapes markup characters and drops invalid ones', () => {
    expect(escapeXml('<a href="x">&\'</a>')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;&apos;&lt;/a&gt;');
    expect(escapeXml('a\u0000b\u001Fc￾d\uD800e')).toBe('abcde');
    expect(escapeXml('line\r\nbreak\rhere')).toBe('line\nbreak\nhere');
    expect(escapeXml('tab\tand 😀')).toBe('tab\tand 😀');
  });
});

describe('signal Atom feed', () => {
  const hostile = toDetail(
    score(makeCve({ id: 'CVE-2026-100001', title: HOSTILE_TITLE, description: HOSTILE_TEXT, affected: [{ vendor: '<b>Evil</b> & Co', product: 'Widget\r\nX', purl: null }] }), {
      kev: [makeKev('CVE-2026-100001', { dateAdded: dateAgo(2) })],
    }),
  );
  const likely = toDetail(score(makeCve({ id: 'CVE-2026-100002', published: daysAgo(3) }), { metasploit: { 'CVE-2026-100002': [msf('exploit/x/y')] } }));
  const quiet = toDetail(score(makeCve({ id: 'CVE-2026-100003' })));
  const xml = signalFeed([quiet, likely, hostile], opts);

  it('is safe with hostile CVE text', () => {
    expectSafeXml(xml);
    expect(xml).toContain('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quoted&quot; &apos;apos&apos; ]]&gt;');
    expect(xml).toContain('&lt;b&gt;Evil&lt;/b&gt; &amp; Co Widget X');
  });

  it('contains only exploited and likely CVEs, newest evidence first', () => {
    const entryIds = [...xml.matchAll(/<id>(tag:[^<]+)<\/id>/g)].map((m) => m[1]);
    expect(entryIds).toEqual([
      `tag:example.test,2026:${BRAND.slug}/signal/CVE-2026-100001/exploited`,
      `tag:example.test,2026:${BRAND.slug}/signal/CVE-2026-100002/likely`,
    ]);
    expect(xml).not.toContain('CVE-2026-100003');
  });

  it('links to the site route and uses stable ids', () => {
    expect(xml).toContain(`<link rel="alternate" type="text/html" href="${SITE}/cve/CVE-2026-100001"/>`);
    expect(xml).toContain(`<link rel="self" type="application/atom+xml" href="${SITE}/feeds/signal.xml"/>`);
    expect(signalFeed([quiet, likely, hostile], opts)).toBe(xml);
  });

  it('titles are "CVE · vendor product · tier" and summaries list the top chips', () => {
    expect(xml).toContain('<title type="text">CVE-2026-100002 · Acme Widget · Likely next</title>');
    expect(xml).toMatch(/<summary type="text">Likely next · score \d+\/100\. Metasploit: exploit\/x\/y \(excellent\);/);
    // the entry is dated by its newest positive evidence (KEV dateAdded), not by the run
    expect(xml).toContain(`<updated>${dateAgo(2)}T00:00:00.000Z</updated>`);
  });

  it('is not re-dated by the daily EPSS score, only by exploitation and exploit evidence', () => {
    const id = 'CVE-2026-100004';
    // likely on EPSS alone: 15 + epss.high 27 + sev.crit_net 13 + SSVC 14 − prior.none 6 = 63
    const epssOnly = toDetail(score(makeCve({ id, published: daysAgo(20), ...cvss(9.8), ssvc: ssvc('none', 'yes', 'total') }), { epss: { [id]: [0.5, 0.99] } }));
    expect(epssOnly.score.tier).toBe('likely');
    expect(epssOnly.reasons.find((r) => r.id === 'epss.high')).toMatchObject({ points: 27, at: dateAgo(0) });
    const kevLater = toDetail(score(makeCve({ id: 'CVE-2026-100005', published: daysAgo(20) }), { epss: { 'CVE-2026-100005': [0.5, 0.99] }, kev: [makeKev('CVE-2026-100005', { dateAdded: dateAgo(6) })] }));
    const feed = signalFeed([epssOnly, kevLater], opts);
    const updated = [...feed.matchAll(/<entry>[\s\S]*?<id>[^<]*\/(CVE-[\d-]+)\/[^<]*<\/id>[\s\S]*?<updated>([^<]+)<\/updated>/g)].map((m) => [m[1], m[2]]);
    expect(updated).toEqual([
      ['CVE-2026-100005', `${dateAgo(6)}T00:00:00.000Z`],
      [id, new Date(daysAgo(20)).toISOString()],
    ]);
  });

  it('caps at 100 entries', () => {
    const many = Array.from({ length: 120 }, (_, i) =>
      toDetail(score(makeCve({ id: `CVE-2026-${300000 + i}` }), { nuclei: { [`CVE-2026-${300000 + i}`]: [{ path: 'http/x.yaml', severity: 'high', url: 'https://x.test' }] } })),
    );
    expect((signalFeed(many, opts).match(/<entry>/g) ?? []).length).toBe(100);
  });

  it('is a valid empty feed when nothing passed', () => {
    const empty = signalFeed([quiet], opts);
    expect(empty).toContain(`<updated>${NOW.toISOString()}</updated>`);
    expect(empty).not.toContain('<entry>');
    expectSafeXml(empty);
  });
});

describe('KEV Atom feed', () => {
  it('lists additions from the last 30 days, newest first, safely escaped', () => {
    const xml = kevFeed(
      [
        kevEntry({ id: 'CVE-2026-1', date_added: dateAgo(31) }),
        kevEntry({ id: 'CVE-2026-2', date_added: dateAgo(1), name: HOSTILE_TITLE, ransomware: 'Known', forensic_triage: true }),
        kevEntry({ id: 'CVE-2026-3', date_added: dateAgo(10), description: HOSTILE_TEXT }),
      ],
      opts,
    );
    expectSafeXml(xml);
    const ids = [...xml.matchAll(/<id>tag:[^<]+\/kev\/([^<]+)<\/id>/g)].map((m) => m[1]);
    expect(ids).toEqual(['CVE-2026-2', 'CVE-2026-3']);
    expect(xml).toContain('<category term="ransomware"/>');
    expect(xml).toContain('Forensic triage requested (BOD 26-04).');
    expect(xml).toContain(`href="${SITE}/cve/CVE-2026-2"`);
  });
});

describe('escapeIcsText / foldLine', () => {
  it('escapes TEXT values per RFC 5545', () => {
    expect(escapeIcsText('a;b,c\\d\ne')).toBe('a\\;b\\,c\\\\d\\ne');
    expect(escapeIcsText('x\r\nATTENDEE:evil\ry')).toBe('x\\nATTENDEE:evil\\ny');
    expect(escapeIcsText('tab\tok\u0000\u001B\u0085')).toBe('tab\tok');
  });

  it('folds at 75 octets without splitting UTF-8 sequences', () => {
    for (const line of ['A'.repeat(300), `DESCRIPTION:${'é'.repeat(200)}`, `SUMMARY:${'😀'.repeat(100)}`, 'short']) {
      const folded = foldLine(line);
      const parts = folded.split('\r\n');
      for (const [i, part] of parts.entries()) {
        expect(Buffer.byteLength(part, 'utf8')).toBeLessThanOrEqual(75);
        if (i > 0) expect(part.startsWith(' ')).toBe(true);
        expect(Buffer.from(part, 'utf8').toString('utf8')).toBe(part);
      }
      expect(folded.replace(/\r\n /g, '')).toBe(line);
    }
    expect(foldLine('x'.repeat(75))).toBe('x'.repeat(75));
    expect(foldLine('x'.repeat(76))).toBe(`${'x'.repeat(75)}\r\n x`);
  });
});

describe('KEV due calendar', () => {
  const entries = [
    kevEntry({ id: 'CVE-2026-10001', due_date: dateAgo(8) }),
    kevEntry({ id: 'CVE-2026-10002', due_date: dateAgo(7) }),
    kevEntry({ id: 'CVE-2026-10003', due_date: dateAgo(-60), name: HOSTILE_TITLE, required_action: HOSTILE_TEXT, vendor: 'Evil;Vendor,Inc\\' }),
    kevEntry({ id: 'CVE-2026-10004', due_date: dateAgo(-61) }),
    kevEntry({ id: 'CVE-2026-10005', due_date: '2026-02-30' }),
    kevEntry({ id: 'not-a-cve\r\nX:1', due_date: dateAgo(0) }),
  ];
  const ics = kevDueCalendar(entries, opts);
  const physical = ics.split('\r\n');
  const logical = ics.replace(/\r\n /g, '').split('\r\n');

  it('uses CRLF everywhere and lines of at most 75 octets', () => {
    expect(ics.startsWith('BEGIN:VCALENDAR\r\nVERSION:2.0\r\n')).toBe(true);
    expect(ics.endsWith('END:VCALENDAR\r\n')).toBe(true);
    expect(ics).not.toMatch(/[^\r]\n|\r[^\n]/);
    for (const line of physical) expect(Buffer.byteLength(line, 'utf8')).toBeLessThanOrEqual(75);
  });

  it('contains one all-day event per due date in [today − 7d, today + 60d]', () => {
    const uids = logical.filter((l) => l.startsWith('UID:'));
    expect(uids).toEqual([`UID:CVE-2026-10002-kev-due@${BRAND.slug}`, `UID:CVE-2026-10003-kev-due@${BRAND.slug}`]);
    const d = dateAgo(7).replace(/-/g, '');
    expect(logical).toContain(`DTSTART;VALUE=DATE:${d}`);
    expect(logical).toContain(`DTEND;VALUE=DATE:${dateAgo(6).replace(/-/g, '')}`);
    expect(logical.filter((l) => l.startsWith('DTSTAMP:')).every((l) => l === 'DTSTAMP:20261026T193000Z')).toBe(true);
  });

  it('cannot be broken out of by hostile text', () => {
    // every logical line is one of our properties; injected CRLFs became "\n" escapes
    const props = new Set(logical.filter(Boolean).map((l) => l.split(/[:;]/)[0]));
    expect([...props].sort()).toEqual(
      ['BEGIN', 'CALSCALE', 'CATEGORIES', 'DESCRIPTION', 'DTEND', 'DTSTAMP', 'DTSTART', 'END', 'METHOD', 'NAME', 'PRODID', 'REFRESH-INTERVAL', 'SUMMARY', 'TRANSP', 'UID', 'URL', 'VERSION', 'X-PUBLISHED-TTL', 'X-WR-CALDESC', 'X-WR-CALNAME'].sort(),
    );
    expect(logical.filter((l) => l === 'BEGIN:VEVENT')).toHaveLength(2);
    expect(logical.some((l) => l.startsWith('ATTENDEE'))).toBe(false);
    const summary = logical.find((l) => l.startsWith('SUMMARY:KEV due: CVE-2026-10003'))!;
    expect(summary).toContain('Evil\\;Vendor\\,Inc\\\\');
    const description = logical.find((l) => l.startsWith('DESCRIPTION:') && l.includes('script'))!;
    expect(description).toContain('\\nATTENDEE:mailto:evil@example.com\\nBEGIN:VEVENT');
    expect(description).not.toMatch(/[\u0000-\u0008]/);
    expect(logical).toContain(`URL:${SITE}/cve/CVE-2026-10003`);
  });

  it('is deterministic for the same inputs', () => {
    expect(kevDueCalendar(entries, opts)).toBe(ics);
  });
});

describe('woke Atom feed', () => {
  const id = 'CVE-2019-0001';
  const kev = [makeKev(id, { dateAdded: dateAgo(2) })];
  const pocs = new Map([[id, [repo(daysAgo(9))]]]);
  const wake = detectWakes({
    now: NOW,
    kev: makeKevCatalog(kev),
    exploitdb: null,
    metasploit: new Map(),
    nuclei: new Map(),
    poc: pocs,
    epss: null,
    epssPast: null,
    epssPastError: null,
    previous: null,
    previousAt: null,
  });
  const s = score(makeCve({ id, published: '2019-05-01T00:00:00.000Z', inWindow: false, title: HOSTILE_TITLE, affected: [{ vendor: '<b>Evil</b> & Co', product: 'Widget', purl: null }] }), {
    kev,
    poc: { [id]: [repo(daysAgo(9))] },
  });
  const woke = buildWoke([s], wake, NOW, new Date(NOW.getTime() - 30 * 86_400_000)).file;
  const xml = wokeFeed(woke, opts);

  it('is safe with hostile CVE text', () => {
    expectSafeXml(xml);
    expect(xml).toContain('&lt;b&gt;Evil&lt;/b&gt; &amp; Co Widget');
  });

  it('has one entry per CVE, titled by its newest signal and dated by it', () => {
    expect([...xml.matchAll(/<entry>/g)]).toHaveLength(1);
    expect(xml).toContain(`<id>tag:example.test,2026:${BRAND.slug}/woke/${id}</id>`);
    expect(xml).toContain(`<title type="text">${id} · &lt;b&gt;Evil&lt;/b&gt; &amp; Co Widget · woke up: added to CISA KEV</title>`);
    expect(xml).toContain(`<updated>${dateAgo(2)}T00:00:00.000Z</updated>`);
    expect(xml).toContain(`<published>${daysAgo(9)}</published>`);
    expect(xml).toContain('<summary type="text">Published May 1, 2019.');
    expect(xml).toContain(`<link rel="alternate" type="text/html" href="${SITE}/woke"/>`);
    expect(xml).toContain('<category term="woke"/>');
  });
});
