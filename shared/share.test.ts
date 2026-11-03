import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { KNOB_DEFAULT, WATCH_FLOOR, type CveDetail } from './contract';
import { COLD_START_DAYS } from './model';
import {
  ALT_MAX,
  BOT_UA_VALUE,
  cleanText,
  DESCRIPTION_MAX,
  escapeHtml,
  genericHead,
  hasShareBlock,
  injectHead,
  isPreviewBot,
  minimalTemplate,
  NOT_IN_DATA,
  notInDataHead,
  readShareRecord,
  SHARE_END,
  SHARE_START,
  shareDescription,
  shareHead,
  shareTitle,
  siteOrigin,
} from './share';
import { SHARE_IMAGE_HEIGHT, SHARE_IMAGE_WIDTH, SHARE_IMAGES } from './share-images';
import * as F from './share.fixtures';
import { fmtDay, fmtPercent, fmtRunTime, verdict } from './verdict';

const ALL: [string, CveDetail][] = Object.entries(F).filter((e): e is [string, CveDetail] => typeof e[1] === 'object' && e[1] !== null && 'score' in e[1]);
const desc = (d: CveDetail, knob = KNOB_DEFAULT) => shareDescription(d, d.score.tier, knob, F.GENERATED_AT);
const head = (d: CveDetail) => shareHead({ origin: F.ORIGIN, detail: d, generatedAt: F.GENERATED_AT });
const cps = (s: string) => Array.from(s).length;
/** content="" of a tag, unescaped. */
function tag(html: string, attr: 'property' | 'name', key: string): string[] {
  const out: string[] = [];
  const re = new RegExp(`<meta ${attr}="${key.replace(/[.:]/g, '\\$&')}" content="([^"]*)" />`, 'g');
  for (const m of html.matchAll(re)) out.push(m[1].replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'));
  return out;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('preview text', () => {
  it('says the verdict, the subject, KEV, exploits and the run time, in that order', () => {
    const expected: Record<string, [string, string]> = {
      EXPLOITED_KEV: [
        'CVE-2026-109618: Exploited, score 100',
        'Patch now: exploited, KEV due Oct 29. PHP Group · PHP. CISA KEV: added Oct 26, due Oct 29. Public exploits: Nuclei 1, Exploit-DB 1, 729 vetted PoC repos (unverified code). As of Nov 3, 2026 06:50 UTC.',
      ],
      EXPLOITED_RANSOMWARE: [
        'CVE-2013-2551: Exploited, score 100',
        'Patch now: exploited, KEV due Apr 18, 2022. Published by MITRE. CISA KEV: added Mar 28, 2022, due Apr 18, 2022, known ransomware use. No public exploit in our feeds yet. As of Nov 3, 2026 06:50 UTC.',
      ],
      EXPLOITED_SSVC: ['CVE-2026-110001: Exploited, score 90', 'Patch now: CISA SSVC says exploitation is active. Microsoft Exchange Server. CISA KEV: not listed. No public exploit in our feeds yet. As of Nov 3, 2026 06:50 UTC.'],
      EXPLOITED_VENDOR: [
        'CVE-2026-86471: Exploited, score 100',
        'Patch now: the vendor reports exploitation. Apache Software Foundation · Apache CouchDB. CISA KEV: not listed. No public exploit in our feeds yet. As of Nov 3, 2026 06:50 UTC.',
      ],
      EXPLOITED_ADP_KEV: [
        'CVE-2026-110002: Exploited, score 90',
        'Patch now: exploited, listed in CISA KEV. PHP Group · PHP. CISA KEV: added Nov 2 (per the CVE record). No public exploit in our feeds yet. As of Nov 3, 2026 06:50 UTC.',
      ],
      LIKELY_MSF: ['CVE-2026-93680: Likely next, score 84', 'Likely next: Metasploit module. IBM · Langflow OSS. CISA KEV: not listed. Public exploits: Metasploit 1, 1 vetted PoC repo (unverified code). Critical 9.8 · network. As of Nov 3, 2026 06:50 UTC.'],
      LIKELY_NUCLEI: [
        'CVE-2026-85714: Likely next, score 58',
        'Likely next: Nuclei template, scannable at internet scale. Stirling-Tools · Stirling-PDF. CISA KEV: not listed. Public exploits: Nuclei 1. High 8.8 · network. As of Nov 3, 2026 06:50 UTC.',
      ],
      LIKELY_EDB: ['CVE-2026-110003: Likely next, score 60', 'Likely next: Exploit-DB entry. Acme · Router. CISA KEV: not listed. Public exploits: Exploit-DB 1. Critical 9.8 · network. As of Nov 3, 2026 06:50 UTC.'],
      LIKELY_POC: [
        'CVE-2026-102428: Likely next, score 56',
        'Likely next: public proof of concept (2 vetted repos). ordasoft.com · OrdaSoft Joomla CCK. CISA KEV: not listed. Public exploits: 2 vetted PoC repos (unverified code). As of Nov 3, 2026 06:50 UTC.',
      ],
      LIKELY_FUNCTIONAL: [
        'CVE-2026-106172: Likely next, score 50',
        'Likely next: vendor CVSS says a working exploit exists. Fortinet · FortiSandbox. CISA KEV: not listed. No public exploit in our feeds yet. Critical 9.6 · network. As of Nov 3, 2026 06:50 UTC.',
      ],
      LIKELY_EPSS: [
        'CVE-2025-28137: Likely next, score 69',
        // The reason (Critical 9.8 · network) would take it past 200 code points.
        'Likely next: EPSS 34.1% chance of exploitation in 30 days. Published by MITRE. CISA KEV: not listed. Public exploits: 1 vetted PoC repo (unverified code). As of Nov 3, 2026 06:50 UTC.',
      ],
      LIKELY_SCORE: [
        'CVE-2026-83396: Likely next, score 50',
        'Likely next: score 50 clears the default knob (50). Oracle Corporation · Oracle Data Integrator. CISA KEV: not listed. No public exploit in our feeds yet. As of Nov 3, 2026 06:50 UTC.',
      ],
      WATCH: [
        'CVE-2026-101416: Watch, score 32',
        'Watch: score 32, below the default knob (50). Oracle Corporation · PeopleSoft Enterprise PeopleTools. CISA KEV: not listed. No public exploit in our feeds yet. As of Nov 3, 2026 06:50 UTC.',
      ],
      QUIET_NOTHING: ['CVE-2026-103061: Quiet, score 0', 'Quiet: no evidence yet, and quiet is not safe. Gleam. CISA KEV: not listed. No public exploit in our feeds after 14 days. As of Nov 3, 2026 06:50 UTC.'],
      QUIET_POC: [
        'CVE-2026-89020: Quiet, score 24',
        'Quiet: score 24, below the watch floor (25), and quiet is not safe. MikroTik · RouterOS. CISA KEV: not listed. Public exploits: 1 vetted PoC repo (unverified code). As of Nov 3, 2026 06:50 UTC.',
      ],
      QUIET_CJK: [
        'CVE-2026-95597: Quiet, score 0',
        'Quiet: score 0, below the watch floor (25), and quiet is not safe. codemstory · 워드프레스 결제 심플페이. CISA KEV: not listed. No public exploit in our feeds after 14 days. As of Nov 3, 2026 06:50 UTC.',
      ],
    };
    for (const [name, [title, description]] of Object.entries(expected)) {
      const d = F[name as keyof typeof F] as CveDetail;
      expect(shareTitle(d, d.score.tier), name).toBe(title);
      expect(desc(d), name).toBe(description);
    }
  });

  it('never says "no evidence" for a Quiet CVE whose score a counted chip raised', () => {
    expect(desc(F.QUIET_POC)).not.toMatch(/no evidence/i);
    expect(desc(F.QUIET_NOTHING)).toMatch(/^Quiet: no evidence yet, and quiet is not safe\./);
  });

  it('only ever says "No public exploit" about our feeds', () => {
    for (const [name, d] of ALL) {
      for (const m of desc(d).matchAll(/no public exploit[^.]*/gi)) expect(m[0], name).toMatch(/^No public exploit in our feeds( after 14 days| yet)$/);
    }
  });

  it('keeps every description within 200 code points, ending with the run time, and every alt within 420', () => {
    for (const [name, d] of ALL) {
      const text = desc(d);
      expect(cps(text), name).toBeLessThanOrEqual(DESCRIPTION_MAX);
      expect(text, name).toMatch(/ As of Nov 3, 2026 06:50 UTC\.$/);
      for (const alt of tag(head(d), 'property', 'og:image:alt')) expect(cps(alt)).toBeLessThanOrEqual(ALT_MAX);
    }
  });

  it('drops reasons, then the exploits row, then shortens the subject, never the verdict, KEV row or run time', () => {
    const long = { ...F.EXPLOITED_KEV, affected: [{ vendor: 'V'.repeat(60), product: 'P'.repeat(80), purl: null }] };
    const text = desc(long);
    expect(cps(text)).toBeLessThanOrEqual(DESCRIPTION_MAX);
    expect(text).toMatch(/^Patch now: exploited, KEV due Oct 29\. V{60} · P+… CISA KEV: added Oct 26, due Oct 29\. As of Nov 3, 2026 06:50 UTC\.$/);
  });

  it('writes no em dash anywhere, even for invalid dates and a non-finite EPSS score', () => {
    const odd = { ...F.LIKELY_EPSS, epss: { score: Number.POSITIVE_INFINITY, percentile: 0, date: 'x', model: '' }, kev: { ...F.EXPLOITED_KEV.kev!, date_added: '2026-13-01', due_date: '' } };
    for (const d of [...ALL.map(([, x]) => x), odd]) {
      for (const text of [desc(d), head(d), desc(d, 60)]) expect(text).not.toContain('\u2014');
    }
    expect(desc(odd)).toContain('Likely next: score 69 clears the default knob (50).');
    expect(desc(odd)).toContain('CISA KEV: listed.');
    expect(genericHead(F.ORIGIN) + notInDataHead(F.ORIGIN, 'CVE-2019-0001') + minimalTemplate(F.ORIGIN)).not.toContain('\u2014');
  });

  it('traces every number to the record, the run time or the published constants', () => {
    const numbersIn = (s: string) => (s.match(/\d+(?:\.\d+)?/g) ?? []).map(Number);
    for (const [name, d] of ALL) {
      const allowed = new Set<number>([d.score.value, KNOB_DEFAULT, WATCH_FLOOR, COLD_START_DAYS, 30, 100]);
      const strings = [d.id, d.cna, ...d.affected.flatMap((a) => [a.vendor, a.product]), ...d.reasons.map((r) => r.label)];
      for (const s of strings) numbersIn(s).forEach((n) => allowed.add(n));
      for (const day of [d.kev?.date_added, d.kev?.due_date, ...d.reasons.map((r) => r.at), F.GENERATED_AT]) numbersIn(day ?? '').forEach((n) => allowed.add(n));
      const e = d.exploits;
      [e.metasploit.length, e.nuclei.length, e.exploitdb.length, e.poc.vetted, e.poc.count].forEach((n) => allowed.add(n));
      if (d.epss && Number.isFinite(d.epss.score)) allowed.add(Number((d.epss.score * 100).toFixed(1)));
      const text = `${shareTitle(d, d.score.tier)} ${desc(d)} ${tag(head(d), 'name', 'twitter:data1')} ${tag(head(d), 'name', 'twitter:data2')}`;
      for (const n of numbersIn(text)) expect(allowed.has(n), `${name}: ${n} in "${text}"`).toBe(true);
    }
  });

  it('dates by the year of the run, not the clock', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2027-01-02T00:00:00Z'));
    const december = { ...F.EXPLOITED_KEV, kev: { ...F.EXPLOITED_KEV.kev!, date_added: '2026-12-27', due_date: '2026-12-30' } };
    const text = shareDescription(december, 'exploited', KNOB_DEFAULT, '2026-12-31T23:10:00Z');
    expect(text).toContain('KEV due Dec 30.');
    expect(text).toContain('CISA KEV: added Dec 27, due Dec 30.');
    expect(text).not.toContain('2026, due');
    expect(text).toMatch(/As of Dec 31, 2026 23:10 UTC\.$/);
  });

  it('follows a turned knob on the CVE page', () => {
    // Before meta.json has loaded there is no run time, so a reason fits.
    expect(shareDescription(F.WATCH, 'watch', 60, null)).toBe('Watch: score 32, below the knob (60). Oracle Corporation · PeopleSoft Enterprise PeopleTools. CISA KEV: not listed. No public exploit in our feeds yet. High 7.5 · network.');
    expect(shareDescription(F.LIKELY_SCORE, 'likely', 45, F.GENERATED_AT)).toMatch(/^Likely next: score 50 clears the knob \(45\)\./);
  });
});

describe('verdict helpers', () => {
  it('format days, run times and percentages without placeholders', () => {
    expect(fmtDay('2026-10-29', 2026)).toBe('Oct 29');
    expect(fmtDay('2025-10-29', 2026)).toBe('Oct 29, 2025');
    expect(fmtDay('2026-10-21T00:00:00.000Z', 2026)).toBe('Oct 21');
    for (const bad of ['2026-02-30', '2026-13-01', 'yesterday', '', null, 42]) expect(fmtDay(bad, 2026)).toBeNull();
    expect(fmtRunTime('2026-11-03T06:50:18.883Z')).toBe('Nov 3, 2026 06:50 UTC');
    expect(fmtRunTime('2026-11-03')).toBeNull();
    expect(fmtPercent(0.142)).toBe('14.2%');
    expect(fmtPercent(0.0042)).toBe('0.42%');
    expect(fmtPercent(0.2)).toBe('20%');
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -0.1, 1.5, '0.1']) expect(fmtPercent(bad)).toBeNull();
  });

  it('phrases ssvc.poc and vendor.poc in words', () => {
    const one = (id: string) => verdict({ ...F.LIKELY_SCORE, reasons: [{ id, label: id, polarity: 'up', family: 'X', points: 10, source: 'computed' }] }, 'likely', 50, 2026).reason;
    expect(one('ssvc.poc')).toBe('CISA SSVC says a proof of concept exists');
    expect(one('vendor.poc')).toBe('vendor CVSS says a proof of concept exists');
    expect(one('x.something_new')).toBe('score 50 clears the default knob (50)');
  });
});

describe('cleanText and escapeHtml', () => {
  it('removes controls, zero-width and bidi characters, and collapses whitespace', () => {
    expect(cleanText('a\u0007b\tc\n\u0085d', 50)).toBe('a b c d');
    expect(cleanText('Mi\u200Bcro\u200Dsoft\uFEFF \u2060Corp', 50)).toBe('Microsoft Corp');
    expect(cleanText('\u202Egnp.exe\u202C \u2066x\u2069', 50)).toBe('gnp.exe x');
    expect(cleanText('lone \uD800 high', 50)).toBe('lone high');
    expect(cleanText('lone \uDC00 low', 50)).toBe('lone low');
    expect(cleanText('a \u2014 b\u2014c', 50)).toBe('a, b-c');
  });

  it('removes every other invisible character: the Arabic letter mark, tag characters, soft hyphens and fillers', () => {
    // U+061C is a bidi control too; tag characters spell hidden text ("A", then the cancel tag).
    expect(cleanText('gnp\u061c.exe', 50)).toBe('gnp.exe');
    expect(cleanText('Evil\u{E0041}\u{E007F}Corp', 50)).toBe('EvilCorp');
    expect(cleanText('Mi\u00adcro\u180esoft\u034f \u3164\u115f\u1160Corp\ufe0f', 50)).toBe('Microsoft Corp');
    // Visible text, emoji and other scripts stay.
    expect(cleanText('\uc6cc\ub4dc\ud504\ub808\uc2a4 \u00b7 Pubjet | \u067e\u0627\u0628\u062c\u062a \ud83d\ude00', 50)).toBe('\uc6cc\ub4dc\ud504\ub808\uc2a4 \u00b7 Pubjet | \u067e\u0627\u0628\u062c\u062a \ud83d\ude00');
  });

  it('cuts by code point, never inside a surrogate pair', () => {
    const s = 'ab😀😀😀';
    expect(cleanText(s, 4)).toBe('ab😀…');
    expect(cleanText(s, 5)).toBe(s);
    for (let n = 1; n < 8; n++) expect(cleanText('😀'.repeat(10), n)).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/);
  });

  it('caps a 1 MB input before any regex work', () => {
    const big = `${' \u200B'.repeat(500_000)}x`;
    const t0 = performance.now();
    expect(cleanText(big, 60)).toBe('');
    expect(cleanText(`x${'y'.repeat(1_000_000)}`, 60)).toHaveLength(60);
    expect(performance.now() - t0).toBeLessThan(50);
  });

  it('escapes the five HTML specials', () => {
    expect(escapeHtml(`<a href="x" title='y'>&</a>`)).toBe('&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  });
});

describe('shareHead', () => {
  const ONCE = ['og:site_name', 'og:type', 'og:url', 'og:title', 'og:description', 'og:image', 'og:image:type', 'og:image:width', 'og:image:height', 'og:image:alt'];
  const ONCE_NAME = ['description', 'twitter:card', 'twitter:title', 'twitter:description', 'twitter:image', 'twitter:image:alt', 'twitter:label1', 'twitter:data1', 'twitter:label2', 'twitter:data2'];

  it('has exactly one of each tag, with the configured origin', () => {
    for (const [name, d] of ALL) {
      const h = head(d);
      for (const k of ONCE) expect(tag(h, 'property', k), `${name} ${k}`).toHaveLength(1);
      for (const k of ONCE_NAME) expect(tag(h, 'name', k), `${name} ${k}`).toHaveLength(1);
      expect(h.match(/<title>/g)).toHaveLength(1);
      expect(h).toContain(`<link rel="canonical" href="${F.ORIGIN}/cve/${d.id}" />`);
      expect(tag(h, 'property', 'og:url')).toEqual([`${F.ORIGIN}/cve/${d.id}`]);
      expect(tag(h, 'name', 'description')).toEqual(tag(h, 'property', 'og:description'));
      expect(tag(h, 'name', 'twitter:description')).toEqual(tag(h, 'property', 'og:description'));
    }
  });

  it('shows the tier image with its own words as alt text', () => {
    for (const d of [F.EXPLOITED_KEV, F.LIKELY_MSF, F.WATCH, F.QUIET_POC]) {
      const img = SHARE_IMAGES[d.score.tier];
      const h = head(d);
      expect(tag(h, 'property', 'og:image')).toEqual([`${F.ORIGIN}${img.path}?v=${img.v}`]);
      expect(tag(h, 'name', 'twitter:image')).toEqual([`${F.ORIGIN}${img.path}?v=${img.v}`]);
      expect(tag(h, 'property', 'og:image:alt')).toEqual([img.alt]);
      expect(tag(h, 'property', 'og:image:width')).toEqual([String(SHARE_IMAGE_WIDTH)]);
    }
    expect(tag(head(F.EXPLOITED_KEV), 'property', 'og:image:alt')).toEqual(['CVErdict verdict: Exploited. Confirmed exploitation: CISA KEV, CISA SSVC or the vendor.']);
    expect(tag(head(F.QUIET_POC), 'property', 'og:image:alt')[0]).toContain('Quiet is not safe');
  });

  it('gives Slack its two fields', () => {
    const h = head(F.EXPLOITED_KEV);
    expect(tag(h, 'name', 'twitter:data1')).toEqual(['Exploited, 100 of 100']);
    expect(tag(h, 'name', 'twitter:data2')).toEqual(['Added Oct 26, due Oct 29']);
    expect(tag(head(F.WATCH), 'name', 'twitter:data2')).toEqual(['Not listed']);
    expect(tag(head(F.EXPLOITED_RANSOMWARE), 'name', 'twitter:data2')).toEqual(['Added Mar 28, 2022, due Apr 18, 2022, known ransomware use']);
  });

  it('keeps hostile upstream text inert', () => {
    const h = head(F.HOSTILE);
    expect(h).not.toMatch(/<script/i);
    expect(h).not.toContain('"><');
    expect(h).not.toMatch(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B\u202E]/);
    expect(h).not.toMatch(/\p{Default_Ignorable_Code_Point}/u);
    // Only <title>, <meta> and <link rel="canonical"> come out, and every attribute is quoted.
    for (const el of h.match(/<[^>]+>/g) ?? []) expect(el).toMatch(/^<(title|\/title|meta (property|name)="[a-z_:0-9]+" content="[^"<>]*" \/|link rel="canonical" href="[^"<>]*" \/)>$/);
    expect(cps(tag(h, 'name', 'description')[0])).toBeLessThanOrEqual(DESCRIPTION_MAX);
  });

  it('gives an ID that is not in the data the site card and says so', () => {
    const h = notInDataHead(F.ORIGIN, 'CVE-2019-0001');
    expect(h).toContain('<title>CVE-2019-0001 · CVErdict</title>');
    expect(tag(h, 'property', 'og:title')).toEqual(['CVE-2019-0001']);
    expect(tag(h, 'property', 'og:description')).toEqual([NOT_IN_DATA]);
    expect(tag(h, 'property', 'og:image')).toEqual([`${F.ORIGIN}/og/site.png?v=${SHARE_IMAGES.site.v}`]);
    expect(h).not.toContain('twitter:label');
  });

  it('has a site card without og:url, which would be wrong for every page but /', () => {
    const h = genericHead('https://example.org/cverdict');
    expect(tag(h, 'property', 'og:image')).toEqual([`https://example.org/cverdict/og/site.png?v=${SHARE_IMAGES.site.v}`]);
    expect(h).not.toContain('og:url');
    expect(h).toContain('<title>CVErdict: the few CVEs that matter today</title>');
  });
});

describe('injectHead', () => {
  const tpl = `<head>\n    <meta charset="UTF-8" />\n    ${SHARE_START}\n    <title>x</title>\n    ${SHARE_END}\n    <link rel="icon" />\n</head><body>${SHARE_END}</body>`;

  it('replaces only the marked block', () => {
    const out = injectHead(tpl, '<title>y</title>');
    expect(out).toBe(`<head>\n    <meta charset="UTF-8" />\n    ${SHARE_START}\n    <title>y</title>\n    ${SHARE_END}\n    <link rel="icon" />\n</head><body>${SHARE_END}</body>`);
  });

  it('returns a template without both markers unchanged', () => {
    expect(injectHead('<head><title>x</title></head>', '<title>y</title>')).toBe('<head><title>x</title></head>');
    expect(injectHead(`<head>${SHARE_START}<title>x</title></head>`, '<title>y</title>')).toBe(`<head>${SHARE_START}<title>x</title></head>`);
    expect(injectHead(`<head>${SHARE_END}${SHARE_START}</head>`, 'y')).toBe(`<head>${SHARE_END}${SHARE_START}</head>`);
  });

  it('says whether a template has a block it can fill', () => {
    expect(hasShareBlock(tpl)).toBe(true);
    expect(hasShareBlock(`${SHARE_START}${SHARE_END}`)).toBe(true);
    expect(hasShareBlock(`<head>${SHARE_END}<title>x</title>${SHARE_START}</head>`)).toBe(false);
    expect(hasShareBlock(`<head>${SHARE_START}</head>`)).toBe(false);
  });

  it('keeps $ patterns in vendor names literal', () => {
    const d = { ...F.LIKELY_MSF, affected: [{ vendor: "Ve$&ndor $' $` $$ $1", product: 'X', purl: null }] };
    const out = injectHead(tpl, head(d));
    expect(out).toContain("Ve$&amp;ndor $&#39; $` $$ $1 · X");
    expect(out.match(/<head>/g)).toHaveLength(1);
    expect(out.match(/<title>/g)).toHaveLength(1);
  });

  it('finds the markers in site/index.html and no share tag outside them', () => {
    const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
    const a = html.indexOf(SHARE_START);
    const b = html.indexOf(SHARE_END);
    expect(a).toBeGreaterThan(0);
    expect(b).toBeGreaterThan(a);
    const outside = html.slice(0, a) + html.slice(b);
    expect(outside).not.toMatch(/og:|twitter:|<title|name="description"/);
    const built = injectHead(html, genericHead(F.ORIGIN));
    expect(built.match(/<title>/g)).toHaveLength(1);
    expect(built).toContain(`<meta property="og:image" content="${F.ORIGIN}/og/site.png?v=${SHARE_IMAGES.site.v}" />`);
  });

  it('has a stand-in page with the markers and the site card', () => {
    const page = minimalTemplate(F.ORIGIN);
    expect(page).toContain(SHARE_START);
    expect(page).toContain(SHARE_END);
    expect(page).toContain('og:image');
    expect(injectHead(page, head(F.WATCH))).toContain('CVE-2026-101416: Watch, score 32');
  });
});

describe('readShareRecord', () => {
  const items = F.shardFile(F.EXPLOITED_KEV, F.QUIET_POC).items;

  it('returns the record, undefined when absent, null when malformed', () => {
    expect(readShareRecord(items, 'CVE-2026-109618')).toBe(items['CVE-2026-109618']);
    expect(readShareRecord(items, 'CVE-2019-0001')).toBeUndefined();
    expect(readShareRecord(null, 'CVE-2026-109618')).toBeNull();
    expect(readShareRecord([], 'CVE-2026-109618')).toBeNull();
  });

  it('accepts reasons with a null date, as real shards have', () => {
    const d = { ...F.EXPLOITED_KEV, reasons: F.EXPLOITED_KEV.reasons.map((r) => ({ ...r, at: null as unknown as string })) };
    expect(readShareRecord({ [d.id]: d }, d.id)).toBe(d);
  });

  it('rejects records whose fields are not what the contract promises', () => {
    const bad: Partial<Record<keyof CveDetail, unknown>>[] = [
      { id: 'CVE-2026-1' },
      { score: { value: Number.NaN, tier: 'exploited' } },
      { score: { value: 101, tier: 'exploited' } },
      { score: { value: 50, tier: 'urgent' } },
      { affected: [{ vendor: 1, product: 'x' }] },
      { reasons: 'none' },
      { reasons: [{ id: 'x', label: 'y', polarity: 'up', family: 'X', points: Number.POSITIVE_INFINITY }] },
      { kev: { date_added: 5 } },
      { epss: { score: '0.5' } },
      { exploits: { metasploit: [], nuclei: [], exploitdb: [], poc: { count: -1, vetted: 0 } } },
      { cna: 'x'.repeat(5000) },
    ];
    for (const over of bad) {
      const d = { ...F.EXPLOITED_KEV, ...over } as unknown as CveDetail;
      expect(readShareRecord({ 'CVE-2026-109618': d }, 'CVE-2026-109618'), JSON.stringify(over).slice(0, 80)).toBeNull();
    }
  });

  it('only reads own properties', () => {
    const parsed = JSON.parse('{"__proto__": {"id": "x"}, "CVE-2026-1": null}') as Record<string, unknown>;
    expect(readShareRecord(parsed, '__proto__')).toBeNull();
    expect(readShareRecord(parsed, 'constructor')).toBeUndefined();
    expect(readShareRecord(parsed, 'toString')).toBeUndefined();
  });
});

describe('siteOrigin', () => {
  it('prefers SITE_URL, then the production domain, then BRAND.siteUrl', () => {
    expect(siteOrigin({ SITE_URL: 'https://owner.github.io/cverdict/', VERCEL_PROJECT_PRODUCTION_URL: 'x.vercel.app' })).toBe('https://owner.github.io/cverdict');
    expect(siteOrigin({ VERCEL_PROJECT_PRODUCTION_URL: 'cverdict-psi.vercel.app' })).toBe('https://cverdict-psi.vercel.app');
    expect(siteOrigin({ SITE_URL: 'javascript:alert(1)', VERCEL_PROJECT_PRODUCTION_URL: '' })).toBe('https://cverdict-psi.vercel.app');
    expect(siteOrigin({ SITE_URL: 'not a url' })).toBe('https://cverdict-psi.vercel.app');
    expect(siteOrigin({})).toBe('https://cverdict-psi.vercel.app');
  });
});

describe('isPreviewBot', () => {
  const BOTS = [
    'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
    'Twitterbot/1.0',
    'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    'facebookexternalhit/1.1 Facebot Twitterbot/1.0',
    'Mastodon/4.3.0 (http.rb/5.2.0; +https://mastodon.social/) Bot',
    'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
    'TelegramBot (like TwitterBot)',
    'WhatsApp/2.23.20.0 A',
    'Mozilla/5.0 (compatible; Bluesky Cardyb/1.1; +mailto:support@bsky.app)',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5 skype-url-preview@microsoft.com',
    'Synapse (bot; +https://github.com/matrix-org/synapse)',
  ];
  const PEOPLE_AND_CRAWLERS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; CUBOT KINGKONG 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Twitter for iPhone/10.70',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [LinkedInApp]/9.30.4',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/490.0.0]',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Slack/4.41.105 Chrome/130.0.0.0 Electron/33.0.2 Safari/537.36 Sonic Slack_SSB/4.41.105',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9170 Chrome/128.0.0.0 Electron/32.2.0 Safari/537.36',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
    '',
  ];

  it('matches link-preview fetchers', () => {
    for (const ua of BOTS) expect(isPreviewBot(ua), ua).toBe(true);
  });

  it('matches no browser, in-app browser, desktop app or crawler', () => {
    for (const ua of PEOPLE_AND_CRAWLERS) expect(isPreviewBot(ua), ua).toBe(false);
  });

  it('is a plain alternation that means the same anchored or not', () => {
    expect(BOT_UA_VALUE).toMatch(/^\.\*\([^()[\]{}?+*\\]+\)\.\*$/);
    const unanchored = new RegExp(BOT_UA_VALUE);
    for (const ua of [...BOTS, ...PEOPLE_AND_CRAWLERS]) expect(unanchored.test(ua), ua).toBe(isPreviewBot(ua));
  });

});

describe('share images', () => {
  it('match their table: SHA-256 prefix, PNG signature and a 1200x630 IHDR', () => {
    for (const [key, img] of Object.entries(SHARE_IMAGES)) {
      const png = readFileSync(new URL(`../site/public${img.path}`, import.meta.url));
      expect(createHash('sha256').update(png).digest('hex').slice(0, 8), key).toBe(img.v);
      expect(png.subarray(0, 8).toString('hex')).toBe('89504e470d0a1a0a');
      expect(png.subarray(12, 16).toString('latin1')).toBe('IHDR');
      expect([png.readUInt32BE(16), png.readUInt32BE(20)]).toEqual([SHARE_IMAGE_WIDTH, SHARE_IMAGE_HEIGHT]);
      expect(png.length).toBeLessThan(120_000);
      expect(img.alt).not.toContain('\u2014');
    }
  });
});
