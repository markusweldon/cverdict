/**
 * Link previews: the text of a CVE's preview (title, description, tags) and the HTML head block
 * that carries it. Used by the bot-only function (api/share.ts), the site build (the static site
 * card in index.html) and the CVE page (document title and meta description).
 *
 * Pure: no DOM or Node APIs. Imports carry `.js` extensions because api/share.ts runs this as
 * plain Node ESM. Every value placed in HTML goes through escapeHtml(); every string from a CVE
 * record (vendor, product, CNA, chip labels) goes through cleanText() first. Every number in the
 * output comes from the record or from KNOB_DEFAULT and WATCH_FLOOR.
 */
import { BRAND } from './brand.js';
import { cnaName } from './cna.js';
import { KNOB_DEFAULT, TIERS, type CveDetail, type Tier } from './contract.js';
import { SHARE_IMAGE_HEIGHT, SHARE_IMAGE_WIDTH, SHARE_IMAGES } from './share-images.js';
import { fmtDay, fmtRunTime, TIER_NAMES, verdict } from './verdict.js';

/**
 * The public origin for absolute URLs in previews: SITE_URL, else the Vercel production domain,
 * else BRAND.siteUrl. Never a request's Host header. No trailing slash; a GitHub Pages URL keeps
 * its base path.
 */
export function siteOrigin(env: Readonly<Record<string, string | undefined>>): string {
  for (const raw of [env.SITE_URL, env.VERCEL_PROJECT_PRODUCTION_URL && `https://${env.VERCEL_PROJECT_PRODUCTION_URL}`]) {
    if (!raw?.trim()) continue;
    try {
      const url = new URL(raw.trim());
      if ((url.protocol === 'https:' || url.protocol === 'http:') && !url.search && !url.hash) return url.href.replace(/\/+$/, '');
    } catch {
      // not a URL: try the next one
    }
  }
  return BRAND.siteUrl;
}

/** index.html carries the share block between these markers; the function replaces what is inside. */
export const SHARE_START = '<!--share:start-->';
export const SHARE_END = '<!--share:end-->';

/** Longest description, in code points. */
export const DESCRIPTION_MAX = 200;
/** Longest image alt text, in code points. */
export const ALT_MAX = 420;

/** C0 and C1 controls (tabs and newlines included): become spaces. */
const CONTROLS = /[\u0000-\u001F\u007F-\u009F]/g;
/**
 * Every default-ignorable code point and lone surrogates: removed, so text cannot hide or reverse.
 * That is the zero-width characters, all bidi controls (U+061C, U+200E, U+200F, U+202A to U+202E,
 * U+2066 to U+2069), word joiners, the BOM, soft hyphens, fillers, variation selectors and the
 * tag characters U+E0000 to U+E007F, which render as nothing and can carry hidden text.
 */
const INVISIBLE = /\p{Default_Ignorable_Code_Point}|\p{Cs}/gu;

/**
 * Plain, single-line, bounded text from untrusted input: controls become spaces, invisible and
 * bidi characters go, whitespace collapses, " U+2014 " becomes ", " (and any other em dash a hyphen),
 * and the result is cut to `max` code points with "…", never inside a surrogate pair.
 */
export function cleanText(input: unknown, max: number): string {
  if (typeof input !== 'string' || max < 1) return '';
  const s = input
    .slice(0, max * 4)
    .replace(CONTROLS, ' ')
    .replace(INVISIBLE, '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/ \u2014 /g, ', ')
    .replace(/\u2014/g, '-');
  const cps = Array.from(s);
  return cps.length <= max ? s : `${cps.slice(0, max - 1).join('').trimEnd()}…`;
}

const ESCAPES: Readonly<Record<string, string>> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
/** Escape for HTML text and double- or single-quoted attribute values. */
export const escapeHtml = (s: string): string => s.replace(/[&<>"']/g, (c) => ESCAPES[c]);

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const isBlank = (s: string) => !s || /^(unknown|n\/a)$/i.test(s);

/** "PHP Group · PHP", the product alone when it starts with the vendor, else "Published by <CNA>". */
export function shareSubject(d: CveDetail): string {
  const a = d.affected[0];
  const vendor = cleanText(a?.vendor, 60);
  const product = cleanText(a?.product, 80);
  if (isBlank(vendor) && isBlank(product)) return `Published by ${cleanText(cnaName(cleanText(d.cna, 60)), 60)}`;
  if (isBlank(vendor)) return product;
  if (isBlank(product) || vendor.toLowerCase() === product.toLowerCase()) return vendor;
  return product.toLowerCase().startsWith(vendor.toLowerCase()) ? product : `${vendor} · ${product}`;
}

/** The KEV part of a preview, as a row ("CISA KEV: added Oct 26, due Oct 29") and as a short field. */
function kevText(d: CveDetail, refYear: number): { row: string; field: string } {
  if (d.kev) {
    const added = fmtDay(d.kev.date_added, refYear);
    const due = fmtDay(d.kev.due_date, refYear);
    const dates = [added && `added ${added}`, due && `due ${due}`].filter(Boolean).join(', ');
    const ransomware = d.kev.ransomware === 'Known' ? ', known ransomware use' : '';
    const field = dates ? `${dates}${ransomware}` : `listed${ransomware}`;
    return { row: `CISA KEV: ${field}`, field: field[0].toUpperCase() + field.slice(1) };
  }
  // Listed through the CISA-ADP KEV block of the CVE record, before the catalog has it.
  const adp = d.reasons.find((r) => r.id === 'kev.listed');
  if (adp) {
    const added = fmtDay(adp.at, refYear);
    const field = added ? `added ${added} (per the CVE record)` : 'listed (per the CVE record)';
    return { row: `CISA KEV: ${field}`, field: field[0].toUpperCase() + field.slice(1) };
  }
  return { row: 'CISA KEV: not listed', field: 'Not listed' };
}

/**
 * "Public exploits: Metasploit 1, Nuclei 1, Exploit-DB 1, 3 vetted PoC repos (unverified code)".
 * Without any, never a universal claim: what our feeds (Metasploit, Nuclei, Exploit-DB,
 * PoC-in-GitHub) have, "after 14 days" only when the x.none chip says absence is settled.
 */
export function exploitsRow(d: CveDetail): string {
  const e = d.exploits;
  const parts: string[] = [];
  if (e.metasploit.length) parts.push(`Metasploit ${e.metasploit.length}`);
  if (e.nuclei.length) parts.push(`Nuclei ${e.nuclei.length}`);
  if (e.exploitdb.length) parts.push(`Exploit-DB ${e.exploitdb.length}`);
  if (e.poc.vetted > 0) parts.push(`${plural(e.poc.vetted, 'vetted PoC repo')} (unverified code)`);
  else if (e.poc.count > 0) parts.push(`${plural(e.poc.count, 'unvetted PoC repo')} (unverified code)`);
  if (parts.length) return `Public exploits: ${parts.join(', ')}`;
  if (d.reasons.some((r) => r.id === 'x.none')) return 'No public exploit in our feeds after 14 days';
  return 'No public exploit in our feeds yet';
}

/**
 * Up to `n` counted chips that raised the score, in reasons[] order. Exploitation (E) and exploit
 * (X) chips are left out: the verdict, the KEV row and the exploits row already say what they say.
 */
export function topReasons(d: CveDetail, n = 2): string[] {
  return d.reasons
    .filter((r) => r.polarity === 'up' && r.points > 0 && r.family !== 'E' && r.family !== 'X')
    .slice(0, n)
    .map((r) => cleanText(r.label, 80))
    .filter(Boolean);
}

/** "CVE-2026-109618: Exploited, score 100". */
export const shareTitle = (d: CveDetail, tier: Tier): string => `${d.id}: ${TIER_NAMES[tier]}, score ${d.score.value}`;

const len = (s: string) => Array.from(s).length;
const sentence = (s: string) => s.replace(/[.\s]+$/, '');

/**
 * The description: verdict, subject, KEV row, exploits row, up to 2 reasons and "As of <run>",
 * joined with ". ". Reasons go first, then the exploits row, then the subject shrinks, until it
 * fits DESCRIPTION_MAX. Without `generatedAt` (the CVE page before meta.json loads) the run time
 * is left out.
 */
export function shareDescription(d: CveDetail, tier: Tier, knob: number, generatedAt: string | null): string {
  const run = fmtRunTime(generatedAt);
  const refYear = generatedAt && run ? new Date(Date.parse(generatedAt)).getUTCFullYear() : new Date().getUTCFullYear();
  const v = verdict(d, tier, knob, refYear);
  const head = cleanText(`${v.head}: ${v.reason}`, 90);
  const kev = kevText(d, refYear).row;
  const tail = run ? [`As of ${run}`] : [];
  let subject = shareSubject(d);
  let exploits: string | null = exploitsRow(d);
  let reasons = topReasons(d);
  // A part cut with "…" reads on without a period after it.
  const build = () =>
    [head, subject, kev, exploits, ...reasons, ...tail]
      .filter((p): p is string => !!p)
      .map((p) => (p.endsWith('…') ? p : `${sentence(p)}.`))
      .join(' ');
  while (len(build()) > DESCRIPTION_MAX && reasons.length) reasons = reasons.slice(0, -1);
  if (len(build()) > DESCRIPTION_MAX) exploits = null;
  if (len(build()) > DESCRIPTION_MAX) {
    const over = len(build()) - DESCRIPTION_MAX;
    subject = len(subject) - over >= 12 ? cleanText(subject, len(subject) - over) : '';
  }
  return cleanText(build(), DESCRIPTION_MAX);
}

/** A tier's image alt text: the image's own words. */
const tierAlt = (tier: Tier) => SHARE_IMAGES[tier].alt;
const imageUrl = (origin: string, key: keyof typeof SHARE_IMAGES) => `${origin}${SHARE_IMAGES[key].path}?v=${SHARE_IMAGES[key].v}`;

type Tag = ['title', string] | ['canonical', string] | ['property' | 'name', string, string];
function render(tags: Tag[]): string {
  return tags
    .map((t) => {
      if (t[0] === 'title') return `<title>${escapeHtml(t[1])}</title>`;
      if (t[0] === 'canonical') return `<link rel="canonical" href="${escapeHtml(t[1])}" />`;
      return `<meta ${t[0]}="${t[1]}" content="${escapeHtml(t[2])}" />`;
    })
    .join('\n    ');
}

const imageTags = (url: string, alt: string): Tag[] => [
  ['property', 'og:image', url],
  ['property', 'og:image:type', 'image/png'],
  ['property', 'og:image:width', String(SHARE_IMAGE_WIDTH)],
  ['property', 'og:image:height', String(SHARE_IMAGE_HEIGHT)],
  ['property', 'og:image:alt', alt],
];

/** The site card: the static block of index.html (no og:url, which would be wrong for every page but /). */
export function genericHead(origin: string): string {
  const alt = SHARE_IMAGES.site.alt;
  return render([
    ['title', `${BRAND.name}: the few CVEs that matter today`],
    ['name', 'description', BRAND.pitch],
    ['property', 'og:site_name', BRAND.name],
    ['property', 'og:type', 'website'],
    ['property', 'og:title', `${BRAND.name}: every CVE gets a verdict`],
    ['property', 'og:description', 'Every verdict comes with receipts. Open-source CVE triage from CISA KEV, EPSS and public exploit feeds, with every score explained.'],
    ...imageTags(imageUrl(origin, 'site'), alt),
    ['name', 'twitter:card', 'summary_large_image'],
    ['name', 'twitter:image:alt', alt],
  ]);
}

/** What the CVE page says for an ID that is in no shard. */
export const NOT_IN_DATA = `Not in ${BRAND.name}'s data, which covers CVEs published in the last 30 days, every CISA KEV entry and older CVEs with new exploit evidence in the last 30 days. The page links to the record on cve.org.`;

const cveUrl = (origin: string, id: string) => `${origin}/cve/${id}`;

/** A valid CVE ID that is not in the data: the site card with "not in the data" text. */
export function notInDataHead(origin: string, id: string): string {
  const alt = SHARE_IMAGES.site.alt;
  return render([
    ['title', `${id} · ${BRAND.name}`],
    ['name', 'description', NOT_IN_DATA],
    ['canonical', cveUrl(origin, id)],
    ['property', 'og:site_name', BRAND.name],
    ['property', 'og:type', 'article'],
    ['property', 'og:url', cveUrl(origin, id)],
    ['property', 'og:title', id],
    ['property', 'og:description', NOT_IN_DATA],
    ...imageTags(imageUrl(origin, 'site'), alt),
    ['name', 'twitter:card', 'summary_large_image'],
    ['name', 'twitter:title', id],
    ['name', 'twitter:description', NOT_IN_DATA],
    ['name', 'twitter:image', imageUrl(origin, 'site')],
    ['name', 'twitter:image:alt', alt],
  ]);
}

/** The per-CVE block, at the default knob (bots never see a turned knob). */
export function shareHead({ origin, detail: d, generatedAt }: { origin: string; detail: CveDetail; generatedAt: string }): string {
  const tier = d.score.tier;
  const title = shareTitle(d, tier);
  const description = shareDescription(d, tier, KNOB_DEFAULT, generatedAt);
  const image = imageUrl(origin, tier);
  const alt = cleanText(tierAlt(tier), ALT_MAX);
  const refYear = new Date(Date.parse(generatedAt)).getUTCFullYear();
  return render([
    ['title', `${title} · ${BRAND.name}`],
    ['name', 'description', description],
    ['canonical', cveUrl(origin, d.id)],
    ['property', 'og:site_name', BRAND.name],
    ['property', 'og:type', 'article'],
    ['property', 'og:url', cveUrl(origin, d.id)],
    ['property', 'og:title', title],
    ['property', 'og:description', description],
    ...imageTags(image, alt),
    ['name', 'twitter:card', 'summary_large_image'],
    ['name', 'twitter:title', title],
    ['name', 'twitter:description', description],
    ['name', 'twitter:image', image],
    ['name', 'twitter:image:alt', alt],
    ['name', 'twitter:label1', 'Verdict'],
    ['name', 'twitter:data1', `${TIER_NAMES[tier]}, ${d.score.value} of 100`],
    ['name', 'twitter:label2', 'CISA KEV'],
    ['name', 'twitter:data2', kevText(d, refYear).field],
  ]);
}

/**
 * Replace what sits between the markers with `head`, by slicing: String.prototype.replace would
 * expand `$&`, `` $` `` and `$'` found in CNA text into pieces of the template. A template without
 * both markers comes back unchanged.
 */
export function injectHead(html: string, head: string): string {
  const block = shareBlock(html);
  if (!block) return html;
  return `${html.slice(0, block[0] + SHARE_START.length)}\n    ${head}\n    ${html.slice(block[1])}`;
}

/** Where the share block's start and end markers are: a start marker with an end marker after it. */
function shareBlock(html: string): [number, number] | null {
  const a = html.indexOf(SHARE_START);
  const b = a < 0 ? -1 : html.indexOf(SHARE_END, a + SHARE_START.length);
  return a < 0 || b < 0 ? null : [a, b];
}

/** True when injectHead() can fill `html`; both markers somewhere in it is not enough. */
export const hasShareBlock = (html: string): boolean => shareBlock(html) !== null;

/** A stand-in page for when the built index.html cannot be loaded: the site card and a link. */
export function minimalTemplate(origin: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    ${SHARE_START}
    ${genericHead(origin)}
    ${SHARE_END}
  </head>
  <body>
    <p><a href="${escapeHtml(origin)}/">${escapeHtml(BRAND.name)}</a></p>
  </body>
</html>
`;
}

// ── Reading a record from an untrusted shard ─────────────────────────────────────────────────

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStr = (v: unknown, max = 400): v is string => typeof v === 'string' && v.length <= max;
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const count = (v: unknown) => isNum(v) && v >= 0 && Number.isInteger(v);
const strArray = (v: unknown, max: number) => Array.isArray(v) && v.length <= max;

/**
 * The record `id` of a parsed shard's `items` when every field the preview reads has the shape
 * and range the contract promises; null otherwise (the caller then answers with the site card).
 * `undefined` when the shard has no such record.
 */
export function readShareRecord(items: unknown, id: string): CveDetail | null | undefined {
  if (!isObj(items)) return null;
  if (!Object.hasOwn(items, id)) return undefined;
  const d = items[id];
  if (!isObj(d) || d.id !== id || !isStr(d.cna)) return null;
  const s = d.score;
  if (!isObj(s) || !isNum(s.value) || s.value < 0 || s.value > 100 || !Number.isInteger(s.value) || !TIERS.includes(s.tier as Tier)) return null;
  if (!strArray(d.affected, 50) || !(d.affected as unknown[]).every((a) => isObj(a) && isStr(a.vendor) && isStr(a.product))) return null;
  if (!strArray(d.reasons, 200)) return null;
  for (const r of d.reasons as unknown[]) {
    if (!isObj(r) || !isStr(r.id, 64) || !isStr(r.label, 1000) || !isStr(r.polarity, 16) || !isStr(r.family, 16) || !isNum(r.points)) return null;
    if (r.at !== undefined && r.at !== null && !isStr(r.at, 40)) return null;
  }
  if (d.kev !== null && (!isObj(d.kev) || !isStr(d.kev.date_added, 40) || !isStr(d.kev.due_date, 40) || !isStr(d.kev.ransomware, 40))) return null;
  if (d.ssvc !== null && (!isObj(d.ssvc) || !isStr(d.ssvc.exploitation, 40))) return null;
  if (d.epss !== null && (!isObj(d.epss) || !isNum(d.epss.score))) return null;
  const e = d.exploits;
  if (!isObj(e) || !strArray(e.metasploit, 1000) || !strArray(e.nuclei, 1000) || !strArray(e.exploitdb, 1000)) return null;
  if (!isObj(e.poc) || !count(e.poc.count) || !count(e.poc.vetted)) return null;
  return d as unknown as CveDetail;
}

// ── Which user-agents get the per-CVE head ───────────────────────────────────────────────────

/**
 * Link-preview fetchers, matched exactly and case-sensitively. Not in-app browsers (LinkedInApp,
 * FBAN, Twitter for iPhone, the Slack/ and discord/ desktop apps), not crawlers (Googlebot,
 * Bingbot, GPTBot, ClaudeBot, AhrefsBot), and not a bare "bot", which matches phones like CUBOT.
 */
export const BOT_UA_TOKENS: readonly string[] = [
  'Slackbot-LinkExpanding',
  'Twitterbot',
  'facebookexternalhit',
  'Facebot',
  'LinkedInBot',
  'Discordbot',
  'TelegramBot',
  'WhatsApp/',
  'Mastodon/',
  'Bluesky Cardyb',
  'SkypeUriPreview',
  'redditbot',
  'Iframely',
  'Embedly',
  'Synapse',
  'Mattermost-Bot',
];

/** The `has` value of the bot rewrite in vercel.json: a plain alternation, the same in Vercel's matcher and in JS. */
export const BOT_UA_VALUE = `.*(${BOT_UA_TOKENS.join('|')}).*`;
const BOT_UA_RE = new RegExp(`^${BOT_UA_VALUE}$`);

/** True for the user-agents the bot rewrite sends to the function. */
export const isPreviewBot = (ua: string): boolean => BOT_UA_RE.test(ua);
