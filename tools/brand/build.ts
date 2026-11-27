/**
 * Builds the README images in docs/assets/ from code: the logo, the diagrams and the social
 * preview source. Run from the repository root:
 *
 *   npm run brand                          # reads the live data branch
 *   npm run brand -- --data <dir>          # or a local data tree (its v1/ folder or the folder above)
 *   npm run brand -- --data <dir> --out <dir>   # and write somewhere else
 *
 * Every number in the images comes from the data (meta.json, stats.json, receipts.json,
 * batches.json and one CVE shard) or from the code (shared/model.ts, shared/contract.ts), and each
 * image says which run it shows. The colours are the site's, read from site/src/styles/tokens.css,
 * and the icons are the site's own (site/src/components/icons.tsx).
 *
 * Each image comes in a dark and a light version for <picture> in the README. The SVGs embed Geist
 * and Geist Mono (SIL OFL 1.1, from @fontsource-variable) as data URIs and contain no scripts, no
 * external references and no foreignObject, so they render the same inside GitHub's image sandbox.
 * tools/brand/render.mjs turns social-preview.svg into the PNG for the repository settings.
 * Brand rules: tools/brand/README.md. Do not hand-edit the SVGs; change this file and rerun it.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BRAND, RAW_DATA_URL } from '../../shared/brand';
import { KNOB_DEFAULT, KNOB_MAX, KNOB_MIN, WATCH_FLOOR, type BatchesFile, type CveDetail, type Meta, type ReceiptsFile, type StatsFile } from '../../shared/contract';
import { BASE_POINTS, CHIPS, COLD_START_DAYS, EXPLOITED_BONUS, EXPLOITED_FLOOR, SCORE_MODEL } from '../../shared/model';
import { cnaName } from '../../shared/cna';
import { shardOf } from '../../shared/shard';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');

// ------------------------------------------------------------------------------------------------
// Arguments and data
// ------------------------------------------------------------------------------------------------

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}
const DATA = arg('data') ?? `${RAW_DATA_URL}/v1`;
/** Where the images go (docs/assets/ unless --out is given, e.g. to try other data). */
const OUT = arg('out') ?? join(ROOT, 'docs', 'assets');
/** A CVE to use as the worked example on the scoring card; picked from the data when absent. */
const EXAMPLE = arg('example');

async function load<T>(file: string): Promise<T> {
  if (/^https?:\/\//.test(DATA)) {
    const res = await fetch(`${DATA}/${file}`);
    if (!res.ok) throw new Error(`${DATA}/${file}: HTTP ${res.status}`);
    return (await res.json()) as T;
  }
  for (const dir of [DATA, join(DATA, 'v1')]) {
    try {
      return JSON.parse(readFileSync(join(dir, file), 'utf8')) as T;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }
  throw new Error(`${file} not found under ${DATA}`);
}

const meta = await load<Meta>('meta.json');
const stats = await load<StatsFile>('stats.json');
const receipts = await load<ReceiptsFile>('receipts.json');
const batches = await load<BatchesFile>('batches.json');

// ------------------------------------------------------------------------------------------------
// Brand tokens (site/src/styles/tokens.css)
// ------------------------------------------------------------------------------------------------

type ThemeName = 'dark' | 'light';
interface Theme {
  name: ThemeName;
  bg: string;
  surface: string;
  raised: string;
  border: string;
  borderStrong: string;
  text: string;
  muted: string;
  faint: string;
  faintUi: string;
  accent: string;
  onAccent: string;
  exploited: string;
  likely: string;
  watch: string;
  quiet: string;
  ai: string;
  ok: string;
  wfQuiet: string;
  wfWatch: string;
  /** Tier text colours: the tier colour, darkened in the light theme to pass AA, as on the site. */
  ink: Record<Tier, string>;
  glow: number;
}
type Tier = 'exploited' | 'likely' | 'watch' | 'quiet';

function tokenBlock(css: string, selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`tokens.css: no ${selector} block`);
  const body = css.slice(css.indexOf('{', start) + 1, css.indexOf('}', start));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) out[m[1]] = m[2].toLowerCase();
  return out;
}

function hex(c: string): [number, number, number] {
  return [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16)) as [number, number, number];
}
/** color-mix(in srgb, a p, b). */
function mix(a: string, b: string, p: number): string {
  const [x, y] = [hex(a), hex(b)];
  return `#${x.map((v, i) => Math.round(v * p + y[i] * (1 - p)).toString(16).padStart(2, '0')).join('')}`;
}

const CSS = readFileSync(join(ROOT, 'site/src/styles/tokens.css'), 'utf8');
function theme(name: ThemeName): Theme {
  const t = tokenBlock(CSS, name === 'dark' ? ':root {' : ":root[data-theme='light']");
  const need = (k: string) => {
    if (!t[k]) throw new Error(`tokens.css (${name}) has no --${k}`);
    return t[k];
  };
  const ink = (k: Tier) => (name === 'light' && k !== 'quiet' ? mix(need(k), need('text'), 0.82) : k === 'quiet' ? need('muted') : need(k));
  return {
    name,
    bg: need('bg'),
    surface: need('surface'),
    raised: need('raised'),
    border: need('border'),
    borderStrong: need('border-strong'),
    text: need('text'),
    muted: need('muted'),
    faint: need('faint'),
    faintUi: need('faint-ui'),
    accent: need('accent'),
    onAccent: need('on-accent'),
    exploited: need('exploited'),
    likely: need('likely'),
    watch: need('watch'),
    quiet: need('quiet'),
    ai: need('ai'),
    ok: need('ok'),
    wfQuiet: need('wf-quiet'),
    wfWatch: need('wf-watch'),
    ink: { exploited: ink('exploited'), likely: ink('likely'), watch: ink('watch'), quiet: ink('quiet') },
    glow: name === 'dark' ? 0.11 : 0.07,
  };
}
const THEMES: Theme[] = [theme('dark'), theme('light')];
/** A tier colour as a fill tint on the card, like the site's --t-* tokens. */
const tint = (T: Theme, c: string, p = 0.12) => mix(c, T.name === 'dark' ? T.bg : T.surface, p);
const card = (T: Theme) => (T.name === 'dark' ? T.bg : T.bg);
const panel = (T: Theme) => (T.name === 'dark' ? T.surface : T.surface);

// ------------------------------------------------------------------------------------------------
// Fonts and text
// ------------------------------------------------------------------------------------------------

const fontFile = (pkg: string, file: string) => readFileSync(join(ROOT, 'node_modules', pkg, 'files', file)).toString('base64');
const FONT_SANS = fontFile('@fontsource-variable/geist', 'geist-latin-wght-normal.woff2');
const FONT_MONO = fontFile('@fontsource-variable/geist-mono', 'geist-mono-latin-wght-normal.woff2');
const SANS = "CVSans, Geist, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";
const MONO = "CVMono, 'Geist Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace";

interface Metrics {
  unitsPerEm: number;
  sans: Record<string, Record<string, number>>;
  mono: Record<string, Record<string, number>>;
}
const METRICS = JSON.parse(readFileSync(join(HERE, 'metrics.json'), 'utf8')) as Metrics;

type Font = 'sans' | 'mono';
function measure(s: string, size: number, font: Font = 'sans', weight = 400, ls = 0): number {
  const ws = Object.keys(METRICS[font]).map(Number);
  const w = ws.reduce((a, b) => (Math.abs(b - weight) < Math.abs(a - weight) ? b : a));
  const row = METRICS[font][String(w)];
  let units = 0;
  for (const ch of s) units += row[ch] ?? 600;
  return (units / METRICS.unitsPerEm) * size + ls * Math.max(0, [...s].length - 1);
}

/** Greedy word wrap to a width. */
function wrap(s: string, max: number, size: number, font: Font = 'sans', weight = 400): string[] {
  const lines: string[] = [];
  let line = '';
  for (const word of s.split(' ')) {
    const next = line ? `${line} ${word}` : word;
    if (line && measure(next, size, font, weight) > max) {
      lines.push(line);
      line = word;
    } else line = next;
  }
  if (line) lines.push(line);
  return lines;
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const r1 = (n: number) => Math.round(n * 10) / 10;

interface TextOpts {
  size?: number;
  weight?: number;
  font?: Font;
  fill: string;
  anchor?: 'start' | 'middle' | 'end';
  ls?: number;
  opacity?: number;
}
function text(x: number, y: number, s: string, o: TextOpts): string {
  const size = o.size ?? 16;
  const attrs = [
    `x="${r1(x)}"`,
    `y="${r1(y)}"`,
    `font-family="${o.font === 'mono' ? MONO : SANS}"`,
    `font-size="${size}"`,
    `font-weight="${o.weight ?? 400}"`,
    `fill="${o.fill}"`,
  ];
  if (o.anchor && o.anchor !== 'start') attrs.push(`text-anchor="${o.anchor}"`);
  if (o.ls) attrs.push(`letter-spacing="${o.ls}"`);
  if (o.opacity !== undefined) attrs.push(`opacity="${o.opacity}"`);
  return `<text ${attrs.join(' ')}>${esc(s)}</text>`;
}
/** Several runs on one baseline, e.g. a bold word and a regular one. */
function runs(x: number, y: number, parts: { s: string; o: TextOpts }[]): string {
  let out = '';
  let cx = x;
  for (const p of parts) {
    const size = p.o.size ?? 16;
    const lead = p.s.length - p.s.trimStart().length;
    const s = p.s.trim();
    cx += lead * measure(' ', size, p.o.font ?? 'sans', p.o.weight ?? 400);
    out += text(cx, y, s, p.o);
    cx += measure(s, size, p.o.font ?? 'sans', p.o.weight ?? 400, p.o.ls ?? 0) + (p.o.ls ?? 0);
    const trail = p.s.length - p.s.trimEnd().length;
    if (s && trail) cx += trail * measure(' ', size, p.o.font ?? 'sans', p.o.weight ?? 400);
  }
  return out;
}
function lines(x: number, y: number, ls: string[], lh: number, o: TextOpts): string {
  return ls.map((l, i) => text(x, y + i * lh, l, o)).join('');
}
/** Monospace uppercase label, the site's eyebrow style. */
const eyebrow = (x: number, y: number, s: string, fill: string, anchor: TextOpts['anchor'] = 'start', size = 13) =>
  text(x, y, s.toUpperCase(), { size, font: 'mono', weight: 500, fill, ls: 1.6, anchor });

const rect = (x: number, y: number, w: number, h: number, rx: number, fill: string, stroke?: string, extra = '') =>
  `<rect x="${r1(x)}" y="${r1(y)}" width="${r1(w)}" height="${r1(h)}" rx="${rx}" fill="${fill}"${stroke ? ` stroke="${stroke}"` : ''}${extra ? ` ${extra}` : ''}/>`;

// ------------------------------------------------------------------------------------------------
// Icons: the site's own 16px stroke icons, read from site/src/components/icons.tsx
// ------------------------------------------------------------------------------------------------

const ICON_SRC = readFileSync(join(ROOT, 'site/src/components/icons.tsx'), 'utf8');
const ICONS: Record<string, { body: string; fill: boolean }> = {};
for (const m of ICON_SRC.matchAll(/export const Icon(\w+) = \(p: IconProps\) => \(\s*<Svg \{\.\.\.p\}( fill)?>([\s\S]*?)<\/Svg>/g)) {
  ICONS[m[1]] = { fill: Boolean(m[2]), body: m[3].replace(/\s+/g, ' ').trim() };
}
const MARK = /<path d="(M3 22\.5[^"]+)"/.exec(ICON_SRC)?.[1];
if (!MARK) throw new Error('icons.tsx: brand mark path not found');

function icon(name: string, x: number, y: number, size: number, color: string, width = 1.5): string {
  const i = ICONS[name];
  if (!i) throw new Error(`icons.tsx has no Icon${name}`);
  const body = i.body.replace(/currentColor/g, color);
  const paint = i.fill ? `fill="${color}" stroke="none"` : `fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round"`;
  return `<g transform="translate(${r1(x)} ${r1(y)}) scale(${size / 16})" ${paint}>${body}</g>`;
}
/** The brand mark: a flat noise floor with one signal spike rising out of it. */
function mark(x: number, y: number, size: number, color: string): string {
  return `<g transform="translate(${r1(x)} ${r1(y)}) scale(${size / 32})" fill="none"><path d="${MARK}" stroke="${color}" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/><circle cx="19" cy="5.5" r="2.2" fill="${color}"/></g>`;
}
/** An icon on a tinted rounded tile. */
function iconTile(T: Theme, name: string, x: number, y: number, size: number, color: string): string {
  return rect(x, y, size, size, Math.round(size / 4), tint(T, color, T.name === 'dark' ? 0.14 : 0.1), mix(color, panel(T), 0.35)) + icon(name, x + size * 0.22, y + size * 0.22, size * 0.56, color, 1.6);
}

// ------------------------------------------------------------------------------------------------
// Document frame
// ------------------------------------------------------------------------------------------------

function svgDoc(w: number, h: number, title: string, desc: string, body: string, opts: { transparent?: boolean } = {}): string {
  const usesMono = body.includes('CVMono');
  const fonts =
    `@font-face{font-family:CVSans;src:url(data:font/woff2;base64,${FONT_SANS}) format('woff2');font-weight:100 900;font-style:normal}` +
    (usesMono ? `@font-face{font-family:CVMono;src:url(data:font/woff2;base64,${FONT_MONO}) format('woff2');font-weight:100 900;font-style:normal}` : '');
  void opts;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-labelledby="t d">` +
    `<title id="t">${esc(title)}</title><desc id="d">${esc(desc)}</desc>` +
    `<style>${fonts}text{font-kerning:normal}</style>` +
    body +
    `</svg>\n`
  );
}

/** The card every diagram sits on: the site's background, a hairline border, a faint dot grid and a lime glow. */
function frame(T: Theme, w: number, h: number, id: string): string {
  const dot = T.name === 'dark' ? '#ffffff' : '#000000';
  return (
    `<defs>` +
    `<pattern id="${id}-dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="12" cy="12" r="1" fill="${dot}" opacity="${T.name === 'dark' ? 0.06 : 0.07}"/></pattern>` +
    `<radialGradient id="${id}-glow" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(${w * 0.08} 0) scale(${w * 0.55} ${h * 0.7})"><stop offset="0" stop-color="${T.accent}" stop-opacity="${T.glow}"/><stop offset="1" stop-color="${T.accent}" stop-opacity="0"/></radialGradient>` +
    `<clipPath id="${id}-clip"><rect width="${w}" height="${h}" rx="20"/></clipPath>` +
    `</defs>` +
    `<g clip-path="url(#${id}-clip)">${rect(0, 0, w, h, 0, card(T))}${rect(0, 0, w, h, 0, `url(#${id}-dots)`)}${rect(0, 0, w, h, 0, `url(#${id}-glow)`)}</g>` +
    rect(0.5, 0.5, w - 1, h - 1, 20, 'none', T.border)
  );
}

/** Eyebrow, title and subtitle at the top left of a card. Returns the svg and the y below it. */
function heading(T: Theme, x: number, y: number, eb: string, title: string, sub?: string, maxW = 900, titleSize = 32): [string, number] {
  let out = eyebrow(x, y, eb, T.faint);
  const tl = wrap(title, maxW, titleSize, 'sans', 600);
  out += lines(x, y + 40, tl, Math.round(titleSize * 1.25), { size: titleSize, weight: 600, fill: T.text, ls: -0.4 });
  let yy = y + 40 + (tl.length - 1) * Math.round(titleSize * 1.25);
  if (sub) {
    const ls = wrap(sub, maxW, 18);
    out += lines(x, yy + 34, ls, 26, { size: 18, fill: T.muted });
    yy += 34 + (ls.length - 1) * 26;
  }
  return [out, yy];
}

function footer(T: Theme, w: number, h: number, left: string, right = BRAND.siteUrl.replace(/^https:\/\//, ''), m = 48): string {
  const rw = measure(right, 14, 'mono', 500) + 26;
  const ls = wrap(left, w - 2 * m - rw - 24, 14);
  const y0 = ls.length > 1 ? h - 37 : h - 28;
  return (
    `<line x1="${m}" y1="${h - 58}" x2="${w - m}" y2="${h - 58}" stroke="${T.border}"/>` +
    lines(m, y0, ls, 18, { size: 14, fill: T.faint }) +
    mark(w - m - rw, h - 44, 18, T.accent) +
    text(w - m, h - 28, right, { size: 14, font: 'mono', weight: 500, fill: T.muted, anchor: 'end' })
  );
}

function arrow(x1: number, y1: number, x2: number, y2: number, color: string, w = 1.5, dash = ''): string {
  const a = Math.atan2(y2 - y1, x2 - x1);
  const s = 7;
  const p1 = [x2 - s * Math.cos(a - 0.45), y2 - s * Math.sin(a - 0.45)];
  const p2 = [x2 - s * Math.cos(a + 0.45), y2 - s * Math.sin(a + 0.45)];
  return (
    `<line x1="${r1(x1)}" y1="${r1(y1)}" x2="${r1(x2)}" y2="${r1(y2)}" stroke="${color}" stroke-width="${w}"${dash ? ` stroke-dasharray="${dash}"` : ''} stroke-linecap="round"/>` +
    `<path d="M${r1(p1[0])} ${r1(p1[1])}L${r1(x2)} ${r1(y2)}L${r1(p2[0])} ${r1(p2[1])}" fill="none" stroke="${color}" stroke-width="${w}" stroke-linecap="round" stroke-linejoin="round"/>`
  );
}

// ------------------------------------------------------------------------------------------------
// Formatting and facts
// ------------------------------------------------------------------------------------------------

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const fmt = (n: number) => n.toLocaleString('en-US');
const pct = (n: number, d: number, digits = 1) => `${((100 * n) / d).toFixed(digits)}%`;
function day(iso: string, year = true): string {
  const d = new Date(iso);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}${year ? `, ${d.getUTCFullYear()}` : ''}`;
}
function stamp(iso: string): string {
  const d = new Date(iso);
  return `${day(iso)} ${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')} UTC`;
}
const RUN = stamp(meta.generated_at);
const C = meta.counts;
const src = (id: string) => meta.sources.find((s) => s.id === id);
const records = (id: string) => {
  const s = src(id);
  return s && s.records !== null && s.records !== undefined ? fmt(s.records) : null;
};
const TIER_NAME: Record<Tier, string> = { exploited: 'Exploited', likely: 'Likely next', watch: 'Watch', quiet: 'Quiet' };
const SITE_STATE = readFileSync(join(ROOT, 'site/src/state.ts'), 'utf8');
const SITE_KNOB_MIN = Number(/SITE_KNOB_MIN\s*=\s*(\d+)/.exec(SITE_STATE)?.[1]);
const SITE_KNOB_MAX = Number(/SITE_KNOB_MAX\s*=\s*(\d+)/.exec(SITE_STATE)?.[1]);
if (!SITE_KNOB_MIN || !SITE_KNOB_MAX) throw new Error('site/src/state.ts: SITE_KNOB_MIN/MAX not found');
const REFRESH = readFileSync(join(ROOT, '.github/workflows/refresh.yml'), 'utf8');
const CRON_MINUTE = /cron:\s*'(\d+) \* \* \* \*'/.exec(REFRESH)?.[1];
if (!CRON_MINUTE) throw new Error('refresh.yml: hourly cron not found');

/** Point range of a family: the strongest chip counts, so the range is [lowest, highest] single chip. */
function familyRange(f: string): [number, number] {
  const pts = CHIPS.filter((c) => c.family === f && c.polarity !== 'info').map((c) => c.points);
  return [Math.min(0, ...pts), Math.max(0, ...pts)];
}
/** SSVC: two decision points that add (automatable, technical impact). */
function ssvcRange(): [number, number] {
  const p = (id: string) => CHIPS.find((c) => c.id === id)?.points ?? 0;
  return [p('ssvc.not_automatable') + p('ssvc.partial'), p('ssvc.automatable') + p('ssvc.total')];
}
const signed = (n: number) => (n > 0 ? `+${n}` : n < 0 ? `−${-n}` : '0');
const range = ([a, b]: [number, number]) => `${signed(a)} to ${signed(b)}`;

/** The wordmark: one <text>, the first part bold, so the browser sets the join. */
function wordmark(x: number, y: number, size: number, fill: string, ls: number): [string, number] {
  const [a, b] = BRAND.wordmark;
  const w = measure(a, size, 'sans', 600, ls) + ls + measure(b, size, 'sans', 400, ls);
  return [
    `<text x="${r1(x)}" y="${r1(y)}" font-family="${SANS}" font-size="${size}" fill="${fill}" letter-spacing="${ls}"><tspan font-weight="600">${esc(a)}</tspan><tspan font-weight="400">${esc(b)}</tspan></text>`,
    w,
  ];
}

// ------------------------------------------------------------------------------------------------
// 1. Logo
// ------------------------------------------------------------------------------------------------

function logo(T: Theme): string {
  // A compact card, like OpenFix's: the mark, the wordmark and a one-line mono tagline on the
  // site's background with its dot grid and lime glow. Shown at 480 px wide in the README.
  const W = 620;
  const H = 180;
  const markSize = 84;
  const size = 58;
  const gap = 20;
  const tag = 'every CVE gets a verdict, with receipts';
  const [, ww] = wordmark(0, 0, size, T.text, -1.2);
  const tw = measure(tag, 15, 'mono', 500);
  const x0 = Math.round((W - (markSize + gap + Math.max(ww, tw + 2))) / 2);
  const base = 96;
  const [wm] = wordmark(x0 + markSize + gap, base, size, T.text, -1.2);
  let b = frame(T, W, H, 'logo');
  b += mark(x0, (H - markSize) / 2 - 2, markSize, T.accent) + wm;
  b += text(x0 + markSize + gap + 2, base + 34, tag, { size: 15, font: 'mono', weight: 500, fill: T.muted });
  return svgDoc(W, H, BRAND.name, `${BRAND.name} logo: a flat noise floor with one signal spike rising out of it, next to the wordmark and the line "every CVE gets a verdict, with receipts", on a card in the site's colours.`, b);
}

// ------------------------------------------------------------------------------------------------
// 2. How it works
// ------------------------------------------------------------------------------------------------

function howItWorks(T: Theme): string {
  const W = 1200;
  const id = 'how';
  let b = '';
  const [hd, hy] = heading(T, 48, 64, 'How it works', 'Public feeds in. One verdict per CVE out. Every hour.', 'A scheduled GitHub Actions run reads every source, scores and tiers each CVE, checks the output and publishes it to the data branch. Everything else just reads that branch.');
  b += hd;

  // Row A: sources
  const groups: { title: string; color: string; icon: string; items: [string, string | null][] }[] = [
    { title: 'CVE records', color: T.muted, icon: 'Layers', items: [['CVE List V5', records('cvelist')], ['CISA Vulnrichment', records('cisa-adp')], ['SSVC and CVSS from CISA', null], ['Nothing from NVD', null]] },
    { title: 'Confirmed exploitation', color: T.ink.exploited, icon: 'Flame', items: [['CISA KEV', records('kev')], ['ENISA EU KEV', records('eu-kev')], ['CIRCL catalog', records('circl-kev')], ['SiberKapan', 'info only']] },
    { title: 'Exploits and odds', color: T.ink.likely, icon: 'Crosshair', items: [['Metasploit', records('metasploit')], ['Nuclei templates', records('nuclei')], ['Exploit-DB', records('exploitdb')], ['PoC-in-GitHub', records('poc-github')], ['EPSS (FIRST)', records('epss')]] },
    { title: 'Package versions', color: T.ai, icon: 'Lock', items: [['OSV.dev', records('osv')], ['For dependency checks only', null], ['Never part of a score', null]] },
  ];
  const gy = hy + 44;
  const gw = (W - 96 - 3 * 16) / 4;
  const rowH = 30;
  const gh = 58 + 5 * rowH + 6;
  groups.forEach((g, i) => {
    const x = 48 + i * (gw + 16);
    b += rect(x, gy, gw, gh, 12, panel(T), T.border);
    b += iconTile(T, g.icon, x + 16, gy + 16, 28, g.color);
    b += text(x + 54, gy + 36, g.title, { size: 17, weight: 600, fill: T.text });
    g.items.forEach(([name, val], j) => {
      const y = gy + 76 + j * rowH;
      const note = val === null;
      if (!note) b += `<circle cx="${x + 22}" cy="${y - 5}" r="3" fill="${g.color}"/>`;
      b += text(note ? x + 22 : x + 34, y, name, { size: note ? 15 : 16, fill: note ? T.faint : T.text, weight: note ? 400 : 450 });
      if (val) b += text(x + gw - 16, y, val, { size: 13.5, font: 'mono', fill: T.faint, anchor: 'end' });
    });
  });

  // Row B: pipeline
  const py = gy + gh + 56;
  for (let i = 0; i < 4; i++) {
    const x = 48 + i * (gw + 16) + gw / 2;
    b += arrow(x, gy + gh + 6, x, py - 8, T.faintUi);
  }
  const ph = 176;
  b += rect(48, py, W - 96, ph, 14, tint(T, T.accent, T.name === 'dark' ? 0.05 : 0.04), mix(T.accent, panel(T), 0.4));
  b += `<circle cx="72" cy="${py + 29}" r="5" fill="${T.accent}"/><circle cx="72" cy="${py + 29}" r="10" fill="none" stroke="${T.accent}" opacity="0.35"/>`;
  b += runs(90, py + 35, [
    { s: 'pipeline/', o: { size: 16, font: 'mono', weight: 600, fill: T.text } },
    { s: `   GitHub Actions, every hour at :${CRON_MINUTE}`, o: { size: 16, fill: T.muted } },
  ]);
  b += text(W - 72, py + 35, 'one failing feed never stops a run', { size: 15, fill: T.faint, anchor: 'end' });
  const stages: [string, string][] = [
    ['Ingest', 'fetch, cache, keep the last good copy'],
    ['Score', `reason chips, a plain sum from ${BASE_POINTS}`],
    ['Tier', `four tiers at the evidence bar (${KNOB_DEFAULT})`],
    ['Emit', 'JSON, 256 CVE shards, Atom, iCal'],
    ['Validate', 'every file checked, or nothing ships'],
  ];
  const sx0 = 72;
  const gap = 30;
  const sw = (W - 144 - 4 * gap) / 5;
  stages.forEach(([name, sub], i) => {
    const x = sx0 + i * (sw + gap);
    const y = py + 58;
    b += rect(x, y, sw, 96, 10, panel(T), T.border);
    b += text(x + 16, y + 28, `0${i + 1}`, { size: 13, font: 'mono', weight: 600, fill: T.accent });
    b += text(x + 44, y + 28, name, { size: 18, weight: 600, fill: T.text });
    b += lines(x + 16, y + 56, wrap(sub, sw - 28, 15), 20, { size: 15, fill: T.muted });
    if (i < 4) b += arrow(x + sw + 6, y + 48, x + sw + gap - 6, y + 48, T.accent, 1.6);
  });

  // Row C: data branch
  const dy = py + ph + 48;
  b += arrow(W / 2, py + ph + 6, W / 2, dy - 8, T.accent, 1.6);
  const dh = 92;
  b += rect(48, dy, W - 96, dh, 14, panel(T), T.borderStrong);
  b += iconTile(T, 'Source', 68, dy + 22, 48, T.accent);
  b += text(132, dy + 42, 'data branch', { size: 20, font: 'mono', weight: 600, fill: T.text });
  b += text(132, dy + 68, 'one orphan commit, replaced every run', { size: 15, fill: T.muted });
  const files = ['v1/meta.json', 'signal.json', 'index.json', 'cve/00…ff.json', 'receipts.json', 'packages.json', 'packages-older.json', 'feeds/*.xml', 'kev-due.ics'];
  let fx = 470;
  let fy = dy + 22;
  for (const f of files) {
    const fw = measure(f, 14, 'mono', 500) + 20;
    if (fx + fw > W - 68) {
      fx = 470;
      fy += 32;
    }
    b += rect(fx, fy, fw, 24, 6, tint(T, T.muted, 0.09), T.border);
    b += text(fx + 10, fy + 17, f, { size: 14, font: 'mono', weight: 500, fill: T.text });
    fx += fw + 8;
  }

  // Row D: outputs
  const oy = dy + dh + 48;
  const outs: { icon: string; title: string; sub: string; color: string }[] = [
    { icon: 'Scan', title: 'cverdict.dev', sub: 'Static site on Vercel. /data/* is rewritten to the branch, so no redeploy.', color: T.accent },
    { icon: 'Rss', title: 'Feeds', sub: 'Atom: signal, KEV, woke up. iCalendar: KEV due dates.', color: T.ink.likely },
    { icon: 'Code', title: 'Open JSON API', sub: 'The data branch on GitHub. No key, CC0 scores.', color: T.ink.watch },
    { icon: 'Terminal', title: 'MCP server', sub: 'npx -y cverdict mcp. Read-only, for AI agents.', color: T.ai },
    { icon: 'Lock', title: 'Check deps', sub: 'npx -y cverdict check, or the GitHub Action. Files stay local.', color: T.ai },
  ];
  const ow = (W - 96 - (outs.length - 1) * 16) / outs.length;
  // Tall enough for the longest description at this column width.
  const oh = 74 + Math.max(...outs.map((o) => wrap(o.sub, ow - 30, 15).length)) * 20 + 14;
  outs.forEach((o, i) => {
    const x = 48 + i * (ow + 16);
    b += rect(x, oy, ow, oh, 12, panel(T), T.border);
    b += iconTile(T, o.icon, x + 16, oy + 16, 32, o.color);
    b += text(x + 60, oy + 38, o.title, { size: 18, weight: 600, fill: T.text, font: o.title.includes('.') ? 'mono' : 'sans' });
    b += lines(x + 16, oy + 74, wrap(o.sub, ow - 30, 15), 20, { size: 15, fill: T.muted });
  });
  // fan-out lines from the branch to the outputs
  const busY = dy + dh + 24;
  const x0 = 48 + ow / 2;
  const x3 = 48 + (outs.length - 1) * (ow + 16) + ow / 2;
  b += `<path d="M${W / 2} ${dy + dh + 4}V${busY}M${x0} ${busY}H${x3}" fill="none" stroke="${T.faintUi}" stroke-width="1.5" stroke-linecap="round"/>`;
  for (let i = 0; i < outs.length; i++) {
    const x = 48 + i * (ow + 16) + ow / 2;
    b += arrow(x, busY, x, oy - 6, T.faintUi);
  }

  const H = oy + oh + 96;
  b += footer(T, W, H, `Record counts from the run of ${RUN}.`);
  return svgDoc(W, H, 'How CVErdict works', 'Public sources feed an hourly GitHub Actions pipeline that ingests, scores, tiers, emits and validates, publishes to the data branch, and five readers use that branch.', frame(T, W, H, id) + b);
}

// ------------------------------------------------------------------------------------------------
// 3. Architecture: the repository
// ------------------------------------------------------------------------------------------------

interface FileRow {
  name: string;
  note: string;
}
function fileBox(T: Theme, x: number, y: number, w: number, head: string, headNote: string, color: string, iconName: string, rows: FileRow[]): [string, number] {
  let b = '';
  const top = 64;
  let h = top;
  const body: string[] = [];
  for (const r of rows) {
    const noteLines = wrap(r.note, w - 40, 14.5);
    body.push(text(x + 20, y + h + 18, r.name, { size: 15, font: 'mono', weight: 600, fill: T.text }) + lines(x + 20, y + h + 40, noteLines, 19, { size: 14.5, fill: T.muted }));
    h += 30 + noteLines.length * 19 + 8;
  }
  h += 10;
  b += rect(x, y, w, h, 14, panel(T), mix(color, panel(T), 0.4));
  b += iconTile(T, iconName, x + 18, y + 16, 32, color);
  b += text(x + 62, y + 38, head, { size: 19, font: 'mono', weight: 600, fill: T.text });
  b += text(x + w - 18, y + 38, headNote, { size: 14, fill: T.faint, anchor: 'end' });
  b += `<line x1="${x + 18}" y1="${y + top - 6}" x2="${x + w - 18}" y2="${y + top - 6}" stroke="${T.border}"/>`;
  b += body.join('');
  return [b, h];
}

function architecture(T: Theme): string {
  const W = 1200;
  let b = '';
  const [hd, hy] = heading(T, 48, 64, 'Architecture', 'Where each part lives in the repository', 'One TypeScript repository. The pipeline writes files, the site, the API, the MCP server and the CLI only read them, and shared/ is the contract both sides import.');
  b += hd;

  // Top: workflows
  const wy = hy + 40;
  const wh = 84;
  b += rect(48, wy, W - 96, wh, 14, panel(T), T.border);
  b += iconTile(T, 'Refresh', 66, wy + 18, 48, T.accent);
  b += text(130, wy + 38, '.github/workflows/refresh.yml', { size: 17, font: 'mono', weight: 600, fill: T.text });
  b += text(130, wy + 64, `cron :${CRON_MINUTE} every hour, or an external timer`, { size: 15, fill: T.muted });
  const jobs = ['Build data', 'Publish', 'Deploy Pages (optional)', 'Watchdog'];
  let jx = W - 72 - jobs.reduce((s, j) => s + measure(j, 14, 'sans', 500) + 22, 0) - 16 * (jobs.length - 1);
  jobs.forEach((j, i) => {
    const jw = measure(j, 14, 'sans', 500) + 22;
    b += rect(jx, wy + 28, jw, 28, 14, tint(T, i === 0 ? T.accent : T.muted, 0.1), T.border);
    b += text(jx + 11, wy + 47, j, { size: 14, weight: 500, fill: T.text });
    jx += jw;
    if (i < jobs.length - 1) {
      b += arrow(jx + 3, wy + 42, jx + 13, wy + 42, T.faintUi, 1.3);
      jx += 16;
    }
  });

  // Columns
  const cy = wy + wh + 44;
  const cw = (W - 96 - 2 * 28) / 3;
  const [pBox, pH] = fileBox(T, 48, cy, cw, 'pipeline/src', 'writes', T.accent, 'Layers', [
    { name: 'sources/*.ts', note: 'One loader per feed: cvelist, kev, catalogs, epss, metasploit, nuclei, exploitdb, poc, osv' },
    { name: 'ingest.ts', note: 'Primary, then fallback, then cache; status per source' },
    { name: 'normalize.ts', note: 'Untrusted CVE JSON 5 to plain, checked records' },
    { name: 'score.ts', note: 'Chips and points, strongest per family' },
    { name: 'woke.ts · receipts.ts', note: 'Old CVEs that woke up; the forward log and backtest' },
    { name: 'batches.ts · stats.ts · packages.ts', note: 'Patch days, counts, OSV package ranges' },
    { name: 'emit/', note: 'json.ts, atom.ts, ics.ts: the output tree in memory' },
    { name: 'validate.ts · run.ts', note: 'Check every file, then swap in atomically' },
  ]);
  b += pBox;
  const sx = 48 + cw + 28;
  const [sBox, sH] = fileBox(T, sx, cy, cw, 'shared/', 'the contract', T.ink.watch, 'Shield', [
    { name: 'contract.ts', note: 'Every file format, field by field, and tierFor()' },
    { name: 'model.ts', note: `Every chip and its points (score model ${SCORE_MODEL})` },
    { name: 'verdict.ts', note: 'The one-line verdict for pages, tickets and previews' },
    { name: 'shard.ts', note: 'FNV-1a of the CVE ID picks one of 256 detail files' },
    { name: 'packages.ts · versions.ts', note: 'Package keys and version ranges for eight ecosystems' },
    { name: 'brand.ts', note: 'Name, repo and URLs, so a fork edits one file' },
  ]);
  b += sBox;
  const rx = sx + cw + 28;
  const [rBox, rH] = fileBox(T, rx, cy, cw, 'readers', 'read only', T.ai, 'Scan', [
    { name: 'site/src/', note: 'Preact and Vite: pages/, components/, the router and the data client' },
    { name: 'site/src/check/', note: 'SBOM and lockfile parsers. Your file never leaves the browser' },
    { name: 'api/share.ts', note: 'Link previews with the verdict, for chat and social bots only' },
    { name: 'mcp/src/', note: 'server.ts, tools.ts, data.ts: the npm package cverdict-mcp' },
    { name: 'cli/src/ · action/', note: 'cverdict-check: the Check Deps matcher for terminals and CI, and the GitHub Action' },
    { name: 'dispatcher/', note: 'The npm package cverdict: cverdict check and cverdict mcp' },
    { name: 'vercel.json', note: 'Rewrites /data/* and /feeds/* to the data branch' },
  ]);
  b += rBox;

  // imports arrows from shared to both sides
  const midY = cy + 110;
  b += arrow(sx - 4, midY, 48 + cw + 6, midY, T.ink.watch, 1.5, '5 4');
  b += arrow(sx + cw + 4, midY, rx - 6, midY, T.ink.watch, 1.5, '5 4');

  // Bottom: publish + data branch
  const colBottom = cy + Math.max(pH, sH, rH);
  const by = colBottom + 50;
  const bh = 84;
  b += rect(48, by, W - 96, bh, 14, tint(T, T.accent, T.name === 'dark' ? 0.05 : 0.04), mix(T.accent, panel(T), 0.4));
  b += iconTile(T, 'Source', 66, by + 18, 48, T.accent);
  b += runs(130, by + 38, [
    { s: 'scripts/publish-data-branch.sh', o: { size: 16, font: 'mono', weight: 600, fill: T.text } },
    { s: '  to the  ', o: { size: 16, fill: T.muted } },
    { s: 'data', o: { size: 16, font: 'mono', weight: 600, fill: T.accent } },
    { s: ' branch', o: { size: 16, fill: T.muted } },
  ]);
  b += text(130, by + 64, 'One parentless commit per run: v1/*.json, v1/cve/00…ff.json, feeds/*.xml, feeds/kev-due.ics', { size: 15, fill: T.muted });
  b += arrow(48 + cw / 2, cy + pH + 6, 48 + cw / 2, by - 8, T.accent, 1.6);
  b += arrow(rx + cw / 2, by - 6, rx + cw / 2, cy + rH + 8, T.ai, 1.6);
  b += text(48 + cw / 2 + 12, (cy + pH + by) / 2 + 5, 'writes', { size: 13, font: 'mono', fill: T.faint });
  b += text(rx + cw / 2 + 12, (cy + rH + by) / 2 + 5, 'fetch', { size: 13, font: 'mono', fill: T.faint });

  // Side line: checks
  const ky = by + bh + 24;
  b += runs(48, ky + 16, [
    { s: 'Also: ', o: { size: 15, fill: T.faint } },
    { s: 'scripts/backtest.ts', o: { size: 14.5, font: 'mono', fill: T.muted } },
    { s: ' and ', o: { size: 15, fill: T.faint } },
    { s: 'calibrate.ts', o: { size: 14.5, font: 'mono', fill: T.muted } },
    { s: ' reproduce the numbers; ', o: { size: 15, fill: T.faint } },
    { s: 'ci.yml', o: { size: 14.5, font: 'mono', fill: T.muted } },
    { s: ' runs typecheck, tests, the builds and smoke tests of every package.', o: { size: 15, fill: T.faint } },
  ]);
  const H = ky + 16 + 86;
  b += footer(T, W, H, `Paths as of ${day(meta.generated_at)}.`);
  return svgDoc(W, H, 'CVErdict architecture', 'The repository by folder: pipeline/src writes, shared/ is the contract, the readers only read, and scripts/publish-data-branch.sh publishes to the data branch.', frame(T, W, H, 'arch') + b);
}

// ------------------------------------------------------------------------------------------------
// 4. Scoring and tiers
// ------------------------------------------------------------------------------------------------

async function exampleCve(): Promise<CveDetail> {
  const want = EXAMPLE ?? null;
  const ids: string[] = [];
  if (want) ids.push(want);
  // Otherwise: the highest-scoring Likely next CVE of the newest big batch whose score uses at least
  // four families and no weaponized chip: a typical "clears the bar on evidence" case.
  const top = [...batches.batches].sort((a, b) => b.count - a.count);
  for (const bt of top) for (const r of bt.top) if (r.tier === 'likely' && !r.w) ids.push(r.id);
  for (const id of ids) {
    const shard = await load<{ items: Record<string, CveDetail> }>(`cve/${shardOf(id)}.json`);
    const d = shard.items[id];
    if (!d) continue;
    const fams = new Set(d.reasons.filter((r) => r.points > 0).map((r) => r.family));
    if (id === want || (fams.size >= 4 && d.score.value < 90)) return d;
  }
  throw new Error('no example CVE found; pass --example CVE-…');
}

/** The scoring card. `narrow` is the phone layout (540 wide), shown by <picture> below 600 px. */
function scoring(T: Theme, ex: CveDetail, narrow = false): string {
  const W = narrow ? 540 : 1200;
  const M = narrow ? 28 : 48;
  const id = narrow ? 'scoren' : 'score';
  let b = '';
  const [hd, hy] = heading(T, M, narrow ? 56 : 64, 'Scoring', 'A score you can add up by hand', `Each signal is a reason chip with fixed points. Within a family only the strongest chip counts, so three PoCs and a Metasploit module are not four times the evidence.`, W - 2 * M, narrow ? 26 : 32);
  b += hd;

  // Formula: six boxes in a row (wide) or in two columns (narrow)
  const fy = hy + (narrow ? 36 : 44);
  const fam: { key: string; name: string; sub: string; r: [number, number] | null; color: string }[] = [
    { key: 'BASE', name: 'Base', sub: 'every CVE', r: null, color: T.muted },
    { key: 'X', name: 'Exploits', sub: 'exploit code, templates, EPSS', r: familyRange('X'), color: T.ink.likely },
    { key: 'SEV', name: 'Severity', sub: 'CVSS from the CNA or CISA', r: familyRange('SEV'), color: T.ink.watch },
    { key: 'SSVC', name: 'CISA SSVC', sub: 'automatable, technical impact', r: ssvcRange(), color: T.ai },
    { key: 'PRIOR', name: 'KEV history', sub: 'vendor or product exploited before', r: familyRange('PRIOR'), color: T.ok },
    { key: 'NOISE', name: 'Noise', sub: 'tutorial code, disputed, WordPress', r: familyRange('NOISE'), color: T.faint },
  ];
  const perRow = narrow ? 2 : 6;
  const plus = 26;
  const fw = (W - 2 * M - (perRow - 1) * plus) / perRow;
  const fh = narrow ? 128 : 140;
  const rowGap = 16;
  fam.forEach((f, i) => {
    const x = M + (i % perRow) * (fw + plus);
    const y = fy + Math.floor(i / perRow) * (fh + rowGap);
    b += rect(x, y, fw, fh, 12, panel(T), T.border);
    b += rect(x + 10, y + 14, 3, fh - 28, 1.5, f.color);
    b += text(x + 24, y + 34, f.name, { size: 16, weight: 600, fill: T.text });
    b += text(x + 24, y + 70, f.r ? range(f.r) : String(BASE_POINTS), { size: f.r ? 21 : 28, font: 'mono', weight: 600, fill: f.color, ls: -0.5 });
    b += lines(x + 24, y + 96, wrap(f.sub, fw - 34, 14), 18, { size: 14, fill: T.muted });
    if (i < fam.length - 1 && (i % perRow) < perRow - 1) b += text(x + fw + plus / 2, y + fh / 2 + 8, '+', { size: 24, weight: 500, fill: T.faint, anchor: 'middle' });
  });
  const fBottom = fy + Math.ceil(fam.length / perRow) * (fh + rowGap) - rowGap;

  // Exploited rule
  const ey = fBottom + 20;
  const ruleParts = [
    { s: 'Confirmed exploitation ', o: { size: 17, weight: 600, fill: T.ink.exploited } },
    { s: `adds ${EXPLOITED_BONUS} and floors the score at ${EXPLOITED_FLOOR}. `, o: { size: 17, weight: 500, fill: T.text } },
    { s: 'CISA KEV, EU KEV, CIRCL, SSVC "active" or the vendor.', o: { size: 17, fill: T.muted } },
  ];
  let eh = 58;
  if (narrow) {
    const tail = wrap(`${ruleParts[1].s}${ruleParts[2].s}`, W - 2 * M - 48, 16);
    eh = 46 + tail.length * 22;
    b += rect(M, ey, W - 2 * M, eh, 12, tint(T, T.exploited, T.name === 'dark' ? 0.12 : 0.08), mix(T.exploited, panel(T), 0.45));
    b += icon('Flame', M + 16, ey + 17, 20, T.ink.exploited, 1.6);
    b += text(M + 46, ey + 33, 'Confirmed exploitation', { size: 17, weight: 600, fill: T.ink.exploited });
    b += lines(M + 46, ey + 58, tail, 22, { size: 16, fill: T.text });
  } else {
    b += rect(M, ey, W - 2 * M, eh, 12, tint(T, T.exploited, T.name === 'dark' ? 0.12 : 0.08), mix(T.exploited, panel(T), 0.45));
    b += icon('Flame', 66, ey + 19, 20, T.ink.exploited, 1.6);
    b += runs(96, ey + 35, ruleParts);
  }

  // Scale
  const sy = ey + eh + (narrow ? 104 : 74);
  const sx0 = narrow ? M + 4 : 64;
  const sx1 = W - (narrow ? M + 4 : 64);
  const xs = (v: number) => sx0 + ((sx1 - sx0) * v) / 100;
  const bandH = 40;
  const scaleTitle = `0 to 100, tiers at the default evidence bar (${KNOB_DEFAULT})`;
  if (narrow) b += lines(M, sy - 62, wrap(scaleTitle, W - 2 * M, 16, 'sans', 600), 21, { size: 16, weight: 600, fill: T.text });
  else b += text(M, sy - 32, scaleTitle, { size: 16, weight: 600, fill: T.text });
  const bands: [number, number, Tier][] = [
    [0, WATCH_FLOOR, 'quiet'],
    [WATCH_FLOOR, KNOB_DEFAULT, 'watch'],
    [KNOB_DEFAULT, 100, 'likely'],
  ];
  for (const [a, z, t] of bands) {
    const c = t === 'quiet' ? T.faintUi : T[t];
    b += rect(xs(a) + 1, sy, xs(z) - xs(a) - 2, bandH, 6, tint(T, c, T.name === 'dark' ? 0.2 : 0.16), mix(c, panel(T), 0.55));
    b += text(xs(a) + (narrow ? 10 : 14), sy + 26, TIER_NAME[t], { size: narrow ? 15 : 16, weight: 600, fill: t === 'quiet' ? T.muted : T.ink[t] });
  }
  // exploited floor zone
  b += `<defs><pattern id="${id}-hatch-${T.name}" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="3" height="8" fill="${T.exploited}" opacity="${T.name === 'dark' ? 0.5 : 0.35}"/></pattern></defs>`;
  b += rect(xs(EXPLOITED_FLOOR), sy, xs(100) - xs(EXPLOITED_FLOOR) - 1, bandH, 6, `url(#${id}-hatch-${T.name})`, T.exploited);
  // Wide: the label sits left of the hatch. Narrow: there is no room, so it sits above the hatch.
  if (narrow) b += text(xs(100), sy - 10, `Exploited ${EXPLOITED_FLOOR}+`, { size: 15, weight: 600, fill: T.ink.exploited, anchor: 'end' });
  else b += text(xs(EXPLOITED_FLOOR) - 10, sy + 26, 'Exploited', { size: 16, weight: 600, fill: T.ink.exploited, anchor: 'end' });
  // ticks
  for (const v of [0, WATCH_FLOOR, KNOB_DEFAULT, EXPLOITED_FLOOR, 100]) {
    b += `<line x1="${xs(v)}" y1="${sy + bandH + 4}" x2="${xs(v)}" y2="${sy + bandH + 10}" stroke="${T.faintUi}"/>`;
    b += text(xs(v), sy + bandH + 28, String(v), { size: 14, font: 'mono', fill: T.faint, anchor: 'middle' });
  }
  // the evidence bar handle and its ranges
  const kx = xs(KNOB_DEFAULT);
  b += rect(xs(SITE_KNOB_MIN), sy - 14, xs(SITE_KNOB_MAX) - xs(SITE_KNOB_MIN), 6, 3, mix(T.accent, panel(T), 0.45));
  b += `<line x1="${kx}" y1="${sy - 20}" x2="${kx}" y2="${sy + bandH + 2}" stroke="${T.accent}" stroke-width="3" stroke-linecap="round"/>`;
  b += `<circle cx="${kx}" cy="${sy - 11}" r="7" fill="${T.accent}"/>`;
  const knobText = `evidence bar: site dial ${SITE_KNOB_MIN} to ${SITE_KNOB_MAX}, API and MCP ${KNOB_MIN} to ${KNOB_MAX}`;
  let wy = sy + bandH + 66;
  if (narrow) {
    b += text(M, sy + bandH + 56, knobText.replace(/^e/, 'E'), { size: 14, fill: T.muted });
    wy += 34;
  } else b += text(xs(SITE_KNOB_MAX) + 10, sy - 7, knobText, { size: 14, fill: T.muted });

  // Worked example on the same scale
  const pos = ex.reasons.filter((r) => r.points !== 0);
  const total = ex.score.value;
  const tierInk = T.ink[ex.score.tier as Tier];
  if (narrow) {
    b += text(M, wy, ex.id, { size: 16, font: 'mono', weight: 600, fill: T.text });
    b += lines(M, wy + 22, wrap(ex.title ?? '', W - 2 * M, 15), 20, { size: 15, fill: T.muted });
    wy += 22 + (wrap(ex.title ?? '', W - 2 * M, 15).length - 1) * 20;
  } else
    b += runs(M, wy, [
      { s: ex.id, o: { size: 16, font: 'mono', weight: 600, fill: T.text } },
      { s: `   ${ex.title ?? ''}`, o: { size: 16, fill: T.muted } },
    ]);
  const by = wy + 16;
  const segs: { label: string; pts: number; color: string }[] = [{ label: 'base', pts: BASE_POINTS, color: T.faintUi }];
  const famColor: Record<string, string> = { X: T.likely, SEV: T.watch, SSVC: T.ai, PRIOR: T.ok, NOISE: T.faint, E: T.exploited };
  for (const r of pos) segs.push({ label: r.label, pts: r.points, color: famColor[r.family] ?? T.muted });
  let cx = 0;
  const bh = 34;
  segs.forEach((s, i) => {
    if (s.pts <= 0) return;
    const x = xs(cx);
    const w = xs(cx + s.pts) - x;
    b += rect(x + 1, by, w - 2, bh, 5, s.color, undefined, `opacity="${i === 0 ? 0.9 : 0.85}"`);
    b += text(x + w / 2, by + 23, signed(s.pts).replace('+', i === 0 ? '' : '+'), { size: narrow ? 14 : 15, font: 'mono', weight: 600, fill: T.name === 'dark' ? '#0a0b0d' : '#ffffff', anchor: 'middle' });
    cx += s.pts;
  });
  let ly: number;
  if (narrow) {
    b += text(xs(cx) + 10, by + 24, `= ${total}`, { size: 20, font: 'mono', weight: 700, fill: tierInk });
    b += text(M, by + bh + 28, `${TIER_NAME[ex.score.tier as Tier]}: at or above the bar of ${KNOB_DEFAULT}`, { size: 15, weight: 600, fill: tierInk });
    ly = by + bh + 28 + 34;
  } else {
    b += text(xs(cx) + 14, by + 24, `= ${total}`, { size: 22, font: 'mono', weight: 700, fill: tierInk });
    b += text(xs(cx) + 14 + measure(`= ${total}`, 22, 'mono', 700) + 12, by + 23, TIER_NAME[ex.score.tier as Tier], { size: 16, weight: 600, fill: tierInk });
    ly = by + bh + 32;
  }
  // legend of the example's chips
  let lx = M;
  for (const s of segs.slice(1)) {
    const label = `${signed(s.pts)} ${s.label}`;
    const lw = measure(label, 14.5, 'sans', 400) + 34;
    if (lx + lw > W - M) {
      lx = M;
      ly += 30;
    }
    b += rect(lx, ly - 17, lw, 26, 6, tint(T, s.color, 0.12), mix(s.color, panel(T), 0.5));
    b += `<circle cx="${lx + 13}" cy="${ly - 4}" r="4" fill="${s.color}"/>`;
    b += text(lx + 24, ly + 1, label, { size: 14.5, fill: T.text });
    lx += lw + 8;
  }
  const zeroes = ex.reasons.filter((r) => r.points === 0).map((r) => r.label);
  ly += 34;
  if (zeroes.length) {
    const zl = wrap(`0 points, shown as context: ${zeroes.join(' · ')}`, W - 2 * M, 14.5);
    b += lines(M, ly, zl, 20, { size: 14.5, fill: T.faint });
    ly += (zl.length - 1) * 20;
  }

  // Tier rules
  const ty = ly + 50;
  const rules: { t: Tier; head: string; body: string; iconName: string }[] = [
    { t: 'exploited', head: 'Patch now', body: 'Any confirmed exploitation chip.', iconName: 'Flame' },
    { t: 'likely', head: 'Patch within days', body: `Score at or above the bar, or a Metasploit module or Nuclei template, which always passes.`, iconName: 'Crosshair' },
    { t: 'watch', head: 'Keep an eye on it', body: `Score from ${WATCH_FLOOR} up to the bar.`, iconName: 'Eye' },
    { t: 'quiet', head: 'No evidence yet', body: `Below ${WATCH_FLOOR}. Quiet is not safe.`, iconName: 'Quiet' },
  ];
  const tCols = narrow ? 2 : 4;
  const tw = (W - 2 * M - (tCols - 1) * 16) / tCols;
  const bodies = rules.map((r) => wrap(r.body, tw - 34, 14.5));
  const th = narrow ? 80 + Math.max(...bodies.map((l) => l.length)) * 19 : 136;
  rules.forEach((r, i) => {
    const x = M + (i % tCols) * (tw + 16);
    const y = ty + Math.floor(i / tCols) * (th + 16);
    const c = r.t === 'quiet' ? T.muted : T.ink[r.t];
    b += rect(x, y, tw, th, 12, tint(T, r.t === 'quiet' ? T.muted : T[r.t], T.name === 'dark' ? 0.1 : 0.07), mix(r.t === 'quiet' ? T.faintUi : T[r.t], panel(T), 0.4));
    b += icon(r.iconName, x + 18, y + 20, 18, c, 1.6);
    b += text(x + 44, y + 35, TIER_NAME[r.t], { size: 18, weight: 600, fill: c });
    b += text(x + 18, y + 64, r.head, { size: 15.5, weight: 600, fill: T.text });
    b += lines(x + 18, y + 88, bodies[i], 19, { size: 14.5, fill: T.muted });
  });
  const tBottom = ty + Math.ceil(rules.length / tCols) * (th + 16) - 16;

  const H = tBottom + 96 + (narrow ? 10 : 0);
  const foot = narrow ? `Points from shared/model.ts (${SCORE_MODEL}). Example from the run of ${RUN}.` : `Points from shared/model.ts (${SCORE_MODEL}). EPSS waits ${COLD_START_DAYS} days. Example from the run of ${RUN}.`;
  b += footer(T, W, H, foot, undefined, M);
  return svgDoc(W, H, 'How a CVErdict score adds up', `A base of ${BASE_POINTS} plus five families of reason chips, the tiers on the 0 to 100 scale, and ${ex.id} worked through to ${total}.`, frame(T, W, H, id) + b);
}

// ------------------------------------------------------------------------------------------------
// 5. Signal and noise: the last 30 days
// ------------------------------------------------------------------------------------------------

/** Ticks per column are a square root of the count, as on the site, so a patch day does not flatten the rest. */
const WF_PITCH = 3;
const WF_SEG = 2;
/** site/src/pulse.ts: the halo radius and how far apart two newly exploited columns share one ring. */
const WF_HALO_R = 17;
const WF_RING_R = 28;

/**
 * The site's spike labels (site/src/pages/Today.tsx annotationsFor): the biggest patch days merged
 * per date, biggest first, at the day's busiest hour, e.g. "Oracle 1,076 + Chrome 353".
 */
function spikeLabels(): { at: number; text: string }[] {
  const start = Date.parse(stats.hourly.start);
  const byDate = new Map<string, BatchesFile['batches']>();
  for (const bt of batches.batches) byDate.set(bt.date, [...(byDate.get(bt.date) ?? []), bt]);
  return [...byDate.entries()]
    .map(([date, list]) => ({ date, list: [...list].sort((a, b) => b.count - a.count), total: list.reduce((s, bt) => s + bt.count, 0) }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 4)
    .map(({ date, list }) => {
      const d0 = Date.parse(`${date}T00:00:00Z`);
      let at = d0 + 12 * 3600e3;
      let best = -1;
      for (let hh = 0; hh < 24; hh++) {
        const c = stats.hourly.counts[Math.floor((d0 + hh * 3600e3 - start) / 3600e3)];
        if (!c) continue;
        const sum = c[0] + c[1] + c[2] + c[3];
        if (sum > best) {
          best = sum;
          at = d0 + hh * 3600e3;
        }
      }
      const named = list.filter((bt) => bt.count >= 300).slice(0, 2);
      return { at, text: (named.length ? named : list.slice(0, 1)).map((bt) => `${cnaName(bt.cna)} ${fmt(bt.count)}`).join(' + ') };
    });
}

/**
 * The signal waterfall as the site draws it (site/src/components/Waterfall.tsx): one column per
 * time slot, LED-style ticks of 2 units every 3, height by the square root of the count, noise
 * (Quiet, then Watch) at the bottom and the passed ticks (Likely next, then Exploited) lit on top
 * with a glow. Columns holding a CVE newly exploited in the last 72 hours get the site's halo and
 * ring. Each tier is one dashed path, which keeps the file small.
 */
function waterfall(T: Theme, x0: number, y0: number, w: number, h: number, opts: { labels?: number; axis?: boolean; id: string; glow?: number }): { svg: string; slotHours: number; fresh: number } {
  const hourly = stats.hourly;
  const start = Date.parse(hourly.start);
  const per = Math.max(1, Math.ceil((hourly.counts.length * WF_PITCH) / w));
  const cols: number[][] = [];
  for (let i = 0; i < hourly.counts.length; i += per) {
    const s = [0, 0, 0, 0];
    for (let j = i; j < Math.min(i + per, hourly.counts.length); j++) for (let k = 0; k < 4; k++) s[k] += hourly.counts[j][k];
    cols.push(s);
  }
  const freshHours = new Map<number, number>();
  for (const [hour, n] of hourly.new_exploited ?? []) freshHours.set(hour, (freshHours.get(hour) ?? 0) + n);
  const freshCol = cols.map((c, i) => {
    let n = 0;
    for (let hh = i * per; hh < (i + 1) * per; hh++) n += freshHours.get(hh) ?? 0;
    return Math.min(n, c[0]);
  });
  const totals = cols.map((c) => c[0] + c[1] + c[2] + c[3]);
  const max = Math.max(1, ...totals);
  const colW = w / cols.length;
  const barW = Math.max(1, colW - (colW >= 3 ? 1 : 0.5));
  const base = Math.round(y0 + h);
  const paths: Record<'quiet' | 'watch' | 'likely' | 'exploited', string> = { quiet: '', watch: '', likely: '', exploited: '' };
  const spots: { cx: number; cy: number; half: number }[] = [];
  const tops: number[] = [];
  cols.forEach((c, i) => {
    const total = totals[i];
    tops.push(base);
    if (total === 0) return;
    const segs = Math.max(1, Math.round((h * Math.sqrt(total / max)) / WF_PITCH));
    const e = c[0] > 0 ? Math.max(1, Math.round((segs * c[0]) / total)) : 0;
    const l = c[1] > 0 ? Math.max(1, Math.round((segs * c[1]) / total)) : 0;
    const rest = Math.max(0, segs - e - l);
    const noise = c[2] + c[3];
    const wt = c[2] > 0 && rest > 0 ? Math.max(1, Math.round((rest * c[2]) / Math.max(1, noise))) : 0;
    const q = Math.max(0, rest - wt);
    const cx = r1(x0 + i * colW + barW / 2);
    let n = 0;
    for (const [tier, k] of [['quiet', q], ['watch', wt], ['likely', l], ['exploited', e]] as const) {
      // From the bottom of tick n up to the top of tick n + k - 1; the dashes start at the bottom.
      if (k > 0) paths[tier] += `M${cx} ${base - WF_PITCH * n}v-${WF_PITCH * k - (WF_PITCH - WF_SEG)}`;
      n += k;
    }
    tops[i] = base - WF_PITCH * n;
    const f = freshCol[i];
    if (f > 0) {
      // The newly exploited ticks are the top of the exploited stack (site/src/pulse.ts freshSegs).
      const ef = f >= c[0] ? e : Math.max(1, Math.min(e - 1, Math.round((e * f) / c[0])));
      const top = base - WF_PITCH * n;
      const bottom = top + WF_PITCH * ef - (WF_PITCH - WF_SEG);
      spots.push({ cx, cy: (top + bottom) / 2, half: (bottom - top) / 2 });
    }
  });
  const glow = opts.glow ?? (T.name === 'dark' ? 3 : 2);
  const dash = `stroke-width="${r1(barW)}" stroke-dasharray="${WF_SEG} ${WF_PITCH - WF_SEG}" fill="none"`;
  let b = `<defs><filter id="${opts.id}-lit" x="-5%" y="-30%" width="110%" height="160%"><feGaussianBlur stdDeviation="${glow}" result="g"/><feMerge><feMergeNode in="g"/><feMergeNode in="SourceGraphic"/></feMerge></filter>`;
  b += `<radialGradient id="${opts.id}-halo"><stop offset="0" stop-color="${T.exploited}" stop-opacity="${T.name === 'dark' ? 0.5 : 0.32}"/><stop offset="0.3" stop-color="${T.exploited}" stop-opacity="${T.name === 'dark' ? 0.36 : 0.23}"/><stop offset="0.65" stop-color="${T.exploited}" stop-opacity="${T.name === 'dark' ? 0.14 : 0.09}"/><stop offset="1" stop-color="${T.exploited}" stop-opacity="0"/></radialGradient></defs>`;
  b += `<rect x="${x0}" y="${base + 1}" width="${w}" height="1" fill="${T.border}"/>`;
  // One ring per group of neighbouring columns, as the site draws them.
  const rings: { cx: number; cy: number; half: number }[] = [];
  for (const s of spots) {
    const last = rings[rings.length - 1];
    if (last && Math.abs(s.cx - last.cx) < WF_RING_R) {
      const l = Math.min(last.cx - last.half, s.cx - s.half);
      const r = Math.max(last.cx + last.half, s.cx + s.half);
      last.cx = (l + r) / 2;
      last.half = (r - l) / 2;
    } else rings.push({ ...s });
  }
  for (const s of spots) b += `<circle cx="${r1(s.cx)}" cy="${r1(s.cy)}" r="${r1(WF_HALO_R + s.half)}" fill="url(#${opts.id}-halo)"/>`;
  const noiseQuiet = T.wfQuiet;
  b += `<path d="${paths.quiet}" stroke="${noiseQuiet}" ${dash}/>`;
  b += `<path d="${paths.watch}" stroke="${T.wfWatch}" ${dash}/>`;
  b += `<g filter="url(#${opts.id}-lit)"><path d="${paths.likely}" stroke="${T.likely}" ${dash}/><path d="${paths.exploited}" stroke="${T.exploited}" ${dash}/></g>`;
  for (const s of rings) b += `<circle cx="${r1(s.cx)}" cy="${r1(s.cy)}" r="${r1(s.half + 10)}" fill="none" stroke="${T.exploited}" stroke-width="1.5" opacity="0.75"/>`;

  if (opts.labels) {
    // The site's spike labels: one row above the plot, biggest first, a smaller one dropped on a collision.
    const taken: [number, number][] = [];
    let shown = 0;
    for (const a of spikeLabels()) {
      if (shown >= opts.labels) break;
      const best = Math.floor((a.at - start) / 3600e3 / per);
      if (best < 0 || best >= cols.length) continue;
      const cx = x0 + best * colW + barW / 2;
      const lw = measure(a.text, 13, 'mono', 400);
      const clamp = (l: number) => Math.min(x0 + w - lw, Math.max(x0, l));
      const hits = (l: number) => taken.some(([a, z]) => l < z + 10 && l + lw > a - 10);
      // Centred on its column, or else just beside the label it would cover, if that stays near the column.
      const tries = [clamp(cx - lw / 2), ...taken.flatMap(([a, z]) => [clamp(z + 12), clamp(a - 12 - lw)])];
      const left = tries.find((l) => !hits(l) && Math.abs(l + lw / 2 - cx) <= lw);
      if (left === undefined) continue;
      taken.push([left, left + lw]);
      shown++;
      const ly = y0 - 14;
      b += text(left, ly, a.text, { size: 13, font: 'mono', fill: T.muted });
      b += `<line x1="${r1(left)}" y1="${ly + 4}" x2="${r1(left + lw)}" y2="${ly + 4}" stroke="${T.borderStrong}"/>`;
      if (tops[best] - 5 > ly + 12) b += `<line x1="${r1(cx)}" y1="${ly + 9}" x2="${r1(cx)}" y2="${r1(tops[best] - 5)}" stroke="${T.border}" stroke-dasharray="2 3"/>`;
    }
  }
  if (opts.axis) {
    const end = start + hourly.counts.length * 3600e3;
    const xOf = (t: number) => x0 + ((t - start) / (end - start)) * w;
    let lastEnd = -Infinity;
    for (let t = Math.ceil(start / 86400e3) * 86400e3; t < end; t += 86400e3) {
      const x = Math.round(xOf(t)) + 0.5;
      const monday = new Date(t).getUTCDay() === 1;
      b += `<line x1="${x}" y1="${base + 2}" x2="${x}" y2="${base + (monday ? 8 : 5)}" stroke="${T.border}"/>`;
      if (monday) {
        const label = day(new Date(t).toISOString(), false);
        const lw = measure(label, 13, 'mono', 400);
        const lx = Math.min(x0 + w - lw, Math.max(x0, x - lw / 2));
        if (lx > lastEnd + 8) {
          b += text(lx, base + 26, label, { size: 13, font: 'mono', fill: T.muted });
          lastEnd = lx + lw;
        }
      }
    }
  }
  return { svg: b, slotHours: per, fresh: freshCol.reduce((s, n) => s + n, 0) };
}

/** The site's waterfall legend: a short dash per tier, and the ring for newly exploited CVEs. */
function legendItems(T: Theme, fresh: number): { label: string; ring: boolean; color: string }[] {
  return [
    { label: 'Exploited', ring: false, color: T.exploited },
    { label: `${fmt(fresh)} newly exploited`, ring: true, color: T.exploited },
    { label: 'Likely next', ring: false, color: T.likely },
    { label: 'Watch', ring: false, color: T.wfWatch },
    { label: 'Quiet', ring: false, color: T.wfQuiet },
  ];
}
function legendKey(T: Theme, it: { label: string; ring: boolean; color: string }, x: number, y: number, size: number): string {
  const key = it.ring
    ? `<circle cx="${r1(x + 6)}" cy="${r1(y - size * 0.36)}" r="5" fill="none" stroke="${it.color}" stroke-width="1.5"/>`
    : `<rect x="${r1(x)}" y="${r1(y - size * 0.36 - 1.5)}" width="12" height="3" rx="1.5" fill="${it.color}"/>`;
  return key + text(x + 18, y, it.label, { size, fill: T.muted });
}
const LEGEND_GAP = 18;
/** One row, ending at xRight. */
function waterfallLegend(T: Theme, xRight: number, y: number, fresh: number, size = 14): string {
  const items = legendItems(T, fresh);
  const widths = items.map((it) => 18 + measure(it.label, size));
  let x = xRight - widths.reduce((s, v) => s + v, 0) - LEGEND_GAP * (items.length - 1);
  let b = '';
  items.forEach((it, i) => {
    b += legendKey(T, it, x, y, size);
    x += widths[i] + LEGEND_GAP;
  });
  return b;
}
/** From the left, wrapped to maxW. Returns the svg and the height it adds below y. */
function waterfallLegendRows(T: Theme, x0: number, y: number, fresh: number, maxW: number, size = 14): [string, number] {
  let b = '';
  let x = x0;
  let yy = y;
  for (const it of legendItems(T, fresh)) {
    const w = 18 + measure(it.label, size);
    if (x > x0 && x + w > x0 + maxW) {
      x = x0;
      yy += 24;
    }
    b += legendKey(T, it, x, yy, size);
    x += w + LEGEND_GAP;
  }
  return [b, yy - y];
}

const TIER_ICON: Record<Tier, string> = { exploited: 'Flame', likely: 'Crosshair', watch: 'Eye', quiet: 'Quiet' };

/**
 * The hero: the last 30 days in numbers, the tier bar and the signal waterfall. `narrow` is the
 * phone layout (540 wide), shown by <picture> below 600 px so the text stays readable there.
 */
function signal(T: Theme, narrow = false): string {
  const W = narrow ? 540 : 1200;
  const M = narrow ? 28 : 48;
  const id = narrow ? 'sign' : 'sig';
  let b = '';
  const from = day(meta.window.from, false);
  const to = day(meta.window.to);
  b += eyebrow(M, narrow ? 52 : 64, `Last ${meta.window.days} days · ${from} to ${to}`, T.faint, 'start', narrow ? 12 : 13);
  const big = narrow ? 54 : 88;
  const bigPass = narrow ? 72 : big + 18;
  const y = narrow ? 126 : 158;
  const pub = fmt(C.window_published);
  const pass = fmt(C.window_passed);
  const pw = measure(pub, big, 'sans', 600, narrow ? -2 : -3);
  b += text(M, y, pub, { size: big, weight: 600, fill: T.muted, ls: narrow ? -2 : -3 });
  const arrowS = narrow ? 24 : 34;
  b += icon('ArrowRight', M + pw + (narrow ? 12 : 22), y - big / 2, arrowS, T.faint, 1.5);
  const sx = M + pw + (narrow ? 48 : 80);
  b += `<defs><filter id="${id}-lime" x="-20%" y="-40%" width="140%" height="180%"><feGaussianBlur stdDeviation="${narrow ? 10 : 14}"/></filter></defs>`;
  if (T.name === 'dark') b += text(sx, y, pass, { size: bigPass, weight: 700, fill: T.accent, ls: -3, opacity: 0.45 }).replace('<text ', `<text filter="url(#${id}-lime)" `);
  b += text(sx, y, pass, { size: bigPass, weight: 700, fill: T.accent, ls: -3 });
  b += text(M, y + (narrow ? 28 : 34), 'new CVEs published', { size: narrow ? 16 : 18, fill: T.muted });
  b += text(sx, y + (narrow ? 28 : 34), 'worth your time', { size: narrow ? 16 : 18, fill: T.text, weight: 500 });
  const ratio = Math.round(C.window_published / C.window_passed);
  let by: number;
  if (narrow) {
    const py = y + 74;
    b += runs(M, py, [
      { s: pct(C.window_passed, C.window_published), o: { size: 22, font: 'mono', weight: 600, fill: T.text } },
      { s: ` of the flood, 1 in ${ratio}`, o: { size: 17, fill: T.muted } },
    ]);
    b += text(M, py + 24, `Exploited or Likely next at the evidence bar of ${KNOB_DEFAULT}`, { size: 14.5, fill: T.faint });
    by = py + 50;
  } else {
    const rx = W - M;
    b += text(rx, y - 52, pct(C.window_passed, C.window_published), { size: 40, font: 'mono', weight: 600, fill: T.text, anchor: 'end' });
    b += text(rx, y - 22, `of the flood, 1 in ${ratio}`, { size: 17, fill: T.muted, anchor: 'end' });
    b += text(rx, y + 8, `Exploited or Likely next at ${KNOB_DEFAULT}`, { size: 15, fill: T.faint, anchor: 'end' });
    by = y + 70;
  }

  // Tier bar, and the site's tier row: icon, name, count.
  const tiers: Tier[] = ['exploited', 'likely', 'watch', 'quiet'];
  const counts = C.window_by_tier;
  const all = tiers.reduce((s, t) => s + counts[t], 0);
  const bw = W - 2 * M;
  let x = M;
  tiers.forEach((t) => {
    const w = Math.max(6, (bw * counts[t]) / all);
    const c = t === 'quiet' ? T.wfQuiet : t === 'watch' ? T.watch : T[t];
    b += rect(x, by, w - 3, 12, 3, c, undefined, t === 'watch' ? 'opacity="0.75"' : '');
    x += w;
  });
  const ts = narrow ? 15.5 : 16;
  const colW2 = (W - 2 * M) / 2;
  let lx = M;
  tiers.forEach((t, i) => {
    const label = TIER_NAME[t];
    const n = fmt(counts[t]);
    const c = t === 'quiet' ? T.muted : T.ink[t];
    const ly = narrow ? by + 44 + Math.floor(i / 2) * 28 : by + 44;
    if (narrow) lx = M + (i % 2) * colW2;
    b += icon(TIER_ICON[t], lx, ly - 13, 16, c, 1.6);
    b += runs(lx + 24, ly, [
      { s: `${label} `, o: { size: ts, fill: c, weight: 500 } },
      { s: n, o: { size: ts, font: 'mono', weight: 600, fill: T.text } },
    ]);
    if (!narrow) lx += 24 + measure(`${label} `, ts, 'sans', 500) + measure(n, ts, 'mono', 600) + 40;
  });

  // Waterfall: title, the site's caption, the legend, then the chart.
  const caption = (hours: number) => `Every CVE in the window, in ${hours}-hour slots. Lit ticks cleared the bar; amber is Watch and grey is Quiet, the noise.`;
  const wh = narrow ? 150 : 200;
  const plotW = W - 2 * M;
  const probe = waterfall(T, M, 0, plotW, wh, { id });
  let ty = narrow ? by + 44 + 28 + 58 : by + 104;
  b += text(M, ty, 'Signal waterfall', { size: 18, weight: 600, fill: T.text });
  if (!narrow) b += waterfallLegend(T, W - M, ty, probe.fresh);
  const capLines = wrap(caption(probe.slotHours), plotW, narrow ? 14.5 : 15);
  b += lines(M, ty + 26, capLines, 20, { size: narrow ? 14.5 : 15, fill: T.muted });
  ty += 26 + (capLines.length - 1) * 20;
  if (narrow) {
    const [lg, lh] = waterfallLegendRows(T, M, ty + 28, probe.fresh, plotW);
    b += lg;
    ty += 28 + lh;
  }
  const wy = ty + (narrow ? 48 : 60);
  const wf = waterfall(T, M, wy, plotW, wh, { id, labels: narrow ? 2 : 4, axis: true });
  b += wf.svg;

  const H = wy + wh + 40 + 80;
  b += footer(T, W, H, `From meta.json and stats.json, run of ${RUN}.`, undefined, M);
  return svgDoc(W, H, 'Signal and noise in the last 30 days', `${fmt(C.window_published)} new CVEs in the last ${meta.window.days} days, ${fmt(C.window_passed)} worth your time, and the signal waterfall of the window.`, frame(T, W, H, id) + b);
}

// ------------------------------------------------------------------------------------------------
// 6. Receipts
// ------------------------------------------------------------------------------------------------

function receiptsCard(T: Theme): string {
  const W = 1200;
  const bt = receipts.backtest;
  if (!bt) throw new Error('receipts.json has no backtest');
  const recent = bt.sets.find((s) => s.key === 'recent');
  if (!recent) throw new Error('receipts.json backtest has no recent set');
  const vol = bt.volume;
  let b = '';
  const [hd, hy] = heading(
    T,
    48,
    64,
    'Receipts · backtest, hindsight',
    'Flagged before CISA listed it in KEV',
    `${recent.n} CVEs CISA added to KEV from ${day(bt.from, false)} to ${day(bt.to)}, scored with only the evidence dated before each listing. Next to two common rules: patch every CVSS 7 or more, or every EPSS 10% or more.`,
    1000,
  );
  b += hd;
  const methods: { key: 'cverdict' | 'cvss7' | 'epss10'; name: string; color: string }[] = [
    { key: 'cverdict', name: 'CVErdict', color: T.accent },
    { key: 'cvss7', name: 'CVSS 7 or more', color: T.muted },
    { key: 'epss10', name: 'EPSS 10% or more', color: T.muted },
  ];
  const caught = (k: string) => recent.strict.find((m) => m.method === k)?.before ?? 0;
  const flagged = (k: string) => vol?.methods.find((m) => m.method === k)?.flagged ?? 0;
  const volN = vol?.n ?? 0;

  const py = hy + 50;
  const colW = (W - 96 - 40) / 2;
  const panels: { title: string; sub: string; val: (k: string) => number; den: number; label: (k: string) => string; good: string }[] = [
    { title: 'KEV CVEs caught before the listing', sub: `of ${recent.n}, higher is better`, val: caught, den: recent.n, label: (k) => `${caught(k)}  (${pct(caught(k), recent.n, 0)})`, good: 'more' },
    { title: 'Alert volume', sub: `share of all ${fmt(volN)} CVEs scored, lower is better`, val: flagged, den: volN, label: (k) => `${fmt(flagged(k))}  (${pct(flagged(k), volN, flagged(k) / volN < 0.01 ? 2 : 1)})`, good: 'fewer' },
  ];
  panels.forEach((p, pi) => {
    const x = 48 + pi * (colW + 40);
    const ph = 300;
    b += rect(x, py, colW, ph, 14, panel(T), T.border);
    b += text(x + 24, py + 40, p.title, { size: 19, weight: 600, fill: T.text });
    b += text(x + 24, py + 66, p.sub, { size: 15, fill: T.faint });
    methods.forEach((m, i) => {
      const y = py + 112 + i * 64;
      const share = p.val(m.key) / p.den;
      const trackW = colW - 48;
      const isUs = m.key === 'cverdict';
      b += text(x + 24, y, m.name, { size: 16, weight: isUs ? 600 : 500, fill: isUs ? T.text : T.muted });
      b += text(x + colW - 24, y, p.label(m.key), { size: 15.5, font: 'mono', weight: isUs ? 600 : 500, fill: isUs ? T.text : T.muted, anchor: 'end' });
      b += rect(x + 24, y + 12, trackW, 14, 7, tint(T, T.muted, 0.12));
      const w = Math.max(4, trackW * share);
      b += rect(x + 24, y + 12, w, 14, 7, isUs ? T.accent : T.name === 'dark' ? '#5b616b' : '#9ca3af');
    });
  });

  // Live record strip
  const ly = py + 300 + 28;
  const fwd = receipts.forward;
  const live = (k: string) => fwd.methods.find((m) => m.method === k);
  const cv = live('cverdict');
  const lh = 92;
  b += rect(48, ly, W - 96, lh, 14, tint(T, T.accent, T.name === 'dark' ? 0.05 : 0.04), mix(T.accent, panel(T), 0.4));
  b += `<circle cx="74" cy="${ly + 33}" r="5" fill="${T.ok}"/>`;
  b += runs(90, ly + 39, [
    { s: 'The live record ', o: { size: 17, weight: 600, fill: T.text } },
    { s: `since ${day(fwd.since)}, ${fmt(fwd.runs)} runs: `, o: { size: 17, fill: T.muted } },
  ]);
  const parts = [
    `CVErdict ${cv?.before ?? 0} of ${fwd.eligible}${cv?.lead ? ` (median ${cv.lead.median} days early)` : ''}`,
    `CVSS 7 ${live('cvss7')?.before ?? 0}`,
    `EPSS 10% ${live('epss10')?.before ?? 0}`,
  ];
  b += text(90, ly + 68, `KEV listings flagged before CISA: ${parts.join(' · ')}. Small so far; it grows every hour.`, { size: 16, fill: T.muted });

  const H = ly + lh + 98;
  b += footer(T, W, H, `receipts.json: backtest of ${day(bt.computed_at)} (${bt.score_model}), live record to ${stamp(fwd.last)}.`);
  return svgDoc(W, H, 'CVErdict receipts', 'The hindsight backtest of CVErdict against CVSS 7 or more and EPSS 10% or more on recent KEV additions, and the live record since it started.', frame(T, W, H, 'rcpt') + b);
}

// ------------------------------------------------------------------------------------------------
// 7. Surfaces
// ------------------------------------------------------------------------------------------------

function surfaces(T: Theme): string {
  const W = 1200;
  let b = '';
  const [hd, hy] = heading(T, 48, 64, 'On the site', 'Twelve ways in, one verdict', 'No account, no tracking, no cookies. Keyboard first: j and k to move, / to search, Ctrl K for everything.');
  b += hd;
  const items: { name: string; route: string; iconName: string; body: string; color: string }[] = [
    { name: 'Today', route: '/', iconName: 'Scan', body: 'The noise meter, the signal waterfall, Heating up, the evidence bar and the signal feed.', color: T.accent },
    { name: 'CVE pages', route: '/cve/<id>', iconName: 'Info', body: 'The verdict, the score chip by chip, what we could not see, "Copy as ticket".', color: T.accent },
    { name: 'KEV Clock', route: '/kev', iconName: 'Clock', body: 'Every KEV due date counting down, with ransomware and forensic flags.', color: T.ink.exploited },
    { name: 'Woke Up', route: '/woke', iconName: 'Alert', body: 'Old CVEs that gained exploitation evidence in the last 30 days.', color: T.ink.exploited },
    { name: 'Receipts', route: '/receipts', iconName: 'Check', body: 'Flagged before KEV, next to CVSS 7 and EPSS 10%, every hit and miss.', color: T.ok },
    { name: 'Check Deps', route: '/check', iconName: 'Lock', body: 'Every CVE an advisory names, for your SBOM or lockfile. Read in your browser, never uploaded.', color: T.ai },
    { name: 'Explore', route: '/explore', iconName: 'Search', body: 'Every CVE of the window, searchable and filterable by day.', color: T.ink.likely },
    { name: 'Batches', route: '/batches', iconName: 'Layers', body: 'Patch days and bulk releases, and the few CVEs in each that matter.', color: T.ink.likely },
    { name: 'The Surge', route: '/surge', iconName: 'Sparkle', body: 'Monthly CVE volume since 1999, Time to KEV, KEV additions and AI-credited CVEs.', color: T.ink.watch },
    { name: 'Method', route: '/method', iconName: 'Filter', body: 'Every chip, its points and the known blind spots.', color: T.ink.watch },
    { name: 'MCP', route: '/mcp', iconName: 'Terminal', body: 'Add the read-only MCP server to an AI agent in one command.', color: T.ai },
    { name: 'Feeds & API', route: '/feeds', iconName: 'Rss', body: 'Atom and iCalendar feeds, the open JSON files and llms.txt.', color: T.muted },
  ];
  const cols = 4;
  const gap = 16;
  const cw = (W - 96 - (cols - 1) * gap) / cols;
  const ch = 158;
  const gy = hy + 44;
  items.forEach((it, i) => {
    const x = 48 + (i % cols) * (cw + gap);
    const y = gy + Math.floor(i / cols) * (ch + gap);
    b += rect(x, y, cw, ch, 12, panel(T), T.border);
    b += iconTile(T, it.iconName, x + 18, y + 18, 36, it.color);
    b += text(x + 66, y + 34, it.name, { size: 18, weight: 600, fill: T.text });
    b += text(x + 66, y + 54, it.route, { size: 13.5, font: 'mono', fill: T.faint });
    b += lines(x + 18, y + 90, wrap(it.body, cw - 34, 15), 20, { size: 15, fill: T.muted });
  });
  const H = gy + 3 * (ch + gap) - gap + 96;
  b += footer(T, W, H, 'All of it reads the same open data branch, refreshed every hour.');
  return svgDoc(W, H, 'CVErdict on the site', 'The twelve pages of cverdict.dev, each with its route and what it shows.', frame(T, W, H, 'surf') + b);
}

// ------------------------------------------------------------------------------------------------
// 8. Social preview (dark only; rendered to PNG by render.mjs)
// ------------------------------------------------------------------------------------------------

function socialPreview(): string {
  const T = THEMES[0];
  const W = 1280;
  const H = 640;
  let b = frame(T, W, H, 'og').replace(/rx="20"/g, 'rx="0"');
  b += mark(80, 74, 88, T.accent);
  b += wordmark(190, 140, 72, T.text, -1.5)[0];
  b += text(80, 250, 'Every CVE gets a verdict.', { size: 56, weight: 600, fill: T.text, ls: -1 });
  b += text(80, 318, 'Every verdict comes with receipts.', { size: 56, weight: 600, fill: T.accent, ls: -1 });
  b += text(80, 372, 'Open-source CVE triage from CISA KEV, EPSS and public exploit feeds.', { size: 26, fill: T.muted });
  let x = 80;
  for (const t of ['exploited', 'likely', 'watch', 'quiet'] as Tier[]) {
    b += rect(x, 408, 18, 18, 4, t === 'quiet' ? T.faintUi : T[t]);
    b += text(x + 28, 424, TIER_NAME[t], { size: 24, fill: T.text });
    x += 28 + measure(TIER_NAME[t], 24) + 40;
  }
  b += waterfall(T, 80, 466, W - 160, 114, { id: 'og' }).svg;
  b += text(W - 80, 140 - 26, BRAND.siteUrl.replace('https://', ''), { size: 26, font: 'mono', weight: 500, fill: T.muted, anchor: 'end' });
  return svgDoc(W, H, 'CVErdict social preview', 'CVErdict: every CVE gets a verdict, every verdict comes with receipts.', b);
}

// ------------------------------------------------------------------------------------------------
// Write
// ------------------------------------------------------------------------------------------------

mkdirSync(OUT, { recursive: true });
const ex = await exampleCve();
const written: string[] = [];
const write = (name: string, svg: string) => {
  writeFileSync(join(OUT, name), svg);
  written.push(`${name} ${(svg.length / 1024).toFixed(0)} KB`);
};
for (const T of THEMES) {
  write(`logo-${T.name}.svg`, logo(T));
  write(`how-it-works-${T.name}.svg`, howItWorks(T));
  write(`architecture-${T.name}.svg`, architecture(T));
  write(`scoring-${T.name}.svg`, scoring(T, ex));
  write(`scoring-narrow-${T.name}.svg`, scoring(T, ex, true));
  write(`signal-${T.name}.svg`, signal(T));
  write(`signal-narrow-${T.name}.svg`, signal(T, true));
  write(`receipts-${T.name}.svg`, receiptsCard(T));
  write(`surfaces-${T.name}.svg`, surfaces(T));
}
write('social-preview.svg', socialPreview());
console.log(written.join('\n'));
console.log(`\ndata: run of ${RUN} (${meta.score_model}); example ${ex.id} = ${ex.score.value}`);
console.log(
  JSON.stringify({
    window: [meta.window.from, meta.window.to],
    published: C.window_published,
    passed: C.window_passed,
    by_tier: C.window_by_tier,
    ytd: C.published_ytd,
    kev_adds_30d: C.kev_adds_30d,
  }),
);
