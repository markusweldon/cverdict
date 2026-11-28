// Renders the static share images (site/public/og/*.png) and writes shared/share-images.ts.
//
// Run by hand when the wording, the colours or the logo change, then commit both:
//   npm --prefix tools/og ci && node tools/og/render.mjs
//
// The images carry no CVE data and no numbers, so they are true for every CVE of their tier at any
// time. The colours are the dark theme's, read from site/src/styles/tokens.css.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';
import satori from 'satori';
import { initWasm, Resvg } from '@resvg/resvg-wasm';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const OUT_DIR = join(ROOT, 'site/public/og');
const TABLE = join(ROOT, 'shared/share-images.ts');
const WIDTH = 1200;
const HEIGHT = 630;

const require = createRequire(import.meta.url);
await initWasm(readFileSync(require.resolve('@resvg/resvg-wasm/index_bg.wasm')));
/**
 * WOFF 1.0 to the plain sfnt (TrueType or OpenType) it wraps, with Node's own zlib. satori and
 * opentype.js unpack WOFF with fflate's 0.7 API, which fflate 0.8 changed; fflate 0.7 has a
 * denial-of-service bug (CVE-2026-45820) fixed in 0.8.3. Handing them the sfnt means fflate is
 * never called, so package.json can pin the fixed 0.8.3 without breaking the fonts.
 */
function woffToSfnt(woff) {
  const v = new DataView(woff.buffer, woff.byteOffset, woff.byteLength);
  if (v.getUint32(0) !== 0x774f4646) return woff; // not 'wOFF': already TTF or OTF
  const flavor = v.getUint32(4);
  const n = v.getUint16(12);
  const tables = [];
  for (let i = 0; i < n; i++) {
    const at = 44 + i * 20;
    const [tag, offset, compLength, origLength, checksum] = [v.getUint32(at), v.getUint32(at + 4), v.getUint32(at + 8), v.getUint32(at + 12), v.getUint32(at + 16)];
    const raw = woff.subarray(offset, offset + compLength);
    const data = compLength < origLength ? inflateSync(raw) : raw;
    if (data.length !== origLength) throw new Error('WOFF table has the wrong length after inflating');
    tables.push({ tag, checksum, data });
  }
  let pow = 1;
  while (pow * 2 <= n) pow *= 2;
  const head = 12 + n * 16;
  const size = tables.reduce((a, t) => a + ((t.data.length + 3) & ~3), head);
  const out = Buffer.alloc(size);
  out.writeUInt32BE(flavor, 0);
  out.writeUInt16BE(n, 4);
  out.writeUInt16BE(pow * 16, 6);
  out.writeUInt16BE(Math.log2(pow), 8);
  out.writeUInt16BE(n * 16 - pow * 16, 10);
  let off = head;
  tables.forEach((t, i) => {
    out.writeUInt32BE(t.tag, 12 + i * 16);
    out.writeUInt32BE(t.checksum, 16 + i * 16);
    out.writeUInt32BE(off, 20 + i * 16);
    out.writeUInt32BE(t.data.length, 24 + i * 16);
    out.set(t.data, off);
    off += (t.data.length + 3) & ~3;
  });
  return out;
}

// satori reads TTF, OTF and WOFF (not WOFF2): the static Latin WOFF files of each weight, unwrapped.
const font = (pkg, file) => woffToSfnt(readFileSync(join(dirname(require.resolve(`${pkg}/package.json`)), 'files', file)));
const fonts = [
  { name: 'Geist', data: font('@fontsource/geist', 'geist-latin-400-normal.woff'), weight: 400, style: 'normal' },
  { name: 'Geist', data: font('@fontsource/geist', 'geist-latin-600-normal.woff'), weight: 600, style: 'normal' },
];

/** Dark theme tokens: the first `--name: #hex;` of each name in tokens.css (the :root block). */
function darkTokens() {
  const css = readFileSync(join(ROOT, 'site/src/styles/tokens.css'), 'utf8');
  const out = {};
  for (const m of css.matchAll(/--([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) if (!(m[1] in out)) out[m[1]] = m[2].toUpperCase();
  for (const k of ['bg', 'raised', 'text', 'muted', 'faint-ui', 'accent', 'exploited', 'likely', 'watch']) {
    if (!out[k]) throw new Error(`tokens.css has no --${k}`);
  }
  return out;
}
const T = darkTokens();
const TIER_INK = { exploited: T.exploited, likely: T.likely, watch: T.watch, quiet: T.muted };
// --quiet (#3A3F47) is a fill for dim waterfall ticks; on the image the stripe needs to be seen.
const TIER_STRIPE = { exploited: T.exploited, likely: T.likely, watch: T.watch, quiet: T['faint-ui'] };

const LOGO = `data:image/svg+xml;base64,${Buffer.from(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="${T.raised}"/><path d="M5 21.5h6l1.4-1.8 1.4 1.8h1.3L18.6 7l2.9 14.5H27" fill="none" stroke="${T.accent}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/><circle cx="18.6" cy="7" r="2" fill="${T.accent}"/></svg>`,
).toString('base64')}`;

/** The words on each image. Plain copy, no em dashes; the alt text repeats them. */
const SITE = {
  title: 'Every CVE gets a verdict.',
  title2: 'Every verdict comes with receipts.',
  line: 'Open-source CVE triage from CISA KEV, EPSS and public exploit feeds. Every score is a sum of reasons you can check.',
  alt: 'CVErdict: every CVE gets a verdict, and every verdict comes with receipts. Tiers: Exploited, Likely next, Watch, Quiet.',
};
const TIERS = {
  exploited: { name: 'Exploited', line: 'Confirmed exploitation: CISA KEV, CISA SSVC or the vendor.' },
  likely: { name: 'Likely next', line: 'A Metasploit module or Nuclei template, or a score that clears the evidence bar.' },
  watch: { name: 'Watch', line: 'Some evidence, below the evidence bar.' },
  quiet: { name: 'Quiet', line: 'Little or no evidence yet, below the evidence bar. Quiet is not safe.' },
};
const FOOTER = 'The CVE, its score and the reasons are in the link text.';

const h = (type, style, ...children) => {
  const kids = children.flat().filter((c) => c !== null && c !== undefined && c !== false);
  return { type, props: { style, children: kids.length === 1 && typeof kids[0] === 'string' ? kids[0] : kids } };
};
const logoRow = (size, fontSize) =>
  h('div', { display: 'flex', alignItems: 'center' }, { type: 'img', props: { src: LOGO, width: size, height: size, style: { marginRight: Math.round(size / 3) } } }, h('div', { display: 'flex', fontSize }, h('div', { display: 'flex', fontWeight: 600 }, 'CVE'), h('div', { display: 'flex', fontWeight: 400 }, 'rdict')));

function siteTree() {
  const swatch = (label, color) =>
    h('div', { display: 'flex', alignItems: 'center', marginRight: 32 }, h('div', { display: 'flex', width: 18, height: 18, borderRadius: 4, background: color, marginRight: 12 }), h('div', { display: 'flex', fontSize: 26 }, label));
  return h(
    'div',
    { width: WIDTH, height: HEIGHT, display: 'flex', flexDirection: 'column', background: T.bg, color: T.text, fontFamily: 'Geist', padding: '64px 72px' },
    logoRow(72, 56),
    h('div', { display: 'flex', marginTop: 56, fontSize: 52, fontWeight: 600, lineHeight: 1.15 }, SITE.title),
    h('div', { display: 'flex', fontSize: 52, fontWeight: 600, lineHeight: 1.15, color: T.accent }, SITE.title2),
    h('div', { display: 'flex', marginTop: 28, fontSize: 28, color: T.muted, maxWidth: 1000, lineHeight: 1.4 }, SITE.line),
    h('div', { display: 'flex', marginTop: 'auto' }, ...Object.entries(TIERS).map(([tier, t]) => swatch(t.name, TIER_STRIPE[tier]))),
  );
}

function tierTree(tier) {
  const ink = TIER_INK[tier];
  return h(
    'div',
    { width: WIDTH, height: HEIGHT, display: 'flex', background: T.bg, color: T.text, fontFamily: 'Geist' },
    h('div', { display: 'flex', width: 14, height: HEIGHT, background: TIER_STRIPE[tier] }),
    h(
      'div',
      { display: 'flex', flexDirection: 'column', width: WIDTH - 14, padding: '64px 72px' },
      logoRow(64, 48),
      h('div', { display: 'flex', marginTop: 64, alignSelf: 'flex-start', border: `3px solid ${ink}`, color: ink, borderRadius: 10, padding: '10px 26px', fontSize: 64, fontWeight: 600, letterSpacing: 1 }, TIERS[tier].name.toUpperCase()),
      // One row per sentence, so a short last word never wraps onto a line of its own.
      h('div', { display: 'flex', flexDirection: 'column', marginTop: 36, fontSize: 34, lineHeight: 1.3 }, ...TIERS[tier].line.split(/(?<=\.) /).map((s) => h('div', { display: 'flex' }, s))),
      h('div', { display: 'flex', marginTop: 'auto', fontSize: 30, color: T.muted }, FOOTER),
    ),
  );
}

const images = [
  { key: 'site', tree: siteTree(), alt: SITE.alt },
  ...Object.keys(TIERS).map((tier) => ({ key: tier, tree: tierTree(tier), alt: `CVErdict verdict: ${TIERS[tier].name}. ${TIERS[tier].line}` })),
];
for (const img of images) if (/\u2014/.test(img.alt)) throw new Error(`em dash in the ${img.key} image text`);

mkdirSync(OUT_DIR, { recursive: true });
const table = [];
for (const img of images) {
  const t0 = performance.now();
  const png = new Resvg(await satori(img.tree, { width: WIDTH, height: HEIGHT, fonts })).render().asPng();
  writeFileSync(join(OUT_DIR, `${img.key}.png`), png);
  const v = createHash('sha256').update(png).digest('hex').slice(0, 8);
  table.push({ key: img.key, path: `/og/${img.key}.png`, v, alt: img.alt });
  console.log(`${img.key}.png ${png.length} B v=${v} ${Math.round(performance.now() - t0)} ms`);
}

const lines = [
  '// Generated by tools/og/render.mjs. Do not edit: change the script and run it again.',
  '',
  '/** Size of every share image (the Open Graph 1.91:1 format). */',
  `export const SHARE_IMAGE_WIDTH = ${WIDTH};`,
  `export const SHARE_IMAGE_HEIGHT = ${HEIGHT};`,
  '',
  '/** The static share images in site/public/og/: path, version (first 8 hex digits of the SHA-256) and alt text. */',
  'export const SHARE_IMAGES = {',
  ...table.map((t) => `  ${t.key}: { path: ${JSON.stringify(t.path)}, v: ${JSON.stringify(t.v)}, alt: ${JSON.stringify(t.alt)} },`),
  '} as const;',
  '',
];
writeFileSync(TABLE, lines.join('\n'));
console.log(`wrote ${TABLE}`);
