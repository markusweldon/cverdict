// Measures the advance widths of Geist and Geist Mono (the fonts the SVGs embed) and writes
// tools/brand/metrics.json, which build.mjs uses to lay out text. Run it only when the fonts
// change; it needs Playwright (npx playwright install chromium):
//   node tools/brand/metrics.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const require = createRequire(join(ROOT, 'package.json'));
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  ({ chromium } = await import('playwright'));
}
const file = (pkg, name) => readFileSync(join(ROOT, 'node_modules', pkg, 'files', name)).toString('base64');
const SANS = file('@fontsource-variable/geist', 'geist-latin-wght-normal.woff2');
const MONO = file('@fontsource-variable/geist-mono', 'geist-mono-latin-wght-normal.woff2');
const CHARS = [...Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)), ...'·→←↑↓×≥≤’‘“”…≠%°–•✓'].join('');
const WEIGHTS = [400, 500, 600, 700];

const browser = await chromium.launch();
const page = await browser.newPage();
await page.setContent(`<style>
@font-face{font-family:S;src:url(data:font/woff2;base64,${SANS}) format('woff2');font-weight:100 900}
@font-face{font-family:M;src:url(data:font/woff2;base64,${MONO}) format('woff2');font-weight:100 900}
</style><span style="font-family:S">a</span><span style="font-family:M">a</span>`);
const out = await page.evaluate(
  async ({ chars, weights }) => {
    await document.fonts.ready;
    for (const w of weights) for (const f of ['S', 'M']) await document.fonts.load(`${w} 100px ${f}`);
    const ctx = document.createElement('canvas').getContext('2d');
    const res = { unitsPerEm: 1000, sans: {}, mono: {} };
    for (const [key, fam] of [['sans', 'S'], ['mono', 'M']]) {
      for (const w of weights) {
        ctx.font = `${w} 1000px ${fam}`;
        const row = {};
        for (const ch of chars) row[ch] = Math.round(ctx.measureText(ch).width);
        res[key][w] = row;
      }
    }
    return res;
  },
  { chars: CHARS, weights: WEIGHTS },
);
await browser.close();
writeFileSync(join(HERE, 'metrics.json'), JSON.stringify(out) + '\n');
console.log('wrote tools/brand/metrics.json');
