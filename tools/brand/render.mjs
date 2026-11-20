// Renders docs/assets/social-preview.svg to docs/assets/social-preview.png (1280x640) for the
// repository's social preview (Settings, General, Social preview). With --preview <dir> it also
// renders every SVG in docs/assets/ at 2x on GitHub's light and dark page colours, loaded through
// <img> as GitHub shows them, so they can be checked by eye. Needs Playwright with Chromium:
//   node tools/brand/render.mjs [--preview <dir>]
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ASSETS = join(HERE, '..', '..', 'docs', 'assets');
const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  ({ chromium } = await import('playwright'));
}
const i = process.argv.indexOf('--preview');
const preview = i > 0 ? process.argv[i + 1] : null;

const TMP = mkdtempSync(join(tmpdir(), 'cverdict-brand-'));
const browser = await chromium.launch();
async function shot(file, out, { scale, bg, width }) {
  const page = await browser.newPage({ deviceScaleFactor: scale, viewport: { width, height: 400 } });
  // A file:// page, so the <img> may load the file:// SVG.
  const html = join(TMP, 'shot.html');
  writeFileSync(html, `<body style="margin:0;background:${bg}"><img id="i" src="${pathToFileURL(join(ASSETS, file))}" style="display:block;width:${width}px"></body>`);
  await page.goto(pathToFileURL(html).href);
  await page.waitForFunction(() => { const i = document.getElementById('i'); return i.complete && i.naturalWidth > 0; });
  await page.waitForTimeout(150);
  await page.locator('#i').screenshot({ path: out, omitBackground: false });
  await page.close();
}

await shot('social-preview.svg', join(ASSETS, 'social-preview.png'), { scale: 1, bg: '#0a0b0d', width: 1280 });
console.log('wrote docs/assets/social-preview.png');

if (preview) {
  mkdirSync(preview, { recursive: true });
  const github = { dark: '#0d1117', light: '#ffffff' };
  for (const f of readdirSync(ASSETS).filter((n) => n.endsWith('.svg'))) {
    const theme = f.includes('-light') ? 'light' : 'dark';
    // 880 px is about the width of a README on github.com.
    await shot(f, join(preview, f.replace(/\.svg$/, '.png')), { scale: 2, bg: github[theme], width: f.startsWith('logo') ? 440 : 880 });
  }
  console.log(`previews in ${preview}`);
}
await browser.close();
rmSync(TMP, { recursive: true, force: true });
