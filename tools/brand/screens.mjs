// Takes the README screenshots and the demo GIF from a running production build of the site:
//
//   npm run build && npm run preview            # or any server that serves site/dist and /data/
//   node tools/brand/screens.mjs --url http://localhost:4173 [--cve CVE-2026-119958]
//
// Writes docs/assets/screens/*.webp (dark theme, 2x) and docs/assets/demo-dark.gif. The page clock
// is set a few minutes after the data's generated_at, so "data age" reads as it did live. The
// Check Deps shot uses a sample package-lock.json written to a temporary folder (it is never
// committed, so no dependency bot picks it up). Needs Playwright with Chromium and ffmpeg.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ASSETS = join(HERE, '..', '..', 'docs', 'assets');
const SCREENS = join(ASSETS, 'screens');
const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  ({ chromium } = await import('playwright'));
}
const arg = (n, d) => {
  const i = process.argv.indexOf(`--${n}`);
  return i > 0 ? process.argv[i + 1] : d;
};
const URL_BASE = arg('url', 'http://localhost:4173').replace(/\/$/, '');
const CVE = arg('cve', 'CVE-2026-119958');
const TMP = mkdtempSync(join(tmpdir(), 'cverdict-screens-'));
mkdirSync(SCREENS, { recursive: true });

const meta = await (await fetch(`${URL_BASE}/data/v1/meta.json`)).json();
const clock = new Date(Date.parse(meta.generated_at) + 9 * 60e3);

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: 'dark', reducedMotion: 'no-preference' });
const page = await ctx.newPage();
await page.clock.install({ time: clock });
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));
page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));

const webp = (png, out) => {
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', png, '-c:v', 'libwebp', '-quality', '86', '-compression_level', '6', out]);
};
async function go(path, ready) {
  await page.goto(`${URL_BASE}${path}`);
  await page.waitForSelector(ready, { timeout: 20000 });
  await page.waitForTimeout(2600); // count-up and chart animations settle
}
async function still(name, clip) {
  const png = join(TMP, `${name}.png`);
  await page.screenshot({ path: png, clip: { x: 0, y: 0, width: 1440, ...clip } });
  webp(png, join(SCREENS, `${name}.webp`));
}

await go(`/cve/${CVE}`, 'h1');
await still('cve', { height: 900 });
await go('/receipts', 'h1');
await still('receipts', { height: 900 });
await go('/kev', 'h1');
await still('kev', { height: 760 });
await go('/woke', 'h1');
await still('woke', { height: 760 });
await go('/surge', 'h1');
await still('surge', { height: 760 });

// Check Deps with a sample lockfile, read in the browser only.
const lock = {
  name: 'demo-app',
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: 'demo-app', version: '1.0.0' },
    'node_modules/electron': { version: '22.3.0' },
    'node_modules/@strapi/strapi': { version: '4.5.0' },
    'node_modules/eslint-config-prettier': { version: '8.10.1' },
    'node_modules/@mockoon/cli': { version: '9.6.0' },
    'node_modules/preact': { version: '10.24.0' },
    'node_modules/express': { version: '4.21.2' },
    'node_modules/lodash': { version: '4.17.21' },
  },
};
const lockDir = join(TMP, 'demo');
mkdirSync(lockDir);
writeFileSync(join(lockDir, 'package-lock.json'), JSON.stringify(lock, null, 2));
await go('/check', 'h1');
await page.locator('input[type=file]').first().setInputFiles(join(lockDir, 'package-lock.json'));
await page.waitForSelector('.checkpk', { timeout: 20000 });
await page.waitForTimeout(800);
// From the results heading down: the verdict groups are the point of this page.
const top = await page.evaluate(() => {
  const h = [...document.querySelectorAll('h2, h3')].find((e) => e.textContent.startsWith('Results for'));
  return h ? h.getBoundingClientRect().top + window.scrollY - 40 : 0;
});
{
  const png = join(TMP, 'check.png');
  await page.screenshot({ path: png, fullPage: true, clip: { x: 0, y: top, width: 1440, height: 820 } });
  webp(png, join(SCREENS, 'check.webp'));
}

// Demo GIF: the evidence bar on Today, Balanced, Broad, Strict and back.
await go('/', '.today__hero');
const box = await page.locator('.today__grid').boundingBox();
const clip = { x: box.x - 16, y: box.y - 16, width: box.width + 32, height: 300 + 16 };
const wf = await page.locator('.today__wf').boundingBox().catch(() => null);
if (wf) clip.height = wf.y + wf.height - clip.y + 16;
let n = 0;
const frame = async () => page.screenshot({ path: join(TMP, `f${String(n++).padStart(4, '0')}.png`), clip });
const hold = async (frames) => {
  for (let k = 0; k < frames; k++) {
    await frame();
    await page.clock.runFor(100).catch(() => page.waitForTimeout(100));
  }
};
await hold(14);
for (const label of ['Broad', 'Strict', 'Balanced']) {
  await page.getByRole('button', { name: new RegExp(`^${label}`) }).first().click();
  await hold(label === 'Balanced' ? 16 : 18);
}
const gif = join(ASSETS, 'demo-dark.gif');
execFileSync('ffmpeg', [
  '-y', '-loglevel', 'error', '-framerate', '10', '-i', join(TMP, 'f%04d.png'),
  '-vf', 'scale=1280:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle',
  '-loop', '0', gif,
]);

await browser.close();
rmSync(TMP, { recursive: true, force: true });
for (const f of [...readdirSync(SCREENS).map((f) => join(SCREENS, f)), gif]) console.log(`${(statSync(f).size / 1024).toFixed(0).padStart(6)} KB  ${f}`);
if (errors.length) {
  console.error(`page errors:\n${errors.join('\n')}`);
  process.exitCode = 1;
}
