// Takes the README screenshots and the demo GIF from a running production build of the site:
//
//   npm run build && npm run preview            # or any server that serves site/dist and /data/
//   node tools/brand/screens.mjs --url http://localhost:4173 [--cve CVE-2026-119958]
//
// Writes docs/assets/screens/*.webp (dark theme, 2x), docs/assets/demo-dark.gif and
// docs/assets/check-repo-dark.gif. The page clock is set a few minutes after the data's
// generated_at, so "data age" reads as it did live. The Check shot uses a sample package-lock.json
// written to a temporary folder (it is never committed, so no dependency bot picks it up).
//
// The repository check GIF checks OWASP/NodeGoat at a pinned commit, the same lockfile as the
// terminal image (tools/brand/build.ts). GitHub's answers are replayed from that commit, fetched
// with git, so the GIF can be made again without GitHub's API limit and shows the same files
// whatever the branch holds today. The page's own code reads and matches them as it would live.
// Needs Playwright with Chromium, git and ffmpeg.
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
await page.mouse.move(4, 896);
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
// Every still is the same size and aspect ratio (16:9 at 2x), cropped to the content column below
// the site header and starting at the part of the page that matters.
const CROP = { x: 112, width: 1216, height: 684 };
/** The page y of the first element matching `sel` (and `text`, if given), minus `off`. */
const topOf = (sel, text, off) =>
  page.evaluate(
    ([sel, text, off]) => {
      const el = [...document.querySelectorAll(sel)].find((e) => !text || e.textContent.trim().toLowerCase().startsWith(text.toLowerCase()));
      return el ? Math.max(0, el.getBoundingClientRect().top + window.scrollY - off) : 64;
    },
    [sel, text, off],
  );
async function still(name, y) {
  // Scrolled, not a full-page shot, so the sticky header stays at the top and out of the crop.
  const top = Math.max(64, y);
  const scroll = await page.evaluate((t) => {
    window.scrollTo(0, Math.max(0, t - 64));
    return window.scrollY;
  }, top);
  await page.waitForTimeout(400);
  const png = join(TMP, `${name}.png`);
  await page.screenshot({ path: png, clip: { ...CROP, y: top - scroll } });
  webp(png, join(SCREENS, `${name}.webp`));
}

// CVE page: the verdict, the evidence and the score panel.
await go(`/cve/${CVE}`, 'h1');
await still('cve', await topOf('h1', null, 52));
// Receipts: the live record and its table.
await go('/receipts', 'h1');
await still('receipts', await topOf('h2', 'The live record', 28));
// KEV Clock: the countdown card and the first due CVEs.
await go('/kev', 'h1');
await still('kev', await topOf('*', 'Next deadline', 24));
await go('/woke', 'h1');
await still('woke', await topOf('h1', null, 56));
await go('/surge', 'h1');
await still('surge', await topOf('h1', null, 56));
// Time to KEV, further down The Surge.
await page.waitForSelector('#lag-h', { timeout: 20000 });
await still('time-to-kev', await topOf('#lag-h', null, 40));
// Heating up on Today, with the start of the signal feed under it.
await go('/', '#heat-h');
await still('heat', await topOf('#heat-h', null, 40));

// Check with a sample lockfile, read in the browser only.
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
await page.locator('.check__modes').getByRole('button', { name: 'Lockfile or SBOM' }).click();
await page.locator('input[type=file]').first().setInputFiles(join(lockDir, 'package-lock.json'));
await page.waitForSelector('.checkpk', { timeout: 20000 });
await page.waitForTimeout(800);
// From the results heading down: the verdict groups are the point of this page.
await still('check', await topOf('h2, h3', 'Results for', 28));

// In CI: the one-click workflow and the command line.
await go('/check', 'h1');
await page.locator('.check__modes').getByRole('button', { name: 'In CI' }).click();
await page.waitForSelector('.check__ci');
await still('check-ci', await topOf('h1', null, 56));

/** Frames to an animated GIF, at 10 frames a second. */
const toGif = (prefix, out, width = 1280) =>
  execFileSync('ffmpeg', [
    '-y', '-loglevel', 'error', '-framerate', '10', '-i', join(TMP, `${prefix}%04d.png`),
    '-vf', `scale=${width}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle`,
    '-loop', '0', out,
  ]);

// Repository check GIF: paste a repository, read its lockfile from GitHub, see the verdicts.
const DEMO = { owner: 'OWASP', repo: 'NodeGoat', branch: 'master', sha: 'c5cb68a7084e4ae7dcc60e6a98768720a81841e8' };
const git = (...a) => execFileSync('git', ['-C', join(TMP, 'repo'), ...a], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
mkdirSync(join(TMP, 'repo'));
git('init', '-q');
git('fetch', '-q', '--depth', '1', `https://github.com/${DEMO.owner}/${DEMO.repo}.git`, DEMO.sha);
const tree = git('ls-tree', '-r', '--long', 'FETCH_HEAD')
  .trim()
  .split('\n')
  .map((l) => {
    const [info, path] = l.split('\t');
    const [, type, sha, size] = info.trim().split(/\s+/);
    return { path, type, sha, size: Number(size) };
  });
const repoApi = `https://api.github.com/repos/${DEMO.owner}/${DEMO.repo}`;
await page.route('https://api.github.com/**', (r) => {
  const u = r.request().url();
  if (u === repoApi) return r.fulfill({ json: { full_name: `${DEMO.owner}/${DEMO.repo}`, default_branch: DEMO.branch } });
  if (u === `${repoApi}/git/trees/${DEMO.branch}?recursive=1`) return r.fulfill({ json: { sha: DEMO.sha, tree, truncated: false } });
  return r.fulfill({ status: 404, json: { message: 'Not Found' } });
});
const rawBase = `https://raw.githubusercontent.com/${DEMO.owner}/${DEMO.repo}/${DEMO.branch}/`;
await page.route('https://raw.githubusercontent.com/**', (r) => {
  const u = r.request().url();
  if (!u.startsWith(rawBase)) return r.fulfill({ status: 404, body: '404: Not Found' });
  const path = decodeURIComponent(u.slice(rawBase.length));
  return r.fulfill({ body: git('show', `FETCH_HEAD:${path}`) });
});
await go('/check', '#check-repo');
await page.mouse.move(4, 896);
const rc = await page.evaluate(() => {
  const a = document.querySelector('h1').getBoundingClientRect();
  return { x: a.left - 24, y: a.top + window.scrollY - 32 };
});
const repoClip = { x: Math.max(0, rc.x), y: Math.max(64, rc.y), width: 1216, height: Math.min(760, 900 - Math.max(64, rc.y)) };
let rn = 0;
const rframe = async () => page.screenshot({ path: join(TMP, `r${String(rn++).padStart(4, '0')}.png`), clip: repoClip });
const rhold = async (frames) => {
  for (let k = 0; k < frames; k++) {
    await rframe();
    await page.waitForTimeout(100);
  }
};
await rhold(8);
await page.locator('#check-repo').click();
for (const ch of `github.com/${DEMO.owner}/${DEMO.repo}`) {
  await page.keyboard.type(ch);
  await rframe();
}
await rhold(6);
await page.getByRole('button', { name: 'Check repo' }).click();
await page.mouse.move(4, 896);
for (let k = 0; k < 40 && !(await page.locator('.checkpk').count()); k++) await rframe();
await page.waitForSelector('.checkpk', { timeout: 20000 });
await page.waitForTimeout(500);
// Glide down to the verdicts, then hold on them. The clip is in viewport terms, so it stays put
// below the sticky header while the page moves under it.
const from = await page.evaluate(() => window.scrollY);
const to = Math.max(0, (await topOf('h2, h3', 'Results for', 28)) - repoClip.y);
for (let k = 1; k <= 12; k++) {
  await page.evaluate((y) => window.scrollTo(0, y), from + (to - from) * (1 - (1 - k / 12) ** 3));
  await page.waitForTimeout(30);
  await rframe();
}
await rhold(40);
await page.unrouteAll({ behavior: 'ignoreErrors' });
const repoGif = join(ASSETS, 'check-repo-dark.gif');
toGif('r', repoGif, 1100);

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
  // Off the dial again, so no hover tooltip covers the frames.
  await page.mouse.move(4, 896);
  await hold(label === 'Balanced' ? 16 : 18);
}
const gif = join(ASSETS, 'demo-dark.gif');
toGif('f', gif);

await browser.close();
rmSync(TMP, { recursive: true, force: true });
for (const f of [...readdirSync(SCREENS).map((f) => join(SCREENS, f)), gif, repoGif]) console.log(`${(statSync(f).size / 1024).toFixed(0).padStart(6)} KB  ${f}`);
if (errors.length) {
  console.error(`page errors:\n${errors.join('\n')}`);
  process.exitCode = 1;
}
