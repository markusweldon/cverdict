# CVErdict brand images

The README's logo, diagrams, screenshots, demo GIF and the repository's social preview are made by
the scripts in this folder, from the site's own tokens, fonts and icons and from real data. Do not
hand-edit the files in `docs/assets/`; change a script and run it again.

| Command | Writes | Needs |
| --- | --- | --- |
| `npm run brand` | `docs/assets/*-dark.svg`, `*-light.svg`, `social-preview.svg` | nothing beyond `npm ci`; reads the live data branch |
| `npm run brand -- --data <dir>` | the same, from a local data tree (`site/public/data`, a pipeline `--out`) | |
| `node tools/brand/render.mjs` | `docs/assets/social-preview.png` (1280x640) | Playwright with Chromium |
| `node tools/brand/render.mjs --preview <dir>` | also every SVG as a 2x PNG on GitHub's light and dark page colours, to check by eye | Playwright |
| `node tools/brand/screens.mjs --url <site>` | `docs/assets/screens/*.webp` and `docs/assets/demo-dark.gif` from a running production build | Playwright, ffmpeg |
| `node tools/brand/metrics.mjs` | `tools/brand/metrics.json`, the font widths `build.ts` lays text out with; only when the fonts change | Playwright |

For the screenshots, build the site (`npm run build`) and serve `site/dist` with `/data/` pointing
at a data tree, for example `npm run preview` after `npm run pipeline` or `npm run mock`. The page
clock is set nine minutes after the data's `generated_at`.

When the data changes, rerun `npm run brand`, `render.mjs` and `screens.mjs` together and update the
numbers and dates in the README text and alt text to the same run: `build.ts` prints the counts it
used.

## Rules

- **Real numbers only.** Every count comes from `meta.json`, `stats.json`, `receipts.json`,
  `batches.json` or a CVE shard, and every image names the run it shows. Points and thresholds come
  from `shared/model.ts`, `shared/contract.ts` and `site/src/state.ts`.
- **The site's look.** Colours are read from `site/src/styles/tokens.css` (dark from `:root`,
  light from `:root[data-theme='light']`), icons from `site/src/components/icons.tsx`, and the mark
  is the site's: a flat noise floor with one signal spike rising out of it.
- **Both GitHub themes.** Every diagram comes in a dark and a light version, shown with `<picture>`
  and `prefers-color-scheme`, so it sits on the page in the reader's theme, as the site does. The
  screenshots and the GIF show the dark theme, the site's default.
- **Safe on GitHub.** No scripts, no external references, no `foreignObject`. The fonts are embedded
  as data URIs, so the text looks the same in GitHub's image sandbox as on the site.
- **Plain copy.** Short sentences, no em dashes. Each image has full alt text in the README that
  carries every number it shows.

## Colour

| Token | Dark | Light | Means |
| --- | --- | --- | --- |
| `--accent` | `#c6f432` | `#4d7c0f` | the signal, what is worth your time; the mark |
| `--exploited` | `#ff4d4f` | `#d92d20` | Exploited |
| `--likely` | `#ff8a3d` | `#c2410c` | Likely next |
| `--watch` | `#f5c542` | `#a16207` | Watch |
| `--quiet` / `--muted` | `#3a3f47` / `#8a919c` | `#9ca3af` / `#5b616b` | Quiet, noise |
| `--ai` | `#8b7cff` | `#6d28d9` | AI credits, CISA SSVC, the MCP server |
| `--bg` | `#0a0b0d` | `#fafaf9` | card background |

## Type

Geist for text and Geist Mono for IDs, paths, numbers in tables and eyebrows, both under the SIL
Open Font License 1.1 (see [ATTRIBUTIONS.md](../../ATTRIBUTIONS.md#fonts)). The wordmark sets
"CVE" in Geist 600 and "rdict" in Geist 400.
