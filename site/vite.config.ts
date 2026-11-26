import { defineConfig, type Plugin } from 'vite';
import preact from '@preact/preset-vite';
import { fileURLToPath } from 'node:url';
import { BRAND } from '../shared/brand.js';
import { llmsTxt } from '../shared/llms.js';
import { genericHead, hasShareBlock, injectHead, siteOrigin } from '../shared/share.js';

// BASE lets the same build target Vercel ("/") and GitHub Pages ("/<repo>/").
const base = process.env.BASE ?? '/';

/**
 * Fills index.html's share block with the site card. Link previews need absolute image URLs, so
 * they use SITE_URL, else Vercel's production domain, else BRAND.siteUrl (shared/share.ts).
 */
function shareHead(): Plugin {
  return {
    name: 'cverdict-share-head',
    transformIndexHtml(html) {
      if (!hasShareBlock(html)) throw new Error('index.html lost its share markers, or has them out of order');
      return injectHead(html, genericHead(siteOrigin(process.env)));
    },
  };
}

/** /llms.txt for AI agents (shared/llms.ts): written into the build, and served by the dev server. */
function llms(): Plugin {
  const text = () => llmsTxt(siteOrigin(process.env), base);
  return {
    name: 'cverdict-llms-txt',
    configureServer(server) {
      server.middlewares.use('/llms.txt', (_req, res) => {
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end(text());
      });
    },
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'llms.txt', source: text() });
    },
  };
}

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  base,
  plugins: [preact(), shareHead(), llms()],
  // Vendor feeds are a Vercel function (api/feed.ts): a build for any other host links to the main site's.
  define: { __VENDOR_FEEDS_ORIGIN__: JSON.stringify(process.env.VERCEL ? '' : BRAND.siteUrl) },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
  },
  server: { port: 5173 },
});
