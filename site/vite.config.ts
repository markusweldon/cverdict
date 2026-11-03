import { defineConfig, type Plugin } from 'vite';
import preact from '@preact/preset-vite';
import { fileURLToPath } from 'node:url';
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

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  base,
  plugins: [preact(), shareHead()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
  },
  server: { port: 5173 },
});
