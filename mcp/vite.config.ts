/**
 * Bundles the stdio server into one file with no runtime dependencies: mcp/dist/cverdict-mcp.mjs,
 * the `bin` of the npm package (mcp/package.json). The SDK and zod are dev dependencies of the
 * repository and are inlined here; their licenses ship as mcp/LICENSE-THIRD-PARTY.
 *
 *   npm run build:mcp                 (MCP_OUT_DIR=<dir> builds elsewhere, as the tests do)
 */
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const here = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  root: here,
  logLevel: 'warn',
  publicDir: false,
  build: {
    ssr: 'src/stdio.ts',
    outDir: process.env.MCP_OUT_DIR ?? 'dist',
    emptyOutDir: true,
    target: 'node22',
    minify: false,
    rolldownOptions: {
      output: { entryFileNames: 'cverdict-mcp.mjs', banner: '#!/usr/bin/env node', codeSplitting: false },
    },
  },
  ssr: { noExternal: true, target: 'node' },
});
