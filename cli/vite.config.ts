/**
 * Bundles the check into one file with no runtime dependencies (Node built-ins only).
 *
 *   npm run build:cli    cli/dist/cverdict-check.mjs, the `bin` of the npm package (cli/package.json)
 *                        and action/dist/index.mjs, the GitHub Action's entry (action/action.yml)
 *
 * CHECK_ENTRY=action picks the Action's entry; CHECK_OUT_DIR builds elsewhere (CI compares a fresh
 * build of the Action with the committed one).
 */
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const here = fileURLToPath(new URL('.', import.meta.url));
const action = process.env.CHECK_ENTRY === 'action';

export default defineConfig({
  root: here,
  logLevel: 'warn',
  publicDir: false,
  build: {
    ssr: action ? 'src/action-main.ts' : 'src/main.ts',
    outDir: process.env.CHECK_OUT_DIR ?? (action ? '../action/dist' : 'dist'),
    emptyOutDir: true,
    target: 'node22',
    minify: false,
    rolldownOptions: {
      output: {
        entryFileNames: action ? 'index.mjs' : 'cverdict-check.mjs',
        banner: action ? '// Built by `npm run build:cli` from cli/src. Do not edit: CI checks it matches the source.' : '#!/usr/bin/env node',
        codeSplitting: false,
      },
    },
  },
  ssr: { noExternal: true, target: 'node' },
});
