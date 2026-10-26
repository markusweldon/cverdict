import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';
import { fileURLToPath } from 'node:url';

// BASE lets the same build target Vercel ("/") and GitHub Pages ("/<repo>/").
const base = process.env.BASE ?? '/';

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  base,
  plugins: [preact()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
  },
  server: { port: 5173 },
});
