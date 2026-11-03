import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['pipeline/test/**/*.test.ts', 'shared/**/*.test.ts', 'site/src/**/*.test.ts', 'mcp/test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
  },
});
