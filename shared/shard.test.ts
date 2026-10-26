import { describe, expect, it } from 'vitest';
import { shardOf, SHARD_COUNT } from './shard';

describe('shardOf', () => {
  it('is stable, case-insensitive and in range', () => {
    expect(shardOf('CVE-2026-104596')).toBe(shardOf('cve-2026-104596'));
    expect(shardOf('CVE-2026-104596')).toMatch(/^[0-9a-f]{2}$/);
    const seen = new Set<string>();
    for (let i = 0; i < 5000; i++) seen.add(shardOf(`CVE-2026-${10000 + i}`));
    expect(seen.size).toBeGreaterThan(SHARD_COUNT * 0.95);
  });
});
