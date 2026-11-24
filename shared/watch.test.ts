import { describe, expect, it } from 'vitest';
import * as site from '../site/src/state';
import { isWatched, matchesName, normalizeName, WATCH_NAME_MAX } from './watch';

describe('watchlist match rule', () => {
  it('is the one the site uses, not a copy', () => {
    expect(site.isWatched).toBe(isWatched);
    expect(site.normalizeName).toBe(normalizeName);
    expect(site.parseWatch('x'.repeat(WATCH_NAME_MAX))).toHaveLength(1);
    expect(site.parseWatch('x'.repeat(WATCH_NAME_MAX + 1))).toEqual([]);
  });

  it('matches the vendor or the product exactly, ignoring case and extra spaces', () => {
    expect(matchesName(['palo alto networks'], ' Palo  Alto\tNetworks ', 'PAN-OS')).toBe(true);
    expect(matchesName(['pan-os'], 'Palo Alto Networks', 'PAN-OS')).toBe(true);
    expect(matchesName(['palo alto'], 'Palo Alto Networks', 'PAN-OS')).toBe(false);
    expect(matchesName([], 'Acme', 'Widget')).toBe(false);
    expect(matchesName([''], '', '')).toBe(false);
    expect(isWatched(['acme'], { v: 'ACME', p: '' })).toBe(true);
  });
});
