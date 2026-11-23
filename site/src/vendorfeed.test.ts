import { describe, expect, it } from 'vitest';
import { normalizeName } from './state';
import { vendorFeedUrl } from './vendorfeed';

describe('vendorFeedUrl', () => {
  it('turns a watched name into its feed URL', () => {
    expect(vendorFeedUrl(normalizeName('  Palo Alto   Networks '), 'https://cverdict.dev')).toBe('https://cverdict.dev/feeds/v/palo-alto-networks.xml');
    expect(vendorFeedUrl('schneider électric', 'https://cverdict-psi.vercel.app/')).toBe('https://cverdict-psi.vercel.app/feeds/v/schneider-electric.xml');
    expect(vendorFeedUrl('f5', 'https://cverdict.dev')).toBe('https://cverdict.dev/feeds/v/f5.xml');
  });

  it('has no URL for a name without ASCII letters or digits', () => {
    expect(vendorFeedUrl('日本', 'https://cverdict.dev')).toBeNull();
    expect(vendorFeedUrl(' - ', 'https://cverdict.dev')).toBeNull();
  });
});
