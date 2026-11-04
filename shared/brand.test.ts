import { describe, expect, it } from 'vitest';
import { BRAND, HOME_TITLE } from './brand';

describe('brand', () => {
  it('splits the name into the two parts of the wordmark, with nothing lost', () => {
    expect(BRAND.wordmark.join('')).toBe(BRAND.name);
    expect(BRAND.wordmark.every((part) => part.length > 0)).toBe(true);
  });

  it('gives the home page one title, starting with the name', () => {
    expect(HOME_TITLE.startsWith(`${BRAND.name}: `)).toBe(true);
    expect(HOME_TITLE).not.toContain('—');
  });
});
