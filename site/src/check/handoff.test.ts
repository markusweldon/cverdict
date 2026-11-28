import { describe, expect, it } from 'vitest';
import { handoff } from './handoff';

describe('handoff', () => {
  it('gives the file once', () => {
    const f = new File(['{}'], 'package-lock.json');
    handoff.put(f);
    expect(handoff.take()).toBe(f);
    expect(handoff.take()).toBeNull();
  });
});
